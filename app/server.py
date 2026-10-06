# -*- coding: utf-8 -*-
"""
server.py — 移动退订网页端（纯 HTTP + 多会话版）

架构：
  · 无浏览器。登录/业务全部 HTTP，设备 460MB 内存可稳跑。
  · 多会话隔离：每个访客一个 sid（cookie 下发），各自独立的 PureLogin 实例、
    独立的图形码与登录态，互不干扰。
  · 会话 TTL + LRU 上限，防止内存泄漏。
  · 登录节流：同一 IP 1 分钟内只允许 N 次发码，规避移动 3007「批量IP账号登录」风控。
    实际瓶颈在移动侧：短信冷却按手机号走，每个号码 1 分钟一次。

API：
  GET  /api/state        当前会话登录态 + 业务数
  GET  /api/busi         当前会话的业务列表
  POST /api/sms          发退订短信码  {busiCode, busiName, confirm:'YES'}
  POST /api/unsub        提交退订      {busiCode, ..., smsCode, confirm:'YES'}
  POST /api/login/start  取图形码（换账号）
  POST /api/login/send   图形码 + 发短信
  POST /api/login/submit 短信码登录
  POST /api/login/logout 退出（销毁会话）
"""
from __future__ import annotations

import json
import re
import secrets
import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path

from flask import Flask, Response, jsonify, make_response, request

sys.path.insert(0, str(Path(__file__).parent))

import core  # noqa: E402
from core import (BASE, CmccAuthError, build_order_infos, encrypt_body,  # noqa: E402
                  fetch_all_busi, http_post, make_token)
from account_pool import AccountPool  # noqa: E402
from ip_pool import IPPool  # noqa: E402
from pure_login import PureLogin  # noqa: E402

app = Flask(__name__)
app.json.ensure_ascii = False

CFG = core.load_config()
_pool = IPPool(log=lambda *a: None)          # B: IPv6 源地址 / C: 代理
_accounts = AccountPool(Path(__file__).resolve().parents[1] / 'data' / 'accounts_pool.json')
UI = (Path(__file__).parent / 'ui.html').read_text(encoding='utf-8')

# ---------------- 会话管理 ----------------

SESSION_COOKIE = 'cmcc_sid'
ACCOUNT_COOKIE = 'cmcc_acct'     # 记住最近使用过的手机号（仅本机浏览器）
SESSION_TTL = 40 * 60          # 40 分钟无操作即回收
SESSION_MAX = 300              # 最多保留 300 个活跃会话
_sessions: 'OrderedDict[str, dict]' = OrderedDict()
_sess_lock = threading.Lock()


def _gc_locked() -> None:
    """清理过期/超量会话（调用方需持有 _sess_lock）。"""
    now = time.time()
    dead = [sid for sid, s in _sessions.items() if now - s['seen'] > SESSION_TTL]
    for sid in dead:
        _sessions.pop(sid, None)
    while len(_sessions) > SESSION_MAX:
        _sessions.popitem(last=False)


def _session() -> tuple[str, dict]:
    """取（或新建）当前访客的会话；无 cookie 时由调用方负责下发。"""
    sid = request.cookies.get(SESSION_COOKIE) or ''
    with _sess_lock:
        _gc_locked()
        s = _sessions.get(sid) if sid else None
        if s is None:
            sid = secrets.token_urlsafe(18)
            egress = _pool.pick(sid)       # 每个访客一个出口（B/C 方案）
            s = {
                'egress': egress,
                'login': PureLogin(log=lambda *a: None, persist=False,
                                   egress=egress),
                'seen': time.time(),
                'phone': '',
                'items': [],          # 业务列表缓存（减少移动接口压力）
                'items_at': 0.0,
                'send_at': 0.0,       # 最近一次发码时间（本地节流）
                'lock': threading.Lock(),   # 该会话的网络独占锁（不阻塞其他访客）
                'batch': {},          # phone -> {'login','captcha_img','sent_at','state','err'}
            }
            _sessions[sid] = s
        s['seen'] = time.time()
        _sessions.move_to_end(sid)
        return sid, s


def _send_at(phone: str) -> float:
    """取某手机号最后一次发码时间（跨会话共享，按号码节流）。"""
    with _sess_lock:
        return _phone_send_at.get(phone, 0.0)


def _mark_send(phone: str) -> None:
    with _sess_lock:
        _phone_send_at[phone] = time.time()


_phone_send_at: dict[str, float] = {}


def _attach_sid(resp, sid: str):
    resp.set_cookie(SESSION_COOKIE, sid, max_age=SESSION_TTL,
                    httponly=True, samesite='Lax')
    return resp


def _items(s: dict, ttl: float = 30.0) -> list:
    """业务列表短缓存：同一会话 30 秒内复用，避免打穿移动接口。"""
    now = time.time()
    if s['items'] and now - s['items_at'] < ttl:
        return s['items']
    lg = s['login']
    phone = s['phone'] or CFG['phone']
    items = fetch_all_busi(lg.cookie_header(), phone)
    s['items'], s['items_at'] = items, now
    return items


# ---------------- 节流（防移动 3007 风控） ----------------

LOGIN_WINDOW = 60.0
LOGIN_MAX_PER_IP = 120         # 每 IP 每分钟上限（100 人共用一条出口/同一 NAT 也够用）
_ip_hits: dict[str, list[float]] = {}
_ip_lock = threading.Lock()


def _client_ip() -> str:
    """Cloudflare 隧道后面的真实访客 IP（CF-Connecting-IP 优先）。"""
    for key in ('CF-Connecting-IP', 'True-Client-IP', 'X-Real-IP'):
        v = (request.headers.get(key) or '').strip()
        if v:
            return v
    xff = (request.headers.get('X-Forwarded-For') or '').split(',')[0].strip()
    return xff or (request.remote_addr or '')


def _ip_allow(ip: str) -> bool:
    now = time.time()
    with _ip_lock:
        hits = [t for t in _ip_hits.get(ip, []) if now - t < LOGIN_WINDOW]
        if len(hits) >= LOGIN_MAX_PER_IP:
            _ip_hits[ip] = hits
            return False
        hits.append(now)
        _ip_hits[ip] = hits
        return True


# ---------------- 页面 ----------------

@app.route('/')
def index():
    sid, _s = _session()
    return _attach_sid(make_response(Response(UI, mimetype='text/html')), sid)


# ---------------- 状态 / 列表 ----------------

@app.route('/api/state')
def api_state():
    sid, s = _session()
    lg = s['login']
    if not lg.sso_ready():
        return _attach_sid(jsonify(ok=True, logged_in=False,
                                   err='尚未登录，请点「切换账号」完成登录'), sid)
    try:
        with s['lock']:
            items = _items(s)
        return _attach_sid(jsonify(ok=True, logged_in=True,
                                   phone=s['phone'] or CFG['phone'],
                                   count=len(items)), sid)
    except CmccAuthError as e:
        return _attach_sid(jsonify(ok=True, logged_in=False, err=str(e)), sid)
    except Exception as e:
        return _attach_sid(jsonify(ok=True, logged_in=False, err=str(e)[:150]), sid)


@app.route('/api/busi')
def api_busi():
    sid, s = _session()
    try:
        with s['lock']:
            items = _items(s)
    except CmccAuthError as e:
        return _attach_sid(jsonify(ok=False, auth=False, err=str(e)), sid)
    except Exception as e:
        return _attach_sid(jsonify(ok=False, err=str(e)[:150]), sid)
    slim = [{k: b.get(k) for k in ('busiName', 'busiType', 'bizCode', 'busiCode', 'spid',
                                   'busiFee', 'isOrdered', 'isUnOrder', 'orderedTime', 'extinctTime')}
            for b in items]
    return _attach_sid(jsonify(ok=True, items=slim), sid)


# ---------------- 发码 / 退订 ----------------

def _nonce(s: dict) -> str:
    """业务接口要的 msgId（原 sessionStorage.aqjg_cmcc_month）。"""
    try:
        lg = s['login']
        st, txt = lg._req(f'{BASE}/v1/auth/loginfo?_={int(time.time() * 1000)}', timeout=20)
        return str((json.loads(txt) or {}).get('msgId') or '')
    except Exception:
        return ''


@app.route('/api/sms', methods=['POST'])
def api_sms():
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    if d.get('confirm') != 'YES':
        return _attach_sid(jsonify(ok=False, err='未确认'), sid)
    bc, nm = d.get('busiCode'), d.get('busiName') or d.get('busiCode')
    if not bc:
        return _attach_sid(jsonify(ok=False, err='缺少 busiCode'), sid)
    try:
        with s['lock']:
            lg = s['login']
            phone = s['phone'] or CFG['phone']
            body = encrypt_body({'msgType': '02', 'busiCode': bc, 'busiName': nm,
                                 'phoneNo': phone}, _nonce(s))
            raw = http_post(f'{BASE}/i/v1/cust/commonSms/{make_token(phone)}',
                            body, lg.cookie_header())
    except CmccAuthError as e:
        return _attach_sid(jsonify(ok=False, err=str(e)), sid)
    except Exception as e:
        return _attach_sid(jsonify(ok=False, err=f'请求失败: {e}'), sid)
    try:
        j = json.loads(raw)
    except Exception:
        return _attach_sid(jsonify(ok=False, err=f'响应异常: {raw[:150]}'), sid)
    if j.get('retCode') == '000000':
        return _attach_sid(jsonify(ok=True, accepted=True), sid)
    return _attach_sid(jsonify(ok=True, accepted=False,
                               err=f"{j.get('retCode')} {j.get('retMsg')}"), sid)


@app.route('/api/unsub', methods=['POST'])
def api_unsub():
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    if d.get('confirm') != 'YES':
        return _attach_sid(jsonify(ok=False, err='未确认'), sid)
    bc, code = d.get('busiCode'), (d.get('smsCode') or '').strip()
    if not bc or not code:
        return _attach_sid(jsonify(ok=False, err='缺少 busiCode 或 smsCode'), sid)
    try:
        with s['lock']:
            lg = s['login']
            phone = s['phone'] or CFG['phone']
            payload = build_order_infos([{
                'busiType': d.get('busiType') or '01',
                'bizCode': d.get('bizCode'),
                'busiCode': bc,
                'spid': d.get('spid'),
            }], code)
            body = encrypt_body(payload, _nonce(s))
            raw = http_post(f'{BASE}/i/v1/busi/ordermodify/{make_token(phone)}',
                            body, lg.cookie_header())
            s['items'], s['items_at'] = [], 0.0     # 写操作后失效缓存
    except CmccAuthError as e:
        return _attach_sid(jsonify(ok=False, err=str(e)), sid)
    except Exception as e:
        return _attach_sid(jsonify(ok=False, err=f'请求失败: {e}'), sid)
    try:
        j = json.loads(raw)
    except Exception:
        return _attach_sid(jsonify(ok=False, err=f'响应异常: {raw[:150]}'), sid)
    if j.get('retCode') == '000000':
        return _attach_sid(jsonify(ok=True, success=True), sid)
    return _attach_sid(jsonify(ok=True, success=False,
                               retCode=j.get('retCode'), retMsg=j.get('retMsg')), sid)


# ---------------- 登录 / 切换账号 ----------------

@app.route('/api/ip/status')
def api_ip_status():
    """出口池状态（B: IPv6 源地址 / C: 代理）。"""
    sid, s = _session()
    return _attach_sid(jsonify(ok=True, pool=_pool.status(),
                               mine=repr(s.get('egress'))), sid)


@app.route('/api/accounts')
def api_accounts():
    """账号池：已登录过的手机号（cookie 复用，无需重新收码）。"""
    sid, s = _session()
    cur = s['phone']
    return _attach_sid(jsonify(ok=True, accounts=_accounts.summary(),
                               current=cur if s['login'].sso_ready() else ''), sid)


@app.route('/api/accounts/use', methods=['POST'])
def api_accounts_use():
    """切换账号：从池子里恢复 cookie，不触发短信链路。"""
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    phone = (d.get('phone') or '').strip()
    item = _accounts.get(phone)
    if not item:
        return _attach_sid(jsonify(ok=False, err='账号池里没有这个号码'), sid)
    lg = PureLogin(log=lambda *a: None, persist=False, egress=s.get('egress'),
                   cookie_items=item['cookies'])
    s['login'], s['phone'] = lg, phone
    s['items'], s['items_at'] = [], 0.0
    try:
        with s['lock']:
            items = _items(s)
    except CmccAuthError as e:
        _accounts.remove(phone)
        return _attach_sid(jsonify(ok=False, err=f'登录态已失效：{e}'), sid)
    except Exception as e:
        return _attach_sid(jsonify(ok=False, err=str(e)[:150]), sid)
    resp = jsonify(ok=True, phone=phone, count=len(items))
    _attach_sid(resp, sid)
    resp.set_cookie(ACCOUNT_COOKIE, phone, max_age=180 * 86400, samesite='Lax')
    return resp


@app.route('/api/accounts/delete', methods=['POST'])
def api_accounts_delete():
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    phone = (d.get('phone') or '').strip()
    return _attach_sid(jsonify(ok=_accounts.remove(phone)), sid)


@app.route('/api/login/auto', methods=['POST'])
def api_login_auto():
    sid, s = _session()
    if s['login'].sso_ready():
        return _attach_sid(jsonify(ok=False, logged_in=True), sid)
    r = s['login'].start(s['phone'] or CFG['phone'])
    if not r.get('ok'):
        return _attach_sid(jsonify(ok=False, err=r.get('err')), sid)
    return _attach_sid(jsonify(ok=True, captcha_img=r.get('captcha_img')), sid)


@app.route('/api/login/start', methods=['POST'])
def api_login_start():
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    phone = (d.get('phone') or '').strip() or s['phone'] or CFG['phone']
    if not _ip_allow(_client_ip()):
        return _attach_sid(jsonify(ok=False, err='操作过于频繁，请稍后再试'), sid)
    r = s['login'].start(phone)
    if not r.get('ok'):
        return _attach_sid(jsonify(ok=False, err=r.get('err')), sid)
    s['phone'], s['items'], s['items_at'] = phone, [], 0.0
    return _attach_sid(jsonify(ok=True, captcha_img=r.get('captcha_img'),
                               phone=phone), sid)


@app.route('/api/login/send', methods=['POST'])
def api_login_send():
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    phone = (d.get('phone') or '').strip() or s['phone'] or CFG['phone']
    captcha = (d.get('captcha') or '').strip()
    # 按手机号节流（跨会话共享）：同一号码 55 秒内只发一次
    now = time.time()
    last = _send_at(phone) or s['send_at']
    if now - last < 55:
        left = int(55 - (now - last))
        return _attach_sid(jsonify(ok=False, err=f'请 {left} 秒后再试'), sid)
    if not _ip_allow(_client_ip()):
        return _attach_sid(jsonify(ok=False, err='操作过于频繁，请稍后再试'), sid)
    r = s['login'].send_sms(phone, captcha)
    if r.get('ok'):
        s['send_at'] = now
        s['phone'] = phone
        _mark_send(phone)
    return _attach_sid(jsonify(**r), sid)


@app.route('/api/login/submit', methods=['POST'])
def api_login_submit():
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    code = (d.get('code') or '').strip()
    if not code:
        return _attach_sid(jsonify(ok=False, err='请输入短信验证码'), sid)
    phone = s['phone'] or CFG['phone']
    r = s['login'].submit_code(code)
    if r.get('ok'):
        s['phone'] = phone
        s['items'], s['items_at'] = [], 0.0
        try:                       # 登录成功 → 落账号池，之后免验证码直接切号
            _accounts.upsert(phone, s['login'].cookie_items())
        except Exception as e:     # noqa: BLE001
            print('[accounts] save failed:', e)
    resp = jsonify(**r)
    _attach_sid(resp, sid)
    if r.get('ok'):
        resp.set_cookie(ACCOUNT_COOKIE, phone, max_age=180 * 86400, samesite='Lax')
    return resp


# ---------------- 批量登录（联通机制：按号码隔离，不共享短信会话） ----------------

BATCH_MAX = 20


def _batch_row(phone: str, item: dict) -> dict:
    return {'phone': phone, 'state': item.get('state') or 'ready',
            'captcha_img': item.get('captcha_img') or '',
            'err': item.get('err') or '',
            'sent': bool(item.get('sent_at')),
            'left': max(0, int(55 - (time.time() - item.get('sent_at', 0))))}


@app.route('/api/batch/state')
def api_batch_state():
    sid, s = _session()
    rows = [_batch_row(p, it) for p, it in s['batch'].items()]
    return _attach_sid(jsonify(ok=True, rows=rows), sid)


@app.route('/api/batch/start', methods=['POST'])
def api_batch_start():
    """粘贴多个手机号：逐个建独立会话并取图形码（不共享 cookie/验证码）。"""
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    raw = d.get('phones')
    if isinstance(raw, str):
        phones = re.split(r'[\s,，、;；]+', raw)
    elif isinstance(raw, list):
        phones = [str(x) for x in raw]
    else:
        phones = []
    seen, uniq = set(), []
    for p in phones:
        p = p.strip()
        if re.fullmatch(r'1\d{10}', p) and p not in seen:
            seen.add(p)
            uniq.append(p)
    uniq = uniq[:BATCH_MAX]
    if not uniq:
        return _attach_sid(jsonify(ok=False, err='没有识别到合法手机号'), sid)

    rows = []
    for phone in uniq:
        item = s['batch'].get(phone)
        if item and item.get('captcha_img') and item.get('state') != 'done':
            rows.append(_batch_row(phone, item))
            continue
        lg = PureLogin(log=lambda *a: None, persist=False, egress=s.get('egress'))
        r = lg.start(phone)
        item = {'login': lg, 'captcha_img': r.get('captcha_img') or '',
                'sent_at': 0.0, 'err': '' if r.get('ok') else (r.get('err') or '取码失败'),
                'state': 'ready' if r.get('ok') else 'error'}
        s['batch'][phone] = item
        rows.append(_batch_row(phone, item))
    return _attach_sid(jsonify(ok=True, rows=rows), sid)


@app.route('/api/batch/refresh', methods=['POST'])
def api_batch_refresh():
    """单个号码重拿图形码（不影响其它号码）。"""
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    phone = (d.get('phone') or '').strip()
    item = s['batch'].get(phone)
    if not item:
        return _attach_sid(jsonify(ok=False, err='该号码不在批量列表中'), sid)
    img = item['login'].refresh_captcha()
    item['captcha_img'] = img or item.get('captcha_img') or ''
    item['state'] = 'ready' if img else 'error'
    item['err'] = '' if img else '图形码刷新失败'
    return _attach_sid(jsonify(ok=bool(img), row=_batch_row(phone, item)), sid)


@app.route('/api/batch/send', methods=['POST'])
def api_batch_send():
    """给某个号码发短信码（图形码 + 风控 token 都在该号码自己的会话里）。"""
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    phone = (d.get('phone') or '').strip()
    captcha = (d.get('captcha') or '').strip()
    item = s['batch'].get(phone)
    if not item:
        return _attach_sid(jsonify(ok=False, err='该号码不在批量列表中'), sid)
    last = _send_at(phone) or item.get('sent_at') or 0
    if time.time() - last < 55:
        left = int(55 - (time.time() - last))
        return _attach_sid(jsonify(ok=False, err=f'该号码 {left} 秒后可再发'), sid)
    if not _ip_allow(_client_ip()):
        return _attach_sid(jsonify(ok=False, err='操作过于频繁，请稍后再试'), sid)
    r = item['login'].send_sms(phone, captcha)
    if r.get('ok'):
        item['sent_at'], item['state'], item['err'] = time.time(), 'sent', ''
        _mark_send(phone)
    else:
        item['state'], item['err'] = 'error', r.get('err') or '发送失败'
        if r.get('captcha_img'):
            item['captcha_img'] = r['captcha_img']
    out = dict(r)
    out['row'] = _batch_row(phone, item)
    return _attach_sid(jsonify(**out), sid)


@app.route('/api/batch/submit', methods=['POST'])
def api_batch_submit():
    """提交短信码；成功即把 cookie 写入账号池。"""
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    phone = (d.get('phone') or '').strip()
    code = (d.get('code') or '').strip()
    item = s['batch'].get(phone)
    if not item:
        return _attach_sid(jsonify(ok=False, err='该号码不在批量列表中'), sid)
    if not code:
        return _attach_sid(jsonify(ok=False, err='请输入短信验证码'), sid)
    r = item['login'].submit_code(code)
    if r.get('ok'):
        item['state'], item['err'] = 'done', ''
        try:
            _accounts.upsert(phone, item['login'].cookie_items())
        except Exception as e:     # noqa: BLE001
            print('[accounts] batch save failed:', e)
    else:
        item['state'], item['err'] = 'error', r.get('err') or '登录失败'
        if r.get('captcha_img'):
            item['captcha_img'] = r['captcha_img']
    out = dict(r)
    out['row'] = _batch_row(phone, item)
    return _attach_sid(jsonify(**out), sid)


@app.route('/api/batch/use', methods=['POST'])
def api_batch_use():
    """把批量里登录成功的号码设为当前操作账号。"""
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    phone = (d.get('phone') or '').strip()
    item = s['batch'].get(phone)
    if not item or item.get('state') != 'done':
        acc = _accounts.get(phone)
        if not acc:
            return _attach_sid(jsonify(ok=False, err='该号码尚未登录成功'), sid)
        s['login'] = PureLogin(log=lambda *a: None, persist=False,
                               egress=s.get('egress'),
                               cookie_items=acc['cookies'])
    s['login'], s['phone'] = item['login'], phone
    s['items'], s['items_at'] = [], 0.0
    try:
        with s['lock']:
            items = _items(s)
    except Exception as e:     # noqa: BLE001
        return _attach_sid(jsonify(ok=False, err=str(e)[:150]), sid)
    return _attach_sid(jsonify(ok=True, phone=phone, count=len(items)), sid)


@app.route('/api/login/logout', methods=['POST'])
def api_login_logout():
    sid, s = _session()
    phone = s['phone']
    if phone and not (request.get_json(force=True, silent=True) or {}).get('keep'):
        _accounts.remove(phone)     # 主动退出 = 把该号码移出账号池
    s['login'].logout()
    with _sess_lock:
        _sessions.pop(sid, None)
    return _attach_sid(jsonify(ok=True), sid)


def _warm_pool():
    """后台预热出口池：首次访问不必等 IPv6 DAD。"""
    try:
        st = _pool.status()
        print('[ippool] ready: %s' % st)
    except Exception as e:      # noqa: BLE001
        print('[ippool] warm failed: %s' % e)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=CFG['port'])
    ap.add_argument('--host', default='0.0.0.0')
    args = ap.parse_args()
    print('=' * 62)
    print('  中国移动 · 业务退订网页端（纯 HTTP / 多会话）')
    print(f'  本机: http://127.0.0.1:{args.port}')
    print('=' * 62)
    threading.Thread(target=_warm_pool, daemon=True).start()
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == '__main__':
    main()
