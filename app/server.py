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
from concurrent.futures import ThreadPoolExecutor
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
VISITOR_COOKIE = 'cmcc_uid'      # 访客身份：账号池归属与隔离的依据
VISITOR_TTL = 180 * 86400        # 180 天
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
    uid = (request.cookies.get(VISITOR_COOKIE) or '').strip()
    with _sess_lock:
        _gc_locked()
        s = _sessions.get(sid) if sid else None
        if s is None:
            sid = secrets.token_urlsafe(18)
            egress = _pool.pick(sid)       # 每个访客一个出口（B/C 方案）
            if not uid:
                uid = secrets.token_urlsafe(24)
            s = {
                'uid': uid,               # 账号池归属：别人的账号本访客看不到
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
    with _sess_lock:
        uid = (_sessions.get(sid) or {}).get('uid')
    if uid:
        resp.set_cookie(VISITOR_COOKIE, uid, max_age=VISITOR_TTL,
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
    return _attach_sid(jsonify(ok=True, accounts=_accounts.summary(s['uid']),
                               current=cur if s['login'].sso_ready() else ''), sid)


@app.route('/api/accounts/use', methods=['POST'])
def api_accounts_use():
    """切换账号：从池子里恢复 cookie，不触发短信链路。"""
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    phone = (d.get('phone') or '').strip()
    item = _accounts.get(phone, s['uid'])
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
        _accounts.remove(phone, s['uid'])
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
    return _attach_sid(jsonify(ok=_accounts.remove(phone, s['uid'])), sid)


# ---------------- 直登（用户自带验证码，本站不发码） ----------------
#
# 发短信这一步发生在用户自己的手机/网络上（他自己的 IP），本站只接收
# 手机号 + 短信码完成登录。实测 login.htm 不校验图形码，所以这条路不需要
# 图形码，也不需要本站发起任何短信请求 —— 从根上绕开"同一 IP 批量发码"风控。

PHONE_CODE_RE = re.compile(r'^1\d{10}$')


def _direct_login(s: dict, phone: str, code: str, egress=None) -> dict:
    """用手机号+短信码登录，成功后写入账号池。

    码由用户在自己的浏览器（自己的 IP）上从 10086.cn 获取，
    本站只负责用「手机号 + 码」完成 login.htm 这一步。
    任何网络异常都收敛成 {'ok': False, 'err': ...}，不让调用方冒 500。
    """
    try:
        lg = PureLogin(log=lambda *a: None, persist=False,
                       egress=egress if egress is not None else s.get('egress'))
        r = lg.start_direct(phone)
        if not r.get('ok'):
            return {'phone': phone, 'ok': False,
                    'err': r.get('err') or '登录页连接失败'}
        out = lg.submit_code(code)
        if not out.get('ok'):
            print('[direct] %s server said: %r' % (phone, out), flush=True)
            return {'phone': phone, 'ok': False,
                    'err': out.get('err') or '登录失败'}
        try:
            _accounts.upsert(phone, lg.cookie_items(), owner=s['uid'])
        except Exception as e:      # noqa: BLE001
            print('[accounts] direct save failed:', e)
        return {'phone': phone, 'ok': True, 'login': lg}
    except Exception as e:          # noqa: BLE001
        print('[direct] %s failed: %r' % (phone, e))
        return {'phone': phone, 'ok': False,
                'err': '网络异常，请重试（%s）' % type(e).__name__}


@app.route('/api/login/direct', methods=['POST'])
def api_login_direct():
    """本站不发码：用户自己在 10086.cn 取码，这里用手机号+码登录。"""
    sid, s = _session()
    d = request.get_json(force=True, silent=True) or {}
    phone = (d.get('phone') or '').strip()
    code = (d.get('code') or '').strip()
    if not PHONE_CODE_RE.match(phone):
        return _attach_sid(jsonify(ok=False, err='请输入 11 位手机号'), sid)
    if not (code.isdigit() and 4 <= len(code) <= 8):
        return _attach_sid(jsonify(ok=False, err='请输入收到的短信验证码'), sid)
    if not _ip_allow(_client_ip()):
        return _attach_sid(jsonify(ok=False, err='操作过于频繁，请稍后再试'), sid)

    _t0 = time.time()
    r = _direct_login(s, phone, code)
    print('[direct] %s ok=%s %.1fs err=%s' % (
        phone, r['ok'], time.time() - _t0, r.get('err') or ''), flush=True)
    if not r['ok']:
        return _attach_sid(jsonify(ok=False, err=r.get('err') or '登录失败'), sid)

    s['login'], s['phone'] = r['login'], phone
    s['items'], s['items_at'] = [], 0.0
    try:
        with s['lock']:
            items = _items(s)
        count = len(items)
    except CmccAuthError as e:
        return _attach_sid(jsonify(ok=False, err=f'登录成功但读取业务失败：{e}'), sid)
    except Exception as e:      # noqa: BLE001
        count = 0
        print('[direct] list failed:', e)
    resp = jsonify(ok=True, phone=phone, count=count)
    _attach_sid(resp, sid)
    resp.set_cookie(ACCOUNT_COOKIE, phone, max_age=180 * 86400, samesite='Lax')
    return resp


@app.route('/api/login/logout', methods=['POST'])
def api_login_logout():
    sid, s = _session()
    phone = s['phone']
    if phone and not (request.get_json(force=True, silent=True) or {}).get('keep'):
        _accounts.remove(phone, s['uid'])     # 主动退出 = 把该号码移出账号池
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
