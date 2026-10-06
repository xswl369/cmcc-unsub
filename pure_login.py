# -*- coding: utf-8 -*-
"""pure_login.py — 中国移动网页登录（纯 HTTP，无浏览器）

为什么存在：设备仅 460MB 内存，Chromium 常驻 ~360MB，登录提交瞬间必 OOM 崩溃。
本模块用 http.cookiejar + RSA(与页面 JSEncrypt 同款 PKCS#1 v1.5) 完整复刻
login.10086.cn 的短信随机码登录链路，不跑任何渲染进程。

链路：
  1. GET  /login.html          → 建立会话 cookie
  2. GET  /captchazh.htm       → 图形码 PNG（服务端把答案绑到当前会话）
  3. POST /verifyCaptcha.htm   → 预校验图形码（可选）
  4. POST /loadToken.action    → 风控 token
  5. POST /sendRandomCodeAction.action (+Xa-before: token) → 发短信
  6. POST /login.htm           → assertAcceptURL + artifact
  7. GET  assertAcceptURL?...  → 落 SSO cookie（cmccssotoken / is_login …）

函数与 LoginFlow 对齐：start / send_sms / submit_code / logout。
"""
from __future__ import annotations

import base64
import http.client
import http.cookiejar
import json
import pickle
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36')

LOGIN_HOST = 'https://login.10086.cn'
LOGIN_URL = (LOGIN_HOST + '/login.html?channelID=12003'
             '&backUrl=https%3A%2F%2Fshop.10086.cn%2Fi%2F%3Ff%3Dhome')
CHANNEL_ID = '12003'
BACK_URL = 'https://shop.10086.cn/i/?f=home'

# login_qr_fun.js 里 et() 用的公钥（JSEncrypt，PKCS#1 v1.5）
RSA_PUB_B64 = (
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsgDq4OqxuEisnk2F0EJFmw4xKa5IrcqEYHvqxPs2'
    'CHEg2kolhfWA2SjNuGAHxyDDE5MLtOvzuXjBx/5YJtc9zj2xR/0moesS+Vi/xtG1tkVaTCba+TV+Y5C61iyr'
    '3FGqr+KOD4/XECu0Xky1W9ZmmaFADmZi7+6gO9wjgVpU9aLcBcw/loHOeJrCqjp7pA98hRJRY+MML8MK15mn'
    'C4ebooOva+mJlstW6t/1lghR8WNV8cocxgcHHuXBxgns2MlACQbSdJ8c6Z3RQeRZBzyjfey6JCCfbEKouVrW'
    'IUuPphBL3OANfgp0B+QG31bapvePTfXU48TYK0M5kE+8LgbbWQIDAQAB'
)

COOKIE_FILE = Path('/opt/cmcc-unsub/data/http_cookies.pkl')
CAPTCHA_FILE = Path('/opt/cmcc-unsub/data/captcha.png')

try:  # Debian 包名 pycryptodomex → Cryptodome；pip 包 → Crypto
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA
except ImportError:  # pragma: no cover
    from Cryptodome.Cipher import PKCS1_v1_5
    from Cryptodome.PublicKey import RSA

_RSA_KEY = RSA.import_key(base64.b64decode(RSA_PUB_B64))


class _BindHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS 连接绑定到指定 IPv6 源地址（B 方案：源地址轮换）。"""

    def __init__(self, host, source_addr=None, **kwargs):
        self._src = source_addr
        super().__init__(host, **kwargs)

    def connect(self):
        if not self._src:
            return super().connect()
        # 必须显式要 AF_INET6：默认 getaddrinfo 会先返回 IPv4，导致源地址绑不上
        try:
            infos = socket.getaddrinfo(self.host, self.port,
                                       socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            # 目标没有 AAAA 记录 → 回退普通连接，别让整条链路失败
            return super().connect()
        last = None
        for af, socktype, proto, _canon, sa in infos:
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(self.timeout)
                sock.bind((self._src, 0))
                sock.connect(sa)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                return
            except OSError as exc:
                last = exc
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
        raise last or OSError('IPv6 connect failed')


class _BindHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, source_addr):
        super().__init__()
        self._src = source_addr

    def https_open(self, req):
        return self.do_open(
            lambda host, **kw: _BindHTTPSConnection(host, source_addr=self._src, **kw),
            req)


def et(plain: str) -> str:
    """等价页面里的 et()：RSA/ECB/PKCS1v1.5 → base64。"""
    cipher = PKCS1_v1_5.new(_RSA_KEY)
    return base64.b64encode(cipher.encrypt(plain.encode('utf-8'))).decode('ascii')


class PureLogin:
    """纯 HTTP 登录会话。cookies 持久化到文件，供业务接口复用。"""

    def __init__(self, log=print, persist=True, cookie_file=None, egress=None,
                 cookie_items=None):
        self.log = log
        self.persist = persist
        self.cookie_file = Path(cookie_file) if cookie_file else COOKIE_FILE
        self.jar = http.cookiejar.CookieJar()
        self.egress = egress
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if egress is not None:
            if getattr(egress, 'is_proxy', False):
                handlers.append(urllib.request.ProxyHandler(
                    {'http': egress.proxy, 'https': egress.proxy}))   # C：代理
            elif getattr(egress, 'src_addr', ''):
                handlers.append(_BindHTTPSHandler(egress.src_addr))    # B：源地址
        self.opener = urllib.request.build_opener(*handlers)
        if cookie_items:                      # 从账号池恢复登录态
            self.set_cookies(cookie_items)
        self.phone = ''
        self.token = ''
        self.captcha_answer = ''

    # ---------- 基础 ----------

    def _req(self, url, data=None, headers=None, timeout=25):
        h = {
            'User-Agent': UA,
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': LOGIN_URL,
            'Origin': LOGIN_HOST,
        }
        if headers:
            h.update(headers)
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        if body is not None:
            h['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
        req = urllib.request.Request(url, data=body, headers=h)
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return r.status, r.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', 'replace')

    def _req_bytes(self, url, timeout=25):
        req = urllib.request.Request(url, headers={
            'User-Agent': UA, 'Referer': LOGIN_URL, 'Accept': 'image/*,*/*;q=0.8'})
        with self.opener.open(req, timeout=timeout) as r:
            return r.status, r.read()

    def save_cookies(self):
        if not self.persist:
            return
        self.cookie_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cookie_file, 'wb') as f:
            pickle.dump([(c.name, c.value, c.domain, c.path) for c in self.jar], f)

    def load_cookies(self) -> bool:
        if not self.persist:
            return False
        try:
            with open(self.cookie_file, 'rb') as f:
                items = pickle.load(f)
        except Exception:
            return False
        for name, value, domain, path in items:
            self.jar.set_cookie(http.cookiejar.Cookie(
                version=0, name=name, value=value, port=None, port_specified=False,
                domain=domain, domain_specified=True, domain_initial_dot=domain.startswith('.'),
                path=path, path_specified=True, secure=True, expires=None,
                discard=False, comment=None, comment_url=None, rest={}))
        return True

    def cookie_header(self, domains=('.10086.cn', 'shop.10086.cn',
                                     '.shop.10086.cn', 'login.10086.cn')) -> str:
        return '; '.join(f'{c.name}={c.value}' for c in self.jar if c.domain in domains)

    def cookie_items(self) -> list:
        """导出 cookie 四元组供账号池持久化。"""
        return [{'name': c.name, 'value': c.value, 'domain': c.domain,
                 'path': c.path} for c in self.jar]

    def set_cookies(self, items: list) -> None:
        """从账号池恢复 cookie（登录态复用的唯一通道）。"""
        for it in items or []:
            try:
                name, value = str(it['name']), str(it['value'])
                domain = str(it.get('domain') or '.10086.cn')
                path = str(it.get('path') or '/')
            except (KeyError, TypeError, ValueError):
                continue
            self.jar.set_cookie(http.cookiejar.Cookie(
                version=0, name=name, value=value, port=None, port_specified=False,
                domain=domain, domain_specified=True,
                domain_initial_dot=domain.startswith('.'),
                path=path, path_specified=True, secure=True, expires=None,
                discard=False, comment=None, comment_url=None, rest={}))

    def sso_ready(self) -> bool:
        names = {c.name for c in self.jar}
        return 'cmccssotoken' in names or 'is_login' in names

    # ---------- 各步骤 ----------

    def start(self, phone: str = ''):
        """GET 登录页 → 取图形码 PNG（dataURL）。"""
        self.phone = phone or self.phone
        self.jar.clear()                      # 换账号必须换会话
        st, _ = self._req(LOGIN_URL, timeout=25)
        if st != 200:
            return {'ok': False, 'err': f'登录页打开失败 HTTP {st}'}
        st, png = self._req_bytes(f'{LOGIN_HOST}/captchazh.htm?type=12&t={int(time.time()*1000)}')
        if st != 200 or not png:
            return {'ok': False, 'err': f'图形码获取失败 HTTP {st}'}
        CAPTCHA_FILE.parent.mkdir(parents=True, exist_ok=True)
        CAPTCHA_FILE.write_bytes(png)
        data_url = 'data:image/png;base64,' + base64.b64encode(png).decode()
        return {'ok': True, 'captcha_img': data_url, 'captcha_required': True}

    def refresh_captcha(self):
        st, png = self._req_bytes(f'{LOGIN_HOST}/captchazh.htm?type=12&t={int(time.time()*1000)}')
        if st != 200 or not png:
            return ''
        CAPTCHA_FILE.write_bytes(png)
        return 'data:image/png;base64,' + base64.b64encode(png).decode()

    def send_sms(self, phone: str, captcha: str):
        """校验图形码 → loadToken → 发短信。"""
        if not phone or not captcha:
            return {'ok': False, 'err': '请填写手机号和图形验证码'}
        self.phone, self.captcha_answer = phone, captcha

        # 预校验（失败直接换图，不浪费一条短信）
        # 页面用 $.getJSON → 必须 GET 传参（POST 会一律判为无效）
        qs = urllib.parse.urlencode({'inputCode': captcha})
        st, txt = self._req(f'{LOGIN_HOST}/verifyCaptcha.htm?{qs}', timeout=20)
        ok_verify = False
        if st == 200:
            try:
                ok_verify = str(json.loads(txt).get('resultCode')) == '0'
            except Exception:
                ok_verify = bool(re.search(r'"?resultCode"?\s*[:=]\s*"?0', txt))
        if not ok_verify:
            return {'ok': False,
                    'err': '图形验证码错误，已自动换一张，请重填',
                    'captcha_img': self.refresh_captcha()}

        # 风控 token
        st, txt = self._req(f'{LOGIN_HOST}/loadToken.action',
                            {'userName': et(phone)}, timeout=20)
        token = ''
        try:
            token = str((json.loads(txt) or {}).get('result') or '')
        except Exception:
            token = ''
        self.token = token

        # 发短信（图形码同样要过 et()）
        st, txt = self._req(
            f'{LOGIN_HOST}/sendRandomCodeAction.action',
            {'userName': et(phone), 'inputCode': et(captcha),
             'type': '01', 'channelID': CHANNEL_ID},
            headers={'Xa-before': token}, timeout=25)
        code = (txt or '').strip().strip('"')
        if code == '0':
            return {'ok': True, 'msg': '短信已发送'}
        tips = {
            '1': '短信随机码暂时不能发送，请一分钟以后再试',
            '2': '短信随机码获取达到上限',
            '3': '短信随机码错误',
            '4005': '手机号码有误，请重新输入',
        }.get(code, f'发送失败（{code or txt[:40]}）')
        return {'ok': False, 'err': tips}

    def submit_code(self, code: str):
        """提交短信码 → 跟随 assertAcceptURL 落 SSO cookie。"""
        code = (code or '').strip()
        if not code:
            return {'ok': False, 'err': '请输入短信验证码'}
        ts = int(time.time() * 1000)
        data = {
            'accountType': '01',
            'account': et(self.phone),
            'password': et(code),
            'pwdType': '02',
            'email_sms': '',
            'inputCode': self.captcha_answer,
            'backUrl': BACK_URL,
            'rememberMe': '0',
            'channelID': CHANNEL_ID,
            'loginMode': '',
            'protocol': 'https:',
            'isNew': '1',
            'deviceId': 'pure-http-' + str(ts),
            'deviceIdSource': 'cache',
            'timestamp': str(ts),
        }
        st, txt = self._req(f'{LOGIN_HOST}/login.htm', data, timeout=45)
        if st != 200:
            return {'ok': False, 'err': f'登录请求失败 HTTP {st}'}
        try:
            j = json.loads(txt)
        except Exception:
            return {'ok': False, 'err': f'响应异常：{txt[:80]}'}

        if str(j.get('result')) != '0':
            code_v = str(j.get('code') or '')
            desc = j.get('desc') or ''
            if code_v == '6001':
                return {'ok': False, 'err': '短信验证码错误或已过期，请重新获取'}
            if code_v in ('8009', '8012', '8002'):
                return {'ok': False, 'err': desc or '账号被锁定或密码错误'}
            if code_v == '3012':
                return {'ok': False, 'err': desc or '验证码错误，请重试',
                        'captcha_img': self.refresh_captcha()}
            return {'ok': False, 'err': desc or f'登录失败（{code_v or j.get("result")}）'}

        # 已有账号提示（result==9）→ 用新账号继续
        if j.get('islocal') is True:
            url = BACK_URL
        else:
            base = str(j.get('assertAcceptURL') or '')
            if not base:
                return {'ok': False, 'err': '登录返回缺少跳转地址'}
            url = (f'{base}?backUrl={urllib.parse.quote(BACK_URL, safe="")}'
                   f'&artifact={j.get("artifact", "")}&type={j.get("type", "")}')
        st, _ = self._req(url, timeout=30)
        if not self.sso_ready():
            return {'ok': False, 'err': '登录跳转后未取得 SSO cookie，请重试'}
        self.save_cookies()
        return {'ok': True, 'phone': self.phone}

    def logout(self):
        self.jar.clear()
        if not self.persist:
            return 'ok'
        try:
            self.cookie_file.unlink()
        except OSError:
            pass
        return 'ok'


if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    lg = PureLogin()
    print(json.dumps(lg.start('13800138000'), ensure_ascii=False)[:200])

