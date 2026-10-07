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
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
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


# 已确认连不通的 v6 源地址（前缀失效等），60 秒内不再重试，避免每次白等
_DEAD_V6: dict[str, float] = {}
_DEAD_V6_TTL = 60.0


def _v6_dead(addr: str) -> bool:
    ts = _DEAD_V6.get(addr)
    if ts is None:
        return False
    if time.time() - ts > _DEAD_V6_TTL:
        _DEAD_V6.pop(addr, None)
        return False
    return True


class _BindHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS 连接绑定到指定 IPv6 源地址（B 方案：源地址轮换）。

    出口失效时（路由被回收、前缀变化）必须尽快放弃并走默认线路，
    否则每个请求都要等到 socket 超时，前端表现成"点了没反应"。
    """

    V6_CONNECT_TIMEOUT = 3.0      # 单次 v6 尝试上限，远小于整体 timeout

    def __init__(self, host, source_addr=None, **kwargs):
        self._src = source_addr
        super().__init__(host, **kwargs)

    def connect(self):
        if not self._src or _v6_dead(self._src):
            return super().connect()
        # 必须显式要 AF_INET6：默认 getaddrinfo 会先返回 IPv4，导致源地址绑不上
        try:
            infos = socket.getaddrinfo(self.host, self.port,
                                       socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            # 目标没有 AAAA 记录 → 回退普通连接，别让整条链路失败
            return super().connect()
        for af, socktype, proto, _canon, sa in infos:
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                # 先试出网能力，再放宽到真实超时（连接成功后读写仍用原超时）
                sock.settimeout(min(self.V6_CONNECT_TIMEOUT, self.timeout or 3.0))
                sock.bind((self._src, 0))
                sock.connect(sa)
                sock.settimeout(self.timeout)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                return
            except OSError:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
        # v6 源地址不通（前缀失效等）→ 标记并回退默认连接
        _DEAD_V6[self._src] = time.time()
        return super().connect()


SO_BINDTODEVICE = 25          # Linux: 把 socket 绑到指定网卡


class _IfaceHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS 连接绑定到指定网卡（多上行出口，真实公网 IP）。

    手机同时有 WiFi 与蜂窝两条上行时，绑不同网卡出网会得到不同公网 IP，
    可把"同一台设备登多个号"拆成"多台设备"。
    """

    def __init__(self, host, iface=None, **kwargs):
        self._iface = iface
        super().__init__(host, **kwargs)

    def connect(self):
        if not self._iface:
            return super().connect()
        last = None
        for af, socktype, proto, _c, sa in socket.getaddrinfo(
                self.host, self.port, socket.AF_INET, socket.SOCK_STREAM):
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(self.timeout)
                sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE,
                                self._iface.encode())
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
        # 绑卡失败（权限不足等）→ 回退默认线路
        return super().connect()


class _IfaceHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, iface):
        super().__init__()
        self._iface = iface

    def https_open(self, req):
        return self.do_open(
            lambda host, **kw: _IfaceHTTPSConnection(host, iface=self._iface, **kw),
            req)


class _BindHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, source_addr):
        super().__init__()
        self._src = source_addr

    def https_open(self, req):
        return self.do_open(
            lambda host, **kw: _BindHTTPSConnection(host, source_addr=self._src, **kw),
            req)


# 设备指纹缓存：seed -> (deviceId, source)。
# seed 为手机号时，同一号码始终得到同一个设备指纹；不同号码互不相同。
_DEVICE_CACHE: dict[str, tuple[str, str]] = {}
_DEVICE_CACHE_LOCK = __import__('threading').Lock()


def device_identity(seed: str = '') -> tuple[str, str]:
    """返回 (deviceId, source)，格式对齐官方 device-fingerprint.js。

    deviceId = 32位hex(visitorId) + '_' + 32位hex(instanceId)
    source   = 'cache'

    传入 seed（手机号）时派生确定性指纹：同一号码每次都得到同一设备，
    不同号码各自独立 —— 避开移动的「同设备登录号码数」限制。
    不传 seed 时退化为随机指纹。
    """
    if not seed:
        return '%s_%s' % (uuid.uuid4().hex, uuid.uuid4().hex), 'cache'
    with _DEVICE_CACHE_LOCK:
        hit = _DEVICE_CACHE.get(seed)
        if hit:
            return hit
    # 用两个不同的盐做 md5，得到两段 32 位 hex（确定性且互不可推）
    import hashlib
    visitor = hashlib.md5(('cmcc-v1|' + seed).encode('utf-8')).hexdigest()
    instance = hashlib.md5(('cmcc-v1-inst|' + seed).encode('utf-8')).hexdigest()
    val = ('%s_%s' % (visitor, instance), 'cache')
    with _DEVICE_CACHE_LOCK:
        _DEVICE_CACHE[seed] = val
    return val


def et(plain: str) -> str:
    """等价页面里的 et()：RSA/ECB/PKCS1v1.5 → base64。"""
    cipher = PKCS1_v1_5.new(_RSA_KEY)
    return base64.b64encode(cipher.encrypt(plain.encode('utf-8'))).decode('ascii')


class PureLogin:
    """纯 HTTP 登录会话。cookies 持久化到文件，供业务接口复用。"""

    def __init__(self, log=print, persist=True, cookie_file=None, egress=None,
                 cookie_items=None, device_id=None):
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
            elif getattr(egress, 'bind_iface', ''):
                handlers.append(_IfaceHTTPSHandler(egress.bind_iface))  # D：多上行
            elif getattr(egress, 'src_addr', ''):
                handlers.append(_BindHTTPSHandler(egress.src_addr))    # B：源地址
        self.opener = urllib.request.build_opener(*handlers)
        if cookie_items:                      # 从账号池恢复登录态
            self.set_cookies(cookie_items)
        self.device_id = device_id            # 该账号专属设备指纹（None=按号码派生）
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

    def start_direct(self, phone: str):
        """直接登录预备：只建立会话，不取图形码（login.htm 不校验图形码）。

        用于"用户自己在手机上取码"的链路：发短信这一步发生在用户自己的
        手机/网络（他自己的 IP），本站只负责用手机号+短信码完成登录。
        """
        self.phone = phone or self.phone
        self.captcha_answer = ''
        self.jar.clear()
        st, _ = self._req(LOGIN_URL, timeout=25)
        if st != 200:
            return {'ok': False, 'err': f'登录页打开失败 HTTP {st}'}
        return {'ok': True, 'phone': self.phone}

    def submit_code(self, code: str):
        """提交短信码 → 跟随 assertAcceptURL 落 SSO cookie。"""
        code = (code or '').strip()
        if not code:
            return {'ok': False, 'err': '请输入短信验证码'}
        ts = int(time.time() * 1000)
        enc = et(code)
        if self.device_id:
            device_id, device_src = self.device_id, 'cache'
        else:
            device_id, device_src = device_identity(self.phone)
        data = {
            'accountType': '01',
            'account': et(self.phone),
            'password': enc,
            'smsPwd': enc,
            'pwdType': '02',
            'email_sms': '',
            'inputCode': self.captcha_answer,
            'backUrl': BACK_URL,
            'rememberMe': '0',
            'channelID': CHANNEL_ID,
            'loginMode': '',
            'protocol': 'https:',
            'isNew': '1',
            'deviceId': device_id,
            'deviceIdSource': device_src,
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
            if code_v == '6113':
                return {'ok': False,
                        'err': 'App 验证码错误或已过期，请重新获取'}
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

