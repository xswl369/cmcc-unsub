# -*- coding: utf-8 -*-
"""
core.py — 中国移动网上营业厅退订核心库（加密链 + 三接口 + CDP 工具）

逆向成果（2026-10-05 逐字节验证）：
  key = iv = "043AOQGK6ykklyZA"  (源码 ["043A","lyZA","OQGK",...] 取偶数下标拼接)
  算法: AES-128-CBC + Pkcs7，双层 base64 (外层b64(内层b64(AES密文)))
  token   = 双层b64(AES(手机号))
  msgId   = 双层b64(AES(str(毫秒时间戳)+nonce))，nonce 来自 sessionStorage.aqjg_cmcc_month
  列表: GET  /i/v1/busi/order/<token>
  退订: POST /i/v1/busi/ordermodify/<token>   body {inParam, msgId}
  发码: POST /i/v1/cust/commonSms/<token>     body {msgType:'02', busiCode, busiName, phoneNo}
"""
from __future__ import annotations

import asyncio
import base64
import configparser
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import websockets

try:  # Debian 打包名 pycryptodomex → Cryptodome；pip 包 pycryptodome → Crypto
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:  # pragma: no cover
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import pad, unpad

ROOT = Path(__file__).resolve().parents[1]
BASE = 'https://shop.10086.cn'
UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36')
KEY = b'043AOQGK6ykklyZA'


# ---------------- 配置 ----------------

def load_config() -> dict:
    cfg = configparser.ConfigParser()
    defaults = {'phone': '13800138000', 'port': '8686', 'cdp_port': '9333', 'access_token': ''}
    path = ROOT / 'config.ini'
    if path.exists():
        cfg.read(path, encoding='utf-8')
    sec = cfg['cmcc'] if cfg.has_section('cmcc') else {}

    def get(k):
        v = sec.get(k, defaults[k]) if hasattr(sec, 'get') else defaults[k]
        return (v or '').strip() or defaults[k]

    return {
        'phone': get('phone'),
        'port': int(get('port')),
        'cdp_port': int(get('cdp_port')),
        'access_token': get('access_token') if sec.get('access_token', '') else '',
    }


# ---------------- AES ----------------

def b64d(s: str) -> bytes:
    s = ''.join(s.split())
    s += '=' * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def aes_enc(plain: str) -> str:
    ct = AES.new(KEY, AES.MODE_CBC, KEY).encrypt(pad(plain.encode('utf-8'), 16))
    return b64e(ct)


def aes_dec(b64_cipher: str) -> str:
    pt = AES.new(KEY, AES.MODE_CBC, KEY).decrypt(b64d(b64_cipher))
    return unpad(pt, 16).decode('utf-8')


def enc_param(inner_b64: str) -> str:
    return b64e(inner_b64.encode('ascii'))


def dec_param(outer_b64: str) -> str:
    return b64d(outer_b64).decode('ascii')


def make_token(phone: str) -> str:
    return enc_param(aes_enc(phone))


def encrypt_body(payload: dict, nonce: str) -> dict:
    in_param = enc_param(aes_enc(json.dumps(payload, ensure_ascii=False, separators=(',', ':'))))
    msg_id = enc_param(aes_enc(str(int(time.time() * 1000)) + nonce))
    return {'inParam': in_param, 'msgId': msg_id}


def decrypt_resp(out_param: str) -> dict:
    return json.loads(aes_dec(dec_param(out_param)))


def build_order_infos(items: list[dict], sms_code: str) -> dict:
    return {'orderInfos': [
        {
            'busiType': it.get('busiType') or '01',
            'bizCode': it.get('bizCode') if it.get('bizCode') is not None else 'null',
            'busiCode': it['busiCode'],
            'spid': it.get('spid') if it.get('spid') is not None else 'null',
            'oprCode': '01',
            'smsCode': sms_code,
        } for it in items
    ]}


# ---------------- HTTP ----------------

class CmccAuthError(RuntimeError):
    """会话失效（服务端返回 500003）。"""


def http_get(url: str, cookie: str) -> str:
    req = urllib.request.Request(url, headers={
        'User-Agent': UA, 'Cookie': cookie, 'Referer': BASE + '/i/?f=busiqrydeal',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
    })
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode('utf-8', 'replace')


def http_post(url: str, body: dict, cookie: str) -> str:
    data = json.dumps(body, separators=(',', ':')).encode()
    req = urllib.request.Request(url, data=data, headers={
        'User-Agent': UA, 'Cookie': cookie, 'Referer': BASE + '/i/?f=busiqrydeal',
        'Content-Type': 'application/json;charset=UTF-8',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.read().decode('utf-8', 'replace')


def fetch_all_busi(cookie: str, phone: str) -> list[dict]:
    """拉全量业务（含前端不可退项），返回扁平列表。"""
    token = make_token(phone)
    raw = http_get(f'{BASE}/i/v1/busi/order/{token}?_={int(time.time()*1000)}', cookie)
    try:
        j = json.loads(raw)
    except Exception:
        raise RuntimeError(f'响应异常: {raw[:120]}')
    if j.get('retCode') == '500003':
        raise CmccAuthError('会话已失效（需重新登录）')
    if j.get('retCode') != '000000':
        raise RuntimeError(f"{j.get('retCode')} {j.get('retMsg')}")
    obj = decrypt_resp(j['data']['outParam'])
    out = []
    if isinstance(obj, list):
        for grp in obj:
            out.extend(grp.get('orderBusis') or [])
    return out


# ---------------- CDP ----------------

def cdp_up(cdp_port: int, timeout: float = 2) -> bool:
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{cdp_port}/json/version', timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def find_10086_tab(cdp_port: int):
    try:
        tabs = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{cdp_port}/json/list', timeout=5).read())
    except Exception as e:
        raise RuntimeError(f'连接 Chrome 调试口失败: {e}')
    return next((t for t in tabs if t.get('type') == 'page' and '10086' in t.get('url', '')), None)


def find_any_page_tab(cdp_port: int):
    """任意普通标签页。未登录时浏览器停在 about:blank，登录流程需要它能直接导航。"""
    try:
        tabs = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{cdp_port}/json/list', timeout=5).read())
    except Exception as e:
        raise RuntimeError(f'连接 Chrome 调试口失败: {e}')
    return next((t for t in tabs if t.get('type') == 'page'), None)


def find_page_tab(cdp_port: int):
    """保活线程用：优先 10086 页面，未登录时退回任意标签页。"""
    return find_10086_tab(cdp_port) or find_any_page_tab(cdp_port)


class CDPSession:
    """异步 CDP 会话（连到某个标签页）。"""

    def __init__(self, ws_url: str):
        self.url = ws_url
        self.ws = None
        self.mid = 0
        self.waiter = {}
        self.task = None
        # 事件订阅：Network.responseReceived 等推送按 method 入队，供 next_event 消费
        self.events: dict[str, list] = {}

    async def __aenter__(self):
        self.ws = await websockets.connect(self.url, max_size=80 * 1024 * 1024)
        self.task = asyncio.create_task(self._recv())
        return self

    async def __aexit__(self, *a):
        if self.task:
            self.task.cancel()
        if self.ws:
            await self.ws.close()

    async def _recv(self):
        async for raw in self.ws:
            msg = json.loads(raw)
            if 'id' in msg and msg['id'] in self.waiter:
                self.waiter.pop(msg['id']).set_result(msg)
            elif 'method' in msg:
                self.events.setdefault(msg['method'], []).append(msg)

    async def next_event(self, method: str, timeout: float = 10):
        """等待一个 CDP 事件；期间其它 method 的推送会留在队列里不丢。"""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            q = self.events.get(method)
            if q:
                return q.pop(0)
            await asyncio.sleep(0.05)
        return None

    async def cmd(self, method, params=None, timeout=30):
        self.mid += 1
        i = self.mid
        fut = asyncio.get_running_loop().create_future()
        self.waiter[i] = fut
        await self.ws.send(json.dumps({'id': i, 'method': method, 'params': params or {}}))
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self.waiter.pop(i, None)

    async def js(self, expr, await_p=False, timeout=30):
        # timeout 可调：页面主线程被同步 XHR 阻塞时 evaluate 会一起挂住，需短超时探测
        r = await self.cmd('Runtime.evaluate',
                            {'expression': expr, 'returnByValue': True, 'awaitPromise': await_p},
                            timeout=timeout)
        res = r.get('result', {})
        if res.get('exceptionDetails'):
            return {'__err__': res['exceptionDetails'].get('text')}
        return res.get('result', {}).get('value')


async def _grab_cookies_async(cdp_port: int):
    tab = find_10086_tab(cdp_port)
    if not tab:
        raise CmccAuthError('尚未登录中国移动，请点右上角「切换账号」完成登录')
    async with CDPSession(tab['webSocketDebuggerUrl']) as s:
        r = await s.cmd('Network.getAllCookies')
        cookies = r.get('result', {}).get('cookies', [])
        jar = '; '.join(
            f"{c['name']}={c['value']}" for c in cookies
            if c.get('domain', '') in ('.10086.cn', 'shop.10086.cn', '.shop.10086.cn', 'login.10086.cn'))
        nonce_enc = await s.js("sessionStorage.getItem('aqjg_cmcc_month')")

    nonce = ''
    if nonce_enc and isinstance(nonce_enc, str):
        try:
            nonce = aes_dec(dec_param(nonce_enc))
        except Exception:
            try:
                nonce = aes_dec(base64.b64decode(nonce_enc).decode())
            except Exception:
                pass
    return jar, nonce


def grab_cookies(cdp_port: int):
    """同步封装：返回 (cookie串, nonce)。"""
    return asyncio.run(_grab_cookies_async(cdp_port))


# ---------------- Chrome 启动 ----------------

def find_chrome() -> str | None:
    """跨平台查找 Chromium / Chrome / Edge 可执行文件。"""
    import shutil

    cands: list[Path] = []
    if os.name == 'nt':
        import winreg  # Windows-only; 延迟导入避免 Linux 启动失败
        for env in ('PROGRAMFILES', 'PROGRAMFILES(X86)', 'LOCALAPPDATA'):
            base = os.environ.get(env)
            if base:
                cands.append(Path(base) / 'Google' / 'Chrome' / 'Application' / 'chrome.exe')
        for hive, key in (
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe'),
        ):
            try:
                with winreg.OpenKey(hive, key) as k:
                    cands.append(Path(winreg.QueryValue(k, None)))
            except OSError:
                pass
        for env in ('PROGRAMFILES(X86)', 'PROGRAMFILES'):
            base = os.environ.get(env)
            if base:
                cands.append(Path(base) / 'Microsoft' / 'Edge' / 'Application' / 'msedge.exe')

    for name in ('chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable',
                 'chrome', 'microsoft-edge', 'msedge'):
        w = shutil.which(name)
        if w:
            cands.append(Path(w))
    cands += [Path(p) for p in (
        '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable', '/snap/bin/chromium', '/opt/chromium/chrome',
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
    )]  # 覆盖 Debian/Ubuntu/macOS 常见安装位置
    for c in cands:
        try:
            if c and c.exists():
                return str(c)
        except OSError:
            continue
    return None


BUSY_FILE = ROOT / 'data' / 'busy.until'


def set_busy(seconds: float) -> None:
    """标记登录/发码/提交进行中：页面同步 XHR 会阻塞 renderer，watchdog 不能当卡死。"""
    try:
        BUSY_FILE.parent.mkdir(parents=True, exist_ok=True)
        BUSY_FILE.write_text(str(time.time() + seconds))
    except OSError:
        pass


def clear_busy(grace: float = 8.0) -> None:
    """操作结束后保留少量宽限，避开收尾阶段仍在跑的同步请求。"""
    set_busy(grace)


def busy_until() -> float:
    try:
        return float(BUSY_FILE.read_text().strip())
    except (OSError, ValueError):
        return 0.0


def is_busy() -> bool:
    return busy_until() > time.time()


def page_responsive(cdp_port: int, timeout: float = 5.0) -> bool:
    """渲染进程是否还能响应 JS。调试口进程活着但 renderer 卡死时 cdp_up 仍为 True。"""
    try:
        tab = find_any_page_tab(cdp_port)
    except Exception:
        return False
    if not tab:
        return False

    async def probe():
        async with CDPSession(tab['webSocketDebuggerUrl']) as s:
            return await s.cmd('Runtime.evaluate',
                                {'expression': '1+1', 'returnByValue': True}, timeout=timeout)

    try:
        r = asyncio.run(probe())
        return r.get('result', {}).get('result', {}).get('value') == 2
    except Exception:
        return False


def kill_chrome() -> None:
    """只杀本项目的 Chromium 实例（按 profile 路径匹配，不动其它浏览器）。"""
    profile = ROOT / 'data' / 'chrome_profile'
    if os.name == 'nt':
        subprocess.run(['taskkill', '/F', '/FI', f'WINDOWTITLE eq *{profile.name}*'],
                       capture_output=True)
        return
    subprocess.run(['pkill', '-f', str(profile)], capture_output=True)
    time.sleep(1.5)


def ensure_chrome(cfg: dict, log=print, force: bool = False) -> bool:
    """确保调试口 Chrome 在线且 renderer 可响应；否则重启实例。"""
    if not force and cdp_up(cfg['cdp_port']):
        if page_responsive(cfg['cdp_port']):
            log('[chrome] 调试口已在线，直接复用')
            return True
        log('[chrome] 页面无响应，重启实例')
        force = True
    if force or cdp_up(cfg['cdp_port']):
        kill_chrome()
    exe = find_chrome()
    if not exe:
        log('[chrome] 未找到 Chrome/Edge，请手动安装')
        return False
    profile = ROOT / 'data' / 'chrome_profile'
    profile.mkdir(parents=True, exist_ok=True)
    args = [exe,
            f"--remote-debugging-port={cfg['cdp_port']}",
            f"--user-data-dir={profile}",
            '--no-first-run', '--no-default-browser-check',
            '--remote-allow-origins=*', '--disable-background-networking',
            '--disable-sync', '--disable-translate', '--mute-audio', '--no-pings',
            '--disable-extensions', '--disable-component-update',
            '--renderer-process-limit=2', '--disk-cache-size=33554432',
            '--disable-blink-features=AutomationControlled',
            f'--user-agent={UA}',
            # 460MB 设备上常驻渲染 10086 首页会持续吃满 CPU；保持空白页，需要时再导航
            'about:blank']
    kwargs: dict = {'close_fds': True, 'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL}
    if os.name == 'nt':
        kwargs['creationflags'] = 0x00000008  # DETACHED_PROCESS
    else:
        # 无显示器 ARM 设备：必须 headless + no-sandbox；start_new_session 脱离父进程避免随服务退出
        args[1:1] = ['--headless=new', '--no-sandbox', '--disable-gpu',
                      '--disable-dev-shm-usage', '--window-size=1280,900']
        kwargs['start_new_session'] = True
    log(f'[chrome] 启动: {exe}')
    subprocess.Popen(args, **kwargs)
    for _ in range(120):  # ARM 上冷启动较慢，最长等 60s
        time.sleep(0.5)
        if cdp_up(cfg['cdp_port']):
            log('[chrome] 已启动')
            return True
    log('[chrome] 启动超时')
    return False


if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    print('token 自检:', make_token('13800138000') == 'QTJoN3llWlFacGN5alN0MFVWc0VLUT09')
