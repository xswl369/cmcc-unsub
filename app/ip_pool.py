# -*- coding: utf-8 -*-
"""ip_pool.py — 出口 IP 池

B 方案（内置，零成本）：IPv6 源地址轮换
  设备有公网 IPv6 段 2001:db8:1234:5678::/64，可自由在该 /64 内取地址。
  实测：不同源地址出网，外部看到的 IP 不同 → 对移动风控是不同来源。

C 方案（多节点）：代理池
  每台设备/线路注册一个 node，按 sid 一致性分配。
  配置放 data/ip_pool.json，支持运行时新增节点，无需重启。

对外只暴露 pick(sid) -> Egress，上层不关心底层是 IPv6 还是代理。
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import subprocess
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CFG_FILE = ROOT / 'data' / 'ip_pool.json'

DEFAULT_CFG = {
    'ipv6': {
        'enabled': True,
        'iface': 'wlan0',
        'prefix': '2001:db8:1234:5678::/64',   # 自动探测失败时用这个
        'count': 24,                            # 预生成多少个源地址
        'ttl': 1800,                            # 每个地址用多久（秒）后换新
    },
    'proxies': [],        # C 方案：['socks5://user:pass@host:port', ...]
    'strategy': 'sid',    # sid=按访客一致性分配 | round=轮询
    # D 方案：多上行网卡（每张卡一个真实公网 IP）
    'uplinks': [],        # ['wlan0', 'ccmni1', ...]
}

_lock = threading.Lock()
_round_robin = 0


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ''


def _rc(cmd) -> int:
    """执行命令只要返回码；任何环境错误都当成失败，绝不向上抛。"""
    try:
        return subprocess.run(cmd, capture_output=True, timeout=10).returncode
    except Exception:
        return 1


def _addr_change(action: str, addr: str, iface: str) -> int:
    """增删 IPv6 地址：先直接执行，被拒绝就借 su 再试一次。"""
    cmd = ['ip', '-6', 'addr', action, '%s/64' % addr, 'dev', iface]
    rc = _rc(cmd)
    if rc == 0:
        return 0
    return _rc(['su', '-c', ' '.join(cmd)])


# 不可作出口的 IPv6 前缀：文档段 / ULA / 链路本地 / 组播
_BAD_V6 = ('2001:db8:', 'fc', 'fd', 'fe80:', 'ff')


def _routable_v6(addr: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(addr)
    except Exception:
        return False
    if ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_loopback:
        return False
    low = addr.lower()
    return not any(low.startswith(p) for p in ('2001:db8:', 'fe80:', 'ff'))


def _existing_global(iface: str):
    """网卡上可用的公网 IPv6（过滤文档段等不可路由地址）。"""
    out = []
    for line in _run(['ip', '-6', 'addr', 'show', 'dev', iface, 'scope', 'global']).splitlines():
        line = line.strip()
        if not line.startswith('inet6 '):
            continue
        addr = line.split()[1].split('/')[0]
        if _routable_v6(addr):
            out.append(addr)
    return out


def _load_cfg():
    cfg = json.loads(json.dumps(DEFAULT_CFG))
    try:
        if CFG_FILE.exists():
            user = json.loads(CFG_FILE.read_text(encoding='utf-8'))
            for k, v in user.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
    except Exception:
        pass
    return cfg


class Egress:
    """一个出口：代理 / IPv6 源地址 / 网卡绑定（三选一）。"""

    __slots__ = ('label', 'src_addr', 'iface', 'proxy', 'born', 'bind_iface')

    def __init__(self, label, src_addr='', iface='', proxy='', bind_iface=''):
        self.label = label
        self.src_addr = src_addr
        self.iface = iface
        self.proxy = proxy
        self.bind_iface = bind_iface      # 绑这个网卡出网（多上行 IP）
        self.born = time.time()

    @property
    def is_proxy(self):
        return bool(self.proxy)

    def __repr__(self):
        kind = ('proxy:' + self.proxy if self.is_proxy
                else (self.src_addr or ('iface:' + self.bind_iface)))
        return '<Egress %s %s>' % (self.label, kind)


def _detect_ipv6_prefix(iface):
    """从网卡上取一个全局 IPv6，推出 /64 前缀。"""
    out = _run(['ip', '-6', 'addr', 'show', 'dev', iface, 'scope', 'global'])
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('inet6 '):
            addr = line.split()[1].split('/')[0]
            try:
                return str(ipaddress.IPv6Network('%s/64' % addr, strict=False))
            except Exception:
                continue
    return ''


class IPPool:
    def __init__(self, log=print):
        self.log = log
        self.cfg = _load_cfg()
        self._egresses = []
        self._added_addrs = []
        self._built_at = 0.0

    # ---------- IPv6 源地址池（B） ----------

    def _build_ipv6(self):
        v6 = self.cfg['ipv6']
        if not v6.get('enabled'):
            return []
        iface = v6.get('iface') or 'wlan0'
        prefix = _detect_ipv6_prefix(iface) or v6.get('prefix') or ''
        if not _routable_v6(prefix.split('/')[0]):
            self.log('[ippool] 前缀不可路由(%s)，跳过 B 方案' % prefix)
            return []
        try:
            net = ipaddress.IPv6Network(prefix, strict=False)
        except Exception:
            return []

        base = net.network_address.exploded.rsplit(':', 3)[0]
        out = []

        # 1) 先吃网卡上已经存在的公网地址（boot 脚本会预置一批）
        for i, addr in enumerate(_existing_global(iface)):
            out.append(Egress('v6-p%d' % i, src_addr=addr, iface=iface))

        # 2) 不够再自己追加（本地 root / su 可用时）
        n = max(1, min(int(v6.get('count') or 16), 200))
        for i in range(n - len(out)):
            rnd = int.from_bytes(os.urandom(6), 'big') or (i + 2)
            addr = str(ipaddress.IPv6Address(
                '%s:%x:%x:%x' % (base, rnd >> 32 & 0xffff,
                                 rnd >> 16 & 0xffff, rnd & 0xffff)))
            if _addr_change('add', addr, iface) != 0:
                break             # 没有权限就停下，用现有地址继续
            self._added_addrs.append(addr)
            out.append(Egress('v6-%d' % i, src_addr=addr, iface=iface))

        # 等 DAD 校验完成：tentative 地址绑定会报 EADDRNOTAVAIL(99)
        self._wait_dad(iface, [e.src_addr for e in out])
        self.log('[ippool] IPv6 出口 %d 个（%s）' % (len(out), prefix))
        return out

    def _wait_dad(self, iface, addrs, timeout=12.0):
        """等 IPv6 地址通过 DAD（不再处于 tentative/dadfailed）。"""
        pend = set(addrs)
        t0 = time.time()
        while pend and time.time() - t0 < timeout:
            out = _run(['ip', '-6', 'addr', 'show', 'dev', iface])
            for line in out.splitlines():
                line = line.strip()
                if not line.startswith('inet6 '):
                    continue
                parts = line.split()
                addr = parts[1].split('/')[0]
                state = ' '.join(parts[2:])
                if addr in pend and 'tentative' not in state and 'dadfailed' not in state:
                    pend.discard(addr)
            if pend:
                time.sleep(0.4)
        if pend:
            self.log('[ippool] %d 个地址 DAD 未完成，已跳过' % len(pend))

    # ---------- 代理池（C） ----------

    def _build_proxies(self):
        out = []
        for i, p in enumerate(self.cfg.get('proxies') or []):
            if isinstance(p, str) and p.strip():
                out.append(Egress('proxy-%d' % i, proxy=p.strip()))
        if out:
            self.log('[ippool] 代理出口 %d 个' % len(out))
        return out

    # ---------- 多上行网卡（D） ----------

    def _build_uplinks(self):
        out = []
        for i, iface in enumerate(self.cfg.get('uplinks') or []):
            if isinstance(iface, str) and iface.strip():
                out.append(Egress('up-%d' % i, iface=iface.strip(),
                                  bind_iface=iface.strip()))
        if out:
            self.log('[ippool] 上行网卡出口 %d 个' % len(out))
        return out

    # ---------- 对外 ----------

    def _rebuild(self):
        with _lock:
            iface = self.cfg['ipv6'].get('iface', 'wlan0')
            for addr in self._added_addrs:
                _addr_change('del', addr, iface)
            self._added_addrs = []
            self._egresses = (self._build_uplinks() + self._build_ipv6()
                              + self._build_proxies())
            self._built_at = time.time()

    def egresses(self):
        ttl = float(self.cfg['ipv6'].get('ttl') or 1800)
        if not self._egresses or time.time() - self._built_at > ttl:
            self._rebuild()
        return list(self._egresses)

    def pick(self, sid=''):
        """给一个访客分配出口：优先代理（C），否则 IPv6 源地址（B）。"""
        global _round_robin
        pool = self.egresses()
        if not pool:
            return None
        proxies = [e for e in pool if e.is_proxy]
        cands = proxies or pool
        strategy = self.cfg.get('strategy') or 'sid'
        if strategy == 'round' or not sid:
            with _lock:
                e = cands[_round_robin % len(cands)]
                _round_robin += 1
            return e
        h = int(hashlib.sha256(sid.encode()).hexdigest()[:8], 16)
        return cands[h % len(cands)]

    def status(self):
        pool = self.egresses()
        return {
            'total': len(pool),
            'uplink': len([e for e in pool if e.bind_iface]),
            'ipv6': len([e for e in pool if e.src_addr and not e.is_proxy]),
            'proxy': len([e for e in pool if e.is_proxy]),
            'sample': [e.label for e in pool[:5]],
        }


if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    pool = IPPool()
    print('status:', json.dumps(pool.status(), ensure_ascii=False))
    for s in range(5):
        e = pool.pick('session-%d' % s)
        print('  session-%d -> %s' % (s, e))
