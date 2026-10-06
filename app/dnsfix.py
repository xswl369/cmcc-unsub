"""dnsfix.py — Termux DNS 修复

问题：Termux 的 libc 解析器 gethostbyname 返回 EAI_NONAME，
但底层 UDP DNS 查询完全正常（实测 rcode=0，返回真实 IP）。

方案：把 DNS 查询用纯 socket 实现，monkey-patch socket.getaddrinfo，
让所有 Python 网络库（urllib/requests）都走这个能用的解析路径。
"""
from __future__ import annotations

import socket
import struct
import threading

_orig_getaddrinfo = socket.getaddrinfo
_cache: dict[str, list] = {}
_lock = threading.Lock()

DNS_SERVERS = ['223.5.5.5', '119.29.29.29', '192.168.21.1']


def _dns_query(name: str, qtype: int = 1, timeout: float = 5.0):
    """纯 socket UDP DNS 查询，返回 (ipv4_list, ipv6_list, cname)。"""
    tid = 0x1234
    header = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    qname = b''
    for part in name.rstrip('.').split('.'):
        qname += bytes([len(part)]) + part.encode('ascii', 'ignore')
    qname += b'\x00'
    packet = header + qname + struct.pack('!HH', qtype, 1)

    for srv in DNS_SERVERS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(packet, (srv, 53))
            data, _ = s.recvfrom(2048)
        except Exception:
            continue
        finally:
            s.close()

        if len(data) < 12 or (data[3] & 0x0f) != 0:
            continue
        ancount = struct.unpack('!H', data[6:8])[0]
        if ancount == 0:
            continue

        # 跳过 question
        i = 12
        while i < len(data) and data[i] != 0:
            if data[i] & 0xc0:
                i += 2
                break
            i += data[i] + 1
        if i < len(data) and data[i] == 0:
            i += 1
        i += 4

        v4, v6, cname = [], [], ''
        for _ in range(ancount):
            if i + 2 > len(data):
                break
            if data[i] & 0xc0 == 0xc0:
                i += 2
            else:
                while i < len(data) and data[i] != 0:
                    i += data[i] + 1
                i += 1
            if i + 10 > len(data):
                break
            rtype, _rc, _ttl, rdlen = struct.unpack('!HHIH', data[i:i + 10])
            i += 10
            rd = data[i:i + rdlen]
            if rtype == 1 and rdlen == 4:
                v4.append(socket.inet_ntoa(rd))
            elif rtype == 28 and rdlen == 16:
                v6.append(socket.inet_ntop(socket.AF_INET6, rd))
            elif rtype == 5:
                # CNAME：解压域名（简化处理）
                j = i
                parts = []
                hops = 0
                while j < len(data) and hops < 10:
                    ln = data[j]
                    if ln == 0:
                        break
                    if ln & 0xc0 == 0xc0:
                        j = ((ln & 0x3f) << 8) | data[j + 1]
                        hops += 1
                        continue
                    parts.append(data[j + 1:j + 1 + ln].decode('ascii', 'ignore'))
                    j += ln + 1
                cname = '.'.join(parts)
            i += rdlen
        return v4, v6, cname
    return [], [], ''


def _getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    # 非字符串 host（已是 IP）直接走原生
    if not isinstance(host, str):
        return _orig_getaddrinfo(host, port, family, type, proto, flags)

    # 已经是 IP 字面量
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    except ValueError:
        pass

    with _lock:
        cached = _cache.get(host)
    if cached is None:
        v4, v6, cname = _dns_query(host, 1)
        if cname and not v4:
            v4b, v6b, _ = _dns_query(cname, 1)
            v4 += v4b
            v6 += v6b
        cached = (v4, v6)
        if v4 or v6:
            with _lock:
                _cache[host] = cached

    v4, v6 = cached
    out = []
    if family in (0, socket.AF_UNSPEC, socket.AF_INET):
        for ip in v4:
            out.append((socket.AF_INET, socket.SOCK_STREAM if type in (0, socket.SOCK_STREAM) else type,
                        proto or 6, '', (ip, port)))
    if family in (0, socket.AF_UNSPEC, socket.AF_INET6):
        for ip in v6:
            out.append((socket.AF_INET6, socket.SOCK_STREAM if type in (0, socket.SOCK_STREAM) else type,
                        proto or 6, '', (ip, port, 0, 0)))
    if not out:
        raise socket.gaierror(-2, 'Name or service not known')
    return out


def install():
    """装上补丁。"""
    socket.getaddrinfo = _getaddrinfo


if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    print('before patch:', end=' ')
    try:
        print(socket.gethostbyname('www.baidu.com'))
    except Exception as e:
        print('ERR', e)

    install()

    print('after patch:', end=' ')
    try:
        print(socket.gethostbyname('www.baidu.com'))
    except Exception as e:
        print('ERR', e)

    for h in ('mirrors.tuna.tsinghua.edu.cn', 'www.baidu.com', 'login.10086.cn'):
        try:
            print(' ', h, '->', _getaddrinfo(h, 443)[0][4])
        except Exception as e:
            print(' ', h, 'ERR', e)
