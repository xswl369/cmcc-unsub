# -*- coding: utf-8 -*-
"""account_pool.py — 已登录账号池（按手机号持久化 cookie）

设计取自联通方案：账号互相隔离，短信链路按手机号限流，
出口 IP 不参与账号归属判定；登录成功后把 cookie 存进池子，
之后任何访客都能直接切换使用，不需要再次收码。
"""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

PHONE_RE = re.compile(r'^1\d{10}$')


def masked(phone: str) -> str:
    return phone[:3] + '****' + phone[-4:] if PHONE_RE.match(phone or '') else (phone or '')


class AccountPool:
    """线程安全的账号池，原子写入 JSON。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._accounts: dict[str, dict] = {}
        self.load()

    # ---------- 持久化 ----------

    def load(self) -> None:
        with self._lock:
            if not self.path.exists():
                return
            try:
                raw = json.loads(self.path.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                return
            accounts = raw.get('accounts') if isinstance(raw, dict) else None
            if not isinstance(accounts, dict):
                return
            for phone, item in accounts.items():
                if not PHONE_RE.match(phone) or not isinstance(item, dict):
                    continue
                cookies = item.get('cookies')
                if not isinstance(cookies, list) or not cookies:
                    continue
                self._accounts[phone] = {
                    'owner': str(item.get('owner') or ''),   # 空 = 历史遗留，默认不对外可见
                    'cookies': cookies,
                    'note': str(item.get('note') or ''),
                    'updated_at': float(item.get('updated_at') or 0),
                }

    def save(self) -> None:
        with self._lock:
            data = {'updated_at': int(time.time() * 1000), 'accounts': self._accounts}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix('.tmp')
            tmp.write_text(json.dumps(data, ensure_ascii=False, separators=(',', ':')),
                           encoding='utf-8')
            tmp.replace(self.path)

    # ---------- 访问 ----------

    def upsert(self, phone: str, cookies: list[dict], owner: str,
               note: str = '') -> dict:
        """写入/更新一个账号；owner 是该账号的归属访客身份。"""
        if not PHONE_RE.match(phone or ''):
            raise ValueError('invalid phone')
        if not owner:
            raise ValueError('owner required')
        item = {'owner': owner, 'cookies': cookies, 'note': note,
                'updated_at': time.time()}
        with self._lock:
            self._accounts[phone] = item
        self.save()
        return item

    def get(self, phone: str, owner: str) -> dict | None:
        """只有归属者能取到；别人的号码一律当作不存在。"""
        with self._lock:
            item = self._accounts.get(phone)
        if item and owner and item.get('owner') == owner:
            return item
        return None

    def remove(self, phone: str, owner: str) -> bool:
        with self._lock:
            item = self._accounts.get(phone)
            if not item or not owner or item.get('owner') != owner:
                return False
            self._accounts.pop(phone, None)
        self.save()
        return True

    def all(self, owner: str) -> list[dict]:
        """只返回该 owner 自己的账号。"""
        with self._lock:
            items = [dict(phone=p, **v) for p, v in self._accounts.items()
                     if v.get('owner') == owner and owner]
        return sorted(items, key=lambda x: x['updated_at'], reverse=True)

    def summary(self, owner: str) -> list[dict]:
        return [{'phone': masked(it['phone']), 'raw': it['phone'],
                 'updated_at': int(it['updated_at']), 'note': it['note']}
                for it in self.all(owner)]

    def count_all(self) -> int:
        """全站账号总数（只给运维看，不暴露归属与号码）。"""
        with self._lock:
            return len(self._accounts)
