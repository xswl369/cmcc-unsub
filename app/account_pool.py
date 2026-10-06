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

    def upsert(self, phone: str, cookies: list[dict], note: str = '') -> dict:
        if not PHONE_RE.match(phone or ''):
            raise ValueError('invalid phone')
        item = {'cookies': cookies, 'note': note,
                'updated_at': time.time()}
        with self._lock:
            self._accounts[phone] = item
        self.save()
        return item

    def get(self, phone: str) -> dict | None:
        with self._lock:
            return self._accounts.get(phone)

    def remove(self, phone: str) -> bool:
        with self._lock:
            existed = self._accounts.pop(phone, None) is not None
        if existed:
            self.save()
        return existed

    def all(self) -> list[dict]:
        with self._lock:
            items = [dict(phone=p, **v) for p, v in self._accounts.items()]
        return sorted(items, key=lambda x: x['updated_at'], reverse=True)

    def summary(self) -> list[dict]:
        return [{'phone': masked(it['phone']), 'raw': it['phone'],
                 'updated_at': int(it['updated_at']), 'note': it['note']}
                for it in self.all()]
