#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WSGI 入口（纯 HTTP 版）：不再启动任何浏览器。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'app'))

import server  # noqa: E402

app = server.app
