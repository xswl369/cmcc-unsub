# gunicorn 单 worker + 多线程（纯 HTTP 版，无浏览器/保活线程）
# 单 worker 是为了让内存里的会话表在所有请求间共享；并发靠线程池。
import os

bind = '0.0.0.0:8686' if os.environ.get('CMCC_PUBLIC_BIND') else '127.0.0.1:8686'
workers = 1
threads = 48            # 100 人并发下每人一次请求：48 线程 + 排队足够
worker_connections = 1000
timeout = 180           # 移动接口偶发慢，给足时间
graceful_timeout = 15
keepalive = 5
accesslog = None
errorlog = '-'
loglevel = 'warning'
