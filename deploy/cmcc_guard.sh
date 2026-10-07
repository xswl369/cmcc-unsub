#!/data/data/com.termux/files/usr/bin/bash
# cmcc_guard.sh — cmcc-unsub 自愈守护（Termux 用户运行，幂等）
#
# 每轮检查并自动恢复四件事：
#   1) IPv6 出口池：接口掉前缀/地址被回收 → 自动补回，并把接口名同步给 ip_pool.json
#   2) 本地 DNS 转发器（cloudflared 强制查 [::1]:53）→ 挂了就重启
#   3) gunicorn（proot Debian, 127.0.0.1:5701）→ 端口不通就拉起
#   4) cloudflared 隧道（2025.10.0 版）→ 进程不在就拉起
#
# 单实例（pid 文件），日志 $HOME/cmcc-logs/guard.log
export PREFIX=/data/data/com.termux/files/usr
export PATH=$PREFIX/bin:$PATH
export HOME=/data/data/com.termux/files/home
export LD_LIBRARY_PATH=$PREFIX/lib
export TZ=CST-8

ROOTFS=$PREFIX/var/lib/proot-distro/containers/debian/rootfs
APP_DATA=$ROOTFS/opt/cmcc-unsub/data
LOGDIR=$HOME/cmcc-logs
LOG=$LOGDIR/guard.log
PIDF=$LOGDIR/guard.pid
IFACE_FILE=$HOME/.cmcc_iface
STATE_FILE=$HOME/.cmcc_pool_state
DNS_PY=$HOME/dns_forward.py
CF_BIN=$HOME/cf_2025.bin
CF_CFG=$HOME/.cloudflared/config.yml
V6_HELPER=$HOME/cmcc_v6.sh
INTERVAL=30
mkdir -p "$LOGDIR"

log() { echo "$(date '+%F %T') $*" >> "$LOG"; }

# ---------- 单实例 ----------
if [ -f "$PIDF" ]; then
  old=$(cat "$PIDF" 2>/dev/null)
  if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
    log "already running (pid=$old), exit"
    exit 0
  fi
fi
echo $$ > "$PIDF"
trap 'rm -f "$PIDF"' EXIT

# ---------- 基础探针 ----------
net_up() { (exec 3<>/dev/tcp/223.5.5.5/443) 2>/dev/null; }

dns_ok() {
  $PREFIX/bin/python3 - <<'PY'
import socket, struct, sys
try:
    h = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    q = b''
    for part in 'www.baidu.com'.split('.'):
        q += bytes([len(part)]) + part.encode()
    q += b'\x00' + struct.pack('!HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(h + q, ('127.0.0.1', 53))
    d, _ = s.recvfrom(2048)
    s.close()
    sys.exit(0 if struct.unpack('!H', d[6:8])[0] > 0 else 1)
except Exception:
    sys.exit(1)
PY
}

port_open() { (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; }

# v6 出口是否真能出网：拿一个本机 v6 源地址连 login.10086.cn 的 v6 地址
# 能连上 → 0；连不上/超时/无地址 → 1
v6_egress_ok() {
  local ifc="$1"
  [ -n "$ifc" ] || return 1
  su -c "$PREFIX/bin/python3 - <<'PY'
import socket, ssl, subprocess, sys
iface = '$ifc'
out = subprocess.run(['ip','-6','addr','show','dev',iface,'scope','global'],
                     capture_output=True, text=True).stdout
src = ''
for line in out.splitlines():
    line = line.strip()
    if line.startswith('inet6 ') and 'tentative' not in line:
        src = line.split()[1].split('/')[0]
        break
if not src:
    sys.exit(1)
dst = '2409:8080:381c:f1c1::3:8a'   # login.10086.cn
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(4)
try:
    s.bind((src, 0))
    s.connect((dst, 443))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.wrap_socket(s, server_hostname='login.10086.cn')
    sys.exit(0)
except Exception:
    sys.exit(1)
finally:
    try: s.close()
    except Exception: pass
PY" >/dev/null 2>&1
}

# ---------- 1) IPv6 出口池 ----------
v6_count() {   # $1=iface
  su -c "ip -6 addr show dev $1 scope global 2>/dev/null | grep -c inet6" 2>/dev/null | tr -d ' \r'
}

detect_iface() {
  local i n
  for i in wlan0 ccmni0 ccmni2; do
    n=$(v6_count "$i")
    [ -n "$n" ] && [ "$n" -ge 20 ] 2>/dev/null && { echo "$i"; return; }
  done
  for i in wlan0 ccmni0 ccmni2; do
    n=$(v6_count "$i")
    [ -n "$n" ] && [ "$n" -ge 1 ] 2>/dev/null && { echo "$i"; return; }
  done
  echo ""
}

write_pool_cfg() {   # $1=iface
  printf '{"ipv6":{"enabled":true,"iface":"%s","count":48,"ttl":1800},"proxies":[],"strategy":"sid"}' "$1" \
    > "$APP_DATA/ip_pool.json"
}

write_pool_cfg_off() {   # v6 出口不可用：关掉池子，全部走默认线路(v4)
  printf '{"ipv6":{"enabled":false},"proxies":[],"strategy":"sid"}' > "$APP_DATA/ip_pool.json"
}

ensure_ipv6() {
  local ifc n cur
  ifc=$(detect_iface)
  if [ -z "$ifc" ]; then
    log "no global ipv6 iface yet"
    return 1
  fi
  n=$(v6_count "$ifc")
  if [ "${n:-0}" -lt 20 ] 2>/dev/null; then
    [ -f "$V6_HELPER" ] && su -c "IFACE=$ifc WANT=48 sh $V6_HELPER" >/dev/null 2>&1
    log "ipv6 refill on $ifc (had $n)"
  fi

  # 出口健康：v6 连不通就关掉池子（退回 v4），通了才启用
  local state="disabled"
  if v6_egress_ok "$ifc"; then
    state="enabled"
  fi

  want="$ifc|$state"
  if [ "$want" != "$(cat $STATE_FILE 2>/dev/null)" ]; then
    echo "$ifc" > "$IFACE_FILE"
    if [ "$state" = "enabled" ]; then
      write_pool_cfg "$ifc"
    else
      write_pool_cfg_off
    fi
    echo "$want" > "$STATE_FILE"
    if [ "$state" = "enabled" ]; then
      log "v6 egress OK on $ifc -> pool enabled ($want), restarting gunicorn"
    else
      log "v6 egress unusable on $ifc -> pool disabled, fallback to v4 ($want), restarting gunicorn"
    fi
    return 2      # 通知调用方重启 gunicorn
  fi
  return 0
}

# ---------- 2) 本地 DNS 转发器 ----------
ensure_dns() {
  dns_ok && return 0
  log "dns forwarder down, restarting"
  su -c "pkill -f dns_forward.py" 2>/dev/null
  sleep 1
  su -c "setsid $PREFIX/bin/python3 $DNS_PY >> $LOGDIR/dnsfwd.log 2>&1 &" 2>/dev/null
  sleep 2
  dns_ok && log "dns forwarder ok" || log "dns forwarder still down"
}

# ---------- 3) gunicorn ----------
start_gunicorn() {
  setsid proot-distro login debian -- /bin/bash -c \
    "cd /opt/cmcc-unsub && exec /usr/bin/python3 -m gunicorn -c gunicorn.conf.py wsgi:app" \
    >> "$LOGDIR/gunicorn.log" 2>&1 &
}

ensure_gunicorn() {
  port_open 5701 && return 0
  log "gunicorn down (5701 closed), starting"
  start_gunicorn
  local i
  for i in $(seq 1 20); do
    sleep 1
    port_open 5701 && { log "gunicorn ok"; return 0; }
  done
  log "gunicorn still down"
}

# ---------- 4) cloudflared ----------
start_cloudflared() {
  setsid "$CF_BIN" --config "$CF_CFG" tunnel run \
    --dns-resolver-addrs 223.5.5.5:53 >> "$LOGDIR/cf25.log" 2>&1 &
}

ensure_tunnel() {
  if pgrep -f 'cf_2025.bin.*tunnel run' >/dev/null 2>&1; then
    return 0
  fi
  log "cloudflared down, starting"
  start_cloudflared
  local i
  for i in $(seq 1 25); do
    sleep 2
    if pgrep -f 'cf_2025.bin.*tunnel run' >/dev/null 2>&1 \
       && grep -q 'Registered tunnel connection' <(tail -40 "$LOGDIR/cf25.log" 2>/dev/null); then
      log "cloudflared ok"
      return 0
    fi
  done
  log "cloudflared started (registration pending)"
}

# ---------- 主循环 ----------
log "guard started pid=$$"
while true; do
  if net_up; then
    ensure_ipv6
    rc=$?
    [ "$rc" = "2" ] && ensure_gunicorn
    ensure_dns
    ensure_gunicorn
    ensure_tunnel
  else
    log "network down, skip this round"
  fi
  sleep "$INTERVAL"
done
