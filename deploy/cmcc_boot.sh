#!/system/bin/sh
# cmcc_boot.sh — 开机自启 cmcc-unsub 全栈（Magisk service.d，root 上下文）
#
# 顺序：等网络 → 补 IPv6 出口地址 → 启动 Termux 侧守护（守护负责
# DNS 转发器 / gunicorn / cloudflared 的检查与拉起）
# 幂等：重复执行不会起重复进程（守护自带 pid 单实例）
LOG=/data/local/tmp/cmcc_boot.log
TERMUX=/data/data/com.termux/files
PREFIX=$TERMUX/usr

{
  echo "== $(date) boot detected =="
  until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 5; done
  sleep 20

  # 等 IPv6 就绪（最多 90s）
  i=0
  while [ $i -lt 18 ]; do
    if ip -6 addr show 2>/dev/null | grep -q 'scope global'; then break; fi
    sleep 5
    i=$((i + 1))
  done

  # 1) 补 IPv6 出口地址（按当前活跃接口自动选）
  for IFACE in wlan0 ccmni0 ccmni2; do
    BASE=$(ip -6 addr show dev "$IFACE" scope global 2>/dev/null \
           | grep -m1 inet6 | awk '{print $2}' | cut -d/ -f1 \
           | awk -F: '{print $1":"$2":"$3":"$4}')
    case "$BASE" in
      240*|2a0*|2001:*) ;;
      *) continue ;;
    esac
    have=$(ip -6 addr show dev "$IFACE" scope global 2>/dev/null | grep -c inet6)
    if [ "$have" -lt 20 ]; then
      IFACE="$IFACE" WANT=48 sh $TERMUX/home/cmcc_v6.sh >> $LOG 2>&1
    fi
    echo "  $IFACE now $(ip -6 addr show dev $IFACE scope global 2>/dev/null | grep -c inet6) addrs"
    break
  done

  # 2) 启动 Termux 守护（以 Termux 用户身份，自带单实例保护）
  su 10271 $PREFIX/bin/bash -c \
    "export PREFIX=$PREFIX; export PATH=$PREFIX/bin:\$PATH; export HOME=$TERMUX/home; \
     export LD_LIBRARY_PATH=$PREFIX/lib; export TZ=CST-8; \
     nohup $TERMUX/home/cmcc_guard.sh >> $TERMUX/home/cmcc-logs/guard.log 2>&1 &"
  echo "  guard launched"
  echo "== $(date) done =="
} >> $LOG 2>&1
