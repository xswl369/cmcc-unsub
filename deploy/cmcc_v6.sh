#!/system/bin/sh
# cmcc_v6.sh — 给指定接口补齐公网 IPv6 源地址 + 路由（root，幂等）
#
# 用法：IFACE=ccmni0 WANT=48 sh cmcc_v6.sh
#
# 关键：光加地址没用 —— 地址所属的 /64 必须有 on-link 路由，否则内核
# 会退回默认路由（可能指向已失效的接口）→ 出网必失败。
# 本脚本同时补：地址、该 /64 的 on-link 路由、以及经接口网关的默认路由。
IFACE="${IFACE:-wlan0}"
WANT="${WANT:-48}"

BASE=$(ip -6 addr show dev "$IFACE" scope global 2>/dev/null \
       | grep -m1 'inet6' | awk '{print $2}' | cut -d/ -f1 \
       | awk -F: '{print $1":"$2":"$3":"$4}')
case "$BASE" in
  240*|2a0*|2001:*) ;;
  *) exit 0 ;;
esac

# 1) /64 on-link 路由（缺了它，出口地址全部不可达）
if ! ip -6 route show table "$IFACE" 2>/dev/null | grep -q "$BASE::/64"; then
  ip -6 route add "$BASE::/64" dev "$IFACE" table "$IFACE" 2>/dev/null
  ip -6 route add "$BASE::/64" dev "$IFACE" 2>/dev/null
fi

# 2) 默认路由：优先沿用 RA 给的网关，没有再自己找
GW=$(ip -6 route show dev "$IFACE" 2>/dev/null | grep -m1 '^fe80' | awk '{print $3}')
if [ -z "$GW" ]; then
  GW=$(ip -6 route show default table "$IFACE" 2>/dev/null | grep -m1 via | awk '{print $3}')
fi
if [ -n "$GW" ]; then
  ip -6 route replace default via "$GW" dev "$IFACE" table "$IFACE" 2>/dev/null
  ip -6 route replace default via "$GW" dev "$IFACE" 2>/dev/null
fi

# 3) 补源地址
have=$(ip -6 addr show dev "$IFACE" scope global 2>/dev/null | grep -c 'inet6')
fails=0
while [ "$have" -lt "$WANT" ] && [ "$fails" -lt 20 ]; do
  addr="$BASE:$(printf '%x:%x:%x:%x' $((RANDOM % 65536)) $((RANDOM % 65536)) $((RANDOM % 65536)) $((RANDOM % 65536)))"
  if ip -6 addr add $addr/64 dev "$IFACE" 2>/dev/null; then
    have=$((have + 1))
    fails=0
  else
    fails=$((fails + 1))
  fi
done

# 4) 自检：能不能真出去（拿一个公网 v6 目标试连）
probe_ok=0
if command -v ping6 >/dev/null 2>&1; then
  ping6 -c 1 -W 2 -I "$IFACE" 2606:4700:4700::1111 >/dev/null 2>&1 && probe_ok=1
fi
echo "$(date '+%F %T') cmcc_v6: $IFACE addrs=$have route64=$(ip -6 route show table $IFACE 2>/dev/null | grep -c "$BASE::/64") default=$(ip -6 route show table $IFACE 2>/dev/null | grep -c default) outbound=$probe_ok"
