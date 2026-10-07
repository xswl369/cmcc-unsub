#!/system/bin/sh
# cmcc_supervise.sh — 守护的守护（Magisk service.d，root 上下文）
#
# cmcc_boot.sh 负责开机拉起一次 cmcc_guard.sh；本脚本常驻，每 60s 检查
# guard 的 pid 文件，发现进程不在了就重新拉起（覆盖 guard 自身崩溃的场景）。
# 网络没起来时也照常重试，guard 内部会自己等网络。
TERMUX=/data/data/com.termux/files
HOME_T=$TERMUX/home
PIDF=$HOME_T/cmcc-logs/guard.pid
LOCK=/data/local/tmp/cmcc_supervise.lock

# 单实例
if [ -f "$LOCK" ]; then
  old=$(cat "$LOCK" 2>/dev/null)
  [ -n "$old" ] && kill -0 "$old" 2>/dev/null && exit 0
fi
echo $$ > "$LOCK"

until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 10; done
sleep 25

while true; do
  alive=0
  if [ -f "$PIDF" ]; then
    pid=$(cat "$PIDF" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && alive=1
  fi
  if [ "$alive" = "0" ]; then
    echo "$(date '+%F %T') supervise: guard not running, restarting" >> /data/local/tmp/cmcc_boot.log
    su 10271 $TERMUX/usr/bin/bash -c \
      "export PREFIX=$TERMUX/usr; export PATH=$TERMUX/usr/bin:\$PATH; \
       export HOME=$HOME_T; export LD_LIBRARY_PATH=$TERMUX/usr/lib; export TZ=CST-8; \
       nohup $HOME_T/cmcc_guard.sh >> $HOME_T/cmcc-logs/guard.log 2>&1 &"
  fi
  sleep 60
done
