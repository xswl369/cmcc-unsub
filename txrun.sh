#!/data/data/com.termux/files/usr/bin/bash
# run.sh — 统一执行入口（设置好 Termux 环境）
export HOME=/data/data/com.termux/files/home
export PREFIX=/data/data/com.termux/files/usr
export TMPDIR=$PREFIX/tmp
export PATH=$PREFIX/bin:$PREFIX/bin/applets
unset LD_PRELOAD
exec "$@"
