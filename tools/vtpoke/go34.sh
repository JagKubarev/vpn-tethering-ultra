#!/system/bin/sh
[ "$(id -u)" = 0 ] || exit 1
/system/bin/sh -n /data/local/tmp/dep/vtpoke/t34.sh || exit 1
setsid nohup sh /data/local/tmp/dep/vtpoke/t34.sh </dev/null >/data/local/tmp/dep/vtpoke/run.out 2>&1 &
echo started
