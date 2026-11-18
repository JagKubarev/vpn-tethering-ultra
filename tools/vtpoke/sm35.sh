#!/system/bin/sh
[ "$(id -u)" = 0 ] || exit 1
/system/bin/sh -n /data/local/tmp/dep/vtpoke/t35.sh || exit 1
VARS="n0 a5" sh /data/local/tmp/dep/vtpoke/t35.sh
cat /data/local/tmp/t35/res /data/local/tmp/t35/ctl | head -60
