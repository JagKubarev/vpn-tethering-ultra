#!/bin/sh
# svc_modes.sh <каталог модуля> <out-файл> (разбиение service.sh, 23.10): служебные режимы service.sh на копии
# модуля; vpn_tether.conf и файл стратегий сетей подменены временными.
set -u
SRC="$1"; OUT="$2"; F=$(mktemp -d); S="$F"
# фикстуры: два vpn_tether.conf и файл стратегий сетей
printf 'ZAPRET_MODE=all\nDNSPROXY_ENABLE=0\nZAPRET_STRATEGY=md5sig\nFOO=1\nKILL_SWITCH=7\n' > "$F/conf1"
printf 'ZAPRET_STRATEGY=custom\nZAPRET_ARGS="--dpi-desync=multisplit --dpi-desync-fake-tls=@G"\nZAPRET_PER_NET=1\r\n' > "$F/conf2"
printf 'mobile:25002|seqovl||YOTA|note|2026-10-01|--dpi-desync=fake --dpi-desync-fake-tls=@G\nwifi:Home|custom|--dpi-desync=multisplit --dpi-desync-fake-tls=@Q|Home|n|d|\nwifi:Bad|custom|--hostlist=/x|Bad|n|d|\n' > "$F/nets"
for sh in mksh "busybox sh"; do
  for cf in none conf1 conf2; do
    T=$(mktemp -d); cp -r "$SRC" "$T/vpn-to-hotspot-usb"; M="$T/vpn-to-hotspot-usb"
    sed -i "s#^USER_CONF=\"/data/adb/vpn_tether.conf\"#USER_CONF=\"$T/vpn_tether.conf\"#; s#^ZAPRET_NETS_FILE=\"/data/adb/vpn_tether_zapret_nets\"#ZAPRET_NETS_FILE=\"$T/nets\"#" "$M/service.sh"
    grep -q "^USER_CONF=\"$T/" "$M/service.sh" || { echo "подмена USER_CONF не удалась"; exit 9; }
    [ "$cf" = none ] || cp "$S/$cf" "$T/vpn_tether.conf"
    cp "$S/nets" "$T/nets"
    run() { printf '### [%s|%s] %s\n' "$sh" "$cf" "$*"; out=$(cd /; $sh "$M/service.sh" "$@" 2>&1); rc=$?; printf '%s\n' "$out" | sed "s#$T#<T>#g"; echo "rc=$rc"; }
    run --defaults
    run --get ZAPRET_MODE
    run --get ZAPRET_STRATEGY
    run --get DNS_DIRECT
    run --get DNS_PHONE
    run --get NOPE
    run --check ZAPRET_ARGS "--dpi-desync=multisplit"
    run --check ZAPRET_ARGS "--hostlist=/x"
    run --check ZAPRET_ARGS "--dpi-desync-fake-tls=@G"
    run --check ZAPRET_ARGS "--dpi-desync-fake-tls=@/etc/x"
    run --check DNS_META_ECS 1.2.3.256
    run --check DNS_META_ECS 1.2.3.4
    run --check ZAPRET_WATCHDOG_MIN 3
    run --check NOPE 1
    run --zapret-strategy mobile:25011 YOTA full
    run --zapret-strategy mobile:25011 YOTA yt
    run --zapret-strategy mobile:25011 YOTA
    run --zapret-strategy wifi:Home "" full
    run --zapret-strategy mobile:99999 "" full
    run --zapret-strategy wifi:Bad "" full
    run --bogus
    rm -rf "$T"
  done
done > "$OUT"
rm -rf "$F"
