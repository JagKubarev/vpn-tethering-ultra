#!/bin/sh
# svc_smoke.sh <каталог module> <оболочка> <каталог результата> [plain|net|vpn]
# (разбиение service.sh, 23.10; нужны root, unshare, iproute2, iptables)
# Демон без аргументов в отдельных mount+net namespace: /data и /system — tmpfs,
# /system/bin/{ip,iptables,ip6tables} — настоящие (правила живут только в netns).
SRC="$1"; SH="$2"; OUT="$3"; SCN="$4"; mkdir -p "$OUT"
unshare -mn sh -c '
set -e
mount -t tmpfs none /data; mount -t tmpfs none /system
mkdir -p /data/local/tmp /data/adb/modules /data/misc/net /system/bin
: > /data/misc/net/rt_tables
ln -s "$(command -v ip)" /system/bin/ip
ln -s "$(command -v iptables)" /system/bin/iptables
ln -s "$(command -v ip6tables)" /system/bin/ip6tables
ip link set lo up
if [ "$4" = net ] || [ "$4" = vpn ]; then
  ip link add rmnet_data0 type bridge; ip addr add 10.0.0.2/24 dev rmnet_data0; ip link set rmnet_data0 up
  ip route add default via 10.0.0.1 dev rmnet_data0
  ip link add wlan2 type bridge; ip addr add 192.168.43.1/24 dev wlan2; ip link set wlan2 up
  ip tuntap add tun0 mode tun; ip addr add 172.19.0.1/30 dev tun0; ip link set tun0 up
  ip rule add from all iif wlan2 lookup 97 pref 21000 2>/dev/null
  if [ "$4" = vpn ]; then echo "1001 tun0" > /data/misc/net/rt_tables; ip route add default dev tun0 table 1001; fi
fi
cp -r "$1" /data/adb/modules/vpn-to-hotspot-usb
printf "ZAPRET_ENABLE=1\nTETHER_STEALTH=1\nYT_DEAD_FAILFAST=1\n" > /data/adb/vpn_tether.conf
cd /
set +e
$2 /data/adb/modules/vpn-to-hotspot-usb/service.sh > "$3/stdout" 2> "$3/stderr" &
P=$!
sleep 30
for t in filter nat mangle; do iptables-save -t $t; ip6tables-save -t $t 2>/dev/null; done > "$3/iptables_mid"
ip rule > "$3/iprule_mid"; ip link > "$3/iplink_mid"
cp /data/adb/modules/vpn-to-hotspot-usb/status "$3/status_mid" 2>/dev/null
cp /data/adb/modules/vpn-to-hotspot-usb/module.prop "$3/moduleprop_mid" 2>/dev/null
kill -TERM $P; wait $P
echo "rc=$?" > "$3/rc"
cp /data/local/tmp/vpn_tether.log "$3/log" 2>/dev/null
cat /data/adb/modules/vpn-to-hotspot-usb/status > "$3/status" 2>/dev/null
iptables-save > "$3/iptables_after" 2>/dev/null
ls /data/local/tmp > "$3/tmpfiles"
ip rule > "$3/iprule"; iptables-save -t mangle >> "$3/iptables_after"; iptables-save -t nat >> "$3/iptables_after"
' smoke "$SRC" "$SH" "$OUT" "$4"
