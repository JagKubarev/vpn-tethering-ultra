#!/bin/sh
# opera_smoke.sh <каталог module> <оболочка> <каталог результата> <hev-socks5-tproxy x86_64 | mock>
# «Telegram через Opera» (OPERA_TG) на стенде: как svc_smoke.sh (root, unshare,
# iproute2, iptables, ss, setpriv, nsenter, python3), демон в своих mount+net
# namespace. opera-proxy — мок (tools/opera_mock_socks.py), hev — настоящий
# (сборка linux-x86_64 того же релиза) или, если ядро без IPv6 (hev открывает
# только AF_INET6), "mock" — tools/opera_mock_tproxy.py с тем же поведением. Клиент раздачи — отдельный netns за
# veth "wlan2". Проверяется: телефон (uid 10100) и раздача к 149.154.167.51
# попадают в мок через TPROXY, обычный адрес — нет; VPN поднялся — правила
# сняты; выход демона — всё убрано.
SRC="$1"; SH="$2"; OUT="$3"; HEV="$4"; MOCK="$(cd "${0%/*}" && pwd)/opera_mock_socks.py"; mkdir -p "$OUT"
unshare -mn sh -c '
SRC="$1"; SH="$2"; OUT="$3"; HEV="$4"; MOCK="$5"
mount -t tmpfs none /data; mount -t tmpfs none /system
mkdir -p /data/local/tmp /data/adb/modules /data/misc/net /system/bin
: > /data/misc/net/rt_tables
ln -s "$(command -v ip)" /system/bin/ip
ln -s "$(command -v iptables)" /system/bin/iptables
ln -s "$(command -v ip6tables)" /system/bin/ip6tables
ip link set lo up
ip link add rmnet_data0 type bridge; ip addr add 10.0.0.2/24 dev rmnet_data0; ip link set rmnet_data0 up
ip route add default via 10.0.0.1 dev rmnet_data0
unshare -n sleep 600 & CP=$!; sleep 0.3
ip link add wlan2 type veth peer name cli0; ip link set cli0 netns $CP
ip addr add 192.168.43.1/24 dev wlan2; ip link set wlan2 up
nsenter -t $CP -n sh -c "ip link set lo up; ip addr add 192.168.43.2/24 dev cli0; ip link set cli0 up; ip route add default via 192.168.43.1"
ip rule add from all iif wlan2 lookup 97 pref 21000 2>/dev/null
ip tuntap add tun0 mode tun; ip link set tun0 up
M=/data/adb/modules/vpn-to-hotspot-usb
cp -r "$SRC" $M
for a in arm64 arm; do
  if [ "$HEV" = mock ]; then
    printf "#!/bin/bash\nexec -a \"\$0\" python3 %s \"\$@\"\n" "${MOCK%/*}/opera_mock_tproxy.py" > $M/bin/hev-socks5-tproxy-$a
  else
    cp "$HEV" $M/bin/hev-socks5-tproxy-$a
  fi
  printf "#!/bin/bash\necho \"Using API proxy candidate: socks5://1.2.3.4:1080\"\nsleep 3\necho \"Selected endpoint address: 77.111.247.10:443\"\necho \"ARGS \$*\"\nexec -a \"\$0\" python3 %s \"\$@\"\n" "$MOCK" > $M/bin/opera-proxy-$a
  chmod 755 $M/bin/hev-socks5-tproxy-$a $M/bin/opera-proxy-$a
done
printf "ZAPRET_ENABLE=0\nDNSPROXY_ENABLE=0\nOPERA_TG=1\nOPERA_COUNTRY=AS\n" > /data/adb/vpn_tether.conf
cd /
$SH $M/service.sh > "$OUT/stdout" 2> "$OUT/stderr" &
P=$!
snap() { { iptables-save -t mangle; iptables-save -t nat; ip rule; ip route show table 3997; } > "$OUT/rules_$1" 2>&1; cp $M/status "$OUT/status_$1" 2>/dev/null; }
pc() { setpriv --reuid=10100 --regid=10100 --clear-groups curl -s -m 5 "http://$1/" 2>&1; echo " rc=$?"; }
tc() { nsenter -t $CP -n curl -s -m 5 "http://$1/" 2>&1; echo " rc=$?"; }
i=0; while [ $i -lt 60 ] && ! grep -q "^opera_scope=phone tether" $M/status 2>/dev/null; do sleep 1; i=$((i+1)); done
echo "ready after ${i}s" > "$OUT/result"
snap on
{ echo "phone TG:    $(pc 149.154.167.51:443)"; echo "phone other: $(pc 8.8.8.8:80)"
  echo "tether TG:   $(tc 149.154.167.51:80)"; echo "tether other: $(tc 8.8.8.8:80)"
  echo "root TG (uid 0, без su -g не перенаправляется): $(curl -s -m 3 http://149.154.167.51:443/; echo " rc=$?")"; } >> "$OUT/result"
# VPN поднялся: адрес на tun0 -> правила снимаются (процессы остаются)
ip addr add 172.19.0.1/30 dev tun0; echo "1001 tun0" > /data/misc/net/rt_tables; ip route add default dev tun0 table 1001
sleep 10; snap vpn
echo "phone TG with VPN: $(pc 149.154.167.51:443)" >> "$OUT/result"
# VPN пропал — правила обратно
ip addr del 172.19.0.1/30 dev tun0
i=0; while [ $i -lt 60 ] && ! grep -q "^opera_scope=phone" $M/status 2>/dev/null; do sleep 1; i=$((i+1)); done
echo "phone TG after VPN down (${i}s): $(pc 149.154.167.51:443)" >> "$OUT/result"
# мок умер -> правила сняты, перезапуск через паузу
pkill -f "^/data/adb/modules/vpn-to-hotspot-usb/bin/opera-proxy-"; sleep 12; snap dead
echo "phone TG while proxy dead: $(pc 149.154.167.51:443)" >> "$OUT/result"
kill -TERM $P; wait $P; echo "rc=$?" > "$OUT/rc"
snap after
cp /data/local/tmp/vpn_tether.log "$OUT/log"; cp /data/local/tmp/vpn_tether_opera.log "$OUT/opera_log" 2>/dev/null
cp /data/local/tmp/vpn_tether_hev.yml "$OUT/hev_yml" 2>/dev/null
ps -eo pid,args | grep -E "opera-proxy|hev-socks5" | grep -v grep > "$OUT/procs_after"
kill $CP
' smoke "$SRC" "$SH" "$OUT" "$HEV" "$MOCK"
