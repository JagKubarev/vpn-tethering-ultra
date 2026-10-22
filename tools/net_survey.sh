# Обзор сети: быстрый подбор по расширенному набору + сводка. Аргумент — метка сети.
M=/data/adb/modules/vpn-to-hotspot-usb
SITES="www.youtube.com i.ytimg.com discord.com gateway.discord.gg x.com www.facebook.com www.instagram.com rutracker.org www.linkedin.com medium.com www.patreon.com soundcloud.com ya.ru www.google.com"
sh $M/webctl.sh zscan-start quick "$SITES" >/dev/null
sleep 2; i=0; while [ $i -lt 120 ]; do sh $M/webctl.sh zscan-status | grep -q alive=0 && break; sleep 3; i=$((i+1)); done
R=/data/local/tmp/vpn_tether_zscan.results
echo "== $1"
W=$(sed -n 's/^wan=//p' $M/status)
echo "link: $(dumpsys wifi 2>/dev/null | grep -m1 -oE 'RSSI: -?[0-9]+, Link speed: [0-9]+Mbps')"
GW=$(ip route show table $W 2>/dev/null | awk '/default/{print $3; exit}')
echo "ping $GW: $(ping -c 10 -i 0.2 -W 1 $GW 2>/dev/null | grep -oE '[0-9]+% packet loss|= [0-9./]+ ms' | tr '
' ' ')"
grep -E '^(state|msg|blocked)=' /data/local/tmp/vpn_tether_zscan.status
echo "-- стратегии (открыл/всего, сломал, мс, этап):"
awk -F'|' '{ a=$5; gsub(/--dpi-desync-/,"",a); gsub(/--dpi-desync=/,"",a); gsub(/fake-tls=@G/,"G",a); printf "%2s/%s brk=%s %4sms %-8s %s\n", $1,$2,$3,$4,$6,substr(a,1,95) }' $R
echo "-- сайты, не открывшиеся НИ одной стратегией:"
for h in $(sed -n 's/^blocked=//p' /data/local/tmp/vpn_tether_zscan.status); do
  n=$(grep -c "${h#www.}:x" $R); t=$(grep -c . $R); [ "$n" = "$t" ] && echo "  $h"
done
echo "leftovers: nat=$(iptables -t nat -S OUTPUT | grep -c 'uid-owner 0 ') post=$(iptables -t mangle -S POSTROUTING | grep -c 'queue-num 203') zret=$(iptables -t mangle -S VPN_ZAPRET | grep -c 'uid-owner 0 ')"
