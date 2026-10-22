# Перепрогон выбранных стратегий N раз (через scan.sh не идём — свой мини-цикл)
M=/data/adb/modules/vpn-to-hotspot-usb; W=$(sed -n 's/^wan=//p' $M/status); CA=/apex/com.android.conscrypt/cacerts; Z=$M/zapret; Q=204
G=$Z/tls_clienthello_www_google_com.bin
echo "link: $(dumpsys wifi | grep -m1 -oE 'RSSI: -?[0-9]+, Link speed: [0-9]+Mbps')"
echo "ping gw: $(ping -c 10 -i 0.2 -W 1 $(ip route show table $W 2>/dev/null | awk '/default/{print $3; exit}') 2>/dev/null | tail -2 | tr '\n' ' ')"
iptables -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
iptables -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null
SITES="www.youtube.com i.ytimg.com discord.com x.com www.facebook.com rutracker.org www.linkedin.com medium.com www.patreon.com soundcloud.com ya.ru"
: > /data/local/tmp/rr.ips
for h in $SITES; do echo "$h $(curl -s -m 6 --capath $CA -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$h&type=A" | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1)" >> /data/local/tmp/rr.ips; done
RULE="-o $W -m owner --uid-owner 0 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
iptables -t mangle -I POSTROUTING 1 $RULE
run() {
  $M/bin/nfqws-arm64 --qnum=$Q --uid=0:0 --bind-fix4 $1 >/dev/null 2>&1 & P=$!; sleep 0.6
  line=""; ok=0; pids=""
  rm -f /data/local/tmp/rr.r.*
  while read -r h ip; do ( r=$(curl -s -o /dev/null -m 8 --interface $W --capath $CA --resolve $h:443:$ip -w '%{http_code}:%{time_total}' https://$h/ 2>/dev/null); echo "$?:$r" > /data/local/tmp/rr.r.$h ) & pids="$pids $!"; done < /data/local/tmp/rr.ips
  wait $pids; kill $P; wait $P 2>/dev/null
  for h in $SITES; do v=$(cat /data/local/tmp/rr.r.$h); case "$v" in *:000:*|*:) line="$line ${h#www.}:x${v%%:*}";; *) ok=$((ok+1));; esac; done
  echo "  $ok/11$line"
}
one() { echo "$1:"; for i in 1 2 3; do run "$2"; done; }
one "md5sig midsld" "--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$G"
one "md5sig 1,midsld" "--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,midsld --dpi-desync-fake-tls=@$G"
one "fakeddisorder md5sig" "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$G"
iptables -t mangle -D POSTROUTING $RULE
iptables -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
iptables -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN
rm -f /data/local/tmp/rr.*
