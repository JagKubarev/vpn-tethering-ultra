M=/data/adb/modules/vpn-to-hotspot-usb; W=$(sed -n 's/^wan=//p' $M/status); CA=/apex/com.android.conscrypt/cacerts; Q=206
G=$M/zapret/tls_clienthello_www_google_com.bin
iptables -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
iptables -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null
RULE="-o $W -m owner --uid-owner 0 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
iptables -t mangle -I POSTROUTING 1 $RULE
$M/bin/nfqws-arm64 --qnum=$Q --uid=0:0 --bind-fix4 --dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,midsld --dpi-desync-fake-tls=@$G >/dev/null 2>&1 & P=$!; sleep 0.6
for ecs in 87.121.82.0/24 185.15.56.0/24 1.2.3.0/24; do
  echo "ECS $ecs:"
  for n in www.instagram.com scontent.cdninstagram.com static.cdninstagram.com www.facebook.com static.xx.fbcdn.net; do
    ip=$(curl -s -m 6 --interface $W --capath $CA "https://dns.google/resolve?name=$n&type=A&edns_client_subnet=$ecs" | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1)
    r=$( [ -n "$ip" ] && curl -s -o /dev/null -m 8 --interface $W --capath $CA --resolve $n:443:$ip -w '%{http_code} %{time_total}s' https://$n/ 2>/dev/null)
    echo "   $n -> ${ip:-—}  с обходом: ${r:-—}"
  done
done
kill $P
iptables -t mangle -D POSTROUTING $RULE
iptables -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
iptables -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN
