M=/data/adb/modules/vpn-to-hotspot-usb; W=$(sed -n 's/^wan=//p' $M/status); CA=/apex/com.android.conscrypt/cacerts; Q=205
G=$M/zapret/tls_clienthello_www_google_com.bin
iptables -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
iptables -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null
RULE="-o $W -m owner --uid-owner 0 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
IPS=""
for i in 1 2 3 4 5 6; do for r in 1.1.1.1 8.8.8.8; do
  ip=$(curl -s -m 5 --capath $CA -H 'accept: application/dns-json' "https://$r/resolve?name=www.instagram.com&type=A" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1)
  [ -z "$ip" ] && ip=$(curl -s -m 5 --capath $CA -H 'accept: application/dns-json' "https://$r/dns-query?name=www.instagram.com&type=A" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1)
  case " $IPS " in *" $ip "*) ;; *) [ -n "$ip" ] && IPS="$IPS $ip" ;; esac
done; done
echo "IPs:$IPS"
iptables -t mangle -I POSTROUTING 1 $RULE
$M/bin/nfqws-arm64 --qnum=$Q --uid=0:0 --bind-fix4 --dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,midsld --dpi-desync-fake-tls=@$G >/dev/null 2>&1 & P=$!; sleep 0.6
for ip in $IPS; do
  w=$(curl -s -o /dev/null -m 8 --interface $W --capath $CA --resolve www.instagram.com:443:$ip -w '%{http_code} tls=%{time_appconnect}s' https://www.instagram.com/ 2>/dev/null; echo -n " rc=$?")
  echo "  $ip с обходом: $w"
done
kill $P
iptables -t mangle -D POSTROUTING $RULE
iptables -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
iptables -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN
