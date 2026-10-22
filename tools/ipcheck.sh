# Блок по IP или по имени: TCP:80, TCP:443 с чужим SNI на тот же IP, несколько IP сервиса
M=/data/adb/modules/vpn-to-hotspot-usb; W=$(sed -n 's/^wan=//p' $M/status); CA=/apex/com.android.conscrypt/cacerts
iptables -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
iptables -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null
for h in ${*:-www.instagram.com}; do
  ips=$(curl -s -m 6 --capath $CA -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$h&type=A" | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -3)
  for ip in $ips; do
    p80=$(curl -s -o /dev/null -m 5 --interface $W --resolve $h:80:$ip -w '%{http_code}' http://$h/ 2>/dev/null; echo -n "/$?")
    alt=$(curl -sk -o /dev/null -m 5 --interface $W --resolve www.google.com:443:$ip -w '%{http_code}' https://www.google.com/ 2>/dev/null; echo -n "/$?")
    tcp=$(timeout 5 /data/adb/ksu/bin/busybox nc -z -w 4 $ip 443 2>/dev/null && echo open || echo closed)
    echo "$h $ip  :80=$p80  tcp443=$tcp  tls(SNI google)=$alt"
  done
done
iptables -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
iptables -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN
