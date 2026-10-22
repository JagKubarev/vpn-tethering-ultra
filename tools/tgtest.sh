# Доступность Telegram напрямую (WAN, мимо VPN) и для сравнения через VPN (tun).
# DC — захардкоженные адреса клиентов; :80 — HTTP-транспорт MTProto (есть ли
# данные после connect), :443/:5222 — только TCP connect. Плюс веб (по имени).
M=/data/adb/modules/vpn-to-hotspot-usb; W=$(sed -n 's/^wan=//p' $M/status); CA=/apex/com.android.conscrypt/cacerts
cleanup() {
  iptables -w 2 -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
  iptables -w 2 -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null
}
trap cleanup EXIT INT TERM HUP
iptables -w 2 -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN      # мимо AdGuard
iptables -w 2 -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null  # без zapret

tcp() {   # tcp IP PORT [iface] -> "ok 0.071s" / "rc=7" / "timeout" (curl без telnet: TCP по http://, важен только connect)
  local o rc
  if [ -n "$3" ]; then o=$(curl -s -o /dev/null -m 4 --interface "$3" -w '%{time_connect}' "http://$1:$2/" 2>/dev/null); rc=$?
  else o=$(curl -s -o /dev/null -m 4 -w '%{time_connect}' "http://$1:$2/" 2>/dev/null); rc=$?; fi
  case "$o" in 0|0.000000|"") [ $rc -eq 28 ] && echo "timeout" || echo "rc=$rc" ;; *) echo "ok ${o}s" ;; esac
}
http80() {  # данные по :80 (MTProto HTTP): код ответа или rc
  local o
  if [ -n "$2" ]; then o=$(curl -s -o /dev/null -m 6 --interface "$2" -w '%{http_code}' "http://$1/api" 2>/dev/null; echo -n " rc=$?")
  else o=$(curl -s -o /dev/null -m 6 -w '%{http_code}' "http://$1/api" 2>/dev/null; echo -n " rc=$?"); fi
  echo "$o"
}

echo "WAN=$W  $(date +%T)"
echo "== DC (WAN | VPN)"
for ip in 149.154.175.53 149.154.167.51 149.154.175.100 149.154.167.91 91.108.56.130 149.154.167.99 149.154.167.41 91.108.4.1 91.108.8.1 91.108.12.1 91.108.16.1 95.161.76.100; do
  pg=$(ping -I "$W" -c 2 -W 2 "$ip" >/dev/null 2>&1 && echo ping-ok || echo ping-no)
  echo "$ip  WAN: 443=$(tcp $ip 443 $W) 5222=$(tcp $ip 5222 $W) 80=$(tcp $ip 80 $W) http=$(http80 $ip $W) $pg  |  VPN: 443=$(tcp $ip 443) http=$(http80 $ip)"
done

echo "== веб (DNS через DoH 1.1.1.1)"
for h in telegram.org t.me web.telegram.org core.telegram.org desktop.telegram.org zws2.web.telegram.org venus.web.telegram.org cdn4.telegram-cdn.org; do
  ips=$(curl -s -m 6 --capath $CA -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$h&type=A" | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -2 | tr '\n' ' ')
  ip=${ips%% *}
  [ -z "$ip" ] && { echo "$h -> нет A"; continue; }
  w=$(curl -s -o /dev/null -m 8 --interface "$W" --capath $CA --resolve "$h:443:$ip" -w '%{http_code} tls=%{time_appconnect}s' "https://$h/" 2>/dev/null; echo -n " rc=$?")
  echo "$h -> $ips  WAN https: $w  tcp443: $(tcp $ip 443 $W)"
done
