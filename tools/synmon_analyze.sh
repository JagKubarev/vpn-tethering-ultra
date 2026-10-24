#!/system/bin/sh
# synmon_analyze.sh — разбор tools/synmon.sh: адреса, которые ни разу не
# соединились, проверка напрямую и через opera-proxy (SOCKS 127.0.0.1:18080).
O=/data/local/tmp/synmon
cat $O/info.txt
echo "SYN-unreplied records: $(wc -l < $O/syn.txt), distinct IPs: $(awk '{print $3}' $O/syn.txt | sort -u | wc -l), established IPs: $(wc -l < $O/est.txt)"
# per ip: distinct connections (src:port), skip IPs that ever established, skip Telegram (идёт через Opera)
awk '{k=$3" "$4; c[k" "$5]=1} END{for (x in c){split(x,a," "); n[a[1]" "a[2]]++} for (y in n) print n[y], y}' $O/syn.txt | sort -rn > $O/cand_all.txt
: > $O/cand.txt
while read n ip port; do
  grep -qxF "$ip" $O/est.txt && continue
  case "$ip" in 149.154.1[6-7][0-9].*|91.108.*|91.105.19[23].*|185.76.151.*|95.161.*) continue ;; esac
  [ "$n" -ge 2 ] && echo "$n $ip $port" >> $O/cand.txt
done < $O/cand_all.txt
echo "candidates (>=2 попыток, ни разу не соединились): $(wc -l < $O/cand.txt)"
W=$(sed -n 's/^wan=//p' /data/adb/modules/vpn-to-hotspot-usb/status)
head -n 40 $O/cand.txt | while read n ip port; do
  d=$(su -g 3999 -c "curl -s -o /dev/null -m 3 --interface $W -w '%{http_code}' http://$ip:$port/" 2>/dev/null)
  o=$(su -g 3997 -c "curl -s -o /dev/null -m 6 --socks5 127.0.0.1:18080 -w '%{http_code}' http://$ip:$port/" 2>/dev/null)
  ptr=$(/data/adb/ksu/bin/busybox nslookup $ip 2>/dev/null | sed -n 's/.*name = //p; s/^Name:[[:space:]]*//p' | grep -v "^$ip$" | head -1)
  echo "$n $ip:$port direct=$d opera=$o ${ptr:-?}"
done
