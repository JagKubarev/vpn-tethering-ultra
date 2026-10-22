ZT=/data/local/tmp/zt; WAN=rmnet_data1; CA=/apex/com.android.conscrypt/cacerts; Q=201; G=$ZT/tls_google.bin
. /dev/null
iptables -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
iptables -t mangle -I POSTROUTING 1 -o $WAN -m owner --uid-owner 0 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass
$ZT/nfqws --qnum=$Q --uid=0:0 --bind-fix4 --dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$G > /dev/null 2>&1 &
P=$!; sleep 1
for run in 1 2 3; do
  ok=0; fail=""
  while read -r h ip; do
    r=$(curl -s -o /dev/null -m 8 --interface $WAN --capath $CA ${ip:+--resolve $h:443:$ip} -w '%{http_code}' https://$h/ 2>/dev/null); rc=$?
    if [ $rc = 0 ] && [ "$r" != 000 ]; then ok=$((ok+1)); else fail="$fail $h:$rc"; fi
  done < $ZT/ips
  echo "run$run: $ok/$(wc -l < $ZT/ips) ok${fail:+  FAIL:$fail}"
done
echo "--- реальная скачка (размер, скорость, время):"
for u in https://www.youtube.com/ https://rutracker.org/forum/index.php https://discord.com/ https://www.linkedin.com/; do
  h=${u#https://}; h=${h%%/*}; ip=$(awk -v h=$h '$1==h{print $2}' $ZT/ips)
  curl -s -o /dev/null -m 20 --interface $WAN --capath $CA --resolve $h:443:$ip -A 'Mozilla/5.0 (Linux; Android 15) Chrome/130 Mobile' -w "$h %{http_code} size=%{size_download} speed=%{speed_download}B/s t=%{time_total}s\n" "$u"; echo "  rc=$?"
done
kill $P
iptables -t mangle -D POSTROUTING -o $WAN -m owner --uid-owner 0 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass
iptables -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN
echo "cleanup: nat=$(iptables -t nat -S OUTPUT | grep -c 'uid-owner 0 ') mangle=$(iptables -t mangle -S POSTROUTING | grep -c NFQUEUE) nfqws=$(pgrep -f 'nfqws --qnum' | wc -l)"
