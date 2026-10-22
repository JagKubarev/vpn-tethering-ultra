ZT=/data/local/tmp/zt; WAN=rmnet_data1; CA=/apex/com.android.conscrypt/cacerts; Q=201
echo "leftover rules: nat=$(iptables -t nat -S OUTPUT | grep -c 'uid-owner 0 ') mangle=$(iptables -t mangle -S POSTROUTING | grep -c NFQUEUE) nfqws=$(pgrep -f 'nfqws --qnum' | wc -l)"
iptables -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
iptables -t mangle -I POSTROUTING 1 -o $WAN -m owner --uid-owner 0 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass
iptables -t mangle -I POSTROUTING 1 -o $WAN -m owner --uid-owner 0 -p tcp --dport 443 -j LOG --log-prefix ZTDBG 2>/dev/null; iptables -t mangle -D POSTROUTING -o $WAN -m owner --uid-owner 0 -p tcp --dport 443 -j LOG --log-prefix ZTDBG 2>/dev/null
$ZT/nfqws --qnum=$Q --bind-fix4 --debug=1 --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq --dpi-desync-fake-tls=@$ZT/tls_google.bin > $ZT/dbg.log 2>&1 &
P=$!; sleep 1
curl -s -o /dev/null -m 6 --interface $WAN --capath $CA --resolve rutracker.org:443:104.21.32.39 -w 'rutracker %{http_code}\n' https://rutracker.org/; echo "rc=$?"
echo "--- mangle POSTROUTING counters:"; iptables -t mangle -L POSTROUTING -v -n | head -6
echo "--- other mangle POSTROUTING chains / order:"; iptables -t mangle -S POSTROUTING | head
kill $P; sleep 0.3
echo "--- nfqws log (after ClientHello):"; sed -n "/id=3 /,/id=6 /p" $ZT/dbg.log | head -60
iptables -t mangle -D POSTROUTING -o $WAN -m owner --uid-owner 0 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass
iptables -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN
echo "after cleanup: nat=$(iptables -t nat -S OUTPUT | grep -c 'uid-owner 0 ') mangle=$(iptables -t mangle -S POSTROUTING | grep -c NFQUEUE)"
