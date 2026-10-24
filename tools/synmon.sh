#!/system/bin/sh
# synmon.sh [секунд] — сборщик неотвеченных SYN (блокировка по IP) из conntrack
# раз в 2 с, на телефоне от root. Результат: /data/local/tmp/synmon/{syn,est}.txt.
# Анализ — tools/synmon_analyze.sh (напрямую / PTR). 24.10.
CT=/data/adb/modules/vpn-to-hotspot-usb/bin/conntrack-arm64
O=/data/local/tmp/synmon; mkdir -p $O; : > $O/syn.txt; : > $O/est.txt
END=$(( $(date +%s) + ${1:-1800} ))
echo "start $(date +%T) wan=$(sed -n 's/^wan=//p' /data/adb/modules/vpn-to-hotspot-usb/status)" > $O/info.txt
while [ $(date +%s) -lt $END ]; do
  t=$(date +%s)
  $CT -L -p tcp 2>/dev/null | awk -v t=$t '
    { st=""; dst=""; dp=""; sp=""; src=""
      for (i=1;i<=NF;i++) {
        if ($i ~ /^(SYN_SENT|ESTABLISHED|TIME_WAIT|FIN_WAIT|CLOSE_WAIT|SYN_RECV|CLOSE|LAST_ACK)$/ && st=="") st=$i
        if ($i ~ /^src=/ && src=="") src=substr($i,5)
        if ($i ~ /^dst=/ && dst=="") dst=substr($i,5)
        if ($i ~ /^sport=/ && sp=="") sp=substr($i,7)
        if ($i ~ /^dport=/ && dp=="") dp=substr($i,7)
      }
      if (dp != "443" && dp != "80") next
      if (dst ~ /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|169\.254\.)/) next
      if (st == "SYN_SENT" && $0 ~ /UNREPLIED/) print "S", t, dst, dp, src ":" sp
      else if ($0 ~ /ASSURED/) print "E", t, dst, dp
    }' > $O/snap
  grep '^S ' $O/snap >> $O/syn.txt
  grep '^E ' $O/snap | awk '{print $3}' >> $O/est.txt
  sort -u $O/est.txt -o $O/est.txt
  sleep 2
done
echo "end $(date +%T)" >> $O/info.txt
