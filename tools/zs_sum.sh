R=/data/local/tmp/vpn_tether_zscan.results
echo "по этапам (стратегий / открыли всё / ломают):"
cut -d'|' -f6 $R | sed 's/^2:.*/2/' | sort | uniq | while read -r s; do
  t=$(cut -d'|' -f1,3,6 $R | sed 's/|2:[a-z0-9]*$/|2/' | grep -c "|$s\$"); a=$(cut -d'|' -f1,3,6 $R | sed 's/|2:[a-z0-9]*$/|2/' | grep -c "^10|0|$s\$"); b=$(cut -d'|' -f1,3,6 $R | sed 's/|2:[a-z0-9]*$/|2/' | grep -cE "^[0-9]+\|[1-9][0-9]*\|$s\$")
  echo "  $s: $t / $a / $b"; done
echo "этап 2 (виды подделок):"; grep '|2:' $R | cut -d'|' -f1,3,4,6 | sed 's/^/  /'
echo "этап 1 не открыли всё:"; grep '|1|' $R | awk -F'|' '$1 < 10 {print "  " $1 " " $5 " :: " $7}' | cut -c1-160
echo "перепроверка:"; grep '|проверка|' $R | cut -d'|' -f1,3,4,5 | cut -c1-150 | sed 's/^/  /'
echo "leftovers: nat=$(iptables -t nat -S OUTPUT | grep -c 'uid-owner 0 ') post=$(iptables -t mangle -S POSTROUTING | grep -c 'queue-num 203') zret=$(iptables -t mangle -S VPN_ZAPRET | grep -c 'uid-owner 0 ') nq=$(pidof nfqws-arm64 | wc -w) tmp=$(ls -d /data/local/tmp/vpn_tether_zscan.tmp 2>/dev/null | wc -l)"
