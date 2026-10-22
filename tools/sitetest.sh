# Что из заблокированного открывается напрямую (WAN, мимо VPN): TCP, HTTPS
# без обхода, с zapret (2 стратегии), и для Meta-хостов — с ECS Европы.
# Аргументы: имена хостов (иначе набор по умолчанию). Запуск: su -c 'sh sitetest.sh'
M=/data/adb/modules/vpn-to-hotspot-usb; W=$(sed -n 's/^wan=//p' $M/status); CA=/apex/com.android.conscrypt/cacerts; Q=207
G=$M/zapret/tls_clienthello_www_google_com.bin
RULE="-o $W -m owner --uid-owner 0 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
P=""
cleanup() {
  [ -n "$P" ] && kill $P 2>/dev/null
  iptables -w 2 -t mangle -D POSTROUTING $RULE 2>/dev/null
  iptables -w 2 -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
  iptables -w 2 -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null
}
trap cleanup EXIT INT TERM HUP
iptables -w 2 -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN               # мимо AdGuard
iptables -w 2 -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null  # без zapret модуля

resolve() {  # resolve HOST [ECS] — через dns.google (запрос идёт по VPN)
  local q="name=$1&type=A"; [ -n "$2" ] && q="$q&edns_client_subnet=$2"
  curl -s -m 6 --capath $CA "https://dns.google/resolve?$q" | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1
}
tcp() {  # tcp IP PORT -> ok/timeout/rc
  local o rc
  o=$(curl -s -o /dev/null -m 4 --interface "$W" -w '%{time_connect}' "http://$1:$2/" 2>/dev/null); rc=$?
  case "$o" in 0|0.000000|"") [ $rc -eq 28 ] && echo "timeout" || echo "rc=$rc" ;; *) echo "ok" ;; esac
}
https() {  # https HOST IP [PATH]
  curl -s -o /dev/null -m 8 --interface "$W" --capath $CA --resolve "$1:443:$2" -w '%{http_code}/%{time_total}s' "https://$1${3:-/}" 2>/dev/null
  echo -n " rc=$?"
}
nfq_start() {  # nfq_start ARGS...
  [ -n "$P" ] && { kill $P 2>/dev/null; wait $P 2>/dev/null; P=""; }
  [ -z "$1" ] && return
  $M/bin/nfqws-arm64 --qnum=$Q --uid=0:0 --bind-fix4 "$@" >/dev/null 2>&1 & P=$!; sleep 0.6
}
S1="${S1:---dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,midsld --dpi-desync-fake-tls=@$G}"
S2="--dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=@$G"

HOSTS="${*:-ru.themoscowtimes.com www.themoscowtimes.com meduza.io www.bbc.com web.whatsapp.com www.whatsapp.com g.whatsapp.net mmg.whatsapp.net static.whatsapp.net}"
echo "WAN=$W  $(date +%T)"
iptables -w 2 -t mangle -I POSTROUTING 1 $RULE
for h in $HOSTS; do
  ip=$(resolve $h); [ -z "$ip" ] && { echo "$h: нет A"; continue; }
  echo "$h -> $ip  tcp443=$(tcp $ip 443)"
  nfq_start; echo "    без обхода: $(https $h $ip)"
  nfq_start $S1; echo "    zapret S1:  $(https $h $ip)"
  nfq_start $S2; echo "    zapret S2:  $(https $h $ip)"
  nfq_start
  case "$h" in *whatsapp*)
    e=$(resolve $h 185.15.56.0/24)
    [ -n "$e" ] && [ "$e" != "$ip" ] && {
      echo "    ECS EU -> $e  tcp443=$(tcp $e 443) tcp5222=$(tcp $e 5222)"
      nfq_start; echo "    ECS без обхода: $(https $h $e)"
      nfq_start $S1; echo "    ECS zapret S1:  $(https $h $e)"
      nfq_start; }
    ;;
  esac
done

echo "== Telegram: другие диапазоны"
for ip in 91.105.192.100 185.76.151.1 149.154.171.5 91.108.20.1 149.154.160.1; do
  echo "$ip  tcp443=$(tcp $ip 443) tcp80=$(tcp $ip 80)"
done
