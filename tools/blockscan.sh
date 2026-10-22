# Массовая проверка: что заблокировано по имени (SNI) и открывается zapret.
# su -c 'sh blockscan.sh LIST [STRATEGY-ARGS]'  -> строки: host ip direct | zapret
#   строки: host|ip|tcp_connect|direct|zapret; direct/zapret = "http_code time_connect time_appconnect curl_rc"
# Без обхода — все хосты параллельно; с обходом (nfqws, по умолчанию стратегия
# модуля fakeddisorder) — только те, где TCP есть, а HTTPS не прошёл.
M=/data/adb/modules/vpn-to-hotspot-usb; W=$(sed -n 's/^wan=//p' $M/status); CA=/apex/com.android.conscrypt/cacerts; Q=208
G=$M/zapret/tls_clienthello_www_google_com.bin
STRAT="${2:---dpi-desync=fake,fakeddisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$G}"
LIST="$1"; D=/data/local/tmp/cc_bs; PAR=${PAR:-10}
RULE="-o $W -m owner --uid-owner 0 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
cleanup() {
  [ -f $D/nfq.pid ] && kill $(cat $D/nfq.pid) 2>/dev/null
  iptables -w 2 -t mangle -D POSTROUTING $RULE 2>/dev/null
  iptables -w 2 -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
  iptables -w 2 -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null
  rm -rf $D
}
trap cleanup EXIT INT TERM HUP
rm -rf $D; mkdir -p $D/r
iptables -w 2 -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN               # мимо AdGuard
iptables -w 2 -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null  # без zapret модуля

HOSTS=$(grep -vE '^[[:space:]]*(#|$)' "$LIST")

resolve() {  # через dns.google (запрос идёт по VPN, ответ не подменён)
  curl -s -m 8 --capath $CA "https://dns.google/resolve?name=$1&type=A" | \
    grep -oE '"data":"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"' | grep -oE '[0-9.]+' | head -1 > $D/r/$1.ip
}
probe() {  # probe HOST MODE
  local ip o rc
  ip=$(cat $D/r/$1.ip 2>/dev/null); [ -z "$ip" ] && return
  o=$(curl -s -o /dev/null -m 8 --interface "$W" --capath $CA --resolve "$1:443:$ip" \
      -w '%{http_code} %{time_connect} %{time_appconnect}' "https://$1/" 2>/dev/null); rc=$?
  echo "$o $rc" > $D/r/$1.$2
  # curl при таймауте TLS пишет time_connect=0, хотя TCP был -> отдельная
  # проверка TCP без SNI: http:// на :443, сервер отвечает/закрывает сразу
  [ "$2" = "d" ] && curl -s -o /dev/null -m 5 --interface "$W" -w '%{time_connect}' "http://$ip:443/" > $D/r/$1.t 2>/dev/null
}
par() {  # par FUNC MODE HOSTS...
  local f=$1 m=$2 n=0 h; shift 2
  for h in "$@"; do $f $h $m & n=$((n + 1)); [ $n -ge $PAR ] && { wait; n=0; }; done
  wait
}

echo "WAN=$W $(date +%T) hosts=$(echo $HOSTS | wc -w)" >&2
par resolve - $HOSTS
par probe d $HOSTS
echo "direct pass done $(date +%T)" >&2

RETRY=""
for h in $HOSTS; do
  [ -f $D/r/$h.d ] || continue
  set -- $(cat $D/r/$h.d)
  # TCP есть (.t > 0), HTTPS не прошёл (rc != 0)
  case "$(cat $D/r/$h.t 2>/dev/null)" in ""|0|0.000000) continue ;; esac
  [ "$4" != "0" ] && RETRY="$RETRY $h"
done
if [ -n "$RETRY" ]; then
  iptables -w 2 -t mangle -I POSTROUTING 1 $RULE
  ( $M/bin/nfqws-arm64 --qnum=$Q --uid=0:0 --bind-fix4 $STRAT >/dev/null 2>&1 & echo $! > $D/nfq.pid )
  sleep 0.8
  par probe z $RETRY
  echo "zapret pass done $(date +%T)" >&2
fi

for h in $HOSTS; do
  echo "$h|$(cat $D/r/$h.ip 2>/dev/null)|$(cat $D/r/$h.t 2>/dev/null)|$(cat $D/r/$h.d 2>/dev/null)|$(cat $D/r/$h.z 2>/dev/null)"
done
