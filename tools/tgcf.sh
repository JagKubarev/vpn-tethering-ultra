# Telegram через Cloudflare (схема tg-ws-proxy): WebSocket-апгрейд на
# https://kwsN.<домен>/apiws напрямую через WAN, без zapret и с ним.
# 101 = WebSocket до DC Telegram открылся. su -c 'sh tgcf.sh домен...'
M=/data/adb/modules/vpn-to-hotspot-usb; W=$(sed -n 's/^wan=//p' $M/status); CA=/apex/com.android.conscrypt/cacerts; Q=210
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
iptables -w 2 -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
iptables -w 2 -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null

ws() {  # ws HOST IP -> http code
  curl -s -o /dev/null -m 8 --http1.1 --interface "$W" --capath $CA --resolve "$1:443:$2" \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Protocol: binary' \
    -w '%{http_code}/%{time_total}s' "https://$1/apiws" 2>/dev/null; echo -n " rc=$?"
}
echo "WAN=$W $(date +%T)"
for d in "$@"; do
  for dc in 2 4; do
    h=kws$dc.$d
    ip=$(curl -s -m 6 --capath $CA "https://dns.google/resolve?name=$h&type=A" | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1)
    [ -z "$ip" ] && { echo "$h: нет A"; continue; }
    a=$(ws $h $ip)
    iptables -w 2 -t mangle -I POSTROUTING 1 $RULE
    $M/bin/nfqws-arm64 --qnum=$Q --uid=0:0 --bind-fix4 --dpi-desync=fake,fakeddisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$G >/dev/null 2>&1 & P=$!; sleep 0.6
    b=$(ws $h $ip)
    kill $P; wait $P 2>/dev/null; P=""
    iptables -w 2 -t mangle -D POSTROUTING $RULE
    echo "$h -> $ip   без zapret: $a   с zapret: $b"
  done
done
