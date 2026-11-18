#!/system/bin/sh
# стенд 16.11: имя в подделке и цели Google — адреса API YouTube, фронты www.youtube.com, i.ytimg.com.
# www.google.com / storage.googleapis.com / контрактцентр.рф. Очередь 211, curl uid 1000, порты 47000–47999
[ "$(id -u)" = 0 ] || { echo "не root"; exit 1; }
M=/data/adb/modules/vpn-to-hotspot-usb; ZAPRET2_DIR=$M/zapret2; N=$M/bin/nfqws2-arm64; Q=211
log() { :; }
. $M/lib/zapret.sh
O=/data/local/tmp/t31; rm -rf $O; mkdir -p $O; chmod 755 $O
C=$(command -v curl || echo $M/bin/curl)
T="youtubei.googleapis.com:172.217.112.4 youtubei.googleapis.com:172.217.113.4 youtubei.googleapis.com:172.217.115.4 youtubei.googleapis.com:172.217.116.4 youtubei.googleapis.com:172.217.117.4 youtubei.googleapis.com:172.217.118.4 youtubei.googleapis.com:172.217.119.4
www.youtube.com:142.251.150.4 www.youtube.com:142.251.151.4 www.youtube.com:142.251.152.4 www.youtube.com:142.251.153.4 www.youtube.com:142.251.154.4 www.youtube.com:142.251.155.4 www.youtube.com:142.251.156.4 www.youtube.com:142.251.157.4
i.ytimg.com:142.251.144.6 i.ytimg.com:142.251.145.6 i.ytimg.com:142.251.146.6 i.ytimg.com:142.251.147.6 i.ytimg.com:142.251.148.6 i.ytimg.com:192.178.40.6 i.ytimg.com:192.178.41.6"
R1="-m owner --uid-owner 1000 -p tcp --sport 47000:47999 --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
R2="-p tcp --sport 443 --dport 47000:47999 -j NFQUEUE --queue-num $Q --queue-bypass"
P=""
cleanup() {
    iptables -t mangle -D POSTROUTING $R1 2>/dev/null; iptables -t mangle -D PREROUTING $R2 2>/dev/null
    [ -n "$P" ] && kill $P 2>/dev/null
    touch $O/done
}
trap cleanup EXIT INT TERM HUP
G=xn--80afcdbalict6afooklqi5o.xn--p1ai
BASE=$(ZAPRET2_FAKE_SNI= zapret2_scan_args vt_soft_crck "$Q")
args() {
    case "$1" in
        g) echo "$BASE" | sed "s/tls_mod=sni=$G://g" ;;
        s) echo "$BASE" | sed "s/sni=$G/sni=storage.googleapis.com/g" ;;
        k) echo "$BASE" | sed "s/sni=$G/sni=xn--80aknbndcreodc3c.xn--p1ai/g" ;;
    esac
}
iptables -t mangle -I POSTROUTING 1 $R1; iptables -t mangle -I PREROUTING 1 $R2
port=${P0:-47100}
for v in ${VARS:-g s k k s g}; do
    set -f
    # shellcheck disable=SC2046
    $N $(args $v) >/dev/null 2>&1 &
    P=$!; set +f; sleep 2
    kill -0 $P 2>/dev/null || { echo "nfqws2 $v не запустился" >> $O/res.txt; P=""; continue; }
    for x in $T; do
        h=${x%%:*}; ip=${x#*:}; port=$((port + 1))
        r=$(su 1000 -c "$C -sk -o /dev/null -m 5 --local-port $port --resolve $h:443:$ip -w '%{http_code} %{time_appconnect}' https://$h/"); rc=$?
        echo "1 $v $h $ip $port $rc $r" >> $O/res.txt
    done
    kill $P; wait $P 2>/dev/null; P=""
done
chmod 644 $O/*
