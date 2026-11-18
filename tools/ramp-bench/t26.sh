#!/system/bin/sh
# стенд 15.11: имя в подделке TLS-части стратегии (tls_google -> tls_mod=sni=<имя>): www.google.com (как
# сейчас), президентскиегранты.рф, 4pda.to. Сайты из подбора, API YouTube, закачка dl.google.com — потолок
# скорости (vk.com/rutube.ru в подделке давали 2,5 Мбит/с). Очередь 211, curl uid 1000, порты 47000–47999
[ "$(id -u)" = 0 ] || { echo "не root"; exit 1; }
M=/data/adb/modules/vpn-to-hotspot-usb; ZAPRET2_DIR=$M/zapret2; N=$M/bin/nfqws2-arm64; Q=211
STR=${STR:-universal_v12_gv}
log() { :; }
. $M/lib/zapret.sh
O=/data/local/tmp/t26; rm -rf $O; mkdir -p $O; chmod 755 $O
C=$(command -v curl || echo $M/bin/curl)
SITES="${SITES:-torproject.org kavkaz-uzel.eu agents.media cherta.media dw.com rfi.fr bbc.com lemonde.fr bbc.co.uk euronews.com voanews.com thebell.io instagram.com x.com discord.com youtubei.googleapis.com www.youtube.com}"
R1="-m owner --uid-owner 1000 -p tcp --sport 47000:47999 --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
R2="-p tcp --sport 443 --dport 47000:47999 -j NFQUEUE --queue-num $Q --queue-bypass"
P=""
cleanup() {
    iptables -t mangle -D POSTROUTING $R1 2>/dev/null; iptables -t mangle -D PREROUTING $R2 2>/dev/null
    [ -n "$P" ] && kill $P 2>/dev/null
    touch $O/done
}
trap cleanup EXIT INT TERM HUP
BASE=$(zapret2_scan_args "$STR" "$Q")
args() {
    case "$1" in
        g) echo "$BASE" ;;
        p) echo "$BASE" | sed 's/fake:blob=tls_google:/fake:blob=tls_google:tls_mod=sni=xn--80afcdbalict6afooklqi5o.xn--p1ai:/g' ;;
        f) echo "$BASE" | sed 's/fake:blob=tls_google:/fake:blob=tls_google:tls_mod=sni=4pda.to:/g' ;;
    esac
}
args p > $O/args_p.txt
iptables -t mangle -I POSTROUTING 1 $R1; iptables -t mangle -I PREROUTING 1 $R2
port=${P0:-47100}
for v in ${VARS:-g p f f p g}; do
    set -f
    # shellcheck disable=SC2046
    $N $([ -n "$DBG" ] && echo "--debug=@$O/nfq_$v.log") $(args $v) >/dev/null 2>&1 &
    P=$!; set +f; sleep 2
    kill -0 $P 2>/dev/null || { echo "nfqws2 $v не запустился" >> $O/res.txt; P=""; continue; }
    for h in $SITES; do
        port=$((port + 1))
        x=$(su 1000 -c "$C -s -o /dev/null -m 6 --local-port $port -w '%{http_code} %{time_appconnect}' https://$h/"); rc=$?
        echo "1 $v $h $port $rc $x" >> $O/res.txt
    done
    port=$((port + 1))
    x=$(su 1000 -c "$C -s -o /dev/null -m 25 --local-port $port -w '%{http_code} %{time_appconnect} %{size_download} %{speed_download}' https://dl.google.com/android/repository/platform-tools-latest-linux.zip"); rc=$?
    echo "S $v dl.google.com $port $rc $x" >> $O/res.txt
    kill $P; wait $P 2>/dev/null; P=""
done
chmod 644 $O/*
