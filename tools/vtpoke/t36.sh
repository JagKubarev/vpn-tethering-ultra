#!/system/bin/sh
# стенд 16.11: synack (поддельный SYN-ACK от клиента на его SYN — из z_attacker, где он под фильтром
# tls_client_hello и не срабатывает). Свой nfqws2 (очередь 211), curl uid 1000 с портов 47000–47999.
#   cur — vt_soft_crck как в подборе; sa — то же + последний профиль на SYN любого 443: synack:repeats=2
# (на SYN имени ещё нет — профили со списками и filter-l7 его не берут; ClientHello уходит в наш TLS-профиль).
# Цели: закрытые сайты, Google/YouTube, видеостойки. Контроль Google мимо обхода (группа 3998) после каждого прогона
[ "$(id -u)" = 0 ] || { echo "не root"; exit 1; }
M=/data/adb/modules/vpn-to-hotspot-usb; ZAPRET2_DIR=$M/zapret2; N=$M/bin/nfqws2-arm64; Q=211
O=/data/local/tmp/t36; rm -rf $O; mkdir -p $O; chmod 755 $O
log() { :; }
. $M/lib/zapret.sh
CUR=$(zapret2_scan_args vt_soft_crck $Q)
SA="--new --filter-tcp=443 --payload=empty --lua-desync=synack:repeats=2"
C=$(command -v curl); GV=rr1---sn-aigl6nzr.googlevideo.com
SITES="${SITES:-rutracker.org www.instagram.com x.com www.facebook.com www.linkedin.com protonmail.com}"
GOO="www.google.com www.youtube.com youtubei.googleapis.com i.ytimg.com"
RACKS="${RACKS:-173.194.188.9 74.125.163.166 74.125.104.199}"
args() {
    case "$1" in
        cur) echo "$CUR" ;;
        sa) echo "$CUR $SA" ;;
        sad) echo "$CUR --debug=@$O/sa.dbg $SA" ;;
    esac
}
RN="-m owner --uid-owner 1000 -p tcp -j RETURN"; RG="-m owner --gid-owner 3998 -p tcp -j RETURN"
R0="-m owner --uid-owner 1000 -p tcp --sport 47000:47999 -j RETURN"
R1="-m owner --uid-owner 1000 -p tcp --sport 47000:47999 --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
R2="-p tcp --sport 443 --dport 47000:47999 -j NFQUEUE --queue-num $Q --queue-bypass"
P=""
cleanup() {
    trap - EXIT INT TERM HUP
    iptables -t nat -D OUTPUT $RN 2>/dev/null; iptables -t nat -D OUTPUT $RG 2>/dev/null; iptables -t mangle -D OUTPUT $R0 2>/dev/null
    iptables -t mangle -D POSTROUTING $R1 2>/dev/null; iptables -t mangle -D PREROUTING $R2 2>/dev/null
    [ -n "$P" ] && kill $P 2>/dev/null
    chmod 644 $O/* 2>/dev/null; touch $O/done
}
trap cleanup EXIT; trap "cleanup; exit 1" INT TERM HUP
ctl() { echo "$(date +%T) $1 https=$(su -g 3998 -c "$C -s -o /dev/null -m 5 -w '%{http_code}' https://www.google.com/generate_204") http=$(su -g 3998 -c "$C -s -o /dev/null -m 5 -w '%{http_code}' http://www.google.com/generate_204")" >> $O/ctl; }
iptables -t nat -I OUTPUT 1 $RN; iptables -t nat -I OUTPUT 1 $RG
iptables -t mangle -I OUTPUT 1 $R0; iptables -t mangle -I POSTROUTING 1 $R1; iptables -t mangle -I PREROUTING 1 $R2
ctl до
n=0
for v in ${VARS:-cur sad cur sa sa cur}; do
    n=$((n + 1))
    set -f
    # shellcheck disable=SC2046
    $N $(args $v) >/dev/null 2>&1 &
    P=$!; set +f; sleep 2
    kill -0 $P 2>/dev/null || { echo "$n $v nfqws2 не запустился" >> $O/res; P=""; continue; }
    W=""
    for h in $SITES $GOO; do
        p=/; case $h in www.google.com|www.youtube.com|youtubei.googleapis.com|i.ytimg.com) p=/generate_204 ;; esac
        ( r=$(su 1000 -c "$C -s -o /dev/null -m 6 --local-port 47000-47999 -w '%{http_code}:%{time_connect}:%{time_appconnect}' https://$h$p"); echo "$n $v site $h $r" >> $O/res ) &
        W="$W $!"
    done
    for i in $RACKS; do
        ( r=$(su 1000 -c "$C -sk -o /dev/null -m 6 --local-port 47000-47999 --resolve $GV:443:$i -w '%{http_code}:%{time_connect}:%{time_appconnect}' https://$GV/generate_204"); echo "$n $v rack $i $r" >> $O/res ) &
        W="$W $!"
    done
    wait $W
    kill $P; wait $P 2>/dev/null; P=""; sleep 1
    ctl "$n$v"
done
sleep 60; ctl после1; sleep 60; ctl после2; sleep 60; ctl после3
