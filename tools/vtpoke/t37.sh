#!/system/bin/sh
# стенд 16.11: малое окно (vt_wssize_ramp, как у демона на молчащих стойках) с synack и без. Свой nfqws2
# (очередь 211), curl uid 1000 с портов 47000–47999, стойки из списка малого окна; пометку видео демона
# снимаем (RETURN в mangle OUTPUT), AdGuard мимо (RETURN в nat). Контроль Google мимо обхода после прогона.
#   r — малое окно + видеоприёмы; rs — то же, а на SYN сначала synack:repeats=2
[ "$(id -u)" = 0 ] || { echo "не root"; exit 1; }
M=/data/adb/modules/vpn-to-hotspot-usb; ZAPRET2_DIR=$M/zapret2; N=$M/bin/nfqws2-arm64; Q=211
O=/data/local/tmp/t37; rm -rf $O; mkdir -p $O; chmod 755 $O
log() { :; }
. $M/lib/zapret.sh
zapret2_strat_load $M/zapret2/strategies/vt_soft_crck.conf
C=$(command -v curl); GV=rr1---sn-aigl6nzr.googlevideo.com
RACKS="${RACKS:-74.125.104.199 74.125.104.202 74.125.104.231 173.194.160.36 74.125.11.33 173.194.6.231 74.125.154.194}"
VID="--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tcp_ts_up:repeats=2 --lua-desync=multisplit:pos=midsld"
BASE="--qnum=$Q --uid=0:3998 --bind-fix4 $Z2_BASE --lua-init=@$M/zapret2/lua/vpn-tether.lua"
args() {
    case "$1" in
        r) echo "$BASE --filter-tcp=443 --out-range=a --payload=all --lua-desync=vt_wssize_ramp:wsize=1:scale=1 $VID" ;;
        rs) echo "$BASE --filter-tcp=443 --out-range=a --payload=empty --lua-desync=synack:repeats=2 --payload=all --lua-desync=vt_wssize_ramp:wsize=1:scale=1 $VID" ;;
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
for v in ${VARS:-r rs rs r r rs rs r}; do
    n=$((n + 1))
    set -f
    # shellcheck disable=SC2046
    $N $(args $v) >/dev/null 2>&1 &
    P=$!; set +f; sleep 2
    kill -0 $P 2>/dev/null || { echo "$n $v nfqws2 не запустился" >> $O/res; P=""; continue; }
    W=""
    for i in $RACKS; do
        ( r=$(su 1000 -c "$C -sk -o /dev/null -m 8 --local-port 47000-47999 --resolve $GV:443:$i -w '%{http_code}:%{time_connect}:%{time_appconnect}:%{time_total}' https://$GV/generate_204"); echo "$n $v $i $r" >> $O/res ) &
        W="$W $!"
    done
    wait $W
    kill $P; wait $P 2>/dev/null; P=""; sleep 1
    ctl "$n$v"
done
