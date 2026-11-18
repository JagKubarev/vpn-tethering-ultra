#!/system/bin/sh
# стенд 16.11: «5 ACK» — пустые ACK перед ClientHello (vt-preack.lua). Свой nfqws2 (очередь 211), curl uid 1000
# с портов 47000–47999. Варианты: n0 — без обхода; a3/a5/a8 — 3/5/8 пустых ACK без ограничения TTL; a5t — 5 с
# TTL 7; cur — vt_soft_crck целиком (как у демона); a5z — 5 ACK + две нулевые подделки и разрез (видеопрофиль).
# Цели: закрытые сайты, API YouTube, видеостойки (обычные и малого окна). Контроль Google мимо обхода до и после
[ "$(id -u)" = 0 ] || { echo "не root"; exit 1; }
M=/data/adb/modules/vpn-to-hotspot-usb; ZAPRET2_DIR=$M/zapret2; N=$M/bin/nfqws2-arm64; Q=211
O=/data/local/tmp/t35; S=/data/local/tmp/dep/vtpoke
rm -rf $O; mkdir -p $O; chmod 755 $O; cp $S/vt-preack.lua $O/; chmod 644 $O/vt-preack.lua
log() { :; }
. $M/lib/zapret.sh
zapret2_strat_load $M/zapret2/strategies/vt_soft_crck.conf
CUR=$(zapret2_scan_args vt_soft_crck $Q)
C=$(command -v curl); GV=rr1---sn-aigl6nzr.googlevideo.com
SITES="${SITES:-rutracker.org www.instagram.com x.com www.facebook.com www.linkedin.com protonmail.com}"
API="youtubei.googleapis.com www.youtube.com"
RACKS="${RACKS:-74.125.104.199 173.194.160.36 74.125.11.33 173.194.188.9 74.125.163.166}"
VID="--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tcp_ts_up:repeats=2 --lua-desync=multisplit:pos=midsld"
BASE="--qnum=$Q --uid=0:3998 --bind-fix4 $Z2_BASE --lua-init=@$M/zapret2/lua/vpn-tether.lua --lua-init=@$O/vt-preack.lua"
P1="--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello"
args() {
    case "$1" in
        n0) echo "$BASE --filter-tcp=443" ;;
        a3) echo "$BASE $P1 --lua-desync=vt_preack:repeats=3" ;;
        a5) echo "$BASE $P1 --lua-desync=vt_preack:repeats=5" ;;
        a8) echo "$BASE $P1 --lua-desync=vt_preack:repeats=8" ;;
        a5t) echo "$BASE $P1 --lua-desync=vt_preack:repeats=5:ip_ttl=7" ;;
        a5z) echo "$BASE --filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=vt_preack:repeats=5 --lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tcp_ts_up:repeats=2 --lua-desync=multisplit:pos=midsld" ;;
        cur) echo "$CUR" ;;
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
for rd in 1 2; do
    for v in ${VARS:-n0 a3 a5 a8 a5t cur a5z}; do
        n=$((n + 1))
        set -f
        # shellcheck disable=SC2046
        $N $(args $v) >/dev/null 2>&1 &
        P=$!; set +f; sleep 2
        kill -0 $P 2>/dev/null || { echo "$rd $v nfqws2 не запустился" >> $O/res; P=""; continue; }
        W=""
        for h in $SITES $API; do
            ( r=$(su 1000 -c "$C -s -o /dev/null -m 6 --local-port 47000-47999 -w '%{http_code}:%{time_appconnect}' https://$h/"); echo "$rd $v site $h $r" >> $O/res ) &
            W="$W $!"
        done
        for i in $RACKS; do
            ( r=$(su 1000 -c "$C -sk -o /dev/null -m 6 --local-port 47000-47999 --resolve $GV:443:$i -w '%{http_code}:%{time_appconnect}' https://$GV/generate_204"); echo "$rd $v rack $i $r" >> $O/res ) &
            W="$W $!"
        done
        wait $W
        kill $P; wait $P 2>/dev/null; P=""; sleep 1
        ctl "$rd$v"
    done
done
sleep 60; ctl после1; sleep 60; ctl после2; sleep 60; ctl после3
