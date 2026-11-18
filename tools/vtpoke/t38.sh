#!/system/bin/sh
# стенд 16.11: «тихие» приёмы для TLS сайтов против нашего (видеопрофиль у всех наш). Свой nfqws2 (очередь 211),
# curl uid 1000 с портов 47000–47999, обычный и большой ClientHello. Контроль Google мимо обхода после прогона.
#   cur — наш: 2 подделки (autottl, плохой ack) + обратный разрез в 7 местах
#   dso — тот же разрез, подделок нет, seqovl=1 (как rostelecom)
#   so  — подделок нет, к первому куску приклеено 681 Б ClientHello Google (как alt6)
#   nz  — 1 подделка со старой меткой времени + разрез посередине имени с наложением 2 Б (как nzapret)
[ "$(id -u)" = 0 ] || { echo "не root"; exit 1; }
M=/data/adb/modules/vpn-to-hotspot-usb; ZAPRET2_DIR=$M/zapret2; N=$M/bin/nfqws2-arm64; Q=211
O=/data/local/tmp/t38; rm -rf $O; mkdir -p $O; chmod 755 $O
log() { :; }
. $M/lib/zapret.sh
zapret2_strat_load $M/zapret2/strategies/vt_soft_crck.conf
C=$(command -v curl); BIG="--curves X25519Kyber768Draft00:X25519"
BASE="--qnum=$Q --uid=0:3998 --bind-fix4 $Z2_BASE --lua-init=@$M/zapret2/lua/vpn-tether.lua $Z2_CUSTOM --new --filter-tcp=443 --filter-l7=tls --payload=tls_client_hello"
POS="pos=1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1"
args() {
    case "$1" in
        cur) echo "$BASE --lua-desync=fake:blob=tls_google:ip_autottl=-1,3-20:repeats=2:tcp_ack=-66000 --lua-desync=multidisorder:$POS" ;;
        dso) echo "$BASE --lua-desync=multidisorder:$POS:seqovl=1" ;;
        so) echo "$BASE --lua-desync=multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google" ;;
        nz) echo "$BASE --lua-desync=fake:blob=tls_google:tcp_ts=-100 --lua-desync=multisplit:seqovl=2:pos=midsld" ;;
    esac
}
T="www.youtube.com/generate_204 youtubei.googleapis.com/generate_204 i.ytimg.com/generate_204 www.google.com/generate_204 discord.com/ rutracker.org/ www.instagram.com/ www.facebook.com/ x.com/ www.linkedin.com/ protonmail.com/ rezka.ag/ meduza.io/ ya.ru/"
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
for v in ${VARS:-cur dso so nz nz so dso cur cur dso so nz}; do
    n=$((n + 1))
    set -f
    # shellcheck disable=SC2046
    $N $(args $v) >/dev/null 2>&1 &
    P=$!; set +f; sleep 2
    kill -0 $P 2>/dev/null || { echo "$n $v nfqws2 не запустился" >> $O/res; P=""; continue; }
    W=""
    for u in $T; do
        ( r=$(su 1000 -c "$C -s -o /dev/null -m 7 --local-port 47000-47999 -w '%{http_code}:%{time_appconnect}' https://$u"); echo "$n $v s ${u%%/*} $r" >> $O/res ) &
        W="$W $!"
        ( r=$(su 1000 -c "$C -s -o /dev/null -m 7 $BIG --local-port 47000-47999 -w '%{http_code}:%{time_appconnect}' https://$u"); echo "$n $v b ${u%%/*} $r" >> $O/res ) &
        W="$W $!"
    done
    wait $W
    kill $P; wait $P 2>/dev/null; P=""; sleep 1
    ctl "$n$v"
done
sleep 60; ctl после1; sleep 60; ctl после2
