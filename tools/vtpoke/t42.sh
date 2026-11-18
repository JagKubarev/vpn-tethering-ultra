#!/system/bin/sh
# стенд 17.11 (копия t34): пустой ACK соединениям телефона — мимо conntrack (как у демона с 17.11, правило CT --notrack
# в raw OUTPUT для пакета vtpoke) и через conntrack (как было до 17.11). Свой nfqws2 (очередь 211) с профилем видео,
# curl uid 1000 с портов 47000–47999, 4 запроса generate_204 в одном соединении.
#   p — vtpoke раз в 3 с, правило notrack демона стоит; q — то же, правило на время варианта снято; c — без пакета.
# Паузы по --rate (4/m — 15 с, 1/m — 60 с)
[ "$(id -u)" = 0 ] || { echo "не root"; exit 1; }
M=/data/adb/modules/vpn-to-hotspot-usb; ZAPRET2_DIR=$M/zapret2; N=$M/bin/nfqws2-arm64; Q=211
O=/data/local/tmp/t42; S=/data/local/tmp/dep/vtpoke
rm -rf $O; mkdir -p $O; chmod 755 $O
log() { :; }
. $M/lib/zapret.sh
zapret2_strat_load $M/zapret2/strategies/vt_soft_crck.conf
C=$(command -v curl || echo $M/bin/curl); H=rr1---sn-aigl6nzr.googlevideo.com
IPS="${IPS:-74.125.104.199 74.125.104.231 173.194.6.231 173.194.160.36 173.194.164.243 74.125.162.137}"
W=$(ip -4 route get 8.8.4.4 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
VID="--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tcp_ts_up:repeats=2 --lua-desync=multisplit:pos=midsld"
ARGS="--qnum=$Q --uid=0:3998 --bind-fix4 $Z2_BASE --lua-init=@$M/zapret2/lua/vpn-tether.lua --filter-tcp=443 --out-range=a --payload=all --lua-desync=vt_wssize_ramp:wsize=1:scale=1 $VID"
R0="-m owner --uid-owner 1000 -p tcp --sport 47000:47999 -j RETURN"
R1="-m owner --uid-owner 1000 -p tcp --sport 47000:47999 --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
R2="-p tcp --sport 443 --dport 47000:47999 -j NFQUEUE --queue-num $Q --queue-bypass"
P=""; PK=""; NTOFF=""
NT="-m mark --mark 0x40000000/0x40000000 -p tcp --tcp-flags ALL ACK -m length --length 40 -j CT --notrack"
cleanup() {
    iptables -t mangle -D OUTPUT $R0 2>/dev/null
    iptables -t mangle -D POSTROUTING $R1 2>/dev/null; iptables -t mangle -D PREROUTING $R2 2>/dev/null
    [ -n "$P" ] && kill $P 2>/dev/null; [ -n "$PK" ] && kill $PK 2>/dev/null
    [ -n "$NTOFF" ] && iptables -t raw -I OUTPUT 1 $NT 2>/dev/null
    chmod 644 $O/* 2>/dev/null; touch $O/done
}
trap cleanup EXIT; trap "cleanup; exit 1" INT TERM HUP
iptables -t mangle -I OUTPUT 1 $R0; iptables -t mangle -I POSTROUTING 1 $R1; iptables -t mangle -I PREROUTING 1 $R2
n=0
for rate in ${RATES:-4/m 1/m}; do
    for v in ${VARS:-q p p q c}; do
        n=$((n + 1))
        set -f
        # shellcheck disable=SC2086
        $N $ARGS >/dev/null 2>&1 &
        P=$!; set +f; sleep 2
        kill -0 $P 2>/dev/null || { echo "$n $v $rate nfqws2 не запустился" >> $O/res; P=""; continue; }
        KA=""; [ $v = k ] && KA="--keepalive-time 3"
        if [ $v = q ]; then iptables -t raw -D OUTPUT $NT 2>/dev/null && NTOFF=1; fi
        echo "$n $v правил notrack: $(iptables -t raw -S OUTPUT | grep -c notrack)" >> $O/nt
        { [ $v = p ] || [ $v = q ]; } && { sh $S/poker.sh $W $O/pokes.$n & PK=$!; }
        WT=""
        for i in $IPS; do
            ( r=$(su 1000 -c "$C -sk -m 10 $KA --local-port 47000-47999 --rate $rate --resolve $H:443:$i -w '%{http_code}:%{num_connects}:%{time_total} ' -o /dev/null -o /dev/null -o /dev/null -o /dev/null https://$H/generate_204 https://$H/generate_204 https://$H/generate_204 https://$H/generate_204"); echo "$n $v $rate $i $r" >> $O/res ) &
            WT="$WT $!"
        done
        wait $WT
        [ -n "$PK" ] && { kill $PK 2>/dev/null; PK=""; }
        kill $P; wait $P 2>/dev/null; P=""
        [ -n "$NTOFF" ] && { iptables -t raw -I OUTPUT 1 $NT 2>/dev/null; NTOFF=""; }
        sleep 1
    done
done
