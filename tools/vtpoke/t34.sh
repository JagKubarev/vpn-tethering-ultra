#!/system/bin/sh
# стенд 16.11 (как t33): простой на стойках малого окна. Свой nfqws2 (очередь 211) с профилем видео, как у
# демона на этих стойках, curl uid 1000 с портов 47000–47999, 4 запроса generate_204 в одном соединении.
#   c — как у демона; p — то же + vtpoke (голый ACK с чужим seq) в каждое соединение стенда раз в 3 с;
#   k — то же + TCP keepalive curl раз в 3 с (настоящий, для сравнения). Паузы 15 и 60 с (предел жизни записи ТСПУ)
[ "$(id -u)" = 0 ] || { echo "не root"; exit 1; }
M=/data/adb/modules/vpn-to-hotspot-usb; ZAPRET2_DIR=$M/zapret2; N=$M/bin/nfqws2-arm64; Q=211
O=/data/local/tmp/t34; S=/data/local/tmp/dep/vtpoke
rm -rf $O; mkdir -p $O; chmod 755 $O
log() { :; }
. $M/lib/zapret.sh
zapret2_strat_load $M/zapret2/strategies/vt_soft_crck.conf
C=$(command -v curl || echo $M/bin/curl); H=rr1---sn-aigl6nzr.googlevideo.com
IPS="${IPS:-74.125.104.199 74.125.104.202 74.125.104.231 173.194.160.36 74.125.11.33 173.194.6.231 74.125.154.194}"
W=$(ip -4 route get 8.8.4.4 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
VID="--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tcp_ts_up:repeats=2 --lua-desync=multisplit:pos=midsld"
ARGS="--qnum=$Q --uid=0:3998 --bind-fix4 $Z2_BASE --lua-init=@$M/zapret2/lua/vpn-tether.lua --filter-tcp=443 --out-range=a --payload=all --lua-desync=vt_wssize_ramp:wsize=1:scale=1 $VID"
R0="-m owner --uid-owner 1000 -p tcp --sport 47000:47999 -j RETURN"
R1="-m owner --uid-owner 1000 -p tcp --sport 47000:47999 --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
R2="-p tcp --sport 443 --dport 47000:47999 -j NFQUEUE --queue-num $Q --queue-bypass"
P=""; PK=""
cleanup() {
    iptables -t mangle -D OUTPUT $R0 2>/dev/null
    iptables -t mangle -D POSTROUTING $R1 2>/dev/null; iptables -t mangle -D PREROUTING $R2 2>/dev/null
    [ -n "$P" ] && kill $P 2>/dev/null; [ -n "$PK" ] && kill $PK 2>/dev/null
    chmod 644 $O/* 2>/dev/null; touch $O/done
}
trap cleanup EXIT; trap "cleanup; exit 1" INT TERM HUP
iptables -t mangle -I OUTPUT 1 $R0; iptables -t mangle -I POSTROUTING 1 $R1; iptables -t mangle -I PREROUTING 1 $R2
n=0
for rate in ${RATES:-4/m 1/m}; do
    for v in ${VARS:-c p p c}; do
        n=$((n + 1))
        set -f
        # shellcheck disable=SC2086
        $N $ARGS >/dev/null 2>&1 &
        P=$!; set +f; sleep 2
        kill -0 $P 2>/dev/null || { echo "$n $v $rate nfqws2 не запустился" >> $O/res; P=""; continue; }
        KA=""; [ $v = k ] && KA="--keepalive-time 3"
        [ $v = p ] && { sh $S/poker.sh $W $O/pokes.$n & PK=$!; }
        WT=""
        for i in $IPS; do
            ( r=$(su 1000 -c "$C -sk -m 10 $KA --local-port 47000-47999 --rate $rate --resolve $H:443:$i -w '%{http_code}:%{num_connects}:%{time_total} ' -o /dev/null -o /dev/null -o /dev/null -o /dev/null https://$H/generate_204 https://$H/generate_204 https://$H/generate_204 https://$H/generate_204"); echo "$n $v $rate $i $r" >> $O/res ) &
            WT="$WT $!"
        done
        wait $WT
        [ -n "$PK" ] && { kill $PK 2>/dev/null; PK=""; }
        kill $P; wait $P 2>/dev/null; P=""; sleep 1
    done
done
