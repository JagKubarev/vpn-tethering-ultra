#!/system/bin/sh
# стенд 17.11: пустой ACK (vtpoke) клиенту раздачи через NAT. Клиент — netns vtt за veth (10.99.0.2), выход через
# MASQUERADE на WAN, как у раздачи; его трафик идёт и через nfqws2 демона (VPN_ZAPRET в POSTROUTING ловит весь
# пересылаемый). Правила демона для раздачи (RST, отказ фронтам) клиента не трогают: ACCEPT с vtt0 первым в FORWARD.
#   c — без пакета; p — раз в 3 с пустой ACK в каждое соединение клиента, по которому ≥2,5 с ничего не шло (ss в
#   netns), с адресом и портом ПОСЛЕ NAT (conntrack: reply dport), мимо conntrack телефона (raw: CT --notrack для
#   40-байтного ACK с меткой 0x40000000 — иначе conntrack заведёт новую запись, и NAT сменит порт).
# 4 запроса generate_204 в одном соединении, паузы по --rate (4/m — 15 с, 1/m — 60 с).
#   t41.sh   (IPS, RATES, VARS, H — из окружения)
[ "$(id -u)" = 0 ] || { echo "не root"; exit 1; }
O=/data/local/tmp/t41; S=/data/local/tmp/dep/vtpoke
rm -rf $O; mkdir -p $O; chmod 755 $O
C=$(command -v curl || echo /data/adb/modules/vpn-to-hotspot-usb/bin/curl); H=${H:-rr1---sn-aigl6nzr.googlevideo.com}
IPS="${IPS:-74.125.104.199 74.125.104.231 173.194.6.231 173.194.160.36 173.194.164.243 74.125.162.137}"
W=$(ip -4 route get 8.8.4.4 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
T=$(ip -4 route get 8.8.4.4 | awk '{for(i=1;i<=NF;i++) if($i=="table") print $(i+1)}')
WIP=$(ip -4 route get 8.8.4.4 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
[ -n "$W" ] && [ -n "$T" ] && [ -n "$WIP" ] || { echo "нет WAN ($W/$T/$WIP)"; exit 1; }
NAT="-s 10.99.0.0/30 -o $W -j MASQUERADE"
NT="-m mark --mark 0x40000000/0x40000000 -p tcp --tcp-flags ALL ACK -m length --length 40 -j CT --notrack"
PK=""
cleanup() {
    trap - EXIT INT TERM HUP
    [ -n "$PK" ] && kill $PK 2>/dev/null
    iptables -t nat -D POSTROUTING $NAT 2>/dev/null
    iptables -t raw -D OUTPUT $NT 2>/dev/null
    iptables -D FORWARD -i vtt0 -j ACCEPT 2>/dev/null; iptables -D FORWARD -o vtt0 -j ACCEPT 2>/dev/null
    ip rule del iif vtt0 lookup "$T" pref 8990 2>/dev/null; ip rule del to 10.99.0.0/30 lookup main pref 8989 2>/dev/null
    ip link del vtt0 2>/dev/null; ip netns del vtt 2>/dev/null
    chmod 644 $O/* 2>/dev/null; touch $O/done
}
trap cleanup EXIT; trap "cleanup; exit 1" INT TERM HUP
ip netns add vtt || exit 1
ip link add vtt0 type veth peer name vtt1 || exit 1
ip link set vtt1 netns vtt
ip addr add 10.99.0.1/30 dev vtt0; ip link set vtt0 up
ip netns exec vtt ip addr add 10.99.0.2/30 dev vtt1
ip netns exec vtt ip link set lo up; ip netns exec vtt ip link set vtt1 up
ip netns exec vtt ip route add default via 10.99.0.1
echo 0 > /proc/sys/net/ipv4/conf/vtt0/rp_filter 2>/dev/null
ip route add 10.99.0.0/30 dev vtt0 table main 2>/dev/null
ip rule add to 10.99.0.0/30 lookup main pref 8989; ip rule add iif vtt0 lookup "$T" pref 8990
iptables -I FORWARD 1 -o vtt0 -j ACCEPT; iptables -I FORWARD 1 -i vtt0 -j ACCEPT
iptables -t nat -I POSTROUTING 1 $NAT
iptables -t raw -I OUTPUT 1 $NT
# проверка пути: HTTP к Google из netns
echo "путь: $(ip netns exec vtt $C -s -m 6 -o /dev/null -w '%{http_code} %{time_total}' http://www.google.com/generate_204)" > $O/res
n=0
for rate in ${RATES:-4/m 1/m}; do
    for v in ${VARS:-c p p c}; do
        n=$((n + 1))
        [ $v = p ] && { sh $S/pokernat.sh $W $WIP $O/pokes.$n & PK=$!; }
        WT=""
        for i in $IPS; do
            ( r=$(ip netns exec vtt $C -sk -m 10 --rate $rate --resolve $H:443:$i -w '%{http_code}:%{num_connects}:%{time_total} ' -o /dev/null -o /dev/null -o /dev/null -o /dev/null https://$H/generate_204 https://$H/generate_204 https://$H/generate_204 https://$H/generate_204); echo "$n $v $rate $i $r" >> $O/res ) &
            WT="$WT $!"
        done
        wait $WT
        [ -n "$PK" ] && { kill $PK 2>/dev/null; wait $PK 2>/dev/null; PK=""; }
        sleep 1
    done
done
