#!/system/bin/sh
# стенд 16.11: отвечает ли видеосервер на vtpoke своим ACK. Одно соединение curl (uid 1000, порт 47555),
# 2 запроса с паузой 20 с; в паузе vtpoke раз в 3 с; дамп tcpdump. Пометку демона снимаем (RETURN)
[ "$(id -u)" = 0 ] || exit 1
D=/data/local/tmp/dep/vtpoke; O=/data/local/tmp/pk1; rm -rf $O; mkdir -p $O; chmod 777 $O
C=$(command -v curl); H=rr1---sn-aigl6nzr.googlevideo.com; IP=${IP:-74.125.104.199}; SP=47555
W=$(ip -4 route get 8.8.4.4 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
WIP=$(ip -4 addr show $W | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')
R0="-m owner --uid-owner 1000 -p tcp --sport 47000:47999 -j RETURN"
cleanup() { iptables -t mangle -D OUTPUT $R0 2>/dev/null; [ -n "$T" ] && kill $T 2>/dev/null; chmod 644 $O/*; touch $O/done; }
trap cleanup EXIT INT TERM HUP
iptables -t mangle -I OUTPUT 1 $R0
tcpdump -i $W -nn -s 96 -w $O/c.pcap "host $IP and tcp port $SP" 2>$O/err & T=$!
sleep 1
( su 1000 -c "$C -sk -m 10 --local-port $SP --rate 3/m --resolve $H:443:$IP -w '%{http_code}:%{num_connects}:%{time_total} ' -o /dev/null -o /dev/null https://$H/generate_204 https://$H/generate_204" > $O/res 2>&1 ) &
sleep 4
n=0; while [ $n -lt 5 ]; do $D/vtpoke-arm64 $W $WIP $SP $IP 443 >> $O/poke 2>&1; echo "$(date +%T.%N | cut -c1-12) poke" >> $O/poke; sleep 3; n=$((n + 1)); done
sleep 15
echo "wan=$W $WIP" >> $O/res
