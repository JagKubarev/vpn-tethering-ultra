#!/system/bin/sh
# стенд 16.11: что запускает волну Google на YOTA — частота соединений с обходом (А) или закрытые имена,
# видные ТСПУ открыто (Б). Каждая попытка: новый адрес (net-renew), 2 мин контроля, нагрузка (сайты из
# list-default по 2 запроса, 8 параллельно), 6 мин контроля. Контроль раз в 15 с: https и http
# www.google.com мимо обхода. А — curl uid 1000 через обход демона; Б — curl root с группой 3998 (VPN_ZAPRET
# её пропускает: прямой запрос). AdGuard для обоих — мимо (RETURN в nat OUTPUT)
[ "$(id -u)" = 0 ] || exit 1
M=/data/adb/modules/vpn-to-hotspot-usb; O=/data/local/tmp/wave1; rm -rf $O; mkdir -p $O; chmod 777 $O
C=$(command -v curl); R=$O/run.out
say() { echo "$(date +%T) $*" >> $R; }
RN="-m owner --uid-owner 1000 -p tcp -j RETURN"; RG="-m owner --gid-owner 3998 -p tcp -j RETURN"
fin() { trap - EXIT INT TERM HUP; iptables -t nat -D OUTPUT $RN 2>/dev/null; iptables -t nat -D OUTPUT $RG 2>/dev/null; sh $M/webctl.sh net-renew >/dev/null 2>&1; say "конец, адрес сменён"; touch $O/done; }
trap fin EXIT; trap "fin; exit 1" INT TERM HUP
iptables -t nat -I OUTPUT 1 $RN; iptables -t nat -I OUTPUT 1 $RG
sed 's/#.*//' $M/zapret/list-default.txt | tr -d ' \r' | grep -E '^[a-z0-9.-]+\.[a-z]+$' | grep -v -e google -e youtube -e '\.ru$' | head -${NS:-150} > $O/sites
say "сайтов $(wc -l < $O/sites)"
ctl() {   # ctl МЕТКА СЕКУНД
    e=$(( $(date +%s) + $2 ))
    while [ $(date +%s) -lt $e ]; do
        s=$(su -g 3998 -c "$C -s -o /dev/null -m 5 -w '%{http_code}' https://www.google.com/generate_204")
        h=$(su -g 3998 -c "$C -s -o /dev/null -m 5 -w '%{http_code}' http://www.google.com/generate_204")
        echo "$(date +%T) $1 https=$s http=$h" >> $O/ctl
        sleep 10
    done
}
load() {   # load А|Б
    U="1000"; [ "$1" = Б ] && U="-g 3998"
    n=0; ok=0; : > $O/load.$T
    for r in 1 2; do
        while read -r h; do
            ( c=$(su $U -c "$C -s -o /dev/null -m 6 -w '%{http_code}' https://$h/"); echo "$h $c" >> $O/load.$T ) &
            n=$((n + 1)); [ $((n % 8)) -eq 0 ] && wait
        done < $O/sites
        wait
    done
    say "нагрузка $1: $(wc -l < $O/load.$T) запросов, ответили $(awk '$2 != "000"' $O/load.$T | wc -l)"
}
T=0
for v in ${VARS:-А Б А Б А Б}; do
    T=$((T + 1))
    k=0
    while :; do
        sh $M/webctl.sh net-renew >/dev/null 2>&1; sleep 30
        W=$(sed -n 's/^wan=//p' $M/status); ad=$(ip -4 addr show $W 2>/dev/null | grep -oE 'inet [0-9.]+')
        s=$(su -g 3998 -c "$C -s -o /dev/null -m 5 -w '%{http_code}' https://www.google.com/generate_204")
        [ "$s" = 204 ] && break
        k=$((k + 1)); say "попытка $T: на адресе $ad Google https=$s — меняю адрес"; [ $k -lt 3 ] || break
    done
    say "попытка $T ($v): адрес $ad"
    ctl "$T$v-до" 120
    t0=$(date +%T); load $v; say "нагрузка $T $v: $t0–$(date +%T)"
    ctl "$T$v-после" 360
    say "попытка $T: https молчал $(grep -c "^.* $T$v-после https=000 http=[23]" $O/ctl) раз из $(grep -c " $T$v-после " $O/ctl) после нагрузки"
done
say DONE
