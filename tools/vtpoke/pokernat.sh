#!/system/bin/sh
# стенд 17.11 (t41): раз в 3 с — vtpoke в каждое установленное соединение клиента netns vtt (:443), по которому
# ≥2,5 с ничего не шло (ss в netns: lastsnd и lastrcv), с адресом WAN и портом после NAT (из conntrack).
#   pokernat.sh ИФЕЙС АДРЕС_WAN ФАЙЛ_СЧЁТЧИКА
S=/data/local/tmp/dep/vtpoke; W=$1; WIP=$2; F=$3
CT=/data/adb/modules/vpn-to-hotspot-usb/bin/conntrack-arm64; [ -x $CT ] || CT=conntrack
while :; do
    ip netns exec vtt ss -tni state established '( dport = :443 )' 2>/dev/null | awk '
        $1 ~ /^[0-9]+$/ && NF >= 4 { l = $3; r = $4; next }
        l != "" { s = 999999; v = 999999
            for (i = 1; i <= NF; i++) { if ($i ~ /^lastsnd:/) s = substr($i, 9) + 0; else if ($i ~ /^lastrcv:/) v = substr($i, 9) + 0 }
            if (s >= 2500 && v >= 2500) { split(l, a, ":"); split(r, b, ":"); print a[2], b[1] } l = "" }' |
    while read -r cp dst; do
        np=$($CT -L -p tcp -s 10.99.0.2 --sport "$cp" -d "$dst" --dport 443 2>/dev/null | awk '{ n = 0; for (i = 1; i <= NF; i++) if ($i ~ /^dport=/) { n++; if (n == 2) { print substr($i, 7); exit } } }')
        [ -n "$np" ] || continue
        $S/vtpoke-arm64 $W $WIP $np $dst 443 >/dev/null 2>&1 && echo "$(date +%s) $cp $np $dst" >> $F
    done
    sleep 3
done
