#!/system/bin/sh
# стенд 16.11: раз в 3 с — vtpoke в каждое установленное соединение стенда (порты 47000–47999 -> :443),
# по которому ≥2,5 с ничего не шло ни туда, ни обратно (ss: lastsnd и lastrcv). Отдельный процесс:
# не наследует trap стенда.   poker.sh ИФЕЙС ФАЙЛ_СЧЁТЧИКА
S=/data/local/tmp/dep/vtpoke; W=$1; F=$2
while :; do
    ss -tni state established '( sport >= :47000 and sport <= :47999 and dport = :443 )' 2>/dev/null | awk '
        $1 ~ /^[0-9]+$/ && NF >= 4 { l = $3; r = $4; next }
        l != "" { s = 999999; v = 999999
            for (i = 1; i <= NF; i++) { if ($i ~ /^lastsnd:/) s = substr($i, 9) + 0; else if ($i ~ /^lastrcv:/) v = substr($i, 9) + 0 }
            if (s >= 2500 && v >= 2500) print l, r; l = "" }' |
    while read -r l r; do
        $S/vtpoke-arm64 $W ${l%:*} ${l##*:} ${r%:*} 443 >/dev/null 2>&1 && echo "$(date +%s) $l $r" >> $F
    done
    sleep 3
done
