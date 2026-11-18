#!/system/bin/sh
# стенд 17.11: QUIC к молчащим стойкам (фильтр «первый пакет ответа 16 03 03» — TCP; пройдёт ли QUIC и с какой
# скоростью). Свой nfqws2 (очередь 211), curl модуля (HTTP/3) от root (от uid 1000 17.11 QUIC отклоняет сам телефон —
# ICMP «порт недоступен» и на cloudflare-quic.com; root на время стенда — мимо AdGuard: UDP 443 и TCP), 2 МБ
# с узла: имя googlevideo, Host dl.google.com (как quic_vid в scan.sh).
#   q  — QUIC + профиль QUIC стратегии (подделка Initial www.google.com);
#   q0 — QUIC без подделки (ACCEPT первым в mangle POSTROUTING — мимо обхода демона, своего nfqws2 нет);
#   t  — TCP с малым окном и видеопрофилем, как у демона на этих стойках
[ "$(id -u)" = 0 ] || { echo "не root"; exit 1; }
M=/data/adb/modules/vpn-to-hotspot-usb; ZAPRET2_DIR=$M/zapret2; N=$M/bin/nfqws2-arm64; Q=211
O=/data/local/tmp/t44; C=/data/local/tmp/t44c/curl
rm -rf $O; mkdir -p $O; chmod 755 $O
# каталог модуля uid 1000 не читает — curl рядом
mkdir -p /data/local/tmp/t44c; cp $M/bin/curl $C; chmod 755 /data/local/tmp/t44c $C
log() { :; }
. $M/lib/zapret.sh
zapret2_strat_load $M/zapret2/strategies/vt_soft_crck.conf
H=rr1---sn-aigl6nzr.googlevideo.com; U="https://$H/linux/direct/google-chrome-stable_current_amd64.deb"
IPS="${IPS:-173.194.6.232 74.125.7.115 74.125.99.19 173.194.19.8 74.125.11.33 173.194.10.71 74.125.154.194 74.125.13.133 173.194.160.36 173.194.164.243}"
VID="--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tcp_ts_up:repeats=2 --lua-desync=multisplit:pos=midsld"
B="--qnum=$Q --uid=0:3998 --bind-fix4 $Z2_BASE --lua-init=@$M/zapret2/lua/vpn-tether.lua"
RT="-m owner --uid-owner 0 -p tcp --sport 47000:47999 --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
RU="-m owner --uid-owner 0 -d 74.125.0.0/16 -p udp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
RU2=$(echo "$RU" | sed "s#74.125.0.0/16#173.194.0.0/16#")
RA="-m owner --uid-owner 0 -d 74.125.0.0/16 -p udp --dport 443 -j ACCEPT"; RA2=$(echo "$RA" | sed "s#74.125.0.0/16#173.194.0.0/16#")
GA="-m owner --uid-owner 0 -p udp --dport 443 -j RETURN"; GN="-m owner --uid-owner 0 -p tcp -j RETURN"
P=""
cleanup() {
    trap - EXIT INT TERM HUP
    iptables -t mangle -D POSTROUTING $RT 2>/dev/null; iptables -t mangle -D POSTROUTING $RU 2>/dev/null; iptables -t mangle -D POSTROUTING $RU2 2>/dev/null
    iptables -t mangle -D POSTROUTING $RA 2>/dev/null; iptables -t mangle -D POSTROUTING $RA2 2>/dev/null
    iptables -D ADGUARD_OUTPUT $GA 2>/dev/null; iptables -t nat -D OUTPUT $GN 2>/dev/null
    [ -n "$P" ] && kill $P 2>/dev/null
    chmod 644 $O/* 2>/dev/null; touch $O/done
}
trap cleanup EXIT; trap "cleanup; exit 1" INT TERM HUP
iptables -t mangle -I POSTROUTING 1 $RT; iptables -t mangle -I POSTROUTING 1 $RU; iptables -t mangle -I POSTROUTING 1 $RU2
iptables -I ADGUARD_OUTPUT 1 $GA; iptables -t nat -I OUTPUT 1 $GN
n=0
for v in ${VARS:-q q0 t t q0 q}; do
    n=$((n + 1))
    case $v in
        q)  A="$B $Z2_QUIC" ;;
        q0) A="" ;;
        t)  A="$B --filter-tcp=443 --out-range=a --payload=all --lua-desync=vt_wssize_ramp:wsize=1:scale=1 $VID" ;;
    esac
    if [ -n "$A" ]; then
        set -f
        # shellcheck disable=SC2086
        $N $A >/dev/null 2>&1 &
        P=$!; set +f; sleep 2
        kill -0 $P 2>/dev/null || { echo "$n $v nfqws2 не запустился" >> $O/res; P=""; continue; }
    else
        iptables -t mangle -I POSTROUTING 1 $RA; iptables -t mangle -I POSTROUTING 1 $RA2
    fi
    case $v in t) PR="--http1.1 --local-port 47000-47999" ;; *) PR="--http3-only" ;; esac
    WT=""
    for i in $IPS; do
        ( r=$($C -sk -m 12 $PR -r 0-2097151 --connect-to $H:443:$i:443 -H 'Host: dl.google.com' -o /dev/null -w '%{http_code}:%{time_starttransfer}:%{time_total}:%{size_download}:%{speed_download}' $U); echo "$n $v $i $r" >> $O/res ) &
        WT="$WT $!"
    done
    wait $WT
    if [ -n "$P" ]; then kill $P; wait $P 2>/dev/null; P=""; else iptables -t mangle -D POSTROUTING $RA 2>/dev/null; iptables -t mangle -D POSTROUTING $RA2 2>/dev/null; fi
    sleep 1
done
