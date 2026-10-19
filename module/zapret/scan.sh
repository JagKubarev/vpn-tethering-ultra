#!/system/bin/sh
# ============================================================================
# Подбор стратегии nfqws (генератор + проверка на живом канале).
#
#   scan.sh quick|full "сайт1 сайт2 ..."
#
# Проверяются только запросы самого сканера (root, curl --interface <WAN>)
# через отдельную очередь NFQUEUE: трафик телефона и раздачи не трогается.
# На время сканирования root-TCP идёт мимо AdGuard (его прокси подменяет
# сертификаты) — после окончания всё снимается (trap).
#
# Результаты: $OUT.status (КЛЮЧ=значение) и $OUT.results:
#   ok|всего|сломал|сред_мс|аргументы|этап|подробности
# В аргументах @G / @Q — fake-файлы модуля (service.sh подставит пути).
# ============================================================================
MODDIR="${0%/*}/.."
[ -f "$MODDIR/service.sh" ] || MODDIR=/data/adb/modules/vpn-to-hotspot-usb
ZDIR="$MODDIR/zapret"
OUT=/data/local/tmp/vpn_tether_zscan
Q=203
MODE="${1:-quick}"
SITES="$2"
[ -n "$SITES" ] || SITES="www.youtube.com i.ytimg.com discord.com gateway.discord.gg x.com www.facebook.com rutracker.org www.linkedin.com ya.ru www.google.com"
# контрольные сайты без блокировок: по ним отличаем "заблокировано" от "нет связи"
for _c in ya.ru www.google.com; do case " $SITES " in *" $_c "*) ;; *) SITES="$SITES $_c" ;; esac; done
CA=/apex/com.android.conscrypt/cacerts
[ -d "$CA" ] || CA=/system/etc/security/cacerts
case "$(uname -m)" in aarch64|arm64) NQ="$MODDIR/bin/nfqws-arm64" ;; *) NQ="$MODDIR/bin/nfqws-arm" ;; esac
WAN=$(sed -n 's/^wan=//p' "$MODDIR/status" 2>/dev/null)
IPT="iptables -w 2"
TMP="$OUT.tmp"

st() { # обновить файл состояния: st key=val ...
    local k
    for k in "$@"; do eval "S_${k%%=*}=\"\${k#*=}\""; done
    {
        echo "state=$S_state"; echo "mode=$MODE"; echo "done=$S_done"; echo "total=$S_total"
        echo "stage=$S_stage"; echo "msg=$S_msg"; echo "blocked=$S_blocked"; echo "started=$S_started"
    } > "$OUT.status.tmp" && mv -f "$OUT.status.tmp" "$OUT.status"
}

RULE="-o $WAN -m owner --uid-owner 0 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
NQPID=""
cleanup() {
    [ -n "$NQPID" ] && kill "$NQPID" 2>/dev/null
    $IPT -t mangle -D POSTROUTING $RULE 2>/dev/null
    $IPT -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
    $IPT -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null
    rm -rf "$TMP"
    rm -f "$OUT.pid"
}
on_exit() {
    cleanup
    [ "$S_state" = "running" ] && st state=stopped msg="остановлено"
}
trap on_exit EXIT
trap 'exit 0' INT TERM

echo $$ > "$OUT.pid"
: > "$OUT.results"
S_done=0; S_total=0; S_blocked=""; S_started=$(date +%H:%M:%S)
st state=running stage="подготовка" msg=""

[ -n "$WAN" ] || { st state=error msg="модуль ещё не видел сеть оператора"; exit 1; }
ip -4 addr show "$WAN" 2>/dev/null | grep -q "inet " || { st state=error msg="у $WAN нет адреса — сеть только что сменилась? Повтори через полминуты"; exit 1; }
[ -x "$NQ" ] || { st state=error msg="нет nfqws"; exit 1; }
mkdir -p "$TMP"
# Сеть, в которой подбираем: лучшая стратегия запоминается для неё
NETID=$(sh "$ZDIR/netid.sh" "$WAN" 2>/dev/null | head -1)
PERNET=$(sh "$MODDIR/service.sh" --get ZAPRET_PER_NET 2>/dev/null)

# мимо AdGuard; основной zapret не трогает запросы сканера
$IPT -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
$IPT -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null

# --- адреса: DoH (обычный DNS мимо VPN оператор может подменить)
st stage="узнаю адреса"
: > "$TMP/ips"
for h in $SITES; do
    ip=$(curl -s -m 6 --capath "$CA" -H 'accept: application/dns-json' \
        "https://1.1.1.1/dns-query?name=$h&type=A" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | head -1 | grep -oE '[0-9.]+')
    [ -n "$ip" ] && echo "$h $ip" >> "$TMP/ips"
done
[ -s "$TMP/ips" ] || { st state=error msg="не удалось узнать адреса сайтов"; exit 1; }
NS=$(wc -l < "$TMP/ips")

# test_sites -> "ok_count avg_ms" и $TMP/res (h ok|rc)
test_sites() {
    local pids=""
    rm -f "$TMP"/r.*
    while read -r h ip; do
        (
            r=$(curl -s -o /dev/null -m 6 --interface "$WAN" --capath "$CA" --resolve "$h:443:$ip" \
                -w '%{http_code} %{time_total}' "https://$h/" 2>/dev/null)
            rc=$?
            set -- $r
            # успех = пришёл HTTP-ответ. ТСПУ режет на рукопожатии; если ответ
            # пришёл, а тело не успело докачаться (медленный канал, rc=28) —
            # блокировку обошли, это не провал стратегии
            if [ -n "$1" ] && [ "$1" != "000" ]; then echo "ok $2" > "$TMP/r.$h"; else echo "x$rc 0" > "$TMP/r.$h"; fi
        ) &
        pids="$pids $!"
    done < "$TMP/ips"
    # ждём только свои curl: голый wait ждал бы и nfqws (он тоже наш потомок)
    wait $pids
}

# --- исходное состояние: что вообще заблокировано
st stage="проверяю, что заблокировано"
test_sites
BASE_OK=""; BLOCKED=""
while read -r h ip; do
    read -r v _ < "$TMP/r.$h"
    if [ "$v" = ok ]; then BASE_OK="$BASE_OK $h"; else BLOCKED="$BLOCKED $h"; fi
done < "$TMP/ips"
st blocked="$(echo $BLOCKED)"
[ -n "$BASE_OK" ] || { st state=error msg="через $WAN не открылся ни один сайт, даже без блокировок — нет интернета или сеть сменилась"; exit 1; }
[ -n "$BLOCKED" ] || { st state=done stage="готово" msg="ни один сайт из набора не заблокирован — подбирать нечего"; exit 0; }

# основной zapret на запросы сканера не влияет и с ним: правило сканера стоит
# в POSTROUTING первым, вердикт NFQUEUE завершает обход mangle
$IPT -t mangle -I POSTROUTING 1 $RULE

# run_strat "<аргументы с @G/@Q>" "этап" -> строка в results
run_strat() {
    local a="$1" stage="$2" real ok=0 brk=0 sum=0 det="" v t
    real=$(echo "$a" | sed "s#@G#@$ZDIR/tls_clienthello_www_google_com.bin#g; s#@Q#@$ZDIR/quic_initial_www_google_com.bin#g")
    "$NQ" --qnum=$Q --uid=0:0 --bind-fix4 $real > "$TMP/nq.log" 2>&1 &
    NQPID=$!
    sleep 0.6
    if ! kill -0 "$NQPID" 2>/dev/null; then
        NQPID=""
        echo "0|$NS|0|0|$a|$stage|nfqws: $(tail -n 1 "$TMP/nq.log" | tr '|' ' ' | cut -c1-80)" >> "$OUT.results"
        return
    fi
    test_sites
    kill "$NQPID" 2>/dev/null; wait "$NQPID" 2>/dev/null; NQPID=""
    while read -r h ip; do
        read -r v t < "$TMP/r.$h"
        if [ "$v" = ok ]; then
            ok=$((ok + 1))
            sum=$(awk -v s="$sum" -v t="$t" 'BEGIN { printf "%d", s + t * 1000 }')
        else
            case " $BASE_OK " in *" $h "*) brk=$((brk + 1)) ;; esac
            det="$det ${h#www.}:$v"
        fi
    done < "$TMP/ips"
    [ "$ok" -gt 0 ] && sum=$((sum / ok))
    echo "$ok|$NS|$brk|$sum|$a|$stage|${det# }" >> "$OUT.results"
    S_done=$((S_done + 1))
    st done=$S_done
}

# лучшие N аргументов из results (не ломают, больше ok, быстрее), фильтр по этапу
best() { # best N [этап]
    grep "|${2:-}" "$OUT.results" | awk -F'|' '$3 == 0' | sort -t'|' -k1,1nr -k4,4n | head -n "$1" | cut -d'|' -f5
}

POS_A="1 2 midsld sniext+1 1,midsld host+1"
FOOL_ALL="md5sig badseq badsum ts datanoack ttl3 ttl5 autottl"
fool_arg() {
    case "$1" in
        ttl*)    echo "--dpi-desync-ttl=${1#ttl}" ;;
        autottl) echo "--dpi-desync-autottl" ;;
        *)       echo "--dpi-desync-fooling=$1" ;;
    esac
}
FAKE="--dpi-desync-fake-tls=@G"

if [ "$MODE" = "quick" ]; then
    # проверенные шаблоны (autottl убран: ломал обычные сайты во всех 6 проверенных сетях)
    S_total=14
    st stage="быстрый подбор"
    while IFS= read -r a; do
        [ -n "$a" ] && run_strat "$a" "быстрый"
    done <<EOF
--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,midsld $FAKE
--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld $FAKE
--dpi-desync=fake,multisplit --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,sniext+1 $FAKE
--dpi-desync=fake,fakedsplit --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1 $FAKE
--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=www.google.com --dpi-desync-fooling=md5sig
--dpi-desync=fake,multidisorder --dpi-desync-fooling=badseq --dpi-desync-split-pos=1,midsld $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=badsum --dpi-desync-split-pos=midsld $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=ts --dpi-desync-split-pos=midsld $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=datanoack --dpi-desync-split-pos=midsld $FAKE
--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=@G $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com
--dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld
--dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=@G
EOF
else
    S_total=$(( 12 + 8 + 26 + 9 ))
    # A: только разрез, без подделок
    st stage="1/4 разрез без подделок"
    for m in multisplit multidisorder; do
        for p in $POS_A; do run_strat "--dpi-desync=$m --dpi-desync-split-pos=$p" "1"; done
    done
    # B: одна подделка с разными способами «испортить» её для сервера
    st stage="2/4 виды подделок"
    for f in $FOOL_ALL; do run_strat "--dpi-desync=fake $(fool_arg $f) $FAKE" "2:$f"; done
    # лучшие 2 вида подделки (по этапу B), иначе md5sig + badseq
    F2=$(grep '|2:' "$OUT.results" | awk -F'|' '$3 == 0 && $1 > 0' | sort -t'|' -k1,1nr -k4,4n | head -n 2 | cut -d'|' -f6 | sed 's/^2://')
    [ -n "$F2" ] || F2="md5sig badseq"
    [ "$(echo $F2 | wc -w)" = 1 ] && F2="$F2 $( [ "$F2" = md5sig ] && echo badseq || echo md5sig )"
    # C: подделка + разрез
    st stage="3/4 подделка + разрез ($(echo $F2))"
    for f in $F2; do
        for m in multisplit multidisorder fakedsplit fakeddisorder; do
            for p in 1 midsld 1,midsld; do
                run_strat "--dpi-desync=fake,$m $(fool_arg $f) --dpi-desync-split-pos=$p $FAKE" "3"
            done
        done
        run_strat "--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=www.google.com $(fool_arg $f)" "3"
    done
    # D: лучшие 3 — с другими вариантами поддельного ClientHello и повторами
    st stage="4/4 варианты подделки"
    best 3 > "$TMP/top3"
    while IFS= read -r a; do
        [ -n "$a" ] || continue
        b=$(echo "$a" | sed 's# --dpi-desync-fake-tls=@G##')
        run_strat "$b --dpi-desync-fake-tls-mod=rnd,dupsid" "4"
        run_strat "$b --dpi-desync-fake-tls=@G --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com" "4"
        run_strat "$a --dpi-desync-repeats=6" "4"
    done < "$TMP/top3"
fi

# перепроверка лучших: случайный успех не должен выиграть
st stage="перепроверяю лучшие"
best 3 > "$TMP/top"
S_total=$((S_done + $(wc -l < "$TMP/top") * 2))
while IFS= read -r a; do
    [ -n "$a" ] || continue
    run_strat "$a" "проверка"
    run_strat "$a" "проверка"
done < "$TMP/top"

# Лучшая: ничего не ломает, открыла больше заблокированных (по худшему из
# прогонов), перепроверена, быстрее. Та же логика, что у таблицы в WebUI.
MSG=""
NB=$(echo $BLOCKED | wc -w)
BEST=$(awk -F'|' -v nb="$NB" '
    { a = $5; ok = $1 + 0; brk = $3 + 0
      if (!(a in runs)) { mn[a] = ok; mb[a] = brk; ns[a] = $2 + 0 }
      runs[a]++; ms[a] += $4
      if (ok < mn[a]) mn[a] = ok
      if (brk > mb[a]) mb[a] = brk }
    END {
      for (a in runs) {
        if (mb[a] > 0) continue
        o = mn[a] - (ns[a] - nb); if (o <= 0) continue
        t = ms[a] / runs[a]
        if (b == "" || o > bo || (o == bo && runs[a] > br) || (o == bo && runs[a] == br && t < bt)) { b = a; bo = o; br = runs[a]; bt = t }
      }
      if (b != "") print bo "|" b
    }' "$OUT.results")
if [ "$PERNET" = "1" ] && [ -n "$BEST" ]; then
    if [ -z "${NETID%%"|"*}" ]; then
        MSG="не понял, что за сеть — стратегия не запомнена, примени вручную"
    elif [ "$(sh "$ZDIR/netid.sh" "$WAN" 2>/dev/null | head -1)" != "$NETID" ]; then
        MSG="сеть сменилась во время подбора — не запоминаю"
    else
        r=$(sh "$MODDIR/webctl.sh" znet-set custom "${BEST#*"|"}" "подбор: открыла ${BEST%%"|"*} из $NB" 2>/dev/null)
        case "$r" in
            OK*) MSG="лучшая запомнена для сети «${NETID#*"|"}» (открыла ${BEST%%"|"*} из $NB)" ;;
            *)   MSG="не удалось запомнить: ${r#ERR }" ;;
        esac
    fi
elif [ -z "$BEST" ]; then
    MSG="ни одна стратегия не открыла заблокированные сайты без поломок"
fi

S_state=done
st stage="готово" msg="$MSG"
