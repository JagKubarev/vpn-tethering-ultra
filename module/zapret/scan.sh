#!/system/bin/sh
# ============================================================================
# Подбор стратегии nfqws (генератор + проверка на живом канале).
#
#   scan.sh quick|full "сайт1 сайт2 ..."
#   scan.sh check            сторож (демон, раз в ~15 мин): работает ли
#                            стратегия сети; нет — прежние рабочие из истории,
#                            потом быстрый подбор. Журнал: $EVENTS.
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
MODE0="$MODE"
SITES="$2"
[ -n "$SITES" ] || SITES="www.youtube.com i.ytimg.com youtubei.googleapis.com discord.com gateway.discord.gg x.com www.facebook.com rutracker.org www.linkedin.com ya.ru www.google.com"
# контрольные сайты без блокировок: по ним отличаем "заблокировано" от "нет связи"
for _c in ya.ru www.google.com; do case " $SITES " in *" $_c "*) ;; *) SITES="$SITES $_c" ;; esac; done
CA=/apex/com.android.conscrypt/cacerts
[ -d "$CA" ] || CA=/system/etc/security/cacerts
case "$(uname -m)" in aarch64|arm64) NQ="$MODDIR/bin/nfqws-arm64" ;; *) NQ="$MODDIR/bin/nfqws-arm" ;; esac
WAN=$(sed -n 's/^wan=//p' "$MODDIR/status" 2>/dev/null)
IPT="iptables -w 2"
TMP="$OUT.tmp"
EVENTS=/data/adb/vpn_tether_zapret_events
HIST=/data/adb/vpn_tether_zapret_hist
ZNETS=/data/adb/vpn_tether_zapret_nets
case "$MODE" in quick|full|check) ;; *) echo "scan.sh: режим quick|full|check" >&2; exit 2 ;; esac

st() { # обновить файл состояния: st key=val ...
    local k
    for k in "$@"; do eval "S_${k%%=*}=\"\${k#*=}\""; done
    {
        echo "state=$S_state"; echo "mode=$MODE"; echo "done=$S_done"; echo "total=$S_total"
        echo "stage=$S_stage"; echo "msg=$S_msg"; echo "blocked=$S_blocked"; echo "started=$S_started"
    } > "$OUT.status.tmp" && mv -f "$OUT.status.tmp" "$OUT.status"
}

# итог последней проверки сторожа — для WebUI: "ЧЧ:ММ|текст"
wd_last() {
    printf '%s|%s\n' "$(date '+%H:%M')" "$*" > "$OUT.wd"
}

# журнал сторожа/подбора: "дата|сеть|событие" (держим последние 300 строк)
event() {
    printf '%s|%s|%s\n' "$(date '+%Y-%m-%d %H:%M')" "${NETID#*"|"}" "$*" | tr -d '\r' >> "$EVENTS"
    [ "$(awk 'END {print NR}' "$EVENTS" 2>/dev/null)" -gt 400 ] && { tail -n 300 "$EVENTS" > "$EVENTS.tmp" && mv -f "$EVENTS.tmp" "$EVENTS"; }
    chmod 600 "$EVENTS" 2>/dev/null
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
    [ "$MODE0" = check ] && [ "$S_state" != done ] && wd_last "не проверил: ${S_msg:-$S_state}"
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

# Большой ClientHello (постквантовый ключ, 2 TCP-сегмента) — как у Chrome и
# AdGuard. 21.10 стратегия открывала 10/10 обычным curl и пропускала половину
# таких. Сайт засчитывается, только если открылся обоими. Не умеет curl —
# проверяем только обычным.
BIG=""
if curl -s -o /dev/null -m 6 --curves X25519Kyber768Draft00:X25519 --interface "$WAN" --capath "$CA" https://ya.ru/ 2>/dev/null; then
    BIG="X25519Kyber768Draft00:X25519"
fi

# test_sites -> "ok_count avg_ms" и $TMP/res (h ok|rc)
test_sites() {
    local pids=""
    rm -f "$TMP"/r.* "$TMP"/b.*
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
        if [ -n "$BIG" ]; then
            (
                c=$(curl -s -o /dev/null -m 6 --curves "$BIG" --interface "$WAN" --capath "$CA" --resolve "$h:443:$ip" \
                    -w '%{http_code}' "https://$h/" 2>/dev/null)
                rc=$?
                if [ -n "$c" ] && [ "$c" != "000" ]; then echo ok > "$TMP/b.$h"; else echo "xb$rc" > "$TMP/b.$h"; fi
            ) &
            pids="$pids $!"
        fi
    done < "$TMP/ips"
    # ждём только свои curl: голый wait ждал бы и nfqws (он тоже наш потомок)
    wait $pids
    # большой ClientHello не прошёл — сайт не открыт
    if [ -n "$BIG" ]; then
        while read -r h ip; do
            v=""; read -r v _ < "$TMP/b.$h" 2>/dev/null
            [ "$v" = ok ] || echo "${v:-xb} 0" > "$TMP/r.$h"
        done < "$TMP/ips"
    fi
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
if [ -z "$BLOCKED" ]; then
    [ "$MODE" = check ] && wd_last "ничего не заблокировано"
    st state=done stage="готово" msg="ни один сайт из набора не заблокирован — подбирать нечего"
    exit 0
fi

# основной zapret на запросы сканера не влияет и с ним: правило сканера стоит
# в POSTROUTING первым, вердикт NFQUEUE завершает обход mangle
$IPT -t mangle -I POSTROUTING 1 $RULE

# run_strat "<аргументы с @G/@Q>" "этап" -> строка в results
run_strat() {
    local a="$1" stage="$2" real ok=0 brk=0 sum=0 det="" v t
    real=$(echo "$a" | sed "s#@G#@$ZDIR/tls_clienthello_www_google_com.bin#g; s#@Q#@$ZDIR/quic_initial_www_google_com.bin#g")
    # группа 3998 = ZAPRET_GID из service.sh: основной zapret её не трогает
    "$NQ" --qnum=$Q --uid=0:3998 --bind-fix4 $real > "$TMP/nq.log" 2>&1 &
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

POS_A="1 2 midsld sniext+1 1,midsld host+1 1,host+1,midsld"
FOOL_ALL="md5sig badseq badsum ts datanoack ttl3 ttl5 autottl"
fool_arg() {
    case "$1" in
        ttl*)    echo "--dpi-desync-ttl=${1#ttl}" ;;
        autottl) echo "--dpi-desync-autottl" ;;
        *)       echo "--dpi-desync-fooling=$1" ;;
    esac
}
FAKE="--dpi-desync-fake-tls=@G"

# Сайты YouTube в наборе — у них может быть своя стратегия (2.22: второй
# профиль nfqws по zapret/list-youtube.txt)
YT_RE='youtube|ytimg|ggpht|googlevideo'
NBY=$(echo $BLOCKED | tr ' ' '\n' | grep -cE "$YT_RE")
# оба профиля для проверки: YouTube по своему списку, остальное — общей
composite() { # composite ОБЩАЯ [YOUTUBE]
    if [ -n "$2" ] && [ "$2" != "$1" ]; then
        echo "--filter-tcp=443 --hostlist=$ZDIR/list-youtube.txt $2 --new --filter-tcp=443 $1"
    else
        echo "$1"
    fi
}

# --- сторож: текущая стратегия -> прежние из истории -> быстрый подбор ----
WD=0
if [ "$MODE" = "check" ]; then
    WD=1
    NB=$(echo $BLOCKED | wc -w)
    # прошла: ничего не сломала и открыла все заблокированные (из 4+ — все, кроме одного)
    passed() {
        run_strat "$1" "$2"
        tail -n 1 "$OUT.results" | awk -F'|' -v nb="$NB" \
            '{ o = $1 - ($2 - nb); need = (nb >= 4) ? nb - 1 : nb; exit !($3 == 0 && o >= need) }'
    }
    # последний прогон не открыл вообще ничего, даже контрольные — это связь
    nothing_opened() { tail -n 1 "$OUT.results" | awk -F'|' '{ exit !($1 == 0) }'; }
    # что не открылось у последнего прогона: "youtube.com:x28 ..." (для журнала)
    last_fail() { tail -n 1 "$OUT.results" | cut -d'|' -f7 | cut -c1-200; }
    # текущая — оба профиля (своя YouTube, если есть), с пометками @G/@Q
    CUR=$(sh "$MODDIR/service.sh" --zapret-strategy "${NETID%%"|"*}" "${NETID#*"|"}" full 2>/dev/null | \
        sed "s#@$ZDIR/tls_clienthello_www_google_com.bin#@G#g; s#@$ZDIR/quic_initial_www_google_com.bin#@Q#g")
    S_total=2
    st stage="проверяю стратегию сети"
    if [ -n "$CUR" ] && { passed "$CUR" "текущая" || passed "$CUR" "текущая"; }; then
        last=$(awk -F'|' 'END {print $3}' "$EVENTS" 2>/dev/null)
        [ "$last" = "сторож: стратегия работает" ] || event "сторож: стратегия работает"
        wd_last "работает"
        st state=done stage="готово" msg="текущая стратегия работает"
        exit 0
    fi
    # 16:21 21.10: все сайты разом "не открылись", подбор выбрал стратегию
    # хуже прежней. Связь пропала — не меняем ничего; иначе перепроверка через минуту.
    if nothing_opened; then
        event "сторож: не открылось вообще ничего, даже контрольные — похоже, связь; стратегию не трогаю"
        wd_last "нет связи, отложил"
        st state=done stage="готово" msg="нет связи — проверка отложена"
        exit 0
    fi
    FAIL1=$(last_fail)
    st stage="перепроверка через минуту"
    sleep 60
    if passed "$CUR" "текущая"; then
        event "сторож: кратковременный сбой ($FAIL1) — через минуту стратегия работает"
        wd_last "работает (был сбой)"
        st state=done stage="готово" msg="кратковременный сбой — стратегия работает"
        exit 0
    fi
    if nothing_opened; then
        event "сторож: не открылось вообще ничего, даже контрольные — похоже, связь; стратегию не трогаю"
        wd_last "нет связи, отложил"
        st state=done stage="готово" msg="нет связи — проверка отложена"
        exit 0
    fi
    event "сторож: стратегия не открывает ($(last_fail)) — ищу замену"
    # прежние стратегии этой сети и сетей с тем же названием (YOTA = 25011 и
    # 25002), новые первыми, без повторов (только свои параметры: custom)
    KEYS=$(L="${NETID#*"|"}" K="${NETID%%"|"*}" awk -F'|' '$4 == ENVIRON["L"] { printf "%s ", $1 } END { print ENVIRON["K"] }' "$ZNETS" 2>/dev/null)
    [ -n "$KEYS" ] || KEYS="${NETID%%"|"*}"
    # строка истории: "общая|youtube" (youtube пусто — одна на всё)
    KS=" $KEYS " awk -F'|' 'index(ENVIRON["KS"], " " $1 " ") && $2 == "custom" && $3 != "" { l[++n] = $3 "|" $6 } END { for (i = n; i >= 1; i--) if (!(l[i] in s)) { s[l[i]] = 1; print l[i] } }' \
        "$HIST" 2>/dev/null > "$TMP/hist"
    S_total=$((S_done + $(wc -l < "$TMP/hist")))
    st stage="пробую прежние стратегии"
    while IFS= read -r h; do
        a="${h%%"|"*}"; y="${h#*"|"}"
        c=$(composite "$a" "$y")
        [ -n "$a" ] && [ "$c" != "$CUR" ] || continue
        if passed "$c" "история" && passed "$c" "история"; then
            if [ "$(sh "$ZDIR/netid.sh" "$WAN" 2>/dev/null | head -1)" != "$NETID" ]; then
                wd_last "сеть сменилась во время проверки"
                st state=done stage="готово" msg="сеть сменилась во время проверки — не запоминаю"
                exit 0
            fi
            r=$(sh "$MODDIR/webctl.sh" znet-set custom "$a" "сторож: прежняя рабочая" "$y" 2>/dev/null)
            event "сторож: вернул прежнюю стратегию: $a${y:+ (YouTube: $y)}"
            wd_last "починил: прежняя стратегия"
            st state=done stage="готово" msg="вернул прежнюю рабочую стратегию"
            exit 0
        fi
    done < "$TMP/hist"
    event "сторож: прежние не подошли — быстрый подбор"
    MODE=quick
fi

if [ "$MODE" = "quick" ]; then
    # проверенные шаблоны (autottl убран: ломал обычные сайты во всех 6 проверенных сетях)
    S_total=19
    st stage="быстрый подбор"
    while IFS= read -r a; do
        [ -n "$a" ] && run_strat "$a" "быстрый"
    done <<EOF
--dpi-desync=multisplit --dpi-desync-split-pos=1,host+1,midsld --dpi-desync-split-seqovl=1
--dpi-desync=multidisorder --dpi-desync-split-pos=1,host+1,midsld
--dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-split-seqovl=1
--dpi-desync=fakedsplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq
--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,midsld $FAKE
--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld $FAKE
--dpi-desync=fake,multisplit --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,sniext+1 $FAKE
--dpi-desync=fake,fakedsplit --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1 $FAKE
--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=www.google.com --dpi-desync-fooling=md5sig
--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=sberbank.ru --dpi-desync-fooling=md5sig
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
    S_total=$(( 14 + 8 + 36 + 3 + 4 + 9 ))
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
            for p in 1 midsld 1,midsld 1,host+1,midsld; do
                run_strat "--dpi-desync=fake,$m $(fool_arg $f) --dpi-desync-split-pos=$p $FAKE" "3"
            done
        done
        run_strat "--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=www.google.com $(fool_arg $f)" "3"
        run_strat "--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=sberbank.ru $(fool_arg $f)" "3"
    done
    # приманки с российским SNI (идеи ZDT-D): ТСПУ свои сайты не блокирует,
    # а при белых списках это может оказаться единственным, что проходит
    st stage="3/4 приманки с российским SNI"
    run_strat "--dpi-desync=fake,hostfakesplit --dpi-desync-split-pos=host+1 --dpi-desync-hostfakesplit-midhost=midsld --dpi-desync-hostfakesplit-mod=host=www.google.com --dpi-desync-fake-tls=@G --dpi-desync-fake-tls-mod=rnd,dupsid,sni=sberbank.ru --dpi-desync-fooling=datanoack --dpi-desync-repeats=6 --dpi-desync-cutoff=n6" "3"
    run_strat "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,sld+1 --dpi-desync-split-seqovl=2 --dpi-desync-split-seqovl-pattern=@G --dpi-desync-fake-tls=@G --dpi-desync-fake-tls-mod=rnd,dupsid,sni=max.ru --dpi-desync-fooling=datanoack --dpi-desync-repeats=6 --dpi-desync-cutoff=n5" "3"
    run_strat "--dpi-desync=fake,multisplit --dpi-desync-split-pos=1,host+1,midsld --dpi-desync-split-seqovl=1 --dpi-desync-fake-tls=@G --dpi-desync-fake-tls-mod=rnd,dupsid,sni=gosuslugi.ru --dpi-desync-fooling=datanoack --dpi-desync-cutoff=n5" "3"
    # C2: разрез с наложением 1 байта (seqovl) — 21.10 YOTA: только он и
    # multidisorder с позиции 1 проходили с ClientHello Chrome/AdGuard
    st stage="3/4 разрез с наложением"
    for p in 1,midsld 1,host+1,midsld 2,midsld host+1,midsld; do
        run_strat "--dpi-desync=multisplit --dpi-desync-split-pos=$p --dpi-desync-split-seqovl=1" "3"
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
# + 2 лучших именно для YouTube (могут не попасть в общие 3)
if [ "$NBY" -gt 0 ]; then
    awk -F'|' -v re="$YT_RE" '$3 == 0 && $5 !~ /--new/ { n = split($7, d, " "); f = 0; for (i = 1; i <= n; i++) if (d[i] ~ re) f++; print f "|" $4 "|" $5 }' "$OUT.results" | \
        sort -t'|' -k1,1n -k2,2n | cut -d'|' -f3 | head -n 2 >> "$TMP/top"
    awk '!s[$0]++' "$TMP/top" > "$TMP/top2" && mv -f "$TMP/top2" "$TMP/top"
fi
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
# По группам: остальные сайты (og) и YouTube (oy) — по худшему из прогонов.
# Общая — лучшая для остальных; для YouTube — своя, только если она открывает
# больше YouTube, чем общая. Обе строки: "открыла|аргументы".
pick() { # pick gen|yt
    awk -F'|' -v nb="$NB" -v nby="$NBY" -v re="$YT_RE" -v want="$1" '
    $5 ~ /--new/ { next }
    { a = $5; brk = $3 + 0; n = split($7, d, " "); fy = 0; fg = 0
      for (i = 1; i <= n; i++) { if (d[i] ~ re) fy++; else fg++ }
      og = (nb - nby) - fg; oy = nby - fy
      if (!(a in runs)) { mg[a] = og; my[a] = oy; mb[a] = brk }
      runs[a]++; ms[a] += $4
      if (og < mg[a]) mg[a] = og
      if (oy < my[a]) my[a] = oy
      if (brk > mb[a]) mb[a] = brk }
    END {
      for (a in runs) {
        if (mb[a] > 0) continue
        o = (want == "yt") ? my[a] : mg[a]; o2 = (want == "yt") ? mg[a] : my[a]
        if (o <= 0 && !(want == "gen" && nb == nby && my[a] > 0)) continue
        t = ms[a] / runs[a]
        if (b == "" || o > bo || (o == bo && o2 > bo2) || (o == bo && o2 == bo2 && runs[a] > br) || (o == bo && o2 == bo2 && runs[a] == br && t < bt)) { b = a; bo = o; bo2 = o2; br = runs[a]; bt = t; byt = my[a] }
      }
      if (b != "") print bo "|" byt "|" b
    }' "$OUT.results"
}
BG=$(pick gen); BY=$(pick yt)
BEST=""; BEST_YT=""
if [ -n "$BG" ]; then
    BEST="${BG%%"|"*}|${BG#*"|"*"|"}"          # "открыла|аргументы" (остальные сайты)
    gy=$(echo "$BG" | cut -d'|' -f2)               # сколько YouTube открывает общая
    if [ -n "$BY" ] && [ "$NBY" -gt 0 ] && [ "${BY%%"|"*}" -gt "$gy" ]; then
        BEST_YT="${BY#*"|"*"|"}"
    fi
fi
if [ "$PERNET" = "1" ] && [ -n "$BEST" ]; then
    if [ -z "${NETID%%"|"*}" ]; then
        MSG="не понял, что за сеть — стратегия не запомнена, примени вручную"
    elif [ "$(sh "$ZDIR/netid.sh" "$WAN" 2>/dev/null | head -1)" != "$NETID" ]; then
        MSG="сеть сменилась во время подбора — не запоминаю"
    else
        if [ -n "$BEST_YT" ]; then
            how="остальные ${BEST%%"|"*} из $((NB - NBY)), YouTube — своя: ${BY%%"|"*} из $NBY"
        else
            how="открыла $((${BEST%%"|"*} + gy)) из $NB"
        fi
        r=$(sh "$MODDIR/webctl.sh" znet-set custom "${BEST#*"|"}" "подбор: $how" "$BEST_YT" 2>/dev/null)
        case "$r" in
            OK*) MSG="лучшая запомнена для сети «${NETID#*"|"}» ($how)" ;;
            *)   MSG="не удалось запомнить: ${r#ERR }" ;;
        esac
    fi
elif [ -z "$BEST" ]; then
    MSG="ни одна стратегия не открыла заблокированные сайты без поломок"
fi

if [ "$WD" = 1 ]; then
    event "сторож: подбор — ${MSG:-готово}"
    case "$MSG" in лучшая*) wd_last "починил: подбор" ;; *) wd_last "не починил: ${MSG:-нет стратегии}" ;; esac
else
    event "подбор ($MODE): ${MSG:-готово}"
fi
S_state=done
st stage="готово" msg="$MSG"
