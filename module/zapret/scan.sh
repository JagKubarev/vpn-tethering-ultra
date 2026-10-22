#!/system/bin/sh
# ============================================================================
# Подбор стратегии nfqws (генератор + проверка на живом канале).
#
#   scan.sh quick|full "сайт1 сайт2 ..."
#   scan.sh sites ["сайт ..."]  сайтам, которых основная стратегия не
#                            открывает, — своя (ZALT); без списка — сайты из
#                            списков zapret (демон, раз в ~3 ч)
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
SITES_ARG="$2"
[ -n "$SITES" ] || [ "$MODE" = sites ] || SITES="www.youtube.com i.ytimg.com youtubei.googleapis.com discord.com gateway.discord.gg x.com www.facebook.com rutracker.org www.linkedin.com ya.ru www.google.com"
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
ZALT=/data/adb/vpn_tether_zapret_alt        # своя стратегия сайтов: ключ|название|сайт|аргументы|дата
ZSKIP=/data/adb/vpn_tether_zapret_altskip   # не открылись ничем: ключ|сайт|epoch (сутки не проверяем)
case "$MODE" in quick|full|check|sites) ;; *) echo "scan.sh: режим quick|full|check|sites" >&2; exit 2 ;; esac

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
# первые ответы сервера на запросы сканера — тоже в nfqws: без них не
# работают --wssize и autottl (2.25). Соединения сканера — по биту connmark.
SCMARK=0x08000000
RULE_MK="-o $WAN -m owner --uid-owner 0 -p tcp --dport 443 -j CONNMARK --set-xmark $SCMARK/$SCMARK"
RULE_IN="-i $WAN -p tcp --sport 443 -m connmark --mark $SCMARK/$SCMARK -m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:3 -j NFQUEUE --queue-num $Q --queue-bypass"
NQPID=""
cleanup() {
    [ -n "$NQPID" ] && kill "$NQPID" 2>/dev/null
    $IPT -t mangle -D POSTROUTING $RULE 2>/dev/null
    $IPT -t mangle -D OUTPUT $RULE_MK 2>/dev/null
    $IPT -t mangle -D PREROUTING $RULE_IN 2>/dev/null
    $IPT -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
    $IPT -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null
    rm -rf "$TMP"
    rm -f "$OUT.pid"
}
on_exit() {
    cleanup
    [ "$S_state" = "running" ] && st state=stopped msg="остановлено"
    [ "$MODE0" = check ] && [ "$S_state" != done ] && wd_last "не проверил: ${S_msg:-$S_state}"
    # проверка сайтов сорвалась (смена сети, VPN, нет адреса) — в журнал, и
    # метка демону: повторить через ~15 мин, а не через ZAPRET_ALT_MIN
    if [ "$MODE0" = sites ] && [ "$S_state" != done ]; then
        event "сайты: не проверил — ${S_msg:-$S_state}"
        : > "$OUT.sitesfail"
    fi
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
if [ "$MODE" = sites ]; then
    [ "$PERNET" = 1 ] && [ -n "${NETID%%"|"*}" ] || { st state=error msg="своя стратегия сайтов — только при «своей стратегии для каждой сети» и понятной сети"; exit 1; }
    if [ -z "$SITES_ARG" ]; then
        # сайты из списков zapret и уже закреплённые; без YouTube (у него
        # свой профиль), исключений и не открывшихся ничем за последние сутки
        sed 's/#.*//' "$ZDIR/list-youtube.txt" "$ZDIR/list-exclude.txt" 2>/dev/null | tr -d ' \r' | grep . > "$TMP/xl"
        cat "$ZSKIP" 2>/dev/null > "$TMP/skip"
        {
            cat "$ZDIR/list-default.txt" /data/adb/vpn_tether_zapret.txt /data/adb/vpn_tether_zapret_auto.txt 2>/dev/null
            [ -f "$ZALT" ] && K="${NETID%%"|"*}" awk -F'|' '$1 == ENVIRON["K"] { print $3 }' "$ZALT"
        } | tr 'A-Z' 'a-z' | sed 's/#.*//; s/^[*.]*//' | tr -d ' \r' | grep -E '^[a-z0-9.-]+\.[a-z0-9-]+$' | \
            K="${NETID%%"|"*}" N=$(date +%s) awk -F'|' '
                FILENAME == ARGV[1] { x[$1] = 1; next }
                FILENAME == ARGV[2] { if ($1 == ENVIRON["K"] && $3 + 86400 > ENVIRON["N"]) sk[$2] = 1; next }
                { h = $1; if ((h in seen) || (h in sk)) next; d = h
                  while (1) { if (d in x) next; i = index(d, "."); if (!i) break; d = substr(d, i + 1) }
                  seen[h] = 1; print h }' "$TMP/xl" "$TMP/skip" - | head -n 400 > "$TMP/sites"
        SITES="$(tr '\n' ' ' < "$TMP/sites")$SITES"
    fi
fi

# мимо AdGuard; основной zapret не трогает запросы сканера
$IPT -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
$IPT -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null

# --- адреса: DoH (обычный DNS мимо VPN оператор может подменить)
st stage="узнаю адреса"
: > "$TMP/ips"
# по 16 сразу: в режиме sites сайтов сотни
# не узнали с первого раза (телефон под нагрузкой, 22.10 после загрузки
# узнались 56 из ~210) — второй заход по оставшимся, по 8 и с запасом времени
resolve() { # resolve ПАРАЛЛЕЛЬНО ТАЙМАУТ
    local n=0 pids="" h
    for h in $SITES; do
        [ -s "$TMP/a.$h" ] && continue
        (
            ip=$(curl -s -m "$2" --capath "$CA" -H 'accept: application/dns-json' \
                "https://1.1.1.1/dns-query?name=$h&type=A" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | head -1 | grep -oE '[0-9.]+')
            [ -n "$ip" ] && echo "$h $ip" > "$TMP/a.$h"
        ) &
        pids="$pids $!"; n=$((n + 1))
        [ $((n % $1)) -eq 0 ] && { wait $pids; pids=""; }
    done
    [ -n "$pids" ] && wait $pids
}
resolve 16 6
resolve 8 10
for h in $SITES; do cat "$TMP/a.$h" 2>/dev/null; done | awk '!s[$1]++' > "$TMP/ips"
rm -f "$TMP"/a.*
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
    local pids="" n=0
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
        # по 16 сайтов сразу (в режиме sites их сотни)
        n=$((n + 1))
        [ $((n % 16)) -eq 0 ] && { wait $pids; pids=""; }
    done < "$TMP/ips"
    # ждём только свои curl: голый wait ждал бы и nfqws (он тоже наш потомок)
    [ -n "$pids" ] && wait $pids
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
# Плановая проверка сайтов: адресов узнали < 60% или «заблокировано» > 90% —
# телефон/сеть не успевали (22.10 19:57: 56 из ~210, из них 54 «закрыты»),
# итог был бы мусором. Ничего не пишем, демон повторит через ~15 мин.
if [ "$MODE" = sites ] && [ -z "$SITES_ARG" ]; then
    _req=$(echo $SITES | wc -w); _got=$(wc -l < "$TMP/ips"); _nb=$(echo $BLOCKED | wc -w)
    if [ $((_got * 10)) -lt $((_req * 6)) ] || { [ "$_got" -ge 20 ] && [ $((_nb * 10)) -gt $((_got * 9)) ]; }; then
        st state=error msg="сеть или телефон не успевали (адресов $_got из $_req, закрыто $_nb) — повторю позже"
        exit 1
    fi
fi
[ -n "$BASE_OK" ] || { st state=error msg="через $WAN не открылся ни один сайт, даже без блокировок — нет интернета или сеть сменилась"; exit 1; }
if [ -z "$BLOCKED" ]; then
    [ "$MODE" = check ] && wd_last "ничего не заблокировано"
    st state=done stage="готово" msg="ни один сайт из набора не заблокирован — подбирать нечего"
    exit 0
fi

# основной zapret на запросы сканера не влияет и с ним: правило сканера стоит
# в POSTROUTING первым, вердикт NFQUEUE завершает обход mangle
$IPT -t mangle -I POSTROUTING 1 $RULE
$IPT -t mangle -I OUTPUT 1 $RULE_MK 2>/dev/null
$IPT -t mangle -I PREROUTING 1 $RULE_IN 2>/dev/null

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

# --- сайты со своей стратегией (2.25, идея byedpi --auto) ------------------
# Сайты из списков (или переданные), которых основная стратегия сети не
# открывает, получают другую: кандидаты — их прежние стратегии, история сети
# и набор проверенных; сайт закрепляется за первой, открывшей его дважды.
# Не больше 3 стратегий на сеть. Итог — ZALT (демон делает из него профили
# nfqws). Не открылся ничем — в ZSKIP на сутки (часто блок по IP).
if [ "$MODE" = "sites" ]; then
    KEY="${NETID%%"|"*}"
    CUR=$(sh "$MODDIR/service.sh" --zapret-strategy "$KEY" "${NETID#*"|"}" full 2>/dev/null | \
        sed "s#@$ZDIR/tls_clienthello_www_google_com.bin#@G#g; s#@$ZDIR/quic_initial_www_google_com.bin#@Q#g")
    GEN=$(sh "$MODDIR/service.sh" --zapret-strategy "$KEY" "${NETID#*"|"}" 2>/dev/null | \
        sed "s#@$ZDIR/tls_clienthello_www_google_com.bin#@G#g; s#@$ZDIR/quic_initial_www_google_com.bin#@Q#g")
    [ -n "$CUR" ] || { st state=error msg="не узнал стратегию сети"; exit 1; }
    # У YouTube своя стратегия — основная для его доменов тоже кандидат (22.10:
    # yt3.ggpht.com, логотипы каналов, открывался только основной); иначе
    # основную все сайты уже не прошли — её не повторяем
    GEN_X="$GEN"
    case "$CUR" in *" --new "*) GEN_X="" ;; esac
    cp -f "$TMP/ips" "$TMP/ips.all"
    use_ips() { # use_ips "h1 h2 ..." -> $TMP/ips, $NS
        L=" $1 " awk 'index(ENVIRON["L"], " " $1 " ")' "$TMP/ips.all" > "$TMP/ips"
        NS=$(wc -l < "$TMP/ips")
    }
    # по последнему test_sites: какие открылись (opened) / нет (failed)
    opened() { while read -r h ip; do read -r v _ < "$TMP/r.$h"; [ "$v" = ok ] && printf '%s ' "$h"; done < "$TMP/ips"; }
    failed() { while read -r h ip; do read -r v _ < "$TMP/r.$h"; [ "$v" = ok ] || printf '%s ' "$h"; done < "$TMP/ips"; }
    minus() { for _h in $1; do case " $2 " in *" $_h "*) ;; *) printf '%s ' "$_h" ;; esac; done; }
    # заблокированные без контрольных
    BL=$(minus "$BLOCKED" "ya.ru www.google.com")
    NB=$(echo $BL | wc -w)
    S_total=4
    st stage="сайты: основная стратегия ($NB заблокированных)"
    F=""
    if [ "$NB" -gt 0 ]; then
        use_ips "$BL"; run_strat "$CUR" "основная"; F=$(failed)
        # не открылся — ещё раз: случайный тайм-аут не повод менять стратегию
        [ -n "$F" ] && { use_ips "$F"; run_strat "$CUR" "основная"; F=$(failed); }
    fi
    NF=$(echo $F | wc -w)
    # (только при плановой: сайты, переданные вручную, подбираем всегда)
    if [ -z "$SITES_ARG" ] && [ "$NB" -ge 3 ] && [ "$NF" -ge "$NB" ]; then
        event "сайты: основная стратегия не открыла ни одного из $NB — это поломка самой стратегии (её чинит сторож), сайты не трогаю"
        st state=done stage="готово" msg="основная стратегия не открыла ни одного заблокированного — её чинит сторож"
        exit 0
    fi
    : > "$TMP/assign"
    if [ -n "$F" ]; then
        # кандидаты: уже закреплённые за сайтами этой сети, история сети (и
        # сетей с тем же названием), проверенный набор; без основной
        {
            [ -f "$ZALT" ] && K="$KEY" awk -F'|' '$1 == ENVIRON["K"] { print $4 }' "$ZALT"
            L="${NETID#*"|"}" K="$KEY" awk -F'|' '$1 == ENVIRON["K"] || ($4 == ENVIRON["L"] && ENVIRON["L"] != "") { print $1 }' "$ZNETS" 2>/dev/null > "$TMP/keys"
            KS=" $(tr '\n' ' ' < "$TMP/keys") " awk -F'|' 'index(ENVIRON["KS"], " " $1 " ") && $2 == "custom" { l[++n] = $3; if ($6 != "") l[++n] = $6 } END { for (i = n; i >= 1; i--) print l[i] }' "$HIST" 2>/dev/null
            cat <<EOF
--dpi-desync=multisplit --dpi-desync-split-pos=1,host+1,midsld --dpi-desync-split-seqovl=1
--dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld
--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=www.google.com --dpi-desync-fooling=md5sig
--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld $FAKE
--dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=@G
--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=@G $FAKE
--dpi-desync=syndata,multisplit --dpi-desync-split-pos=1,host+1,midsld --dpi-desync-split-seqovl=1
--dpi-desync=fakedsplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq
EOF
        } | G="$GEN_X" awk 'NF && $0 != ENVIRON["G"] && !s[$0]++' | head -n 10 > "$TMP/cands"
        S_total=$((S_done + $(wc -l < "$TMP/cands") * 2))
        NUSED=0
        while IFS= read -r a <&3; do
            [ -n "$F" ] || break
            [ "$NUSED" -lt 3 ] || break
            st stage="сайты: подбираю для $(echo $F | wc -w)"
            use_ips "$F"; run_strat "$a" "сайты"; O=$(opened)
            [ -n "$O" ] || continue
            use_ips "$O"; run_strat "$a" "сайты"; O=$(opened)
            [ -n "$O" ] || continue
            for h in $O; do printf '%s|%s\n' "$h" "$a" >> "$TMP/assign"; done
            NUSED=$((NUSED + 1))
            F=$(minus "$F" "$O")
        done 3< "$TMP/cands"
    fi
    if [ "$(sh "$ZDIR/netid.sh" "$WAN" 2>/dev/null | head -1)" != "$NETID" ]; then
        st state=stopped stage="готово" msg="сеть сменилась во время проверки — не запоминаю"
        exit 0
    fi
    # проверенные сайты теряют прежние записи, закреплённые получают новые;
    # не проверенные (адрес не узнали) остаются как были
    T=" $(awk '{print $1}' "$TMP/ips.all" | tr '\n' ' ') "
    D=$(date '+%Y-%m-%d %H:%M')
    {
        [ -f "$ZALT" ] && K="$KEY" T="$T" awk -F'|' '!($1 == ENVIRON["K"] && index(ENVIRON["T"], " " $3 " "))' "$ZALT"
        while IFS='|' read -r h a; do printf '%s|%s|%s|%s|%s\n' "$KEY" "${NETID#*"|"}" "$h" "$a" "$D"; done < "$TMP/assign"
    } > "$ZALT.tmp" && chmod 600 "$ZALT.tmp" && mv -f "$ZALT.tmp" "$ZALT"
    NOW=$(date +%s)
    {
        [ -f "$ZSKIP" ] && K="$KEY" T="$T" N="$NOW" awk -F'|' '$3 + 86400 > ENVIRON["N"] && !($1 == ENVIRON["K"] && index(ENVIRON["T"], " " $2 " "))' "$ZSKIP"
        for h in $F; do printf '%s|%s|%s\n' "$KEY" "$h" "$NOW"; done
    } > "$ZSKIP.tmp" && chmod 600 "$ZSKIP.tmp" && mv -f "$ZSKIP.tmp" "$ZSKIP"
    NA=$(wc -l < "$TMP/assign")
    NT=$(awk 'END {print NR}' "$TMP/ips.all")
    if [ -n "$SITES_ARG" ]; then
        if [ "$NB" -eq 0 ]; then MSG="открывается и без обхода"
        elif [ "$NA" -gt 0 ]; then MSG="подобрана своя стратегия: $(cut -d'|' -f2 "$TMP/assign" | head -1)"
        elif [ -z "$F" ]; then MSG="основная стратегия открывает — своя не нужна (в режиме «из списка» сайт должен быть в списке)"
        else MSG="не открылся ни одной стратегией — похоже, блок по IP"; fi
    else
        MSG="проверено $NT, заблокировано $NB, своя стратегия у $NA$([ -n "$F" ] && echo ", не открылись ничем: $(echo $F | wc -w)")"
    fi
    event "сайты$([ -n "$SITES_ARG" ] && echo " ($SITES_ARG)"): $MSG$([ "$NA" -gt 0 ] && echo " — $(cut -d'|' -f1 "$TMP/assign" | head -n 8 | tr '\n' ' ')")$([ -n "$F" ] && echo "; ничем: $(echo $F | tr ' ' '\n' | head -n 8 | tr '\n' ' ')")"
    S_state=done
    st stage="готово" msg="$MSG"
    exit 0
fi

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
    S_total=22
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
--dpi-desync=syndata,multisplit --dpi-desync-split-pos=1,host+1,midsld --dpi-desync-split-seqovl=1
--dpi-desync=multisplit --dpi-desync-split-pos=1,host+1,midsld --dpi-desync-split-seqovl=1 --dup=2 --dup-cutoff=n3 --dup-fooling=md5sig
--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=www.google.com --dpi-desync-fooling=md5sig --wssize=1:6
EOF
else
    S_total=$(( 14 + 8 + 36 + 3 + 4 + 9 + 10 ))
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
    # E (2.25): новые приёмы nfqws к двум лучшим — дубли пакетов с порчей,
    # TTL настоящих пакетов, маленькое окно сервера, данные в SYN
    st stage="5/5 новые приёмы"
    best 2 > "$TMP/top2e"
    while IFS= read -r a; do
        [ -n "$a" ] || continue
        run_strat "$a --dup=2 --dup-cutoff=n3 --dup-fooling=md5sig" "5"
        run_strat "$a --dup=1 --dup-cutoff=n3 --dup-autottl" "5"
        run_strat "$a --orig-autottl=+5 --orig-mod-cutoff=n3" "5"
        run_strat "$a --wssize=1:6" "5"
        run_strat "$(echo "$a" | sed 's/--dpi-desync=/--dpi-desync=syndata,/')" "5"
    done < "$TMP/top2e"
fi

# перепроверка лучших: случайный успех не должен выиграть
st stage="перепроверяю лучшие"
best 3 > "$TMP/top"
# + 2 лучших именно для YouTube (могут не попасть в общие 3)
if [ "$NBY" -gt 0 ]; then
    awk -F'|' -v re="$YT_RE" '$3 == 0 && $5 !~ /--new/ && $7 !~ /^nfqws: / { n = split($7, d, " "); f = 0; for (i = 1; i <= n; i++) if (d[i] ~ re) f++; print f "|" $4 "|" $5 }' "$OUT.results" | \
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
    # nfqws не запустился: в $7 текст ошибки, а не сайты — иначе такая
    # стратегия считалась открывшей почти всё (и YouTube целиком)
    $7 ~ /^nfqws: / { next }
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
