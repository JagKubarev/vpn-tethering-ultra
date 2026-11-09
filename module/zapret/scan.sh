#!/system/bin/sh
# ============================================================================
# Подбор стратегии nfqws (генератор + проверка на живом канале).
#
#   scan.sh quick|full "сайт1 сайт2 ..."
#   scan.sh yt|dc            только YouTube или только Discord: быстрый набор и
#                            замер скорости, меняется только его стратегия
#   scan.sh quic             проходит ли QUIC YouTube с подделкой в этой сети
#                            (итог — ZQUIC, показывает WebUI, подделку не включает)
#   scan.sh sites ["сайт ..."]  сайтам, которых основная стратегия не
#                            открывает, — своя (ZALT); без списка — сайты из
#                            списков zapret (демон, раз в ~6 ч)
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
#   ok|всего|сломал|сред_мс|аргументы|этап|подробности|мс_YouTube|мс_Discord
# Замер скорости (yt|dc) — $OUT.speed: КБ/с|аргументы.
# В аргументах @G / @Q — fake-файлы модуля (service.sh подставит пути).
# ============================================================================
MODDIR="${0%/*}/.."
[ -f "$MODDIR/service.sh" ] || MODDIR=/data/adb/modules/vpn-to-hotspot-usb
PATH="$PATH:$MODDIR/bin"; export PATH   # curl: нет системного — свой из модуля
BB=/data/adb/ksu/bin/busybox
[ -x "$BB" ] || BB=/data/adb/magisk/busybox
[ -x "$BB" ] || BB=/data/adb/ap/bin/busybox
# в Android 8 нет awk (MT6580, 04.11): этот скрипт идёт под mksh, не под busybox
command -v awk >/dev/null 2>&1 || awk() { "$BB" awk "$@"; }
ZDIR="$MODDIR/zapret"
OUT=/data/local/tmp/vpn_tether_zscan
Q=203
MODE="${1:-quick}"
MODE0="$MODE"
# подбор одной группы — быстрый набор со своим концом (см. GRP ниже)
GRP=""
case "$MODE" in yt|dc) GRP=$MODE; MODE=quick ;; esac
# сторож пишет в свои файлы: иначе через 15 минут он стирал таблицу подбора, и в
# WebUI это выглядело как новый подбор (05.11). Замок и метки — общие
OUTB=$OUT
[ "$MODE" = check ] && OUT=/data/local/tmp/vpn_tether_zcheck
SITES="$2"
SITES_ARG="$2"
case "$GRP" in
    yt) SITES="www.youtube.com i.ytimg.com youtubei.googleapis.com" ;;
    dc) SITES="discord.com gateway.discord.gg cdn.discordapp.com" ;;
esac
[ -n "$SITES" ] || [ "$MODE" = sites ] || SITES="www.youtube.com i.ytimg.com youtubei.googleapis.com discord.com gateway.discord.gg x.com www.facebook.com rutracker.org www.linkedin.com ya.ru www.google.com"
# контрольные сайты без блокировок: по ним отличаем "заблокировано" от "нет связи"
for _c in ya.ru www.google.com; do case " $SITES " in *" $_c "*) ;; *) SITES="$SITES $_c" ;; esac; done
CA=/apex/com.android.conscrypt/cacerts
[ -d "$CA" ] || CA=/system/etc/security/cacerts
# адрес через DoH. 1.1.1.1 в Android 8 не проходит проверку: корня SSL.com нет в
# cacerts (MT6580, rc=60), тогда 8.8.8.8
doh_ip() {   # имя таймаут [сколько адресов]
    local u r
    for u in "https://1.1.1.1/dns-query?name=$1&type=A" "https://8.8.8.8/resolve?name=$1&type=A"; do
        r=$(curl -s -m "$2" --capath "$CA" -H 'accept: application/dns-json' "$u" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | head -n "${3:-1}" | grep -oE '[0-9.]+')
        [ -n "$r" ] && { echo "$r"; return 0; }
    done
    return 1
}
# --- QUIC: системный curl его не умеет, поэтому свой из модуля (HTTP/3) --------
# 05.11 на YOTA: без подделки QUIC закрыт по имени (Google и Cloudflare отвечают,
# YouTube молчит), с настоящим Initial Google проходит при любом числе повторов.
# Обход и AdGuard (REJECT UDP 443) снимаются только на время проверки, только для
# root и только на WAN. Качаем 2 МБ: важно, идёт ли видео, а не его скорость.
QC="$MODDIR/bin/curl"
QCTL="cloudflare-quic.com www.google.com"
QYT="www.youtube.com i.ytimg.com youtubei.googleapis.com"
QH=rr1---sn-gvnuxaxjvh-n8vz.googlevideo.com
ZQUIC=/data/adb/vpn_tether_zapret_quic      # ключ|название|1 подделка проходит, 0 нет|epoch
QBY=0
nq_up() { # nq_up "<аргументы с @G/@Q>" -> nfqws на очереди сканера, $NQPID
    local real
    real=$(echo "$1" | sed "s#@G#@$ZDIR/tls_clienthello_www_google_com.bin#g; s#@Q#@$ZDIR/quic_initial_www_google_com.bin#g")
    # группа 3998 = ZAPRET_GID из service.sh: основной zapret её не трогает
    "$NQ" --qnum=$Q --uid=0:3998 --bind-fix4 $real > "$TMP/nq.log" 2>&1 &
    NQPID=$!
    sleep 0.6
}
quic_try() { # quic_try "сайт ..." -> сколько ответили по QUIC
    local h pids=""
    rm -f "$TMP"/q.*
    for h in $1; do
        (
            ip=$(sed -n "s/^$h //p" "$TMP/qips")
            [ -n "$ip" ] || exit 0
            c=$("$QC" -s -k -o /dev/null -m 5 --http3-only --interface "$WAN" --resolve "$h:443:$ip" -w '%{http_code}' "https://$h/" 2>/dev/null)
            case "$c" in ''|000) ;; *) : > "$TMP/q.$h" ;; esac
        ) &
        pids="$pids $!"
    done
    wait $pids
    ls "$TMP"/q.* 2>/dev/null | wc -l
}
quic_vid() { # скачалось ли с именем видеосервера: файл как в speed_one
    local ip c
    for ip in $QIPS; do
        c=$("$QC" -s -k -o /dev/null -m 6 -r 0-2097151 --http3-only --interface "$WAN" --connect-to "$QH:443:$ip:443" -H 'Host: dl.google.com' \
            -w '%{http_code}' "https://$QH/linux/direct/google-chrome-stable_current_amd64.deb" 2>/dev/null)
        case "$c" in 2*) return 0 ;; esac
    done
    return 1
}
quic_rules() { # quic_rules -I|-D
    local a="$1"
    [ "$a" = -I ] && a="-I POSTROUTING 1" || a="-D POSTROUTING"
    $IPT -t mangle $a -o "$WAN" -m owner --uid-owner 0 ! --gid-owner 3999 -p udp --dport 443 $CB_OUT -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass 2>/dev/null
    [ "$1" = -I ] && a="-I OUTPUT 1" || a="-D OUTPUT"
    $IPT $a -o "$WAN" -m owner --uid-owner 0 -p udp --dport 443 -j ACCEPT 2>/dev/null
}
quic_save() { # quic_save 1|0
    {
        [ -f "$ZQUIC" ] && K="${NETID%%"|"*}" awk -F'|' '$1 != ENVIRON["K"]' "$ZQUIC"
        printf '%s|%s|%s|%s\n' "${NETID%%"|"*}" "${NETID#*"|"}" "$1" "$(date +%s)"
    } > "$ZQUIC.tmp" && chmod 600 "$ZQUIC.tmp" && mv -f "$ZQUIC.tmp" "$ZQUIC"
}
quic_check() { # итог — в $QMSG; не понятно или нет связи — ничего не запоминаем
    local h ip b c g s1 s2 v=0
    QMSG=""
    # в волну Google YouTube молчит при любом обходе: вышло бы «подделка не помогает»
    if [ -n "$(find "$OUTB.wave" -maxdepth 0 -mmin -15 2>/dev/null)" ]; then
        QMSG="QUIC: недавно была волна Google — проверю позже"
        return 1
    fi
    "$QC" --version 2>/dev/null | grep -q HTTP3 || { QMSG="QUIC: в модуле curl без HTTP/3"; return 1; }
    [ "$PERNET" = 1 ] && [ -n "${NETID%%"|"*}" ] || { QMSG="QUIC: только при «своей стратегии для каждой сети» и понятной сети"; return 1; }
    st stage="проверяю QUIC"
    : > "$TMP/qips"
    for h in $QCTL $QYT; do ip=$(doh_ip "$h" 6); [ -n "$ip" ] && echo "$h $ip" >> "$TMP/qips"; done
    QIPS=$(doh_ip dl.google.com 6 3)
    # адрес не узнали — это сбой DoH, а не провал подделки
    for h in $QYT; do grep -q "^$h " "$TMP/qips" || QIPS=""; done
    [ -n "$QIPS" ] || { QMSG="QUIC: не узнал адреса сайтов — итог не меняю"; return 1; }
    QBY=1; quic_rules -I
    c=$(quic_try "$QCTL"); b=$(quic_try "$QYT")
    if [ "$c" -eq 0 ]; then
        quic_rules -D; QBY=0
        QMSG="QUIC: контрольные сайты молчат, это сеть или AdGuard — итог не меняю"
        event "$QMSG"
        return 1
    fi
    nq_up "--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=@Q"
    if ! kill -0 "$NQPID" 2>/dev/null; then
        NQPID=""; quic_rules -D; QBY=0
        QMSG="QUIC: nfqws не запустился ($(tail -n 1 "$TMP/nq.log" | cut -c1-80)) — итог не меняю"
        event "$QMSG"
        return 1
    fi
    s1=$(quic_try "$QYT"); quic_vid && v=1; s2=$(quic_try "$QYT"); g=$(quic_try www.google.com)
    kill "$NQPID" 2>/dev/null; wait "$NQPID" 2>/dev/null; NQPID=""
    quic_rules -D; QBY=0
    if [ "$(sh "$ZDIR/netid.sh" "$WAN" 2>/dev/null | head -1)" != "$NETID" ]; then
        QMSG="QUIC: сеть сменилась во время проверки — не запоминаю"
    elif [ "$g" -eq 0 ]; then
        # Google молчит и по TCP — волна или сбой. По TCP отвечает — его QUIC в этой
        # сети закрыт, подделка не помогла
        c=$("$QC" -s -k -o /dev/null -m 5 --interface "$WAN" -w '%{http_code}' https://www.google.com/generate_204 2>/dev/null)
        if [ "$c" = 204 ]; then
            quic_save 0
            QMSG="QUIC: к Google закрыт и с подделкой, остаётся закрытие"
        else
            QMSG="QUIC: Google молчит и по TCP, похоже на сбой или волну — итог не меняю"
        fi
    elif [ "$s1" -eq 3 ] && [ "$s2" -eq 3 ] && [ "$v" = 1 ]; then
        quic_save 1
        QMSG="QUIC: подделка проходит, без неё открывается $b из 3"
    else
        quic_save 0
        QMSG="QUIC: подделка не помогает (открыла $s1 и $s2 из 3, видео $([ "$v" = 1 ] && echo идёт || echo нет)), остаётся закрытие"
    fi
    event "$QMSG"
}

case "$(uname -m)" in aarch64|arm64) NQ="$MODDIR/bin/nfqws-arm64" ;; *) NQ="$MODDIR/bin/nfqws-arm" ;; esac
WAN=$(sed -n 's/^wan=//p' "$MODDIR/status" 2>/dev/null)
IPT="iptables -w 2"
TMP="$OUT.tmp"
EVENTS=/data/adb/vpn_tether_zapret_events
HIST=/data/adb/vpn_tether_zapret_hist
ZNETS=/data/adb/vpn_tether_zapret_nets
ZALT=/data/adb/vpn_tether_zapret_alt        # своя стратегия сайтов: ключ|название|сайт|аргументы|дата
ZSKIP=/data/adb/vpn_tether_zapret_altskip   # не открылись ничем: ключ|сайт|epoch (сутки не проверяем)
ZAUTO=/data/adb/vpn_tether_zapret_auto.txt  # автосписок nfqws
case "$MODE" in quick|full|check|sites|quic) ;; *) echo "scan.sh: режим quick|full|check|sites|quic|yt|dc" >&2; exit 2 ;; esac

st() { # обновить файл состояния: st key=val ...
    local k
    for k in "$@"; do eval "S_${k%%=*}=\"\${k#*=}\""; done
    {
        echo "state=$S_state"; echo "mode=$MODE"; echo "done=$S_done"; echo "total=$S_total"
        echo "stage=$S_stage"; echo "msg=$S_msg"; echo "blocked=$S_blocked"; echo "started=$S_started"; echo "grp=${GRP:-$S_grp}"
    } > "$OUT.status.tmp" && mv -f "$OUT.status.tmp" "$OUT.status"
}

# итог последней проверки сторожа — для WebUI: "ЧЧ:ММ|текст"
wd_last() {
    printf '%s|%s\n' "$(date '+%H:%M')" "$*" > "$OUTB.wd"
}

# журнал сторожа/подбора: "дата|сеть|событие" (держим последние 300 строк)
event() {
    printf '%s|%s|%s\n' "$(date '+%Y-%m-%d %H:%M')" "${NETID#*"|"}" "$*" | tr -d '\r' >> "$EVENTS"
    [ "$(awk 'END {print NR}' "$EVENTS" 2>/dev/null)" -gt 400 ] && { tail -n 300 "$EVENTS" > "$EVENTS.tmp" && mv -f "$EVENTS.tmp" "$EVENTS"; }
    chmod 600 "$EVENTS" 2>/dev/null
}

# ! --gid-owner 3999: DoH dnsproxy (root, группа 3999) тестовые стратегии не
# трогают — иначе его новые соединения во время подбора резались/ломались
# ядро без connbytes (zapret_caps демона): в очередь — все пакеты сканера,
# ответы — тоже все, но только его соединений (connmark), трафика мало
CB_OUT="-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:20"   # как у демона (ZAPRET_CB_OUT)
CB_IN="-m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:3"
grep -q '^cb=0' /data/local/tmp/vpn_tether_zcaps 2>/dev/null && { CB_OUT=""; CB_IN=""; }
RULE="-o $WAN -m owner --uid-owner 0 ! --gid-owner 3999 -p tcp --dport 443 $CB_OUT -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
# первые ответы сервера на запросы сканера — тоже в nfqws: без них не
# работают --wssize и autottl (3.6). Соединения сканера — по биту connmark.
SCMARK=0x08000000
RULE_MK="-o $WAN -m owner --uid-owner 0 -p tcp --dport 443 -j CONNMARK --set-xmark $SCMARK/$SCMARK"
RULE_IN="-i $WAN -p tcp --sport 443 -m connmark --mark $SCMARK/$SCMARK $CB_IN -j NFQUEUE --queue-num $Q --queue-bypass"
NQPID=""
BYPASS=0    # 1 = исключения uid 0 (nat OUTPUT, VPN_ZAPRET) поставлены нами
cleanup() {
    [ -n "$NQPID" ] && kill "$NQPID" 2>/dev/null
    $IPT -t mangle -D POSTROUTING $RULE 2>/dev/null
    $IPT -t mangle -D OUTPUT $RULE_MK 2>/dev/null
    $IPT -t mangle -D PREROUTING $RULE_IN 2>/dev/null
    [ "$QBY" = 1 ] && quic_rules -D
    # такие же ставят проверки WebUI (webctl.sh sitetest и др.): выход до
    # установки своих не должен снимать чужие
    if [ "$BYPASS" = 1 ]; then
        $IPT -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
        $IPT -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null
    fi
    rm -rf "$TMP"
    rm -f "$OUTB.pid"
}
on_exit() {
    cleanup
    [ "$S_state" = "running" ] && st state=stopped msg="остановлено"
    [ "$MODE0" = check ] && [ "$S_state" != done ] && wd_last "не проверил: ${S_msg:-$S_state}"
    # проверка сайтов сорвалась (смена сети, VPN, нет адреса) — в журнал, и
    # метка демону: повторить через ~час, а не через ZAPRET_ALT_MIN
    if [ "$MODE0" = sites ] && [ "$S_state" != done ]; then
        event "сайты: не проверил — ${S_msg:-$S_state}"
        : > "$OUT.sitesfail"
    fi
}
# уже идёт другой scan.sh (демон и WebUI в один такт): общие $TMP, очередь
# и pid-файл — второй испортил бы первому данные и удалил его pid
_p=$(cat "$OUTB.pid" 2>/dev/null)
if [ -n "$_p" ] && [ "$_p" != "$$" ] && kill -0 "$_p" 2>/dev/null; then
    case "$(tr '\0' ' ' < "/proc/$_p/cmdline" 2>/dev/null)" in *zapret/scan.sh*) exit 0 ;; esac
fi
trap on_exit EXIT
trap 'exit 0' INT TERM

echo $$ > "$OUTB.pid"
# идёт регистрация WARP (warp/warp.sh gen) — подождать. После pid: пока ждём,
# демон и WebUI видят «подбор идёт» и второй scan.sh не запустят. Замок старше
# 3 мин — от убитого процесса (gen обновляет его на каждом конфиге)
# Ждём, пока замок свежий (до 5 мин): gen 5 бывает дольше 2 мин, а после
# прежних 90 с подбор шёл при живой очереди gen — базовая проверка через
# его nfqws, закрытые сайты «открыты без обхода» (ревью PR #20). Не дождались — отказ
_i=0; while [ -n "$(find /data/local/tmp/vpn_tether_warpgen.lock -maxdepth 0 -mmin -3 2>/dev/null)" ] && [ $_i -lt 300 ]; do sleep 1; _i=$((_i + 1)); done
[ -z "$(find /data/local/tmp/vpn_tether_warpgen.lock -maxdepth 0 -mmin -3 2>/dev/null)" ] ||     { st state=error msg="идёт создание конфигов WARP — подбор отложен"; exit 1; }
# nfqws на нашей очереди от убитого (kill -9, OOM) прогона: иначе очередь
# занята, все прогоны «nfqws: …», и сирота портит HTTPS от root
for _p in $(pgrep -f "nfqws.*--qnum=$Q " 2>/dev/null); do kill -9 "$_p" 2>/dev/null; done
S_done=0; S_total=0; S_blocked=""; S_grp=""; S_started=$(date +%H:%M:%S)
# проверка QUIC своей таблицы не даёт: оставляем таблицу прошлого подбора
if [ "$MODE" = quic ]; then
    S_blocked=$(sed -n 's/^blocked=//p' "$OUT.status" 2>/dev/null)
    S_grp=$(sed -n 's/^grp=//p' "$OUT.status" 2>/dev/null)
else
    : > "$OUT.results"
    : > "$OUT.speed"
fi
st state=running stage="подготовка" msg=""

# Сторож вскоре после волны Google (метка от прошлого сторожа моложе 15 мин):
# не проверять и ничего не слать. В волну застревает почти всё видео, демон
# звал бы сторожа каждые 3 мин, и каждый раз — залп запросов к закрытым сайтам
if [ "$MODE" = check ] && [ -n "$(find "$OUTB.wave" -maxdepth 0 -mmin -15 2>/dev/null)" ]; then
    st state=done stage="готово" msg="недавно была волна Google — проверка отложена"
    exit 0
fi
# Подбор YouTube в волну выбрал бы случайную: 05.11 в 20:43 сайты то открывались, то
# нет, и проверенную стратегию сменила та, что проскочила. Метку ставит сторож
if [ "$GRP" = yt ] && [ -n "$(find "$OUTB.wave" -maxdepth 0 -mmin -15 2>/dev/null)" ]; then
    st state=error msg="сейчас волна Google: подбор YouTube выбрал бы случайную стратегию. Повторите через 15 минут"
    exit 1
fi

[ -n "$WAN" ] || { st state=error msg="модуль ещё не видел сеть оператора"; exit 1; }
ip -4 addr show "$WAN" 2>/dev/null | grep -q "inet " || { st state=error msg="у $WAN нет адреса — сеть только что сменилась? Повторите через полминуты"; exit 1; }
[ -x "$NQ" ] || { st state=error msg="нет nfqws"; exit 1; }
mkdir -p "$TMP"
# Сеть, в которой подбираем: лучшая стратегия запоминается для неё
NETID=$(sh "$ZDIR/netid.sh" "$WAN" 2>/dev/null | head -1)
PERNET=$(sh "$MODDIR/service.sh" --get ZAPRET_PER_NET 2>/dev/null)
AUTOPICK=$(sh "$MODDIR/service.sh" --get ZAPRET_AUTOPICK 2>/dev/null)   # 0: только показывать, не запоминать
if [ -n "$GRP" ]; then
    [ "$PERNET" = 1 ] && [ -n "${NETID%%"|"*}" ] || { st state=error msg="своя стратегия YouTube и Discord — только при «своей стратегии для каждой сети» и понятной сети"; exit 1; }
fi
if [ "$MODE" = sites ]; then
    [ "$PERNET" = 1 ] && [ -n "${NETID%%"|"*}" ] || { st state=error msg="своя стратегия сайтов — только при «своей стратегии для каждой сети» и понятной сети"; exit 1; }
    if [ -z "$SITES_ARG" ]; then
        # сайты из списков zapret и уже закреплённые; без YouTube (у него
        # свой профиль), исключений и не открывшихся ничем за последние сутки
        # и без Google (list-noauto, 3.20.2): ему обход сам не назначает
        sed 's/#.*//' "$ZDIR/list-youtube.txt" "$ZDIR/list-exclude.txt" "$ZDIR/list-noauto.txt" 2>/dev/null | tr -d ' \r' | grep . > "$TMP/xl"
        cat "$ZSKIP" 2>/dev/null > "$TMP/skip"
        {
            cat "$ZDIR/list-default.txt" /data/adb/vpn_tether_zapret.txt /data/adb/vpn_tether_zapret_auto.txt 2>/dev/null
            [ -f "$ZALT" ] && K="${NETID%%"|"*}" awk -F'|' '$1 == ENVIRON["K"] { print $3 }' "$ZALT"
        } | tr 'A-Z' 'a-z' | sed 's/#.*//; s/^[*.]*//' | tr -d ' \r' | grep -E '^[a-z0-9.-]+\.[a-z0-9-]+$' | \
            K="${NETID%%"|"*}" N=$(date +%s) awk -F'|' '
                FILENAME == ARGV[1] { x[$1] = 1; next }
                FILENAME == ARGV[2] { if ($1 == ENVIRON["K"] && $3 + 72000 > ENVIRON["N"]) sk[$2] = 1; next }
                { h = $1; if ((h in seen) || (h in sk)) next; d = h
                  while (1) { if (d in x) next; i = index(d, "."); if (!i) break; d = substr(d, i + 1) }
                  seen[h] = 1; print h }' "$TMP/xl" "$TMP/skip" - | head -n 400 > "$TMP/sites"
        SITES="$(tr '\n' ' ' < "$TMP/sites")$SITES"
    fi
fi

# мимо AdGuard; основной zapret не трогает запросы сканера
BYPASS=1
$IPT -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
$IPT -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null

if [ "$MODE" = quic ]; then
    quic_check
    st state=done stage="готово" msg="$QMSG"
    exit 0
fi

# Свой видеосервер YouTube в набор (идея zapretgui, blockcheck): YOTA режет
# ClientHello с именем *.googlevideo.com (25.10), а в наборе только сайт и
# картинки — стратегия YouTube подбиралась без видео. redirector по HTTP
# отвечает «IP => узел» (tzfraa-cd), имя узла посимвольно переводится в
# rr1---sn-….googlevideo.com. Только подбор и только если в наборе YouTube.
# Берём, только если узел отвечает с чужим именем (www.google.com): тогда его
# молчание с родным — фильтр по имени. 29.10 узел оказался 173.194.1.6 —
# мёртвый на пути YOTA и с чужим именем (3.20.1), открыть его нечем.
if [ "$MODE" = quick ] || [ "$MODE" = full ]; then
    case " $SITES " in
        *googlevideo.com*) ;;
        *youtube.com*|*ytimg.com*)
            # до 13 с (4 + 5 + 4) — видно в WebUI, а не «подготовка»
            st stage="ищу видеосервер YouTube"
            # имя не пустое: строка «=>» без имени не заслоняет следующую
            _gv=$(curl -s -m 4 --interface "$WAN" "http://redirector.googlevideo.com/report_mapping?di=no" 2>/dev/null | \
                sed -n 's/.*=> *\([a-z0-9-][a-z0-9-]*\).*/\1/p' | head -n 1)
            case "$_gv" in
                ''|*[!uzpkfa50vqlgb61wrmhc72xsnid83ytoje94-]*) ;;
                *)
                    _gh="rr1---sn-$(echo "$_gv" | tr 'uzpkfa50vqlgb61wrmhc72xsnid83ytoje94' '0123456789abcdefghijklmnopqrstuvwxyz').googlevideo.com"
                    _gi=$(doh_ip "$_gh" 5)
                    _gc=""
                    [ -n "$_gi" ] && _gc=$(curl -s -k -o /dev/null -m 4 --interface "$WAN" --connect-to "www.google.com:443:$_gi:443" \
                        -w '%{http_code}' https://www.google.com/generate_204 2>/dev/null)
                    if [ -n "$_gc" ] && [ "$_gc" != 000 ]; then SITES="$SITES $_gh"; SPD_H="$_gh"; fi ;;
            esac ;;
    esac
fi

# --- адреса: DoH (обычный DNS мимо VPN оператор может подменить)
st stage="узнаю адреса"
: > "$TMP/ips"
# по 16 сразу: в режиме sites сайтов сотни
# не узнали с первого раза (телефон под нагрузкой, 22.10 после загрузки
# узнались 56 из ~210) — второй заход по оставшимся, по 8 и с запасом времени
# Проверка сайтов — адрес как у браузера (31.10): DNS телефона завёрнут в
# dnsproxy модуля (DoH, Meta через ECS), а 1.1.1.1 отдаёт другое: Instagram —
# 157.240.205.174, закрытый по IP (TCP молчит), браузеру — 57.144.74.34 (301),
# и Meta раз в сутки «не открывалась ничем». Только пока DNS телефона через DoH
# модуля (не оператор, не VPN). Адрес — из строки PING (getaddrinfo; формат у
# iputils и busybox один); пусто или 0.x/127.x/частный (AdGuard глушит
# телеметрию) — как раньше, через 1.1.1.1. Подбор и сторож — по-прежнему 1.1.1.1
SYSDNS=0
[ "$MODE" = sites ] && grep -q '^phone_dns=1' "$MODDIR/status" 2>/dev/null && \
    grep -q '^dns_degraded=0' "$MODDIR/status" 2>/dev/null && SYSDNS=1
# хук DNS телефона пропускает весь uid 0 мимо dnsproxy (DNSPROXY_SU_G=0 и обычный DNS по имени,
# или так до 09.11) — у ping (root) был бы DNS оператора, а не как у браузера. Только правило
# целиком: «-d адрес … --uid-owner 0 -j RETURN» (мимо — лишь серверы самого dnsproxy) не мешает
[ "$SYSDNS" = 1 ] && $IPT -t nat -S VPN_PHONE_DNS 2>/dev/null | grep -qx -- '-A VPN_PHONE_DNS -m owner --uid-owner 0 -j RETURN' && SYSDNS=0
resolve() { # resolve ПАРАЛЛЕЛЬНО ТАЙМАУТ
    local n=0 pids="" h
    for h in $SITES; do
        [ -s "$TMP/a.$h" ] && continue
        (
            ip=""
            [ "$SYSDNS" = 1 ] && ip=$(ping -c 1 -W 1 "$h" 2>/dev/null | sed -n '1s/^PING [^(]*(\([0-9.]*\)).*/\1/p')
            case "$ip" in 0.*|127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|169.254.*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) ip="" ;; esac
            [ -n "$ip" ] || ip=$(doh_ip "$h" "$2")
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
# Kyber — системный curl (BoringSSL), MLKEM — свой из модуля (OpenSSL)
for g in X25519Kyber768Draft00:X25519 X25519MLKEM768:X25519; do
    curl -s -o /dev/null -m 6 --curves "$g" --interface "$WAN" --capath "$CA" https://ya.ru/ 2>/dev/null && { BIG="$g"; break; }
done

# test_sites -> "ok_count avg_ms" и $TMP/res (h ok|rc)
TPAR=16; [ "$MODE" = sites ] && TPAR=4
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
        # по 16 сайтов сразу; проверка сайтов (сотни) — по 4: залп ~400
        # ClientHello к закрытым именам за минуту, похоже, провоцирует ТСПУ
        # резать абоненту всё на минуты (31.10 14:21: «закрыто 198 из 202»)
        n=$((n + 1))
        [ $((n % TPAR)) -eq 0 ] && { wait $pids; pids=""; }
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
# Напрямую только контрольные, остальные считаем закрытыми (кроме заданных вручную).
# 06.11 на YOTA прямые запросы к закрытым именам запускали волну Google через минуту на
# адресах 188.162.5 и .12 (3 из 3, держится до смены адреса), без них 0 из 3. Автопроверка
# слала такие каждые 15 мин. Без прямого ответа сайт не сравнить: «ломает» видно только на контрольных
: > "$TMP/ips.rest"
if [ -z "$SITES_ARG" ]; then
    L=" ya.ru www.google.com " awk -v rest="$TMP/ips.rest" \
        'index(ENVIRON["L"], " " $1 " ") { print; next } { print > rest }' "$TMP/ips" > "$TMP/ips.dir" && \
        mv -f "$TMP/ips.dir" "$TMP/ips"
fi
test_sites
BASE_OK=""; BLOCKED=""
while read -r h ip; do
    # нет файла — не брать v от прошлого сайта
    v=""; read -r v _ < "$TMP/r.$h" 2>/dev/null
    if [ "$v" = ok ]; then BASE_OK="$BASE_OK $h"; else BLOCKED="$BLOCKED $h"; fi
done < "$TMP/ips"
while read -r h ip; do BLOCKED="$BLOCKED $h"; done < "$TMP/ips.rest"
cat "$TMP/ips.rest" >> "$TMP/ips"
st blocked="$(echo $BLOCKED)"
# Плановая проверка сайтов: адресов узнали < 60% — телефон/сеть не успевали (22.10 19:57:
# 56 из ~210), итог был бы мусором. Контрольный не открылся — связь или волна: сайты
# напрасно получили бы отметку «ничем». Ничего не пишем, демон повторит через ~час.
if [ "$MODE" = sites ] && [ -z "$SITES_ARG" ]; then
    _req=$(echo $SITES | wc -w); _got=$(wc -l < "$TMP/ips")
    _cb=0
    case " $BASE_OK " in *" ya.ru "*) ;; *) _cb=1 ;; esac
    # Google молчит: по HTTP отвечает — волна, откладываем; нет — закрыт в этой сети, не повод
    case " $BASE_OK " in *" www.google.com "*) ;; *)
        [ "$(curl -s -o /dev/null -m 5 --interface "$WAN" -w '%{http_code}' http://www.google.com/generate_204 2>/dev/null)" = 204 ] && _cb=1 ;;
    esac
    if [ $((_got * 10)) -lt $((_req * 6)) ] || [ "$_cb" = 1 ]; then
        st state=error msg="сеть не готова (адресов $_got из $_req, открылись контрольные:$BASE_OK) — повторю позже"
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
    local a="$1" stage="$2" ok=0 brk=0 sum=0 det="" v t
    nq_up "$a"
    if ! kill -0 "$NQPID" 2>/dev/null; then
        NQPID=""
        # итоги прошлого прогона не должны сойти за итоги этого (opened/failed)
        rm -f "$TMP"/r.* "$TMP"/b.*
        echo "0|$NS|0|0|$a|$stage|nfqws: $(tail -n 1 "$TMP/nq.log" | tr '|' ' ' | cut -c1-80)" >> "$OUT.results"
        return
    fi
    test_sites
    kill "$NQPID" 2>/dev/null; wait "$NQPID" 2>/dev/null; NQPID=""
    local ysum=0 yn=0 dsum=0 dn=0
    while read -r h ip; do
        v=""; t=""; read -r v t < "$TMP/r.$h" 2>/dev/null
        if [ "$v" = ok ]; then
            ok=$((ok + 1))
            sum=$(awk -v s="$sum" -v t="$t" 'BEGIN { printf "%d", s + t * 1000 }')
            case "$h" in *youtube*|*ytimg*|*ggpht*|*googlevideo*)
                yn=$((yn + 1)); ysum=$(awk -v s="$ysum" -v t="$t" 'BEGIN { printf "%d", s + t * 1000 }') ;;
            *discord*|*dis.gd*)
                dn=$((dn + 1)); dsum=$(awk -v s="$dsum" -v t="$t" 'BEGIN { printf "%d", s + t * 1000 }') ;;
            esac
        else
            case " $BASE_OK " in *" $h "*) brk=$((brk + 1)) ;; esac
            det="$det ${h#www.}:$v"
        fi
    done < "$TMP/ips"
    [ "$ok" -gt 0 ] && sum=$((sum / ok))
    [ "$yn" -gt 0 ] && ysum=$((ysum / yn))
    [ "$dn" -gt 0 ] && dsum=$((dsum / dn))
    # 8-е и 9-е поля — среднее время только YouTube и Discord: их стратегии
    # выбираются отдельно
    echo "$ok|$NS|$brk|$sum|$a|$stage|${det# }|$ysum|$dsum" >> "$OUT.results"
    S_done=$((S_done + 1))
    st done=$S_done
}

# Скорость для подбора yt|dc. Открытая страница мало что говорит о видео и файлах,
# поэтому качаем до 8 МБ за 6 с. Discord — установщик с его CDN. YouTube — приём
# webctl ytspeed: без подписанной ссылки большого файла на видеосервере нет,
# поэтому файл с dl.google.com, а имя в TLS — видеосервера.
SPD_H="${SPD_H:-rr1---sn-gvnuxaxjvh-n8vz.googlevideo.com}"   # свой сервер, если нашёлся выше
speed_one() { # -> КБ/с, 0 — не скачалось
    local r ip
    if [ "$GRP" = yt ]; then
        # следующий адрес, если не скачалось: 05.11 в 23:17 стратегия дала 0 и 0 на одном
        # адресе, а через 10 минут на трёх других 14–29 Мбит/с
        for ip in $SPD_IPS; do
            r=$(curl -s -k -o /dev/null -m 6 -r 0-8388607 --interface "$WAN" --connect-to "$SPD_H:443:$ip:443" -H 'Host: dl.google.com' \
                -w '%{http_code} %{speed_download}' "https://$SPD_H/linux/direct/google-chrome-stable_current_amd64.deb" 2>/dev/null)
            case "$r" in 2*) break ;; esac
        done
    else
        r=$(curl -s -k -L -o /dev/null -m 6 -r 0-8388607 --interface "$WAN" -w '%{http_code} %{speed_download}' \
            'https://discord.com/api/downloads/distributions/app/installers/latest?channel=stable&platform=win&arch=x64' 2>/dev/null)
    fi
    set -- $r
    case "$1" in 2*) r="${2%%.*}"; echo $((r / 1024)) ;; *) echo 0 ;; esac
}
speed_strat() { # speed_strat "<аргументы с @G/@Q>" -> строка в $OUT.speed
    local a="$1" c=0
    nq_up "$a"
    kill -0 "$NQPID" 2>/dev/null && c=$(speed_one)
    kill "$NQPID" 2>/dev/null; wait "$NQPID" 2>/dev/null; NQPID=""
    echo "$c|$a" >> "$OUT.speed"
    S_done=$((S_done + 1))
    st done=$S_done
}

# лучшие N аргументов из results (не ломают, больше ok, быстрее), фильтр по этапу
best() { # best N [этап]
    grep "|${2:-}" "$OUT.results" | awk -F'|' '$3 == 0' | sort -t'|' -k1,1nr -k4,4n | head -n "$1" | cut -d'|' -f5
}

POS_A="1 2 midsld sniext+1 1,midsld host+1 1,host+1,midsld"
# ts один нельзя: у клиентов Windows TCP timestamps выключены, фейк дойдёт до
# сервера. В паре с md5sig (быстрый подбор) можно: фейк отбросит и там
FOOL_ALL="md5sig badseq badsum datanoack ttl3 ttl5 autottl"
fool_arg() {
    case "$1" in
        ttl*)    echo "--dpi-desync-ttl=${1#ttl}" ;;
        autottl) echo "--dpi-desync-autottl" ;;
        *)       echo "--dpi-desync-fooling=$1" ;;
    esac
}
FAKE="--dpi-desync-fake-tls=@G"

# Сайты YouTube и Discord в наборе — у них может быть своя стратегия (3.4: свой
# профиль nfqws по zapret/list-youtube.txt и list-discord.txt)
YT_RE='youtube|ytimg|ggpht|googlevideo'
DC_RE='discord|dis[.]gd'
NBY=$(echo $BLOCKED | tr ' ' '\n' | grep -cE "$YT_RE")
NBD=$(echo $BLOCKED | tr ' ' '\n' | grep -cE "$DC_RE")
# все профили для проверки: YouTube и Discord по своим спискам, остальное — общей
composite() { # composite ОБЩАЯ [YOUTUBE] [DISCORD]
    local p=""
    [ -n "$2" ] && [ "$2" != "$1" ] && p="--filter-tcp=443 --hostlist=$ZDIR/list-youtube.txt $2 --new "
    [ -n "$3" ] && [ "$3" != "$1" ] && p="$p--filter-tcp=443 --hostlist=$ZDIR/list-discord.txt $3 --new "
    if [ -n "$p" ]; then echo "$p--filter-tcp=443 $1"; else echo "$1"; fi
}

# стратегия текущей сети с метками @G/@Q: "" — общая, yt|dc — группы, full — все профили
strat_of() {
    sh "$MODDIR/service.sh" --zapret-strategy "${NETID%%"|"*}" "${NETID#*"|"}" "$1" 2>/dev/null | \
        sed "s#@$ZDIR/tls_clienthello_www_google_com.bin#@G#g; s#@$ZDIR/quic_initial_www_google_com.bin#@Q#g"
}

# Подбор одной группы: что сравниваем и с чем. Общая и текущая своя — тоже кандидаты
if [ -n "$GRP" ]; then
    if [ "$GRP" = yt ]; then GNAME=YouTube; G_RE=$YT_RE; G_T=8; NBG=$NBY; else GNAME=Discord; G_RE=$DC_RE; G_T=9; NBG=$NBD; fi
    if [ "$NBG" -eq 0 ]; then
        st state=done stage="готово" msg="$GNAME открывается и без обхода — подбирать нечего"
        exit 0
    fi
    GENX=$(strat_of)
    OWNX=$(strat_of "$GRP")
    [ -n "$GENX" ] || { st state=error msg="не узнал стратегию сети"; exit 1; }
    [ "$GRP" = yt ] && SPD_IPS=$(doh_ip dl.google.com 6 3)
fi

# --- сайты со своей стратегией (3.6, идея byedpi --auto) ------------------
# Сайты из списков (или переданные), которых основная стратегия сети не
# открывает, получают другую: кандидаты — их прежние стратегии, история сети
# и набор проверенных; сайт закрепляется за первой, открывшей его дважды.
# Не больше 3 стратегий на сеть. Итог — ZALT (демон делает из него профили
# nfqws). Не открылся ничем — в ZSKIP на сутки (часто блок по IP).
if [ "$MODE" = "sites" ]; then
    KEY="${NETID%%"|"*}"
    CUR=$(strat_of full)
    GEN=$(strat_of)
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
    # нет файла (nfqws не запустился) — не открылся: read без файла оставлял
    # в v значение от прошлого сайта
    opened() { while read -r h ip; do v=""; read -r v _ < "$TMP/r.$h" 2>/dev/null; [ "$v" = ok ] && printf '%s ' "$h"; done < "$TMP/ips"; }
    failed() { while read -r h ip; do v=""; read -r v _ < "$TMP/r.$h" 2>/dev/null; [ "$v" = ok ] || printf '%s ' "$h"; done < "$TMP/ips"; }
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
        event "сайты: основная стратегия не открыла ни одного из $NB — это поломка самой стратегии (её чинит автопроверка), сайты не трогаю"
        st state=done stage="готово" msg="основная стратегия не открыла ни одного заблокированного — её чинит автопроверка"
        exit 0
    fi
    : > "$TMP/assign"
    if [ -n "$F" ]; then
        # кандидаты: уже закреплённые за сайтами этой сети, история сети (и
        # сетей с тем же названием), проверенный набор; без основной
        {
            [ -f "$ZALT" ] && K="$KEY" awk -F'|' '$1 == ENVIRON["K"] { print $4 }' "$ZALT"
            L="${NETID#*"|"}" K="$KEY" awk -F'|' '$1 == ENVIRON["K"] || ($4 == ENVIRON["L"] && ENVIRON["L"] != "") { print $1 }' "$ZNETS" 2>/dev/null > "$TMP/keys"
            KS=" $(tr '\n' ' ' < "$TMP/keys") " awk -F'|' 'index(ENVIRON["KS"], " " $1 " ") && $2 == "custom" { l[++n] = $3; if ($6 != "") l[++n] = $6; if ($7 != "") l[++n] = $7 } END { for (i = n; i >= 1; i--) print l[i] }' "$HIST" 2>/dev/null
            echo @@   # дальше встроенный набор
            cat <<EOF
--dpi-desync=multisplit --dpi-desync-split-pos=1,host+1,midsld --dpi-desync-split-seqovl=1
--dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld
--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=www.google.com --dpi-desync-fooling=md5sig
--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld $FAKE
--dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=@G
--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=@G $FAKE
--dpi-desync=fakedsplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq
EOF
        # всего 5: до 3 из истории сети, остальные из встроенного набора
        } | G="$GEN_X" awk '$0 == "@@" { b = 1; next } NF && $0 != ENVIRON["G"] && !/--wssize|syndata/ && !s[$0]++ {
            if (b) { if (n < 5) { print; n++ } } else if (n < 3) { print; n++ } }' > "$TMP/cands"
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
    # не проверенные (адрес не узнали) остаются как были. Не открывшиеся
    # ничем — тоже: чаще это провал сети во время проверки (02.11: bbc, linkedin,
    # viber «ничем», а основной обход их открывает), а без записи сайт сутки
    # (ZSKIP) сидел бы на основной стратегии, которая его не открывает.
    # По облачному ревью (PR #18): запись «ничем» живёт 3 суток от даты
    # записи (O; без date -d — не живёт), новые записи — первыми: демон
    # берёт до 3 стратегий по порядку файла, старые не вытесняют новые
    TA=" $(awk '{print $1}' "$TMP/ips.all" | tr '\n' ' ') "
    T=" $(minus "$TA" "$F") "
    D=$(date '+%Y-%m-%d %H:%M')
    O=$(date -d "@$(($(date +%s) - 259200))" '+%Y-%m-%d %H:%M' 2>/dev/null)
    [ -n "$O" ] || O=9999
    {
        while IFS='|' read -r h a; do printf '%s|%s|%s|%s|%s\n' "$KEY" "${NETID#*"|"}" "$h" "$a" "$D"; done < "$TMP/assign"
        [ -f "$ZALT" ] && K="$KEY" T="$T" TA="$TA" O="$O" awk -F'|' '!($1 == ENVIRON["K"] && (index(ENVIRON["T"], " " $3 " ") || (index(ENVIRON["TA"], " " $3 " ") && $5 < ENVIRON["O"])))' "$ZALT"
    } > "$ZALT.tmp" && chmod 600 "$ZALT.tmp" && mv -f "$ZALT.tmp" "$ZALT"
    NOW=$(date +%s)
    # ZSKIP — по всем проверенным (TA), иначе у «ничем» копились дубли
    {
        [ -f "$ZSKIP" ] && K="$KEY" T="$TA" N="$NOW" awk -F'|' '$3 + 72000 > ENVIRON["N"] && !($1 == ENVIRON["K"] && index(ENVIRON["T"], " " $2 " "))' "$ZSKIP"
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
        MSG="проверено $NT, через обход $NB, своя стратегия у $NA$([ -n "$F" ] && echo ", не открылись ничем: $(echo $F | wc -w)")"
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
    # последний прогон не открыл вообще ничего, даже контрольные — это связь.
    # Не «nfqws: …» (не запустился — сломана стратегия, а не связь) и не пустой
    # файл: раньше и то и другое было «нет связи», и сломанную стратегию
    # сторож не менял никогда (ревью PR #20)
    nothing_opened() { tail -n 1 "$OUT.results" | awk -F'|' '{ n = 1; r = ($1 == 0 && $7 !~ /^nfqws: /) } END { exit !(n && r) }'; }
    # что не открылось у последнего прогона: "youtube.com:x28 ..." (для журнала)
    last_fail() { tail -n 1 "$OUT.results" | cut -d'|' -f7 | cut -c1-200; }
    # Волна ТСПУ на Google: HTTPS ко всем его адресам молчит и без обхода, HTTP
    # отвечает — стратегия ни при чём. 03.11 08:01 сторож в волну счёл её
    # сломанной, подбор (Google ожил к концу) заменил рабочую стратегию YOTA и
    # стёр её стратегию YouTube. Запросы сканера мимо AdGuard и основного
    # обхода (выше), nfqws сканера между прогонами не запущен — напрямую.
    # Волна — метка $OUT.wave: следующие 15 мин сторож не проверяет (в начале,
    # до всех запросов), и выход
    wave_google() {
        _g443=$(curl -s -o /dev/null -m 5 --interface "$WAN" --capath "$CA" -w '%{http_code}' https://www.google.com/generate_204 2>/dev/null)
        _g80=$(curl -s -o /dev/null -m 5 --interface "$WAN" -w '%{http_code}' http://www.google.com/generate_204 2>/dev/null)
        [ "$_g443" = 000 ] && [ "$_g80" = 204 ] || return 0
        touch "$OUTB.wave"
        event "автопроверка: Google по HTTPS молчит и без обхода, по HTTP отвечает — волна ТСПУ, стратегию не трогаю ($(last_fail))"
        wd_last "волна Google, отложил"
        st state=done stage="готово" msg="волна Google (HTTPS молчит и без обхода) — стратегию не трогаю"
        exit 0
    }
    # текущая — оба профиля (своя YouTube, если есть), с пометками @G/@Q
    CUR=$(strat_of full)
    # не узнали текущую — проверять нечего (раньше пустой CUR тоже шёл как «нет связи»)
    [ -n "$CUR" ] || { st state=error msg="не удалось узнать текущую стратегию сети"; exit 1; }
    S_total=2
    st stage="проверяю стратегию сети"
    if [ -n "$CUR" ] && { passed "$CUR" "текущая" || passed "$CUR" "текущая"; }; then
        last=$(awk -F'|' 'END {print $3}' "$EVENTS" 2>/dev/null)
        [ "$last" = "автопроверка: стратегия работает" ] || event "автопроверка: стратегия работает"
        wd_last "работает"
        st state=done stage="готово" msg="текущая стратегия работает"
        exit 0
    fi
    # 16:21 21.10: все сайты разом "не открылись", подбор выбрал стратегию
    # хуже прежней. Связь пропала — не меняем ничего; иначе перепроверка через минуту.
    if nothing_opened; then
        event "автопроверка: не открылось вообще ничего, даже контрольные — похоже, связь; стратегию не трогаю"
        wd_last "нет связи, отложил"
        st state=done stage="готово" msg="нет связи — проверка отложена"
        exit 0
    fi
    # сразу, а не после минуты и третьего прогона: в волну они — лишний залп
    wave_google
    FAIL1=$(last_fail)
    st stage="перепроверка через минуту"
    sleep 60
    if passed "$CUR" "текущая"; then
        event "автопроверка: кратковременный сбой ($FAIL1) — через минуту стратегия работает"
        wd_last "работает (был сбой)"
        st state=done stage="готово" msg="кратковременный сбой — стратегия работает"
        exit 0
    fi
    if nothing_opened; then
        event "автопроверка: не открылось вообще ничего, даже контрольные — похоже, связь; стратегию не трогаю"
        wd_last "нет связи, отложил"
        st state=done stage="готово" msg="нет связи — проверка отложена"
        exit 0
    fi
    # волна могла начаться за эту минуту
    wave_google
    # Без прямых запросов не видно, закрыт ли сайт вообще: в сети без блокировок сторож менял
    # бы стратегию зря. Спрашиваем напрямую только то, что не открылось, и не больше трёх имён
    _df=0; _do=0
    for _t in $(last_fail); do
        # в журнале имена без www.: www.youtube.com записан как youtube.com
        _h=$(awk -v h="${_t%%:*}" '$1 == h || $1 == "www." h { print $1; exit }' "$TMP/ips")
        _ip=$(awk -v h="$_h" '$1 == h { print $2; exit }' "$TMP/ips")
        [ -n "$_ip" ] || continue
        _df=$((_df + 1))
        _c=$(curl -s -o /dev/null -m 5 --interface "$WAN" --capath "$CA" --resolve "$_h:443:$_ip" -w '%{http_code}' "https://$_h/" 2>/dev/null)
        [ -n "$_c" ] && [ "$_c" != 000 ] && _do=$((_do + 1))
        [ "$_df" -ge 3 ] && break
    done
    if [ "$_df" -gt 0 ] && [ "$_do" = "$_df" ]; then
        event "автопроверка: стратегия не открывает ($(last_fail)), но напрямую сайты открыты — блокировки нет, не меняю"
        wd_last "работает (напрямую открыто)"
        st state=done stage="готово" msg="сайты открыты напрямую — блокировки нет"
        exit 0
    fi
    if [ "$AUTOPICK" = 0 ]; then
        event "автопроверка: стратегия не открывает ($(last_fail)) — автоподбор выключен, не меняю"
        wd_last "не открывает, автоподбор выключен"
        st state=done stage="готово" msg="стратегия не открывает сайты, автоподбор выключен"
        exit 0
    fi
    event "автопроверка: стратегия не открывает ($(last_fail)) — ищу замену"
    # прежние стратегии этой сети и сетей с тем же названием (YOTA = 25011 и
    # 25002), новые первыми, без повторов (только свои параметры: custom)
    KEYS=$(L="${NETID#*"|"}" K="${NETID%%"|"*}" awk -F'|' '$4 == ENVIRON["L"] { printf "%s ", $1 } END { print ENVIRON["K"] }' "$ZNETS" 2>/dev/null)
    [ -n "$KEYS" ] || KEYS="${NETID%%"|"*}"
    # строка истории: "общая|youtube|discord" (пусто — как общая)
    KS=" $KEYS " awk -F'|' 'index(ENVIRON["KS"], " " $1 " ") && $2 == "custom" && $3 != "" { l[++n] = $3 "|" $6 "|" $7 } END { for (i = n; i >= 1; i--) if (!(l[i] in s)) { s[l[i]] = 1; print l[i] } }' \
        "$HIST" 2>/dev/null | grep -vE -e '--wssize|syndata' > "$TMP/hist"
    S_total=$((S_done + $(wc -l < "$TMP/hist")))
    st stage="пробую прежние стратегии"
    while IFS= read -r h; do
        a="${h%%"|"*}"; y="${h#*"|"}"; d="${y#*"|"}"; y="${y%%"|"*}"
        c=$(composite "$a" "$y" "$d")
        [ -n "$a" ] && [ "$c" != "$CUR" ] || continue
        if passed "$c" "история" && passed "$c" "история"; then
            if [ "$(sh "$ZDIR/netid.sh" "$WAN" 2>/dev/null | head -1)" != "$NETID" ]; then
                wd_last "сеть сменилась во время проверки"
                st state=done stage="готово" msg="сеть сменилась во время проверки — не запоминаю"
                exit 0
            fi
            r=$(sh "$MODDIR/webctl.sh" znet-set custom "$a" "автопроверка: прежняя рабочая" "$y" "$d" 2>/dev/null)
            # не сохранилась — не «починил», а дальше по истории и подбор (ревью PR #20)
            case "$r" in
                OK*) ;;
                *) event "автопроверка: прежнюю не сохранил (${r:-нет ответа}) — пробую дальше"; continue ;;
            esac
            event "автопроверка: вернул прежнюю стратегию: $a${y:+ (YouTube: $y)}${d:+ (Discord: $d)}"
            wd_last "починил: прежняя стратегия"
            st state=done stage="готово" msg="вернул прежнюю рабочую стратегию"
            exit 0
        fi
    done < "$TMP/hist"
    event "автопроверка: прежние не подошли — быстрый подбор"
    MODE=quick
fi

if [ "$MODE" = "quick" ]; then
    # проверенные шаблоны (autottl убран: ломал обычные сайты во всех 6 проверенных сетях)
    # Четыре с badseq в конце — из Zapret-Manager и Flowseal: 05.11 на YOTA открыли
    # 10 из 10 сайтов и качали с именем видеосервера в обоих кругах (8–27 Мбит/с).
    # Две последних — по мотивам ByeDPI, md5sig вместо его ttl (подделки с ttl на YOTA
    # плохие): там же 10 из 10, 13–24 Мбит/с
    # Три в самом конце — из пресетов zapret2 (сама стратегия, ts заменён на md5sig, кроме
    # hostfakesplit: там ts,md5sig, Windows-раздаче не мешает): 06.11 на YOTA 10 из 10 в
    # обоих кругах, с именем видеосервера 3–15 Мбит/с
    # + S_done: после сторожа (check) прогоны уже были — иначе «30 из 22»
    S_total=$((S_done + 31))
    st stage="быстрый подбор${GNAME:+: $GNAME}"
    if [ -n "$GRP" ]; then
        S_total=$((S_total + 2))
        run_strat "$GENX" "быстрый"
        [ "$OWNX" != "$GENX" ] && run_strat "$OWNX" "быстрый"
    fi
    while IFS= read -r a; do
        [ -n "$a" ] && run_strat "$a" "быстрый"
        # от сторожа — до первой, открывшей всё без поломок: меньше залп (31.10);
        # по кнопке — все, там нужна таблица и самая быстрая
        [ "$MODE0" = check ] && tail -n 1 "$OUT.results" | awk -F'|' '{ exit !($2 > 0 && $1 == $2 && $3 == 0) }' && break
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
--dpi-desync=hostfakesplit --dpi-desync-repeats=4 --dpi-desync-fooling=ts,md5sig --dpi-desync-hostfakesplit-mod=host=ozon.ru
--dpi-desync=hostfakesplit --dpi-desync-repeats=4 --dpi-desync-fooling=ts,md5sig --dpi-desync-hostfakesplit-mod=host=www.google.com
--dpi-desync=fake,multidisorder --dpi-desync-fooling=badseq --dpi-desync-split-pos=1,midsld $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=badsum --dpi-desync-split-pos=midsld $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=datanoack --dpi-desync-split-pos=midsld $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=datanoack --dpi-desync-split-pos=midsld --dpi-desync-fake-tls-mod=rnd,rndsni,padencap
--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=@G $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com
--dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld
--dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=@G
--dpi-desync=multisplit --dpi-desync-split-pos=1,host+1,midsld --dpi-desync-split-seqovl=1 --dup=2 --dup-cutoff=n3 --dup-fooling=md5sig
--dpi-desync=fake,multidisorder --dpi-desync-fooling=badseq,badsum --dpi-desync-badseq-increment=0 --dpi-desync-badack-increment=-66000 --dpi-desync-split-pos=1,2,3,5,105,host+5,sld-1,endsld-5,endsld --dpi-desync-fake-tls-mod=rnd $FAKE
--dpi-desync=fake,multisplit --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=1000 --dpi-desync-repeats=6 $FAKE
--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=10000000 --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=@G --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com
--dpi-desync=fake,fakedsplit --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2 --dpi-desync-repeats=8 --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com
--dpi-desync=fake,multisplit --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld+1,host+3,midsld+5 --dpi-desync-fake-tls-mod=rnd $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,host+1,host+3,host+6,host+9,host+12,host+15,host+20,host+25,host+30,host+35 --dpi-desync-fake-tls-mod=rnd,sni=www.google.com $FAKE
--dpi-desync=fake,multisplit --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,host+2,sld+2,sld+5,sniext+1,sniext+2,endhost-2 --dpi-desync-fake-tls-mod=rnd $FAKE
--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,host+2,sld+2,sld+5,sniext+1,sniext+2,endhost-2 --dpi-desync-fake-tls-mod=rnd $FAKE
--dpi-desync=hostfakesplit --dpi-desync-repeats=4 --dpi-desync-fooling=ts,md5sig --dpi-desync-ts-increment=-1000 --dpi-desync-hostfakesplit-mod=host=ozon.ru
EOF
else
    S_total=$(( 14 + 7 + 32 + 4 + 5 + 12 + 6 ))
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
                # fakedsplit/fakeddisorder режут в одном месте: 1,midsld = midsld (замер 04.11)
                case "$m:$p" in faked*:1,midsld) continue ;; esac
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
    run_strat "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=3,sld+1 --dpi-desync-split-seqovl=2 --dpi-desync-split-seqovl-pattern=@G --dpi-desync-fake-tls=@G --dpi-desync-fake-tls-mod=rnd,dupsid,sni=max.ru --dpi-desync-fooling=datanoack --dpi-desync-repeats=6 --dpi-desync-cutoff=n5" "3"
    run_strat "--dpi-desync=fake,multisplit --dpi-desync-split-pos=1,host+1,midsld --dpi-desync-split-seqovl=1 --dpi-desync-fake-tls=@G --dpi-desync-fake-tls-mod=rnd,dupsid,sni=gosuslugi.ru --dpi-desync-fooling=datanoack --dpi-desync-cutoff=n5" "3"
    # подставное имя в hostfakesplit — VK (есть во всех белых списках; фейки
    # с ним — у magisk-zapret2)
    run_strat "--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=vk.com --dpi-desync-fooling=md5sig" "3"
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
        # случайное имя + padding-расширение (самый частый вариант в наборах
        # zapretdiscordyoutube/src)
        run_strat "$b --dpi-desync-fake-tls-mod=rnd,rndsni,padencap" "4"
        run_strat "$a --dpi-desync-repeats=6" "4"
    done < "$TMP/top3"
    # E (3.6): новые приёмы nfqws к двум лучшим — дубли пакетов с порчей и
    # TTL настоящих пакетов. n3 — только SYN и ACK; d2 ClientHello тоже не
    # дублирует, если его режет desync (замер 04.11), а цепляет ACK после него.
    # --wssize и syndata здесь нет: они работают на SYN, когда имени ещё нет, —
    # подбор их мерил, а профиль со списком не применял (03.11 выиграла с --wssize).
    st stage="5/5 новые приёмы"
    best 2 > "$TMP/top2e"
    while IFS= read -r a; do
        [ -n "$a" ] || continue
        run_strat "$a --dup=2 --dup-cutoff=n3 --dup-fooling=md5sig" "5"
        run_strat "$a --dup=1 --dup-cutoff=n3 --dup-autottl" "5"
        run_strat "$a --orig-autottl=+5 --orig-mod-cutoff=n3" "5"
    done < "$TMP/top2e"
fi

# перепроверка лучших: случайный успех не должен выиграть
st stage="перепроверяю лучшие"
# лучшие для группы: поломки других сайтов не в счёт, её стратегия к ним не применяется
top_grp() { # top_grp РЕГУЛЯРКА ПОЛЕ_ВРЕМЕНИ СКОЛЬКО
    awk -F'|' -v re="$1" -v t="$2" '$5 !~ /--new/ && $7 !~ /^nfqws: / { n = split($7, d, " "); f = 0; for (i = 1; i <= n; i++) if (d[i] ~ re) f++; print f "|" $t + 0 "|" $5 }' "$OUT.results" | \
        sort -t'|' -k1,1n -k2,2n | cut -d'|' -f3 | awk '!s[$0]++' | head -n "$3"
}
if [ -n "$GRP" ]; then
    { echo "$GENX"; echo "$OWNX"; top_grp "$G_RE" "$G_T" 5; } > "$TMP/top"
else
    best 3 > "$TMP/top"
    # + 2 лучших именно для YouTube и Discord (могут не попасть в общие 3)
    [ "$NBY" -gt 0 ] && top_grp "$YT_RE" 8 2 >> "$TMP/top"
    [ "$NBD" -gt 0 ] && top_grp "$DC_RE" 9 2 >> "$TMP/top"
fi
awk '!s[$0]++' "$TMP/top" > "$TMP/top2" && mv -f "$TMP/top2" "$TMP/top"
S_total=$((S_done + $(wc -l < "$TMP/top") * 2))
while IFS= read -r a; do
    [ -n "$a" ] || continue
    run_strat "$a" "проверка"
    run_strat "$a" "проверка"
done < "$TMP/top"

# Подбор группы: из открывших больше всех — самая быстрая. Скорость на YOTA — лотерея
# по адресам (ytslow.sh), а обход её почти не меняет (замеры 04–05.11), поэтому
# берём худший из двух замеров, а своя вместо общей — только если быстрее в 1.5 раза
if [ -n "$GRP" ]; then
    awk -F'|' -v re="$G_RE" '$6 == "проверка" && $7 !~ /^nfqws: / { n = split($7, d, " "); f = 0; for (i = 1; i <= n; i++) if (d[i] ~ re) f++
        if (!($5 in w) || f > w[$5]) w[$5] = f } END { for (a in w) print w[a] "|" a }' "$OUT.results" | sort -t'|' -k1,1n > "$TMP/gf"
    GF=$(head -n 1 "$TMP/gf" | cut -d'|' -f1)
    GO=$((NBG - ${GF:-$NBG}))
    # сейчас своей нет — OWNX совпадает с общей
    OLD="$OWNX"; [ "$OLD" = "$GENX" ] && OLD=""
    if [ "$GO" -le 0 ]; then
        MSG="$GNAME: ни одна стратегия не открыла заблокированные сайты"
    else
        awk -F'|' -v m="$GF" '$1 == m' "$TMP/gf" | cut -d'|' -f2- > "$TMP/gc"
        # Нынешней своей хватает одной удачной перепроверки из двух: сбой на застрявшем
        # адресе (06.11 у соседней стратегии 5 из 6) не повод её менять
        OB=$(A="$OLD" awk -F'|' -v re="$G_RE" '$5 == ENVIRON["A"] && $6 == "проверка" && $7 !~ /^nfqws: / { n = split($7, d, " "); f = 0; for (i = 1; i <= n; i++) if (d[i] ~ re) f++
            if (m == "" || f < m) m = f } END { print m }' "$OUT.results")
        if [ -n "$OB" ] && [ "$OB" -le "$GF" ] && ! grep -qxF -e "$OLD" "$TMP/gc"; then echo "$OLD" >> "$TMP/gc"; fi
        S_total=$((S_done + $(wc -l < "$TMP/gc") * 2))
        st stage="$GNAME: замеряю скорость"
        for _r in 1 2; do
            while IFS= read -r a; do speed_strat "$a"; done < "$TMP/gc"
        done
        awk -F'|' '!($2 in m) || $1 < m[$2] { m[$2] = $1 } END { for (a in m) print m[a] "|" a }' "$OUT.speed" | sort -t'|' -k1,1nr > "$TMP/gs"
        SB=$(head -n 1 "$TMP/gs" | cut -d'|' -f1); SA=$(head -n 1 "$TMP/gs" | cut -d'|' -f2-)
        SG=$(G="$GENX" awk -F'|' '$2 == ENVIRON["G"] { print $1 }' "$TMP/gs")
        NEW=""
        if [ -z "$SG" ]; then NEW="$SA"
        elif [ "$SA" != "$GENX" ] && [ "$SB" -gt 0 ] && [ $((SB * 2)) -ge $((SG * 3)) ]; then NEW="$SA"; fi
        # Нынешняя своя остаётся, если открыла столько же и лучшая не быстрее её в 1.5 раза:
        # 06.11 разброс 20 против 25 Мбит/с сменил badseq на разрез без подделки.
        # Её скорость — лучший из двух замеров: один обрыв не повод менять рабочую.
        # Открыла меньше — её нет в замерах, и правило её не держит
        SO=$(G="$OLD" awk -F'|' '$2 == ENVIRON["G"] && $1 > m { m = $1 } END { print m + 0 }' "$OUT.speed")
        if [ -n "$OLD" ] && [ "$SO" -gt 0 ] && [ $((SB * 2)) -lt $((SO * 3)) ]; then NEW="$OLD"; SB="$SO"; fi
        if [ "$SB" -eq 0 ]; then how="скорость не измерилась"
        elif [ -z "$SG" ]; then how="$((SB / 128)) Мбит/с, общая открывает меньше"
        else how="$((SB / 128)) Мбит/с, у общей $((SG / 128))"; fi
        if { [ -n "$SG" ] || [ -n "$OLD" ]; } && [ "$SB" -eq 0 ]; then
            # все нули: сбой замера или скачивание закрыто для всех. Выбирать не из чего
            MSG="$GNAME: скорость не измерилась, стратегию не меняю"
        elif [ "$AUTOPICK" = 0 ]; then
            MSG="$GNAME: автоподбор выключен, стратегию не меняю — выберите в таблице"
        elif [ "$(sh "$ZDIR/netid.sh" "$WAN" 2>/dev/null | head -1)" != "$NETID" ]; then
            MSG="сеть сменилась во время подбора — не запоминаю"
        else
            # та же, что сейчас: файл сетей и историю не трогаем
            r=OK; [ "$NEW" = "$OLD" ] || r=$(sh "$MODDIR/webctl.sh" znet-own "$GRP" "$NEW" 2>/dev/null)
            case "$r" in
                OK*) if [ -n "$NEW" ]; then MSG="$GNAME: своя стратегия, открыла $GO из $NBG, $how"
                     else MSG="$GNAME: подходит общая, открыла $GO из $NBG, $how"; fi ;;
                *)   MSG="не удалось запомнить: ${r#ERR }" ;;
            esac
        fi
    fi
    event "подбор: $MSG"
    S_state=done
    st stage="готово" msg="$MSG"
    exit 0
fi

# Лучшая: ничего не ломает, открыла больше заблокированных (по худшему из
# прогонов), перепроверена, быстрее. Та же логика, что у таблицы в WebUI.
MSG=""
NB=$(echo $BLOCKED | wc -w)
# По группам: остальные сайты (og), YouTube (oy), Discord (od) — по худшему из
# прогонов. Общая — лучшая для остальных. YouTube и Discord выбираются сами по
# себе: только их сайты и их время, другие сайты эти стратегии не трогают.
# Строка: "открыла|открыла_YouTube|открыла_Discord|аргументы".
pick() { # pick gen|yt|dc
    awk -F'|' -v nb="$NB" -v nby="$NBY" -v nbd="$NBD" -v re="$YT_RE" -v rd="$DC_RE" -v want="$1" '
    $5 ~ /--new/ { next }
    # nfqws не запустился: в $7 текст ошибки, а не сайты — иначе такая
    # стратегия считалась открывшей почти всё (и YouTube целиком)
    $7 ~ /^nfqws: / { next }
    { a = $5; brk = $3 + 0; n = split($7, d, " "); fy = 0; fd = 0; fg = 0
      for (i = 1; i <= n; i++) { if (d[i] ~ re) fy++; else if (d[i] ~ rd) fd++; else fg++ }
      og = (nb - nby - nbd) - fg; oy = nby - fy; od = nbd - fd
      if (!(a in runs)) { mg[a] = og; my[a] = oy; md[a] = od; mb[a] = brk }
      runs[a]++; ms[a] += (want == "yt") ? $8 : (want == "dc") ? $9 : $4
      if (og < mg[a]) mg[a] = og
      if (oy < my[a]) my[a] = oy
      if (od < md[a]) md[a] = od
      if (brk > mb[a]) mb[a] = brk }
    END {
      for (a in runs) {
        if (mb[a] > 0 && want == "gen") continue
        o = (want == "yt") ? my[a] : (want == "dc") ? md[a] : mg[a]
        o2 = (want == "gen") ? my[a] + md[a] : 0
        if (o <= 0 && !(want == "gen" && nb == nby + nbd && o2 > 0)) continue
        t = ms[a] / runs[a]
        if (b == "" || o > bo || (o == bo && o2 > bo2) || (o == bo && o2 == bo2 && runs[a] > br) || (o == bo && o2 == bo2 && runs[a] == br && t < bt)) { b = a; bo = o; bo2 = o2; br = runs[a]; bt = t; byt = my[a]; bdc = md[a] }
      }
      if (b != "") print bo "|" byt "|" bdc "|" b
    }' "$OUT.results"
}
# Для znet-set: найденная своя, «=» — оставить прежнюю, пусто — стереть. Прежнюю мог
# найти замер скорости: подбор по сайтам имени видеосервера может и не видеть, поэтому
# стираем, только если сторож видел, что не открываются именно эти сайты
own_arg() { # own_arg НАЙДЕННАЯ РЕГУЛЯРКА
    if [ -n "$1" ]; then echo "$1"
    elif [ "$WD" = 1 ] && echo "$FAIL1" | grep -qE "$2"; then echo ""
    else echo "="; fi
}
# своя — если открывает больше или при том же счёте быстрее на 20%:
# меньше — разброс сети, менять стратегию не за что
grp_ms() { A="$1" awk -F'|' -v t="$2" '$5 == ENVIRON["A"] && $t > 0 { s += $t; n++ } END { if (n) printf "%d", s / n; else print 0 }' "$OUT.results"; }
grp_best() { # grp_best yt|dc ПОЛЕ_ВРЕМЕНИ ОТКРЫЛА_ОБЩАЯ ОБЩАЯ -> своя или пусто
    local b a m g
    b=$(pick "$1"); [ -n "$b" ] || return 0
    a=$(echo "$b" | cut -d'|' -f4-)
    m=$(grp_ms "$a" "$2"); g=$(grp_ms "$4" "$2")
    if [ "${b%%"|"*}" -gt "$3" ] || { [ "${b%%"|"*}" = "$3" ] && [ "$a" != "$4" ] && [ "$m" -gt 0 ] && [ $((m * 5)) -lt $((g * 4)) ]; }; then
        echo "$a"
    fi
}
BG=$(pick gen)
BEST=""; BEST_YT=""; BEST_DC=""
if [ -n "$BG" ]; then
    ga=$(echo "$BG" | cut -d'|' -f4-)
    BEST="${BG%%"|"*}|$ga"                         # "открыла|аргументы" (остальные сайты)
    gy=$(echo "$BG" | cut -d'|' -f2)               # сколько YouTube открывает общая
    gd=$(echo "$BG" | cut -d'|' -f3)               # и сколько Discord
    [ "$NBY" -gt 0 ] && BEST_YT=$(grp_best yt 8 "$gy" "$ga")
    [ "$NBD" -gt 0 ] && BEST_DC=$(grp_best dc 9 "$gd" "$ga")
fi
if [ "$PERNET" = "1" ] && [ -n "$BEST" ]; then
    if [ -z "${NETID%%"|"*}" ]; then
        MSG="не понял, что за сеть — стратегия не запомнена, примени вручную"
    elif [ "$AUTOPICK" = 0 ]; then
        MSG="автоподбор выключен, стратегию не меняю — выберите в таблице"
    elif [ "$(sh "$ZDIR/netid.sh" "$WAN" 2>/dev/null | head -1)" != "$NETID" ]; then
        MSG="сеть сменилась во время подбора — не запоминаю"
    else
        if [ -n "$BEST_YT$BEST_DC" ]; then
            how="остальные ${BEST%%"|"*} из $((NB - NBY - NBD))${BEST_YT:+, YouTube — своя}${BEST_DC:+, Discord — своя}"
        else
            how="открыла $((${BEST%%"|"*} + gy + gd)) из $NB"
        fi
        r=$(sh "$MODDIR/webctl.sh" znet-set custom "${BEST#*"|"}" "подбор: $how" "$(own_arg "$BEST_YT" "$YT_RE")" "$(own_arg "$BEST_DC" "$DC_RE")" 2>/dev/null)
        case "$r" in
            OK*) MSG="лучшая запомнена для сети «${NETID#*"|"}» ($how)" ;;
            *)   MSG="не удалось запомнить: ${r#ERR }" ;;
        esac
    fi
elif [ -z "$BEST" ]; then
    MSG="ни одна стратегия не открыла заблокированные сайты без поломок"
fi

if [ "$WD" = 1 ]; then
    event "автопроверка: подбор — ${MSG:-готово}"
    case "$MSG" in лучшая*) wd_last "починил: подбор" ;; *) wd_last "не починил: ${MSG:-нет стратегии}" ;; esac
else
    event "подбор ($MODE): ${MSG:-готово}"
fi
S_state=done
st stage="готово" msg="$MSG"
