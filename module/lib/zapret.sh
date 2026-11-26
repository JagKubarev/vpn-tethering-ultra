# shellcheck shell=sh
# lib/zapret.sh — обход DPI: QUIC_BLOCK_APPS, zapret/nfqws (стратегии сетей,
# правила, сторож, проверка сайтов, согласование с состоянием).
# Часть демона service.sh: подключается из него через ".", сам не запускается.
# Настройки (USER CONFIG) и общие переменные — в service.sh.

# ============================================================================
# QUIC_BLOCK_APPS: UDP 443 этих приложений -> REJECT (filter OUTPUT, v4+v6).
# Не зависит от режима и VPN: через VPN приложение просто идёт по TCP.
# uid берём по владельцу /data/data/<пакет>; переустановка меняет uid —
# поэтому из цикла раз в ~30с, пересборка только при изменении.
# ============================================================================
QUIC_UIDS=""
QUIC_LOGGED=0
QUIC_FAKE_UIDS=""        # клиенты YouTube с подделкой QUIC (QUIC_YT_FAKE)
QUIC_SIG=""              # «закрытые|с подделкой» — пересборка только при изменении
CHAIN_QUIC_FAKE="VPN_QUIC_FAKE"   # mangle POSTROUTING: UDP 443 клиентов YouTube -> nfqws
# QUIC_BLOCK_YT=1: клиенты YouTube и Google Play (com.android.vending) — без
# QUIC, если установлены; при QUIC_YT_FAKE — с подделкой (Play качает с тех
# же серверов Google и так же ждёт QUIC, который ТСПУ режет молча)
QUIC_YT_PKGS="com.android.vending com.google.android.youtube com.google.android.apps.youtube.music com.google.android.apps.youtube.kids com.google.android.youtube.tv app.revanced.android.youtube app.revanced.android.apps.youtube.music app.rvx.android.youtube app.rvx.android.apps.youtube.music app.morphe.android.youtube app.morphe.android.apps.youtube.music com.vanced.android.youtube com.vanced.android.apps.youtube.music org.schabi.newpipe com.github.libretube"
quic_yt_pkgs() {   # установленные клиенты YouTube (при QUIC_BLOCK_YT=1), не из ручного списка
    local p
    [ "$QUIC_BLOCK_YT" = "1" ] || return 0
    # сверка с ручным списком — после клонов: основной там, а клон pkg@N — нет, ему подделка своя
    for p in $(pkg_with_clones $QUIC_YT_PKGS); do
        case " $QUIC_BLOCK_APPS " in *" $p "*) continue ;; esac
        echo "$p"
    done | tr '\n' ' '
}

# Подделка QUIC вместо закрытия (QUIC_YT_FAKE=1). Замер 29.10 на YOTA: QUIC
# YouTube без обхода — 0 ответов (ТСПУ режет молча, YouTube ждёт и уходит на
# TCP); с fake QUIC x6 (как в magisk-zapret2) — работает, 20 МБ по QUIC за
# 2,5 мин, перемотка быстрее. Только когда подделка точно уйдёт: nfqws
# запущен, есть connbytes (иначе в очередь весь поток), мимо VPN/WARP — иначе
# закрываем, как раньше: голый QUIC умирал бы молча
# Профиль UDP должен быть у запущенного nfqws: после «Применить» аргументы
# пересобираются только в следующем пересчёте — без профиля QUIC прошёл бы голым
quic_fake_on() {
    # ZAPRET_PHONE=0 — обход только для раздачи: трафик телефона не трогаем
    [ "$QUIC_BLOCK_YT" = "1" ] && [ "$QUIC_YT_FAKE" = "1" ] && [ "$ZAPRET_STATE" = "on" ] && \
        [ "$ZAPRET_PHONE" = "1" ] && zapret_cap cb && zapret_cap nfq || return 1
    case "$ZAPRET_ARGS_RUN" in *quic_initial_www_google_com.bin*) return 0 ;; esac
    return 1
}

quic_block_uids() {   # пакеты
    local p u out=""
    for p in $1; do
        u=$(pkg_uid "$p")
        case "$u" in ''|*[!0-9]*) continue ;; esac
        [ "$u" -ge 10000 ] && out="$out $u"
    done
    echo "${out# }"
}

# AdGuard (ADGUARD_OUTPUT в filter OUTPUT) закрывает UDP 443 всем, кого
# фильтрует, — и клиентам YouTube, и подделкам nfqws (sendto -> EPERM, замер
# 29.10). При подделке — RETURN в начало его цепочки: дальше обычные правила
# Android (учёт трафика, фоновые ограничения), мимо AdGuard. Цена: QUIC
# YouTube AdGuard не фильтрует — реклама через AdGuard может вернуться.
# AdGuard пересоздаёт цепочку при перезапуске — сверяем каждый проход (~30 с)
QUIC_AG_UIDS=""          # uid клиентов YouTube с RETURN в ADGUARD_OUTPUT
quic_adguard() {   # uid клиентов YouTube с подделкой; пусто — снять свои правила
    local t u
    for t in "$iptables" "$ip6tables"; do
        $t -L ADGUARD_OUTPUT -n >/dev/null 2>&1 || continue
        for u in $QUIC_AG_UIDS; do
            case " $1 " in *" $u "*) ;; *) $t -D ADGUARD_OUTPUT -p udp --dport 443 -m owner --uid-owner "$u" -j RETURN 2>/dev/null ;; esac
        done
        # gid nfqws — и при подделке QUIC раздачи: её подделки тоже идут через OUTPUT
        if [ -n "$1" ] || [ "$ZAPRET_QF_ON" = "1" ]; then
            $t -C ADGUARD_OUTPUT -p udp --dport 443 -m owner --gid-owner "$ZAPRET_GID" -j RETURN 2>/dev/null || \
                $t -I ADGUARD_OUTPUT 1 -p udp --dport 443 -m owner --gid-owner "$ZAPRET_GID" -j RETURN 2>/dev/null
            for u in $1; do
                $t -C ADGUARD_OUTPUT -p udp --dport 443 -m owner --uid-owner "$u" -j RETURN 2>/dev/null || \
                    $t -I ADGUARD_OUTPUT 1 -p udp --dport 443 -m owner --uid-owner "$u" -j RETURN 2>/dev/null
            done
        else
            $t -D ADGUARD_OUTPUT -p udp --dport 443 -m owner --gid-owner "$ZAPRET_GID" -j RETURN 2>/dev/null
        fi
    done
    QUIC_AG_UIDS="$1"
}

quic_block_apply() {
    local uids fuids t u rj blk yt fake=0
    yt=$(quic_yt_pkgs)
    quic_fake_on && fake=1
    # закрыть: ручной список, плюс клиенты YouTube, если не подделка
    blk="$QUIC_BLOCK_APPS"
    [ "$fake" = 1 ] || blk="$blk $yt"
    blk=$(echo $blk)
    uids=$(quic_block_uids "$blk")
    fuids=""
    [ "$fake" = 1 ] && fuids=$(quic_block_uids "$yt")
    # список опустел (клиент YouTube удалён, а QUIC_BLOCK_APPS пуст) — снять
    # цепочки, иначе REJECT остаётся на uid удалённого пакета
    if [ -z "$uids" ] && [ -z "$fuids" ]; then
        [ "$QUIC_LOGGED" = "1" ] && { quic_block_down; log "QUIC: закрывать некому — правила сняты"; }
        quic_adguard ""   # RETURN для gid nfqws при подделке QUIC раздачи
        return 0
    fi
    if [ "$uids|$fuids" = "$QUIC_SIG" ] && [ "$QUIC_LOGGED" = "1" ] && \
       $iptables -C OUTPUT -j "$CHAIN_QUIC" 2>/dev/null && \
       { [ -z "$fuids" ] || $iptables -t mangle -C POSTROUTING -j "$CHAIN_QUIC_FAKE" 2>/dev/null; }; then
        quic_adguard "$fuids"   # AdGuard мог пересоздать цепочку
        return 0
    fi
    for t in "$iptables" "$ip6tables"; do
        rj="icmp-port-unreachable"
        [ "$t" = "$ip6tables" ] && rj="icmp6-port-unreachable"
        $t -N "$CHAIN_QUIC" 2>/dev/null
        $t -F "$CHAIN_QUIC" 2>/dev/null
        for u in $uids; do
            $t -A "$CHAIN_QUIC" -p udp --dport 443 -m owner --uid-owner "$u" \
                -j REJECT --reject-with "$rj" 2>/dev/null
        done
        $t -C OUTPUT -j "$CHAIN_QUIC" 2>/dev/null || $t -I OUTPUT 1 -j "$CHAIN_QUIC" 2>/dev/null
        # первые пакеты QUIC клиентов YouTube — в nfqws (профиль --filter-udp=443)
        $t -t mangle -N "$CHAIN_QUIC_FAKE" 2>/dev/null
        $t -t mangle -F "$CHAIN_QUIC_FAKE" 2>/dev/null
        if [ -n "$fuids" ]; then
            $t -t mangle -A "$CHAIN_QUIC_FAKE" -o tun+ -j RETURN 2>/dev/null
            $t -t mangle -A "$CHAIN_QUIC_FAKE" -o warp+ -j RETURN 2>/dev/null
            for u in $fuids; do
                # shellcheck disable=SC2086
                $t -t mangle -A "$CHAIN_QUIC_FAKE" -p udp --dport 443 -m owner --uid-owner "$u" $ZAPRET_CB_OUT \
                    -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null
            done
            $t -t mangle -C POSTROUTING -j "$CHAIN_QUIC_FAKE" 2>/dev/null || \
                $t -t mangle -A POSTROUTING -j "$CHAIN_QUIC_FAKE" 2>/dev/null
        else
            $t -t mangle -D POSTROUTING -j "$CHAIN_QUIC_FAKE" 2>/dev/null
        fi
    done
    [ -n "$uids" ] && log "QUIC (UDP 443) закрыт для: ${blk% } (uid: $uids)"
    [ -n "$fuids" ] && log "QUIC клиентов YouTube и Play — с подделкой (uid: $fuids)$($iptables -L ADGUARD_OUTPUT -n >/dev/null 2>&1 && echo ', мимо AdGuard')"
    quic_adguard "$fuids"
    QUIC_UIDS="$uids"
    QUIC_FAKE_UIDS="$fuids"
    QUIC_SIG="$uids|$fuids"
    QUIC_LOGGED=1
}

quic_block_down() {
    local t _n
    for t in "$iptables" "$ip6tables"; do
        _n=0
        while [ $_n -lt 8 ] && $t -D OUTPUT -j "$CHAIN_QUIC" 2>/dev/null; do _n=$((_n + 1)); done
        $t -F "$CHAIN_QUIC" 2>/dev/null
        $t -X "$CHAIN_QUIC" 2>/dev/null
        _n=0
        while [ $_n -lt 8 ] && $t -t mangle -D POSTROUTING -j "$CHAIN_QUIC_FAKE" 2>/dev/null; do _n=$((_n + 1)); done
        $t -t mangle -F "$CHAIN_QUIC_FAKE" 2>/dev/null
        $t -t mangle -X "$CHAIN_QUIC_FAKE" 2>/dev/null
    done
    # и RETURN от убитого демона (kill -9, обновление): его список uid потерян
    QUIC_AG_UIDS="$QUIC_AG_UIDS $(quic_block_uids "$(pkg_with_clones $QUIC_YT_PKGS)")"
    quic_adguard ""
    QUIC_UIDS=""
    QUIC_FAKE_UIDS=""
    QUIC_SIG=""
    QUIC_LOGGED=0
}

# ============================================================================
# zapret (nfqws): обход DPI для трафика мимо VPN.
#  - mangle POSTROUTING -> VPN_ZAPRET: первые пакеты HTTPS-соединений уходят
#    в nfqws (очередь ZAPRET_QNUM). Пропускаем: tun* (VPN), lo, локальные
#    сети, пакеты самого nfqws (метка и группа ZAPRET_GID), VPN-клиентов,
#    dnsproxy.
#    Раздача (пакеты без сокета) обрабатывается всегда, телефон — если
#    ZAPRET_PHONE=1.
#  - mangle PREROUTING -> VPN_ZAPRET_IN: первые ответы — nfqws по ним видит
#    обрывы/заглушки и пополняет автосписок (режим list), а --wssize и
#    autottl берут из них окно и TTL сервера (3.6: в любом режиме).
#  - filter FORWARD -> VPN_ZAPRET_QUIC: QUIC раздачи мимо VPN -> REJECT.
# Хуки ставятся В КОНЕЦ цепочек: вердикт NFQUEUE завершает обход таблицы,
# а системные цепочки (учёт трафика, idletimer) должны отработать раньше.
# ============================================================================
ZAPRET_ARGS_RUN=""
ZAPRET_EXCL_RUN=""

# Что умеет iptables ядра (лог 4PDA 26.10: Xiaomi, ядро 5.10 — правило с
# connbytes не вставало, обход не работал вовсе, а сторож каждые 15 с ставил
# правила заново). Пробуем один раз в пустой, ни к чему не подключённой цепочке.
#   нет NFQUEUE   — обход невозможен (состояние nokernel, без повторов);
#   нет connbytes — в nfqws все исходящие HTTPS-пакеты (не первые 20), ответы
#                   не идут (это была бы вся закачка): нет автосписка и
#                   подстройки по ответу сервера (autottl, --wssize);
#   нет string    — нет «мимо кэшей оператора» и отбоя мёртвых серверов YouTube.
# Итог — и в файл: проверка сайта, подбор и регистрация WARP ставят свои правила.
ZAPRET_CAPS=""                  # «cb=1 str=1 nfq=1», пусто — ещё не проверяли
ZAPRET_CAPS_FILE=/data/local/tmp/vpn_tether_zcaps
# Первые 20 исходящих пакетов соединения (было 9). В счёт идут и подделки nfqws: у YouTube
# (fake ×6 + разрез) окно 9 кончалось на первом же ClientHello, и повтор потерянной части
# уходил мимо обхода с открытым именем — ТСПУ резал, сервер молчал. 08.11, netem (RTT ~380 мс,
# потери 4%): живых среди отбитых «принял ClientHello и молчит» 5 из 22 против 10–13 при 9.
# 17.11 — 40: у nfqws2 (vt_soft_crck + synack) до первого ответа сервера уходит 14 пакетов, один повтор
# ClientHello уже не влезал бы и в 20 (в 15 у nfqws2 — тем более). Каждый повтор с обходом — ещё ~10
ZAPRET_CB_OUT="-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:40"

ZAPRET_CAPS_TRIES=0
# от прошлой загрузки: /data/local/tmp её переживает. Только демон: файл подключают и scan.sh, и webctl.sh (сборка
# аргументов nfqws2) — они стирали итог демона, и на ядре без connbytes их правила вставали с ним и не работали (17.11)
case "${0##*/}" in service.sh) rm -f "$ZAPRET_CAPS_FILE" 2>/dev/null ;; esac
# 0 — проверено (ZAPRET_CAPS заполнен), 1 — не сейчас (сбой не от ядра: замок
# xtables у netd/scan.sh, не создалась цепочка) — повтор в следующем такте.
# Иначе разовый сбой на загрузке выключал zapret до перезагрузки (ревью 27.10)
zapret_caps() {
    local c=VPN_ZCAP cb=0 str=0 nfq=0 own=1 e miss=""
    [ -n "$ZAPRET_CAPS" ] && return 0
    $iptables -t mangle -N $c 2>/dev/null; $iptables -t mangle -F $c 2>/dev/null
    if ! e=$($iptables -t mangle -L $c -n 2>&1 >/dev/null); then
        ZAPRET_CAPS_TRIES=$((ZAPRET_CAPS_TRIES + 1))
        [ "$ZAPRET_CAPS_TRIES" = 3 ] && log "WARNING: zapret: не проверить возможности ядра — iptables не создаёт цепочку (${e%%
*}); повторяю"
        return 1
    fi
    # сбой от замка — не ответ ядра
    zcap_lockerr() { case "$1" in *xtables\ lock*|*[Tt]emporarily*|*[Rr]esource\ busy*|*holding*) return 0 ;; esac; return 1; }
    if e=$($iptables -t mangle -A $c -p tcp --dport 443 $ZAPRET_CB_OUT -j RETURN 2>&1); then cb=1
    elif zcap_lockerr "$e"; then $iptables -t mangle -F $c 2>/dev/null; $iptables -t mangle -X $c 2>/dev/null; return 1
    else miss="$miss connbytes (${e%%
*})"; fi
    if e=$($iptables -t mangle -A $c -p tcp -m string --string googlevideo.com --algo bm -j RETURN 2>&1); then str=1
    elif zcap_lockerr "$e"; then $iptables -t mangle -F $c 2>/dev/null; $iptables -t mangle -X $c 2>/dev/null; return 1
    else miss="$miss string (${e%%
*})"; fi
    if e=$($iptables -t mangle -A $c -p tcp -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>&1); then nfq=1
    elif zcap_lockerr "$e"; then $iptables -t mangle -F $c 2>/dev/null; $iptables -t mangle -X $c 2>/dev/null; return 1
    else miss="$miss NFQUEUE (${e%%
*})"; fi
    $iptables -t mangle -F $c 2>/dev/null; $iptables -t mangle -X $c 2>/dev/null
    # не прошло ничего — подозрительно (iptables сломан, а не ядро): три такта подряд
    if [ "$cb$str$nfq" = "000" ] && [ "$ZAPRET_CAPS_TRIES" -lt 2 ]; then
        ZAPRET_CAPS_TRIES=$((ZAPRET_CAPS_TRIES + 1)); return 1
    fi
    zapret_owner_works || own=0
    ZAPRET_CAPS="cb=$cb str=$str nfq=$nfq own=$own"
    printf '%s\n' $ZAPRET_CAPS > "$ZAPRET_CAPS_FILE" 2>/dev/null
    [ -n "$miss" ] && log "WARNING: zapret: ядро не умеет:$miss"
    [ "$own" = 0 ] && log "WARNING: zapret: на этом ядре правила по приложениям в POSTROUTING срабатывают на всё — «мимо обхода» по приложениям не работает, остаются исключения по сайтам"
    if [ "$nfq" = 0 ]; then
        log "WARNING: zapret: без NFQUEUE обход невозможен — выключен до перезагрузки; нужен VPN или другое ядро"
    elif [ "$cb" = 0 ]; then
        ZAPRET_CB_OUT=""
        log "WARNING: zapret: упрощённый режим (ядро без connbytes) — в nfqws все исходящие пакеты TCP, кроме пустых ACK (больше нагрузка), без подстройки по ответу сервера (autottl, --wssize), UDP (звонки, QUIC) — мимо обхода; автосписок — только по зависаниям$([ "$ZAPRET_ENGINE" = nfqws2 ] && [ -s "$ZAPRET_NETS_FILE" ] && echo ". Движок nfqws2: стратегии сетей, подобранные для nfqws1, не действуют — до подбора nfqws2 общая (сайты могут не открываться, подбор — в WebUI)")"
        # GGC и отбой мёртвых — по одной строке SNI, без «первых пакетов»
        GGC_MATCH="-p tcp --dport 443 -m string --string googlevideo.com --algo bm"
        GVT_MATCH="-p tcp --dport 443 -m string --string gvt1.com --algo bm"
        yt_match_build
        # хуки от убитого демона с этим совпадением: чистка при старте снимала
        # только вариант с connbytes
        zapret_ggc_hooks_off "$iptables"; zapret_ggc_hooks_off "$ip6tables"; yt_dead_hooks_off
    fi
    [ "$str" = 0 ] && log "WARNING: zapret: без string — «YouTube мимо кэшей оператора» и повтор застрявших видеосоединений недоступны"
    return 0
}
# На части старых ядер (MT6580, 3.18) -m owner в POSTROUTING совпадает с любым
# значением, в OUTPUT — нет: обход молча не видел трафик, а подбор шёл успешно
zapret_owner_works() {
    local r="-d 127.0.0.2 -m owner --uid-owner 12345 -j RETURN" n
    $iptables -t mangle -I POSTROUTING 1 $r 2>/dev/null || return 0
    ping -c 1 -W 1 127.0.0.2 >/dev/null 2>&1
    n=$($iptables -t mangle -L POSTROUTING -v -n -x 2>/dev/null | grep -m1 '127\.0\.0\.2' | sed 's/^ *//' | cut -d' ' -f1)
    $iptables -t mangle -D POSTROUTING $r 2>/dev/null
    [ "${n:-0}" = 0 ]
}
zapret_cap() { case " $ZAPRET_CAPS " in *" $1=1 "*) return 0 ;; esac; return 1; }

zapret_alive() {
    local pid
    pid=$(cat "$ZAPRET_PID_FILE" 2>/dev/null)
    # своя очередь: nfqws подбора (203) или WebUI (202) с номером умершего
    # основного сошёл бы за живой
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && grep -q "qnum=$ZAPRET_QNUM" "/proc/$pid/cmdline" 2>/dev/null
}

# Идёт подбор / сторож / проверка сайтов: pid жив и это scan.sh (pid-файл
# с прошлой загрузки мог достаться чужому процессу — сторож молчал бы вечно)
zscan_running() {
    local pid
    pid=$(cat "$ZSCAN_PID_FILE" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 1
    case "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" in *zapret/scan.sh*) return 0 ;; esac
    return 1
}
ZSCAN_JUST_TS=0   # сторож только что запустил scan.sh (его pid-файла ещё нет)

# Все nfqws на нашей очереди, в т.ч. оставшиеся от убитого демона
zapret_kill_all() {
    local p
    for p in $(pgrep -f "nfqws.*--qnum=$ZAPRET_QNUM " 2>/dev/null); do kill "$p" 2>/dev/null; done
    sleep 0.3
    for p in $(pgrep -f "nfqws.*--qnum=$ZAPRET_QNUM " 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
    rm -f "$ZAPRET_PID_FILE"
}

# appId (uid по модулю 100000 — и клоны) приложений с VpnService: запомненный «владелец VPN» остаётся в
# исключениях, только пока его uid — VPN-клиент. 26.11 на 13T в файле были uid удалённых VPN-клиентов, которые
# Android отдал Google Переводчику и Новостям: их ClientHello к Google шли без обхода (а прямые запросы к
# закрытым именам Google запускают волну на YOTA, 06.11). Раз в 10 мин или по требованию (force); команда не
# ответила или пусто — пусто, и тогда список не трогаем
# Снимок — в файле: zapret_vpn_uids зовут через $(...), переменная из подоболочки не вернулась бы
VPN_SVC_FILE=/data/local/tmp/vpn_tether_vpnsvc
vpn_service_ids() {   # [force] -> appId через пробел; пусто — список неизвестен (не ответил, обрезан)
    local now ts ids="" o u t n p v to=""
    now=$(date +%s)
    if [ "$1" != force ] && read -r ts ids < "$VPN_SVC_FILE" 2>/dev/null && [ $((now - ts)) -lt 600 ] 2>/dev/null; then
        echo "$ids"; return 0
    fi
    ids=""
    # тайм-аут 10 с, а не 3: на MT6580 cmd медленный, и обрезанный список выбросил бы настоящий VPN-клиент
    [ -n "$TIMEOUT_CMD" ] && to="${TIMEOUT_CMD%3}10"
    # каждый запущенный пользователь (клоны, рабочий профиль): «--user all» команда не принимает
    for u in $(pm list users 2>/dev/null | sed -n 's/.*UserInfo{\([0-9]*\):.*} running.*/\1/p'); do
        o=$($to sh -c "cmd package query-services --user $u --brief -a android.net.VpnService 2>/dev/null")
        case "$o" in *"No services found"*) continue ;; esac
        # всё или ничего: «N services found» и столько же «Service #» — иначе обрезан, снимок пустой (файл не трогаем)
        t=$(printf '%s\n' "$o" | sed -n 's/^\([0-9][0-9]*\) services\{0,1\} found.*/\1/p' | head -1)
        n=$(printf '%s\n' "$o" | grep -c 'Service #')
        if [ -z "$t" ] || [ "$t" != "$n" ]; then ids=""; break; fi
        for p in $(printf '%s\n' "$o" | sed -n 's|^ *\([A-Za-z0-9_][A-Za-z0-9_.]*\)/.*|\1|p' | sort -u); do
            if [ "$u" = 0 ]; then v=$(pkg_uid "$p"); else v=$(pkg_uid "$p@$u"); fi
            case "$v" in ''|*[!0-9]*) continue ;; esac
            ids="$ids $((v % 100000))"
        done
    done
    ids=$(echo $ids | tr ' ' '\n' | sort -u | tr '\n' ' '); ids="${ids% }"
    echo "$now $ids" > "$VPN_SVC_FILE"
    echo "$ids"
}
uid_pkg() {   # uid -> пакет, по владельцу папки данных (pm --uid есть не на всех прошивках)
    ls -ln "/data/user/$(($1 / 100000))/" 2>/dev/null | awk -v u="$1" '$3 == u { print $NF; exit }'
}
# uid из ZAPRET_VPN_UIDS_FILE, у которых сейчас VPN-клиент; остальные — из файла вон (с записью в журнал)
zapret_vpn_learned() {
    local svc u keep="" drop="" pass
    for pass in 1 2; do
        # лишние по снимку — переспросить свежим: VPN-клиент мог встать после снимка
        if [ "$pass" = 2 ]; then svc=$(vpn_service_ids force); else svc=$(vpn_service_ids); fi
        [ -n "$svc" ] || { tr -c '0-9' ' ' < "$ZAPRET_VPN_UIDS_FILE"; return 0; }
        keep=""; drop=""
        for u in $(tr -c '0-9' ' ' < "$ZAPRET_VPN_UIDS_FILE"); do
            case " $svc " in *" $((u % 100000)) "*) keep="$keep $u" ;; *) drop="$drop $u" ;; esac
        done
        [ -z "$drop" ] && break
    done
    if [ -n "$drop" ]; then
        for u in $drop; do
            log "zapret: uid $u больше не VPN-клиент ($(uid_pkg "$u" | grep . || echo 'не установлен')) — убрал из исключений обхода"
        done
        if [ -n "$keep" ]; then printf '%s\n' $keep > "$ZAPRET_VPN_UIDS_FILE.tmp"; else : > "$ZAPRET_VPN_UIDS_FILE.tmp"; fi
        mv -f "$ZAPRET_VPN_UIDS_FILE.tmp" "$ZAPRET_VPN_UIDS_FILE"
    fi
    echo "${keep# }"
}

# uid мимо обхода: VPN-клиенты (известные пакеты + владельцы VPN, замеченные
# раньше, если они всё ещё VPN-клиенты) и приложения из ZAPRET_EXCL_APPS
zapret_vpn_uids() {
    local p u out=""
    for p in $VPN_CLIENT_PKGS $ZAPRET_EXCL_APPS; do
        u=$(pkg_uid "$p")
        case "$u" in ''|*[!0-9]*) continue ;; esac
        out="$out $u"
    done
    [ -f "$ZAPRET_VPN_UIDS_FILE" ] && out="$out $(zapret_vpn_learned)"
    echo $out | tr ' ' '\n' | awk '$1 ~ /^[0-9]+$/ && $1 >= 10000' | sort -un | tr '\n' ' '
}

# Владелец поднятого VPN (любой клиент, даже не из списка) — запоминаем
zapret_learn_vpn_owner() {
    local u
    # с таймаутом, как в get_vpn_dns: dumpsys мог повесить цикл (ревью PR #19)
    u=$($TIMEOUT_CMD sh -c "dumpsys connectivity 2>/dev/null" | grep -A3 'VPN CONNECTED' | grep -oE 'OwnerUid: [0-9]+' | head -1 | grep -oE '[0-9]+$')
    case "$u" in ''|*[!0-9]*) return 0 ;; esac
    [ "$u" -ge 10000 ] || return 0
    grep -qx "$u" "$ZAPRET_VPN_UIDS_FILE" 2>/dev/null && return 0
    echo "$u" >> "$ZAPRET_VPN_UIDS_FILE"
    log "zapret: uid $u (владелец VPN) — в исключения"
}

# Профили nfqws для сайтов со своей стратегией (ZALT_FILE, пишет scan.sh
# sites) — по профилю на стратегию, до 3. Своих записей у сети нет — берём
# записи сети с тем же названием (YOTA = 25011 и 25002). Файлы списков
# переписываются только при изменении: nfqws сам перечитывает их.
zapret_alt_profiles() {
    local ex="$1" i=0 a f out="" nre
    nre=$(zapret_zone_re "$ZAPRET_LIST_NOAUTO")
    if [ "$ZAPRET_ALT" = "1" ] && [ "$ZAPRET_PER_NET" = "1" ] && [ -n "$NET_KEY" ] && [ -f "$ZALT_FILE" ]; then
        # записи nfqws2 (z2:) — мимо: иначе сеть только с ними не брала бы записи nfqws1 сети с тем же названием
        K="$NET_KEY" L="$NET_LABEL" awk -F'|' '
            $4 ~ /^z2:/ { next }
            $1 == ENVIRON["K"] { k[++nk] = $4 "|" $3 }
            ENVIRON["L"] != "" && $2 == ENVIRON["L"] { l[++nl] = $4 "|" $3 }
            END { if (nk) { for (i = 1; i <= nk; i++) print k[i] } else for (i = 1; i <= nl; i++) print l[i] }' \
            "$ZALT_FILE" 2>/dev/null > "$ZALT_RUN.lst"
        cut -d'|' -f1 "$ZALT_RUN.lst" | awk '!s[$0]++' > "$ZALT_RUN.args"
        while IFS= read -r a <&3; do
            [ "$i" -lt 3 ] || break
            zapret_args_valid "$a" || continue
            i=$((i + 1)); f="$ZALT_RUN.$i"
            # Google (list-noauto) — только сайты из списков (ZAPRET_RU_RUN):
            # остальные попадали сюда из автосписка (29.10: 93 записи разом)
            A="$a" R="$nre" KS=" $(tr '\n' ' ' < "$ZAPRET_RU_RUN" 2>/dev/null) " awk -F'|' '
                $1 == ENVIRON["A"] && $2 ~ /^[a-z0-9.-]+$/ &&
                (ENVIRON["R"] == "" || $2 !~ ENVIRON["R"] || index(ENVIRON["KS"], " " $2 " ")) { print $2 }' \
                "$ZALT_RUN.lst" | sort -u > "$f.new"
            if [ ! -s "$f.new" ]; then rm -f "$f.new"; i=$((i - 1)); continue; fi
            if cmp -s "$f.new" "$f"; then rm -f "$f.new"; else mv -f "$f.new" "$f"; fi
            out="$out--filter-tcp=443 $ex --hostlist=$f $(zapret_strategy_args "$ZAPRET_DIR" custom "$a") --new "
        done 3< "$ZALT_RUN.args"
    fi
    i=$((i + 1))
    while [ "$i" -le 3 ]; do rm -f "$ZALT_RUN.$i"; i=$((i + 1)); done
    printf '%s' "$out"
}
# сколько сайтов в профилях запущенного nfqws (по его аргументам)
zapret_alt_count() {
    local i n=0
    for i in 1 2 3; do
        case "$1 " in *"--hostlist=$ZALT_RUN.$i "*) n=$((n + $(wc -l < "$ZALT_RUN.$i" 2>/dev/null || echo 0))) ;; esac
    done
    echo "$n"
}

# ERE «домен из файла или его поддомен» (list-rutld.txt, list-noauto.txt); пусто — нет
zapret_zone_re() {
    local z
    z=$(sed 's/#.*//' "$@" 2>/dev/null | tr -d ' \r' | tr 'A-Z' 'a-z' | grep -E '^[a-z0-9.-]+$' | \
        sed 's/\./\\./g' | tr '\n' '|')
    # "|" в кавычках: в mksh голый | в шаблоне — «или», хвост не срезался, и
    # пустая альтернатива «…|)$» роняла awk телефона (illegal primary, ревью 3.20.2)
    z="${z%"|"}"
    [ -n "$z" ] && echo "(^|\\.)($z)\$"
}

# .ru/.su/.рф-сайты и сайты Google (list-noauto), которые явно есть во
# встроенном или своём списке — им обход нужен (заблокированные СМИ, YouTube);
# файл переписывается только при изменении
zapret_ru_listed() {   # [встроенный список]: у nfqws2 — его user.list, а не list-default
    local re
    re=$(zapret_zone_re "$ZAPRET_LIST_RUTLD" "$ZAPRET_LIST_NOAUTO")
    [ -n "$re" ] || re='^$'
    { sed 's/#.*//' "${1:-$ZAPRET_LIST_DEFAULT}"; sed 's/#.*//' "$ZAPRET_LIST_USER" 2>/dev/null; } | \
        tr -d ' \r' | tr 'A-Z' 'a-z' | grep -E "$re" | sort -u > "$ZAPRET_RU_RUN.new"
    if cmp -s "$ZAPRET_RU_RUN.new" "$ZAPRET_RU_RUN"; then rm -f "$ZAPRET_RU_RUN.new"; else mv -f "$ZAPRET_RU_RUN.new" "$ZAPRET_RU_RUN"; fi
}
# российские зоны и Google из автосписка — вон (попадали туда по случайным обрывам)
zapret_auto_clean_ru() {
    local n re
    [ -s "$ZAPRET_LIST_AUTO" ] || return 0
    re=$(zapret_zone_re "$ZAPRET_LIST_RUTLD" "$ZAPRET_LIST_NOAUTO")
    [ -n "$re" ] || return 0
    n=$(grep -cE "$re" "$ZAPRET_LIST_AUTO")
    [ "${n:-0}" -gt 0 ] || return 0
    grep -vE "$re" "$ZAPRET_LIST_AUTO" > "$ZAPRET_LIST_AUTO.tmp"
    cat "$ZAPRET_LIST_AUTO.tmp" > "$ZAPRET_LIST_AUTO"; rm -f "$ZAPRET_LIST_AUTO.tmp"
    log "zapret: из автосписка убраны российские сайты и Google ($n): их обход сам не берёт"
}

# Автосписок только растёт: сайт попадает туда после 3 случайных обрывов и
# остаётся навсегда (29.10: 194 записи — Google, Авито, телеметрия). nfqws
# даты не пишет — первое появление помним сами (ZAPRET_AUTO_SEEN); старше
# ZAPRET_AUTO_DAYS — вон. Файл тот же (cat, не mv): nfqws его перечитывает
zapret_auto_age() {
    local now n
    [ -f "$ZAPRET_LIST_AUTO" ] || return 0
    now=$(date +%s)
    # часы ещё не выставлены (загрузка без сети и RTC): новые записи получили
    # бы дату ~1970 и все разом ушли бы, когда время придёт — ждём (ревью 3.20.2)
    [ "${now:-0}" -gt 1767225600 ] || return 0
    # новые записи — с текущим временем; ушедшие из автосписка — из учёта
    touch "$ZAPRET_AUTO_SEEN"; chmod 600 "$ZAPRET_AUTO_SEEN"
    awk -v now="$now" 'FILENAME == ARGV[1] { if ($2 ~ /^[0-9]+$/) t[$1] = $2; next }
        NF && $1 !~ /^#/ && !s[$1]++ { print $1, (($1 in t) ? t[$1] : now) }' \
        "$ZAPRET_AUTO_SEEN" "$ZAPRET_LIST_AUTO" > "$ZAPRET_AUTO_SEEN.tmp" || { rm -f "$ZAPRET_AUTO_SEEN.tmp"; return 0; }
    n=$(awk -v lim=$((now - ZAPRET_AUTO_DAYS * 86400)) '$2 < lim' "$ZAPRET_AUTO_SEEN.tmp" | grep -c .)
    if [ "${n:-0}" -gt 0 ]; then
        awk -v lim=$((now - ZAPRET_AUTO_DAYS * 86400)) 'FILENAME == ARGV[1] { if ($2 < lim) old[$1] = 1; next }
            !($1 in old)' "$ZAPRET_AUTO_SEEN.tmp" "$ZAPRET_LIST_AUTO" > "$ZAPRET_LIST_AUTO.tmp" && \
            cat "$ZAPRET_LIST_AUTO.tmp" > "$ZAPRET_LIST_AUTO"
        awk -v lim=$((now - ZAPRET_AUTO_DAYS * 86400)) '$2 >= lim' "$ZAPRET_AUTO_SEEN.tmp" > "$ZAPRET_AUTO_SEEN.tmp2" && \
            mv -f "$ZAPRET_AUTO_SEEN.tmp2" "$ZAPRET_AUTO_SEEN.tmp"
        rm -f "$ZAPRET_LIST_AUTO.tmp"
        log "zapret: из автосписка убраны записи старше $ZAPRET_AUTO_DAYS дн. ($n) — заблокированные nfqws добавит снова"
    fi
    # 600 до mv — файл ни на миг не 644 (umask 022); без изменений не пишем:
    # зовётся раз в ~30 с, а записи меняются раз в часы
    chmod 600 "$ZAPRET_AUTO_SEEN.tmp"
    if cmp -s "$ZAPRET_AUTO_SEEN.tmp" "$ZAPRET_AUTO_SEEN"; then rm -f "$ZAPRET_AUTO_SEEN.tmp"; else mv -f "$ZAPRET_AUTO_SEEN.tmp" "$ZAPRET_AUTO_SEEN"; fi
}

# журнал причин автосписка — не больше ~256 КБ (nfqws открывает файл на каждую
# запись, так что обрезать можно на ходу; тот же inode — cat, а не mv)
zapret_auto_log_trim() {
    local s
    s=$(wc -c < "$ZAPRET_AUTO_LOG" 2>/dev/null) || return 0
    [ "${s:-0}" -gt 262144 ] || return 0
    tail -n 1500 "$ZAPRET_AUTO_LOG" > "$ZAPRET_AUTO_LOG.tmp" && cat "$ZAPRET_AUTO_LOG.tmp" > "$ZAPRET_AUTO_LOG"
    rm -f "$ZAPRET_AUTO_LOG.tmp"
}
# лог nfqws — тоже: «rawsend: bind (ignoring)» на каждый подставной пакет
# раздачи (лог 4PDA 26.10) рос бы до перезапуска. Открыт с >> (O_APPEND) —
# обрезка на ходу безопасна
zapret_nfqws_log_trim() {
    local s
    s=$(wc -c < "$ZAPRET_LOG" 2>/dev/null) || return 0
    [ "${s:-0}" -gt 524288 ] || return 0
    tail -n 200 "$ZAPRET_LOG" > "$ZAPRET_LOG.tmp" && cat "$ZAPRET_LOG.tmp" > "$ZAPRET_LOG"
    rm -f "$ZAPRET_LOG.tmp"
}

# DoH/DoT-серверы из настроек для обхода (DNS_VIA_ZAPRET): «имена|адреса|порты|имена без обхода»,
# каждое через запятую. Имя из URL — dns_hosts_of (lib/dns.sh); порт — из URL, иначе 443 у https:// и 853 у
# tls://. Адреса — серверы, заданные адресом, и запасной bootstrap DoH (DNS_BOOTSTRAP_ENC)
# DoH, которые обход ломает: любой fake доходит до сервера и рвёт TLS (09.11, YOTA: LibreDNS
# напрямую 3/3, через обход 0/3 с md5sig и badseq; без fake открывается, но без fake не
# открывается dns.zapret.moe). Им — пустой профиль первым: соединение идёт как есть.
# tamaev-gifts.xyz — так же (12.11, YOTA: через обход 0/5, напрямую 5/5 за 0,1–0,25 с); dns.dagami.ru — так же
# (09.11 и 18.11, YOTA: через обход 0 из 8 имён, напрямую 4–5 из 8 с прокси). С новым приёмом профиля (нулевая
# подделка, 18.11 стенд t41): LibreDNS 4/6 против 6/6 без приёмов — по-прежнему «как есть»; dagami стенд на curl не
# меряет (по HTTP/1.1 молчит и без приёмов, отвечает только dnsproxy по HTTP/2) — оставлен «как есть»
ZAPRET_DOH_ASIS="doh.libredns.gr tamaev-gifts.xyz dns.dagami.ru"
zapret_doh_targets() {
    local u h hp p n="" i="" ps="" x=""
    for u in $DNS_UPSTREAMS $DNS_FALLBACKS $DNS_GEO_UPSTREAMS $DNS_META_UPSTREAMS $DNS_BOOTSTRAP_ENC; do
        case "$u" in https://*) p=443 ;; tls://*) p=853 ;; *) continue ;; esac
        h=$(dns_hosts_of "$u")
        hp=${u#*://}; hp=${hp%%/*}
        case "$hp" in *:[0-9]*) p=${hp##*:} ;; esac
        case "$h" in '') continue ;; esac
        ps="$ps $p"
        case " $ZAPRET_DOH_ASIS " in *" $h "*) x="$x $h"; continue ;; esac
        case "$h" in *[!0-9.]*) n="$n $h" ;; *) i="$i $h" ;; esac
    done
    # без повторов, через запятую
    _zdt_j() { echo "$@" | tr ' ' '\n' | awk 'NF && !s[$0]++' | tr '\n' ',' | sed 's/,$//'; }
    # shellcheck disable=SC2086
    printf '%s|%s|%s|%s\n' "$(_zdt_j $n)" "$(_zdt_j $i)" "$(_zdt_j $ps)" "$(_zdt_j $x)"
}

# --- движок nfqws2 (ZAPRET_ENGINE=nfqws2): zapret2, стратегии nfqws2-android ---------------
# Стратегия — файл zapret2/strategies/<ZAPRET2_STRATEGY>.conf в формате nfqws2-android v3.0.0
# (авторы — strategies/meta.tsv, файлы — zapret2/SOURCE.txt). Из него берутся только приёмы: основа
# (Lua, подделки), TCP, QUIC, UDP и свои профили стратегии. Порты, режимы, списки, исключения и
# профили DoH — наши. Свои: --uid=0:$ZAPRET_GID (по группе правила пропускают его собственные
# пакеты — метку на rmnet стирает qcom_qos_reset), --bind-fix, список «мимо обхода» (банки,
# Госуслуги), свой список сайтов из WebUI. Порты и лимит пакетов у всех стратегий выпуска одни
ZAPRET2_TP="80,443,1984,2053,2083,2087,2096,5222,8443"
ZAPRET2_UP="443,590:600,1400,3478:3481,5349,19294:19344,49152:65535"
# Первые пакеты соединения в nfqws2: исходящие — 40, ответы — 15 (у nfqws2-android обе 15: PKT_LIMIT_OUT/IN).
# 17.11, 13T, YOTA: до первых данных от сервера телефон отправил 14 пакетов (SYN, ACK, 2 поддельных SYN-ACK,
# 2 подделки, 8 кусков разреза) — повтор потерянного ClientHello (метро, слабый Wi-Fi) уходил 15-м и дальше
# мимо nfqws2 целиком, с открытым именем: ТСПУ резал соединение и, похоже, копил штраф до волны Google.
# Тот же урок у nfqws1 — 08.11 (9 -> 20, ZAPRET_CB_OUT)
ZAPRET2_PKT=40
ZAPRET2_PKT_IN=15
# Каким движком запускать: nfqws2 — если выбран, есть бинарник и Lua; иначе прежний nfqws1.
# Ядро без connbytes — тоже nfqws2, в упрощённом режиме, как у nfqws1: в очередь весь исходящий TCP, кроме
# порта 80 и пустых ACK (zapret2_rules), приёмы — на первых 20 перехваченных пакетах (zapret2_args): пустые ACK в счёт
# не идут, так что это примерно connbytes 1:40, где считаются все исходящие (ревью 18.11).
# 17.11 стенд cbbench: на пакет nfqws2 не дороже nfqws1 — 13T ~47 мкс против ~66, Redmi 4X (3.18) 120–160 против 200–240
ZAPRET2_FAIL=0     # nfqws2 не запустился — до выключения обхода работаю на nfqws1
zapret_engine() {
    [ "$ZAPRET2_FAIL" != 1 ] && [ "$ZAPRET_ENGINE" = nfqws2 ] && [ -n "$NFQWS2_BIN" ] && [ -f "$ZAPRET2_DIR/lua/zapret-lib.lua" ] && \
        { echo nfqws2; return 0; }
    echo nfqws1
}
# Файл выбранной стратегии; нет такого — vt_soft_crck
zapret2_strat_file() {
    local f="$ZAPRET2_DIR/strategies/${ZAPRET2_EFF:-${ZAPRET2_STRATEGY:-vt_soft_crck}}.conf"
    [ -f "$f" ] || f="$ZAPRET2_DIR/strategies/vt_soft_crck.conf"
    echo "$f"
}
# Приёмы стратегии одним чтением файла -> Z2_BASE, Z2_CUSTOM, Z2_UDP, Z2_QUIC, Z2_TCP, Z2_SYN (каждый одной
# строкой). Файл — модуля (формат nfqws2-android: присваивания с $LUA_DIR/$BLOBS_DIR/$LISTS_DIR),
# читается в подоболочке. NFQWS_ARGS_SYN — наше: приёмы на SYN клиента (у vt_soft_crck — synack), профилем последним
zapret2_strat_load() {   # файл
    local _o
    _o=$(
        LUA_DIR="$ZAPRET2_DIR/lua"; BLOBS_DIR="$ZAPRET2_DIR/blobs"; LISTS_DIR="$ZAPRET2_DIR/lists"; LOG_DIR=/dev/null
        . "$1" >/dev/null 2>&1
        for _v in NFQWS_BASE_ARGS NFQWS_ARGS_CUSTOM NFQWS_ARGS_UDP NFQWS_ARGS_QUIC NFQWS_ARGS NFQWS_ARGS_SYN; do
            eval "printf '%s' \"\$$_v\"" | tr '\n\t' '  ' | tr -s ' '
            echo
        done
    )
    { read -r Z2_BASE; read -r Z2_CUSTOM; read -r Z2_UDP; read -r Z2_QUIC; read -r Z2_TCP; read -r Z2_SYN; } <<EOF
$_o
EOF
    # имя в подделке — из конфига (ZAPRET2_FAKE_SNI), у всех стратегий одно и для демона, и для подбора. Только общий
    # профиль (сайты, API YouTube): свои профили стратегий (Google, YouTube, Discord у alt*, видео у vt_soft_crck) авторы
    # делали с подделкой Google под адреса Google — имя .рф там ТСПУ видел бы на адресе Google (ревью 18.11)
    [ -n "$ZAPRET2_FAKE_SNI" ] && Z2_TCP=$(zapret2_fake_sni "$Z2_TCP")
    # hostfakesplit_alt — из zapret-smart.lua, а alt13 и eduncey его не подключают: nfqws2 не
    # запускался («desync function 'hostfakesplit_alt' does not exist», подбор 13.11 на YOTA).
    # Файл при загрузке только объявляет функции и таблицы — умный режим сам не включается
    case "$Z2_BASE" in *zapret-smart.lua*) ;; *)
        case "$Z2_CUSTOM $Z2_UDP $Z2_QUIC $Z2_TCP" in *hostfakesplit_alt*) Z2_BASE="$Z2_BASE --lua-init=@$ZAPRET2_DIR/lua/zapret-smart.lua" ;; esac ;;
    esac
}
# Для WebUI (status zapret2_gfake): имя в подделке Google общего профиля действующей стратегии — то, что заменит
# ZAPRET2_FAKE_SNI; «-» — такой подделки нет, имя ставить некуда. zapret2_ts: 1 — есть подделки со сдвигом tcp_ts=N (им нужны метки
# времени TCP у клиента; у Windows их нет — WebUI показывает команду netsh), 0 — нет. Считается при смене стратегии (не на каждый статус) —
# в основном процессе, не в $(…): иначе запомненное терялось бы. Список в WebUI устаревал бы с обновлением стратегий
Z2_GF_KEY=""; Z2_GF=""; Z2_TS=""
zapret2_gfake_upd() {
    local f k r
    f=$(zapret2_strat_file); k="$f|$ZAPRET2_ARGS"
    [ "$k" = "$Z2_GF_KEY" ] && return 0
    # имя — родное, из файла: без подстановки ZAPRET2_FAKE_SNI (в подоболочке; ревью 18.11 — показывалось выбранное)
    r=$(
        ZAPRET2_FAKE_SNI=""
        zapret2_strat_load "$f"; t="$Z2_TCP"; [ -n "$ZAPRET2_ARGS" ] && t="$ZAPRET2_ARGS"
        # Подделки, которые держатся на сдвиге метки времени (tcp_ts=N), в любом профиле: у клиента без меток
        # (Windows) сдвигать нечего, fool_nots заменяет его на badseq+badack, но хуже (стенд 12.11, hardcorp74:
        # без меток 64 из 72 сайтов, с метками — 71). tcp_ts_up (поднять метку, если есть) — не в счёт: он лишь
        # дополняет плохой ack, а без метки fool_nots добавляет и плохой seq — замены хватает (у vt_soft_crck
        # так видеопрофиль; Kubarev 18.11: подсказка при vt_soft_crck лишняя)
        ts=0; printf '%s\n' "$Z2_CUSTOM $t $Z2_SYN" | tr ' ' '\n' | \
            grep -E '^--lua-desync=(fake|hostfakesplit|hostfakesplit_alt|fakedsplit|fakeddisorder):' | grep -qE 'tcp_ts=' && ts=1
        case "$t" in *fake:blob=tls_google*)
            n=$(printf '%s\n' "$t" | tr ' ' '\n' | grep 'fake:blob=tls_google' | grep -oE 'sni=[^:,]+' | head -1); n=${n#sni=} ;;
            *) n=- ;; esac
        echo "${n:-www.google.com} $ts"
    )
    set -- $r
    # не разобрали — не запоминаем: следующий статус попробует снова, а не «не знаю» до смены стратегии
    [ -n "$2" ] || { Z2_GF=""; Z2_TS=""; return 0; }
    Z2_GF_KEY="$k"; Z2_GF="$1"; Z2_TS="$2"
}
# ZAPRET2_FAKE_SNI: у подделок blob=tls_google (поддельный ClientHello www.google.com) имя — из конфига:
# есть tls_mod с sni= — меняем его, есть tls_mod без sni — дописываем, нет — ставим tls_mod=sni=<имя>.
# Подделки из других файлов и нулей (видео) не трогаем
zapret2_fake_sni() {   # приёмы
    printf '%s\n' "$1" | awk -v n="$ZAPRET2_FAKE_SNI" '{
        for (i = 1; i <= NF; i++) {
            t = $i
            if (t ~ /^--lua-desync=fake:blob=tls_google(:|$)/) {
                c = split(t, f, ":"); o = ""; m = 0
                for (j = 1; j <= c; j++) {
                    if (f[j] ~ /^tls_mod=/) {
                        m = 1
                        if (f[j] ~ /(=|,)sni=/) sub(/sni=[^,]*/, "sni=" n, f[j]); else f[j] = f[j] ",sni=" n
                    }
                    o = o (j > 1 ? ":" : "") f[j]
                }
                if (!m) sub(/blob=tls_google/, "blob=tls_google:tls_mod=sni=" n, o)
                t = o
            }
            printf "%s%s", (i > 1 ? " " : ""), t
        }
        print ""
    }'
}
# Наше (исключения, списки, адреса) — к каждому профилю стратегии: у z2r_rocket в TCP их три через
# --new, и дописанное в конец строки досталось бы только последнему — первые два шли бы на все
# сайты, банки из «мимо обхода» тоже (ревью 13.11)
zapret2_add() {   # ПРОФИЛИ ДОБАВКА
    [ -n "$1" ] || return 0
    echo "$1" | sed "s# --new # $2 --new #g; s#\$# $2#"
}
# Для подбора (scan.sh): стратегия ко всем сайтам набора — её основа, свои профили и TCP, без
# наших списков; fool_nots — как у демона
zapret2_scan_args() {   # имя очередь
    zapret2_strat_load "$ZAPRET2_DIR/strategies/$1.conf"
    echo "--qnum=$2 --uid=0:3998 --bind-fix4 $Z2_BASE --lua-init=@$ZAPRET2_DIR/lua/vpn-tether.lua ${Z2_CUSTOM:+$Z2_CUSTOM --new }$Z2_TCP${Z2_SYN:+ --new --filter-tcp=443 $Z2_SYN}" | zapret2_fool
}
# Для «Проверить QUIC» (scan.sh quic) у nfqws2: основа стратегии и её профиль QUIC
zapret2_scan_quic_args() {   # имя очередь
    zapret2_strat_load "$ZAPRET2_DIR/strategies/$1.conf"
    [ -n "$Z2_QUIC" ] || return 1
    echo "--qnum=$2 --uid=0:3998 --bind-fix4 $Z2_BASE --lua-init=@$ZAPRET2_DIR/lua/vpn-tether.lua $Z2_QUIC"
}
# Стратегия сайтам со своей стратегией (ZAPRET_ALT) — одна у демона (zapret2_alt_profiles) и у подбора
# (zapret2_scan_site_args): TLS-приёмы её TCP на порт 443, без её своих профилей (googlevideo у vt_soft_crck) и UDP.
# Со своими списками или несколькими профилями в TCP (z2r_rocket) — нет: список сайтов дописался бы к
# их спискам. -> Z2_SITE (и Z2_BASE от zapret2_strat_load); 1 — сайтам не годится
zapret2_site_tcp() {   # имя
    case "$1" in ''|*[!A-Za-z0-9_]*) return 1 ;; esac
    [ -f "$ZAPRET2_DIR/strategies/$1.conf" ] || return 1
    zapret2_strat_load "$ZAPRET2_DIR/strategies/$1.conf"
    case "$Z2_TCP" in *[!\ ]*) ;; *) return 1 ;; esac
    case " $Z2_TCP " in *" --new "*|*--hostlist*|*--ipset*) return 1 ;; esac
    Z2_SITE=$(echo "$Z2_TCP" | sed 's/--filter-tcp=[^ ]*/--filter-tcp=443/g; s/--filter-l7=[^ ]*/--filter-l7=tls/g')
}
# Для подбора сайтов (scan.sh sites): кандидат — ровно тем профилем, что демон потом даст сайтам
# (ревью 15.11: мерили со всеми профилями стратегии — сайт мог открыться тем, чего демон ему не даёт)
# Приёмы на SYN (synack) — от основной стратегии сети (третий аргумент): у демона её профиль SYN последним
# достаётся всем соединениям, в том числе сайтам со своей стратегией (ревью 17.11)
zapret2_scan_site_args() {   # имя очередь [основная_стратегия]
    local syn=""
    if [ -n "$3" ] && [ -f "$ZAPRET2_DIR/strategies/$3.conf" ]; then
        zapret2_strat_load "$ZAPRET2_DIR/strategies/$3.conf"; syn="$Z2_SYN"
    fi
    zapret2_site_tcp "$1" || return 1
    echo "--qnum=$2 --uid=0:3998 --bind-fix4 $Z2_BASE --lua-init=@$ZAPRET2_DIR/lua/vpn-tether.lua $Z2_SITE${syn:+ --new --filter-tcp=443 $syn}" | zapret2_fool
}
# Подделка, которую берут приёмы сайтов, а в основе nfqws2 она под тем же именем, но другая
# (--blob=имя:… первым объявлением выигрывает) -> её имя; нет — пусто
zapret2_blob_clash() {   # основа основа_стратегии приёмы
    printf '%s\n%s\n%s\n' "$1" "$2" "$3" | awk '
        function nm(t) { t = substr(t, 8); sub(/:.*/, "", t); return t }
        NR == 1 { for (i = 1; i <= NF; i++) if ($i ~ /^--blob=/ && !(nm($i) in v)) v[nm($i)] = $i; next }
        NR == 2 { for (i = 1; i <= NF; i++) if ($i ~ /^--blob=/ && (nm($i) in v) && v[nm($i)] != $i) c[nm($i)] = 1; next }
        { for (b in c) if (match($0, "=" b "([: ]|$)")) { print b; exit } }'
}
# Подделкам, которые держатся на метке времени TCP (tcp_ts, tcp_ts_up), — свои обманки из
# vpn-tether.lua: у соединения без метки (Windows-клиенты раздачи) tcp_ts ничего не делает и
# подделка доходит до сервера как настоящая; тогда badseq+badack (с badsum — только badack).
# С меткой ничего не меняется. Только функции, где обманки идут лишь на подделки (fake,
# hostfakesplit и hostfakesplit_alt, fakedsplit, fakeddisorder); у multisplit/multidisorder они
# легли бы на настоящие сегменты. Уже со сдвигом seq или своим fool= — не трогаем. Стенд 12.11 (hardcorp74, YOTA):
# без меток 69 из 72 против 30, с метками 70 против 68
zapret2_fool() {
    awk '{
        for (i = 1; i <= NF; i++) {
            t = $i
            if (t ~ /^--lua-desync=(fake|hostfakesplit|hostfakesplit_alt|fakedsplit|fakeddisorder):/ && t ~ /tcp_ts(=|_up)/) {
                if (t ~ /tcp_seq=/ || t ~ /:fool=/) { } else if (t ~ /:badsum/) t = t ":fool=fool_nots_ack"; else t = t ":fool=fool_nots"
            }
            printf "%s%s", (i > 1 ? " " : ""), t
        }
        print ""
    }'
}
# ip_autottl подделок — не дальше 5 хопов (для профиля кэшей оператора в zapret2_args)
zapret2_ttlcap() {
    awk '{
        for (i = 1; i <= NF; i++) {
            t = $i
            if (t ~ /^--lua-desync=/ && match(t, /:ip_autottl=-?[0-9]+,[0-9]+-[0-9]+/)) {
                s = RSTART; l = RLENGTH; a = substr(t, s, l)
                match(a, /,[0-9]+-/); lo = substr(a, RSTART + 1, RLENGTH - 2) + 0
                match(a, /-[0-9]+$/); hi = substr(a, RSTART + 1) + 0
                if (hi > 5 && lo <= 5) t = substr(t, 1, s - 1) substr(a, 1, RSTART) "5" substr(t, s + l)
            }
            printf "%s%s", (i > 1 ? " " : ""), t
        }
        print ""
    }'
}
# Сайты со своей стратегией у nfqws2 (ZAPRET_ALT; записи «z2:<стратегия>» в ZALT_FILE пишет scan.sh
# sites) — как zapret_alt_profiles у nfqws1: до 3 стратегий, по профилю на каждую со своим списком
# сайтов (файлы ZALT_RUN.1..3; nfqws2 сам перечитывает их при изменении). Профиль — zapret2_site_tcp;
# основа стратегии (Lua, подделки) — к основе nfqws2, кроме уже объявленных подделок с тем же именем.
# Разные файлы под одним именем бывали только у UDP (discord_udp, stun_fake — приёмам TCP не нужны);
# если такая подделка нужна приёмам сайтов — стратегию пропускаем с записью в лог (её приёмы взяли бы
# чужую подделку). -> Z2_ALT_P (профили через --new), Z2_ALT_BASE; без подоболочки —
# zapret2_strat_load меняет Z2_*, их zapret2_args к этому времени уже разобрал
zapret2_alt_profiles() {   # «мимо обхода» основа
    local ex="$1" i=0 s n f c w="" nre
    Z2_ALT_P=""; Z2_ALT_BASE=""
    if [ "$ZAPRET_ALT" = "1" ] && [ "$ZAPRET_PER_NET" = "1" ] && [ -n "$NET_KEY" ] && [ -f "$ZALT_FILE" ]; then
        nre=$(zapret_zone_re "$ZAPRET_LIST_NOAUTO")
        K="$NET_KEY" L="$NET_LABEL" awk -F'|' '
            $4 !~ /^z2:/ { next }
            $1 == ENVIRON["K"] { k[++nk] = $4 "|" $3 }
            ENVIRON["L"] != "" && $2 == ENVIRON["L"] { l[++nl] = $4 "|" $3 }
            END { if (nk) { for (i = 1; i <= nk; i++) print k[i] } else for (i = 1; i <= nl; i++) print l[i] }' \
            "$ZALT_FILE" 2>/dev/null > "$ZALT_RUN.lst"
        for s in $(cut -d'|' -f1 "$ZALT_RUN.lst" | awk '!x[$0]++'); do
            [ "$i" -lt 3 ] || break
            n=${s#z2:}
            zapret2_site_tcp "$n" || continue
            c=$(zapret2_blob_clash "$2$Z2_ALT_BASE" "$Z2_BASE" "$Z2_SITE")
            [ -n "$c" ] && { w="$w $n ($c)"; continue; }
            f="$ZALT_RUN.$((i + 1))"
            # Google (list-noauto) — только сайты из списков (ZAPRET_RU_RUN), как у nfqws1
            A="$s" R="$nre" KS=" $(tr '\n' ' ' < "$ZAPRET_RU_RUN" 2>/dev/null) " awk -F'|' '
                $1 == ENVIRON["A"] && $2 ~ /^[a-z0-9.-]+$/ &&
                (ENVIRON["R"] == "" || $2 !~ ENVIRON["R"] || index(ENVIRON["KS"], " " $2 " ")) { print $2 }' \
                "$ZALT_RUN.lst" | sort -u > "$f.new"
            [ -s "$f.new" ] || { rm -f "$f.new"; continue; }
            if cmp -s "$f.new" "$f"; then rm -f "$f.new"; else mv -f "$f.new" "$f"; fi
            i=$((i + 1))
            Z2_ALT_P="${Z2_ALT_P:+$Z2_ALT_P --new }$(zapret2_add "$Z2_SITE" "$ex --hostlist=$f")"
            Z2_ALT_BASE="$Z2_ALT_BASE $Z2_BASE"
        done
    fi
    while [ $((i + 1)) -le 3 ]; do i=$((i + 1)); rm -f "$ZALT_RUN.$i"; done
    # zapret2_args зовут в подоболочке раз в такт пересчёта — в лог только при перемене
    if [ "$w" != "$(cat "$ZALT_RUN.warn" 2>/dev/null)" ]; then
        if [ -n "$w" ]; then
            log "WARNING: zapret: nfqws2 — стратегия сайтов пропущена:$w — под этим именем в основе другая подделка"
            echo "$w" > "$ZALT_RUN.warn"
        else
            rm -f "$ZALT_RUN.warn"
        fi
    fi
}
# основа + основа стратегий сайтов: повторы — мимо, подделка с уже объявленным именем — мимо
zapret2_base_merge() {   # основа добавка
    printf '%s %s\n' "$1" "$2" | awk '{
        for (i = 1; i <= NF; i++) {
            t = $i
            if (t in seen) continue
            if (t ~ /^--blob=/) { b = substr(t, 8); sub(/:.*/, "", b); if (b in blob) continue; blob[b] = 1 }
            if (t ~ /^--lua-gc/) { if (gc) continue; gc = 1 }
            seen[t] = 1; o = o (o == "" ? "" : " ") t
        }
        print o
    }'
}
# Приёмы стратегии для видео — к профилю малого окна (YT_WSSIZE_RAMP): её профиль googlevideo из своих
# (у vt_soft_crck), иначе первый профиль TLS; без фильтров выбора (порт, протокол, списки): профиль выбирается по
# адресу стойки ещё на SYN. Без --payload в начале — tls_client_hello: после vt_wssize_ramp стоит
# --payload=all, и приёмы легли бы на каждый пакет
zapret2_ramp_techs() {   # свои_профили профиль_TLS
    printf '%s\n%s\n' "$1" "$2" | awk '
        { n = split($0, seg, / --new /); for (i = 1; i <= n; i++) s[++m] = seg[i]; if (NR == 1) nc = m }
        END {
            p = ""
            for (i = 1; i <= nc; i++) if (s[i] ~ /googlevideo/) { p = s[i]; break }
            if (p == "") p = s[nc + 1]
            k = split(p, t, " "); o = ""
            for (j = 1; j <= k; j++) if (t[j] !~ /^--(filter-|hostlist|ipset|name=)/) o = o (o == "" ? "" : " ") t[j]
            if (o !~ /^--payload=/) o = "--payload=tls_client_hello " o
            print o
        }'
}
zapret2_args() {
    local L="$ZAPRET2_DIR/lua" B="$ZAPRET2_DIR/blobs" S="$ZAPRET2_DIR/lists" ex="" us="" f base custom udp quic tcp syn tcpt extra ipset P=""
    grep -q '[a-z0-9]' "$ZAPRET_LIST_EXCL" 2>/dev/null && ex="--hostlist-exclude=$ZAPRET_LIST_EXCL"
    grep -q '[a-z0-9]' "$ZAPRET_LIST_USER" 2>/dev/null && us="--hostlist=$ZAPRET_LIST_USER"
    f=$(zapret2_strat_file)
    zapret2_strat_load "$f"
    # основа стратегии + свои: vpn-tether.lua (fool_nots) и подделка vt_tls для профилей DoH (своё
    # имя: у чужой стратегии tls_clienthello может не быть или быть другим файлом)
    base="$Z2_BASE --lua-init=@$L/vpn-tether.lua --blob=vt_tls:@$B/tls_clienthello.bin"
    custom="$Z2_CUSTOM"; udp="$Z2_UDP"; quic="$Z2_QUIC"; tcp="$Z2_TCP"; syn="$Z2_SYN"
    # свои приёмы TCP (ZAPRET2_ARGS) — вместо приёмов стратегии; её подделки и Lua остаются
    [ -n "$ZAPRET2_ARGS" ] && tcp="--filter-tcp=443,80,1984,5222 --filter-l7=http,tls $ZAPRET2_ARGS"
    # имя в подделке (ZAPRET2_FAKE_SNI) — и в своих приёмах: выбранное в WebUI действует на всё
    [ -n "$ZAPRET2_ARGS" ] && [ -n "$ZAPRET2_FAKE_SNI" ] && tcp=$(zapret2_fake_sni "$tcp")
    # hostfakesplit_alt в своих приёмах — zapret-smart.lua, как в zapret2_strat_load для файла
    case "$base" in *zapret-smart.lua*) ;; *) case "$ZAPRET2_ARGS" in *hostfakesplit_alt*) base="$base --lua-init=@$L/zapret-smart.lua" ;; esac ;; esac
    # «мимо обхода» — в каждый профиль по именам
    custom=$(zapret2_add "$custom" "$ex")
    quic=$(zapret2_add "$quic" "$ex")
    tcp=$(zapret2_add "$tcp" "$ex")
    # только TLS — для адресов (ipset) и «всех сайтов»: те же приёмы, без порта 80 и HTTP;
    # HTTP-обход — только сайтам из списков, как у nfqws1 (тот порт 80 не трогал вовсе). Сняли 12.11,
    # пока у Windows-клиентов раздачи HTTP к адресам ipset (Akamai, Cloudflare, Google) приходил
    # испорченным — «нет интернета» (msftconnecttest — 400), падала проверка отзыва сертификата
    # (OCSP по HTTP). Причину с тех пор лечит fool_nots; вернуть — только после замера
    tcpt=$(echo "$tcp" | sed 's/--filter-tcp=[^ ]*/--filter-tcp=443,1984,5222/g; s/--filter-l7=[^ ]*/--filter-l7=tls/g')
    # .ru/.su/.рф и Google (list-noauto) — как у nfqws1: профиль по именам их не трогает и в автосписок
    # не берёт; такие сайты из списков (user.list nfqws2 и свой) — своим профилем перед ним. Google
    # (Play, YouTube) это не задевает: его адреса — в ipset.list, а профиль по адресам идёт раньше
    local rux="" ruh=""
    if grep -q '^[a-z]' "$ZAPRET_LIST_RUTLD" "$ZAPRET_LIST_NOAUTO" 2>/dev/null; then
        grep -q '^[a-z]' "$ZAPRET_LIST_RUTLD" 2>/dev/null && rux="--hostlist-exclude=$ZAPRET_LIST_RUTLD"
        grep -q '^[a-z]' "$ZAPRET_LIST_NOAUTO" 2>/dev/null && rux="$rux --hostlist-exclude=$ZAPRET_LIST_NOAUTO"
        zapret_ru_listed "$S/user.list"
        # exclude.list nfqws2 — и здесь: в zru googleapis.com с поддоменами, а там fcm/gcm (push)
        [ -s "$ZAPRET_RU_RUN" ] && ruh="--hostlist=$ZAPRET_RU_RUN --hostlist-exclude=$S/exclude.list"
    fi
    # ZAPRET_MODE: list — списки nfqws2 и свой + автосписок (MODE_AUTO nfqws2-android) с нашим
    # порогом. all — как у nfqws1: все сайты только по TLS; QUIC и HTTP (порт 80) — по спискам, как
    # в list. Без автосписка: профиль с ним забирает себе все сайты (следит за обрывами), и до
    # профиля «все сайты» после него дело бы не дошло
    if [ "$ZAPRET_MODE" = "all" ]; then
        extra="--hostlist=$S/user.list $us --hostlist-exclude=$S/exclude.list $rux"
    else
        extra="--hostlist=$S/user.list $us --hostlist-auto=$ZAPRET_LIST_AUTO --hostlist-auto-fail-threshold=$ZAPRET_AUTO_FAIL --hostlist-auto-debug=$ZAPRET_AUTO_LOG --hostlist-exclude=$S/exclude.list $rux"
    fi
    ipset="--ipset=$S/ipset.list --ipset-exclude=$S/ipset_exclude.list --ipset-ip=0.0.0.0"
    # профили — через --new; пустой (у стратегии нет UDP или QUIC) пропускаем
    _z2p() { [ -n "$1" ] && P="${P:+$P --new }$1"; }
    # Малое окно молчащим стойкам (YT_WSSIZE_RAMP, yt_ramp_hit) — первым: профиль по адресу выбирается на
    # SYN, а без фильтров протокола и имени он же остаётся за соединением при пересмотре (протокол, имя).
    # В файле всегда есть 0.0.0.0/32: пустой список у nfqws2 — «любой адрес»
    if [ "$YT_WSSIZE_RAMP" = "1" ] && [ "$YT_DEAD_FAILFAST" = "1" ]; then
        grep -q '^0\.0\.0\.0/32$' "$YT_RAMP_RUN" 2>/dev/null || echo 0.0.0.0/32 >> "$YT_RAMP_RUN"
        _z2p "--filter-tcp=443 --ipset=$YT_RAMP_RUN --out-range=a --payload=all --lua-desync=vt_wssize_ramp:wsize=1:scale=1 $(zapret2_ramp_techs "$custom" "$tcpt")"
    fi
    # DoH через обход (DNS_VIA_ZAPRET): свои профили первыми; «как есть» (ZAPRET_DOH_ASIS) — пустой профиль.
    # Приём — как у видеопрофиля vt_soft_crck: 2 нулевые подделки с плохим ack и разрез посередине имени. 18.11 YOTA
    # режет по имени cloudflare-dns.com и dns.zapret.moe; стенд t40 (своя копия nfqws2, по 6 запросов): прежний
    # (подделка vt_tls с md5 + multidisorder midsld) — 0/6 и 0/6, этот — 6/6 и 6/6 (0,28 и 0,52 с); так же открывали
    # общий профиль vt_soft_crck (с synack и без) и fakedsplit с плохим seq/ack; hostfakesplit, seqovl, подделки с
    # tcp_ts или tcp_seq — 0
    local dt dn di dpp dx dd
    if [ "$DNS_VIA_ZAPRET" = "1" ]; then
        dt=$(zapret_doh_targets)
        dn=${dt%%"|"*}; dt=${dt#*"|"}; di=${dt%%"|"*}; dt=${dt#*"|"}; dpp=${dt%%"|"*}; dx=${dt#*"|"}
        # тот же приём — у регистрации WARP (bypass_on в warp/warp.sh): менять вместе
        dd="--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tcp_ts_up:repeats=2 --lua-desync=multisplit:pos=midsld"
        [ -n "$dx" ] && _z2p "--filter-tcp=$dpp --hostlist-domains=$dx"
        [ -n "$dn" ] && _z2p "--filter-tcp=$dpp --filter-l7=tls $ex --hostlist-domains=$dn $dd"
        [ -n "$di" ] && _z2p "--filter-tcp=$dpp --filter-l7=tls --ipset-ip=$di $dd"
    fi
    # Кэши оператора (googlevideo.com на адрес вне сетей Google — YOTA 188.170.166.x) — своим профилем
    # первым: те же приёмы TLS, но ip_autottl не дальше 5 хопов. Замер 14.11 (YOTA, TTL подделки 3…64):
    # ТСПУ — между 5-м и 6-м хопом; кэш с подделкой, дошедшей до него, — 0 из 30 (autottl ставит 8:
    # обратно 9 хопов), с TTL 3–5 — 17 из 18. Всем такой потолок нельзя: youtubei.googleapis.com с TTL
    # до 5 — 0 из 18, приложение YouTube молчало. Только у стратегий с autottl в TCP и без своего
    # профиля googlevideo (у hardcorp74 он кэш открывает и так — 10 из 10)
    local ggc=""
    case "$tcp" in *ip_autottl=*)
        case "$custom" in *googlevideo*) ;; *)
            ggc=$(echo "$tcpt" | zapret2_ttlcap)
            ggc=$(zapret2_add "$ggc" "--hostlist-domains=googlevideo.com --ipset-exclude=$ZAPRET_DIR/google-ipv4.txt --ipset-exclude=$ZAPRET_DIR/google-ipv6.txt") ;;
        esac ;;
    esac
    _z2p "$ggc"
    # сайты со своей стратегией (ZAPRET_ALT) — раньше общих профилей: их стратегия не открывает
    zapret2_alt_profiles "$ex" "$base"
    _z2p "$Z2_ALT_P"
    [ -n "$Z2_ALT_BASE" ] && base=$(zapret2_base_merge "$base" "$Z2_ALT_BASE")
    # порядок — как _startup_args: свои профили, UDP, QUIC (адреса, имена), TCP (адреса, имена);
    # .ru и Google из списков — между адресами и именами
    _z2p "$custom"
    _z2p "$udp"
    if [ -n "$quic" ]; then
        _z2p "$(zapret2_add "$quic" "$ipset")"
        [ -n "$ruh" ] && _z2p "$(zapret2_add "$quic" "$ruh")"
        _z2p "$(zapret2_add "$quic" "$extra")"
    fi
    _z2p "$(zapret2_add "$tcpt" "$ipset")"
    [ -n "$ruh" ] && _z2p "$(zapret2_add "$tcp" "$ruh")"
    _z2p "$(zapret2_add "$tcp" "$extra")"
    [ "$ZAPRET_MODE" = "all" ] && _z2p "$(zapret2_add "$tcpt" "--hostlist-exclude=$S/exclude.list $rux")"
    # приёмы стратегии на SYN клиента (NFQWS_ARGS_SYN, у vt_soft_crck — synack) — последним профилем, без фильтров
    # по имени и протоколу: на SYN их ещё нет, а профили выше с --filter-l7 и списками SYN не берут. Стоял бы
    # раньше — при пересмотре профиля на ClientHello забрал бы соединение у профилей с приёмами TLS. Стойкам малого
    # окна — нет: их профиль первый и берёт SYN по адресу. Из локальной копии: Z2_* к этому месту перезаписаны
    # стратегиями сайтов (zapret2_alt_profiles) — 17.11 на 13T synack из-за этого не встал
    [ -n "$syn" ] && _z2p "--filter-tcp=443 $syn"
    # малое окно: настоящий масштаб окна соединения vt_wssize_ramp держит в conntrack nfqws2, а тот по
    # умолчанию забывает соединение через 300 с без пакетов (60:300:60:60) — пул YouTube простаивает
    # дольше, и после простоя сервер видел бы окно в ~128 раз меньше. Закрытые уходят по FIN/RST (их
    # пакеты в очереди всегда), так что час держат только живые
    local ct=""
    [ "$YT_WSSIZE_RAMP" = "1" ] && [ "$YT_DEAD_FAILFAST" = "1" ] && ct="--ctrack-timeouts=60:3600:60:60"
    echo "--qnum=$ZAPRET_QNUM --uid=0:$ZAPRET_GID --bind-fix4 --bind-fix6 $ct $base $P" | tr '\n' ' ' | tr -s ' ' | zapret2_fool | \
        if zapret_cap cb; then cat; else sed -E 's/(--filter-(tcp|udp)=[^ ]*)/\1 --out-range=-n20/g'; fi
}
# Название стратегии и автор (meta.tsv) — для журнала и WebUI
zapret2_strat_label() {
    local n
    n=$(basename "$(zapret2_strat_file)" .conf)
    # автор — в скобках, если это не имя самой стратегии (hardcorp74, MartinBacker)
    echo "$n$(awk -F'\t' -v n="$n" '$1 == n && $2 != n { printf " (%s)", $2 }' "$ZAPRET2_DIR/strategies/meta.tsv" 2>/dev/null)"
}
# правило с портами: multiport, а на ядре без него — по порту
zapret2_rule() {   # таблица цепочка proto dports|sports порты "доп." цель...
    local t="$1" c="$2" pr="$3" d="$4" ps="$5" x="$6" p sd
    shift 6
    # shellcheck disable=SC2086
    $t -t mangle -A "$c" -p "$pr" -m multiport --"$d" "$ps" $x "$@" 2>/dev/null && return 0
    if [ "$d" = dports ]; then sd="--dport"; else sd="--sport"; fi
    for p in $(echo "$ps" | tr ',' ' '); do
        # shellcheck disable=SC2086
        $t -t mangle -A "$c" -p "$pr" $sd "$p" $x "$@" 2>/dev/null
    done
}
# Ядро без connbytes: в очередь шёл бы каждый исходящий пакет TCP, а при закачке это почти одни пустые ACK — приёмам они
# не нужны (им — SYN, ClientHello, FIN/RST). Пустой ACK (флаги ровно ACK, длина до 52 байт у IPv4 и до 72 у IPv6:
# заголовки с метками времени, без данных) — мимо очереди. Больше нельзя: 80 пропускало и сегменты до 28 байт данных
# без PSH (ClientHello, порезанный обходчиком на ноутбуке, начинается с 1–2 байт); ACK с SACK (при потерях) идут в
# очередь, их мало. Стойкам малого окна (CHAIN_YT_RAMP, раньше этого правила) — все пакеты: vt_wssize_ramp правит
# окно и в ACK. Issue #26 (Realme, ядро без connbytes: батарея и system_server от очереди на весь HTTPS)
zapret_ack_skip() {   # таблица [условие — только такие пакеты]
    local t="$1" l=52
    zapret_cap cb && return 0
    [ "$t" = "$ip6tables" ] && l=72
    shift
    # shellcheck disable=SC2068
    $t -t mangle -A "$CHAIN_ZAPRET" -p tcp $@ --tcp-flags ALL ACK -m length --length 0:$l -j RETURN 2>/dev/null
}
zapret2_rules() {   # таблица: правила очереди nfqws2 в уже открытые цепочки VPN_ZAPRET/_IN
    local t="$1" q="-j NFQUEUE --queue-num $ZAPRET_QNUM --queue-bypass"
    local co="-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:$ZAPRET2_PKT"
    local ci="-m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:$ZAPRET2_PKT_IN" cb=1
    # ядро без connbytes: правила с ним не встают (2>/dev/null) — в очереди не было бы ничего. Исходящий TCP —
    # весь (как nfqws1 в упрощённом режиме), UDP (звонки, QUIC; QUIC раздачи закрыт, как у nfqws1) и ответы с
    # данными — мимо: это был бы весь поток. Ответы SYN-ACK/FIN/RST — по флагам, их мало
    # Порт 80 — тоже мимо: закачки по HTTP (обновления Windows, Steam) шли бы через nfqws2 целиком; nfqws1 брал только 443
    local tp="$ZAPRET2_TP"
    zapret_cap cb || { co=""; cb=0; tp=$(echo ",$ZAPRET2_TP," | sed 's/,80,/,/; s/^,//; s/,$//'); }
    # молчащие стойки (YT_WSSIZE_RAMP) — все исходящие пакеты, раньше правил с connbytes; только IPv4
    if [ "$t" = "$iptables" ]; then
        yt_ramp_on && yt_ramp_sync "$(date +%s)"
        yt_ramp_chain
        yt_ramp_on && $t -t mangle -A "$CHAIN_ZAPRET" -p tcp --dport 443 -j "$CHAIN_YT_RAMP" 2>/dev/null
    fi
    zapret_ack_skip "$t"
    # shellcheck disable=SC2086
    [ "$cb" = 1 ] && zapret2_rule "$t" "$CHAIN_ZAPRET" udp dports "$ZAPRET2_UP" "" $co $q
    # shellcheck disable=SC2086
    zapret2_rule "$t" "$CHAIN_ZAPRET" tcp dports "$tp" "" $co $q
    # FIN/RST — в nfqws2: по ним он закрывает соединения у себя (circular)
    # shellcheck disable=SC2086
    zapret2_rule "$t" "$CHAIN_ZAPRET" tcp dports "$ZAPRET2_TP" "--tcp-flags fin fin" $q
    # shellcheck disable=SC2086
    zapret2_rule "$t" "$CHAIN_ZAPRET" tcp dports "$ZAPRET2_TP" "--tcp-flags rst rst" $q
    # ответы: SYN-ACK/FIN/RST и первые пакеты — circular по ним видит, прошёл ли приём
    # shellcheck disable=SC2086
    zapret2_rule "$t" "$CHAIN_ZAPRET_IN" tcp sports "$ZAPRET2_TP" "--tcp-flags syn,ack syn,ack" $q
    # shellcheck disable=SC2086
    zapret2_rule "$t" "$CHAIN_ZAPRET_IN" tcp sports "$ZAPRET2_TP" "--tcp-flags fin fin" $q
    # shellcheck disable=SC2086
    zapret2_rule "$t" "$CHAIN_ZAPRET_IN" tcp sports "$ZAPRET2_TP" "--tcp-flags rst rst" $q
    [ "$cb" = 1 ] || return 0
    # shellcheck disable=SC2086
    zapret2_rule "$t" "$CHAIN_ZAPRET_IN" udp sports "$ZAPRET2_UP" "" $ci $q
    # shellcheck disable=SC2086
    zapret2_rule "$t" "$CHAIN_ZAPRET_IN" tcp sports "$ZAPRET2_TP" "" $ci $q
}

# режим, которым на деле работает nfqws1 (zapret_args): запасным движком — всегда list
zapret1_mode() { [ "$ZAPRET_ENGINE" = nfqws1 ] && echo "$ZAPRET_MODE" || echo "list (запасной движок)"; }
zapret_args() {
    [ "$ZAPRET_ENGINE_EFF" = nfqws2 ] && { zapret2_args; return 0; }
    local a="--qnum=$ZAPRET_QNUM --uid=0:$ZAPRET_GID --bind-fix4 --bind-fix6" ex="" g alt rup="" rux="" q dp=""
    # банки и Госуслуги — мимо обхода в любом профиле (и в автосписок не попадут)
    grep -q '[a-z0-9]' "$ZAPRET_LIST_EXCL" 2>/dev/null && ex="--hostlist-exclude=$ZAPRET_LIST_EXCL"
    # .ru/.su/.рф: основной профиль их не трогает и в автосписок не берёт;
    # такие сайты из списков — своим профилем перед ним, с той же стратегией
    # Google (list-noauto) — так же: в основной профиль и автосписок не берём
    if grep -q '^[a-z]' "$ZAPRET_LIST_RUTLD" "$ZAPRET_LIST_NOAUTO" 2>/dev/null; then
        grep -q '^[a-z]' "$ZAPRET_LIST_RUTLD" 2>/dev/null && rux="--hostlist-exclude=$ZAPRET_LIST_RUTLD"
        grep -q '^[a-z]' "$ZAPRET_LIST_NOAUTO" 2>/dev/null && rux="$rux --hostlist-exclude=$ZAPRET_LIST_NOAUTO"
        zapret_ru_listed
        [ -s "$ZAPRET_RU_RUN" ] && rup="--filter-tcp=443 $ex --hostlist=$ZAPRET_RU_RUN $(zapret_strategy_args "$ZAPRET_DIR" "$ZAPRET_EFF_STRATEGY" "$ZAPRET_EFF_ARGS") --new "
    fi
    g="--filter-tcp=443 $ex $rux"
    # nfqws1 запасным (nfqws2 не запустился / его нет) — по спискам, как до умолчания all (19.11): на таких
    # ядрах слабые телефоны, а all на nfqws1 не меряли. «Все сайты» — только если nfqws1 выбран руками
    if [ "$ZAPRET_MODE" = "list" ] || [ "$ZAPRET_ENGINE" != nfqws1 ]; then
        g="$g --hostlist=$ZAPRET_LIST_DEFAULT"
        # пустой список не передаём: не полагаемся на то, как nfqws его трактует
        grep -q '[a-z0-9]' "$ZAPRET_LIST_USER" 2>/dev/null && g="$g --hostlist=$ZAPRET_LIST_USER"
        g="$g --hostlist-auto=$ZAPRET_LIST_AUTO --hostlist-auto-fail-threshold=$ZAPRET_AUTO_FAIL --hostlist-auto-debug=$ZAPRET_AUTO_LOG"
    fi
    g="$g $(zapret_strategy_args "$ZAPRET_DIR" "$ZAPRET_EFF_STRATEGY" "$ZAPRET_EFF_ARGS")"
    # сайты со своей стратегией — самыми первыми профилями, затем YouTube:
    # nfqws берёт первый подходящий
    alt=$(zapret_alt_profiles "$ex")
    # QUIC клиентов YouTube (QUIC_YT_FAKE): в очередь попадает только их UDP 443
    # (quic_block_apply), по нему — 6 поддельных QUIC Initial google.com.
    # Раздаче (ZAPRET_QUIC_FAKE) — весь UDP 443, поэтому банки/Госуслуги мимо ($ex)
    q=""
    { [ "$QUIC_BLOCK_YT" = "1" ] && [ "$QUIC_YT_FAKE" = "1" ]; } || [ "$ZAPRET_QUIC_FAKE" = "1" ] && \
        q="--filter-udp=443 $ex --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=$ZAPRET_DIR/quic_initial_www_google_com.bin --new "
    if [ -n "$ZAPRET_EFF_DC" ] && grep -q '[a-z0-9]' "$ZAPRET_LIST_DC" 2>/dev/null; then
        rup="--filter-tcp=443 $ex --hostlist=$ZAPRET_LIST_DC $(zapret_strategy_args "$ZAPRET_DIR" custom "$ZAPRET_EFF_DC") --new $rup"
    fi
    # DoH через обход (DNS_VIA_ZAPRET): серверы из настроек — своим профилем первым. Отдельно
    # от основного: тот не трогает .ru (MagicDNS, GeoHide тоже могут резать), и в режиме «всё»
    # тоже. Стратегия своя, постоянная — md5sig, а не стратегия сети: 09.11 из 31 стратегии
    # подбора одна (multisplit с --dup) ломала весь DoH, три не открывали dns.zapret.moe, md5sig
    # прошла все 8 серверов (так же устроено в nfqws2-android-ext). Имена — прямо в аргументах:
    # смена серверов в настройках меняет аргументы, и nfqws перезапускается сам. Адреса без
    # имени (8.8.4.4) — мимо
    # Серверы, заданные адресом (и bootstrap DoH 1.1.1.1/8.8.8.8), — отдельным профилем по
    # адресу: в режиме «всё» иначе они шли бы стратегией сети. Порты — из URL (dns.geohide.ru:444)
    if [ "$DNS_VIA_ZAPRET" = "1" ]; then
        local dt dn di dpp dx ds
        dt=$(zapret_doh_targets)
        dn=${dt%%"|"*}; dt=${dt#*"|"}; di=${dt%%"|"*}; dt=${dt#*"|"}; dpp=${dt%%"|"*}; dx=${dt#*"|"}
        ds=$(zapret_strategy_args "$ZAPRET_DIR" md5sig)
        [ -n "$dn" ] && dp="--filter-tcp=$dpp $ex --hostlist-domains=$dn $ds --new "
        [ -n "$di" ] && dp="$dp--filter-tcp=$dpp --ipset-ip=$di $ds --new "
        [ -n "$dx" ] && dp="--filter-tcp=$dpp --hostlist-domains=$dx --new $dp"
    fi
    if [ -n "$ZAPRET_EFF_YT" ] && grep -q '[a-z0-9]' "$ZAPRET_LIST_YT" 2>/dev/null; then
        echo "$a $q$dp$alt--filter-tcp=443 $ex --hostlist=$ZAPRET_LIST_YT $(zapret_strategy_args "$ZAPRET_DIR" custom "$ZAPRET_EFF_YT") --new $rup$g"
    else
        echo "$a $q$dp$alt$rup$g"
    fi
}

# Какая стратегия для текущей сети: запомненная для неё или общая
zapret_pick_strategy() {
    local e rc
    ZAPRET_EFF_STRATEGY="$ZAPRET_STRATEGY"
    ZAPRET_EFF_ARGS="$ZAPRET_ARGS"
    ZAPRET_EFF_YT=""
    ZAPRET_EFF_DC=""
    ZAPRET_NET_SRC="default"
    ZAPRET2_EFF="$ZAPRET2_STRATEGY"
    ZAPRET2_NET_SRC="default"
    QUIC_NET=""
    [ "$ZAPRET_PER_NET" = "1" ] && [ -n "$NET_KEY" ] || return 0
    # nfqws2 — своя запись сети (свой файл); не годится — общая, как у nfqws1
    local n2
    n2=$(zapret2_net_entry "$NET_KEY" "$NET_LABEL" "$ZAPRET2_DIR/strategies"); rc=$?
    if [ -n "$n2" ]; then
        ZAPRET2_EFF="$n2"; ZAPRET2_NET_SRC="net"; [ "$rc" = 3 ] && ZAPRET2_NET_SRC="label"
    elif [ "$rc" = 2 ] && [ "$ZAPRET2_NET_BAD" != "$NET_KEY" ]; then
        log "WARNING: zapret: запись nfqws2 для сети «$NET_LABEL» в $ZAPRET2_NETS_FILE не прошла проверку — общая стратегия"
        ZAPRET2_NET_BAD="$NET_KEY"
    fi
    QUIC_NET=$(K="$NET_KEY" L="$NET_LABEL" awk -F'|' '$1 == ENVIRON["K"] { k = $3 } ENVIRON["L"] != "" && $2 == ENVIRON["L"] { l = $3 } END { print ((k != "") ? k : l) }' "$ZAPRET_QUIC_FILE" 2>/dev/null)
    e=$(zapret_net_entry "$NET_KEY" "$NET_LABEL"); rc=$?
    if [ "$rc" = 2 ]; then
        [ "$ZAPRET_NET_BAD" = "$NET_KEY" ] || log "WARNING: zapret: запись для сети «$NET_LABEL» в $ZAPRET_NETS_FILE не прошла проверку — общая стратегия"
        ZAPRET_NET_BAD="$NET_KEY"
        return 0
    fi
    [ -n "$e" ] || return 0
    ZAPRET_EFF_STRATEGY="${e%%"|"*}"
    e="${e#*"|"}"
    ZAPRET_EFF_ARGS="${e%%"|"*}"
    e="${e#*"|"}"
    ZAPRET_EFF_YT="${e%%"|"*}"
    ZAPRET_EFF_DC="${e#*"|"}"
    ZAPRET_NET_SRC="net"
    [ "$rc" = 3 ] && ZAPRET_NET_SRC="label"
}

# Узнать сеть (zapret/netid.sh): при смене WAN / по сигналу смены сети, а на
# Wi-Fi ещё и раз в ~30с — другая точка доступа может дать тот же wlan0 и
# даже тот же адрес со шлюзом. Мобильную сеть периодически не опрашиваем:
# content query дорогой, а смена SIM для данных и так меняет WAN.
net_identity_reconcile() {
    local d k l
    if [ "$ZAPRET_PER_NET" != "1" ]; then
        [ -n "$NET_KEY" ] && ZAPRET_NET_DIRTY=1
        NET_KEY=""; NET_LABEL=""; NET_ID_WAN="-"
        return 0
    fi
    NET_ID_TICK=$((NET_ID_TICK + 1))
    if [ "$NET_ID_FORCE" != "1" ] && [ "$LAST_WAN_IFACE" = "$NET_ID_WAN" ]; then
        case "$LAST_WAN_IFACE" in
            wlan*|swlan*) [ "$NET_ID_TICK" -ge 15 ] || return 0 ;;
            *) return 0 ;;
        esac
    fi
    NET_ID_TICK=0
    NET_ID_FORCE=0
    NET_ID_WAN="$LAST_WAN_IFACE"
    d=""
    [ -n "$LAST_WAN_IFACE" ] && d=$(sh "$ZAPRET_NETID" "$LAST_WAN_IFACE" 2>/dev/null | head -1)
    k="${d%%"|"*}"; l="${d#*"|"}"
    [ -n "$k" ] || l=""
    [ "$k" = "$NET_KEY" ] && return 0
    # другая точка с тем же адресом и шлюзом (handle_change её не видит) — WARP
    # проверить сразу, как при смене сети в loop.sh
    [ -n "$k" ] && [ -n "$NET_KEY" ] && { WARP_CHECK_TS=0; WARP_NETCHG=1; WARP_BAD=""; WARP_EP_FULL=0; WARP_RETRY_TS=0; }
    NET_KEY="$k"
    NET_LABEL="$l"
    log "Сеть: ${NET_LABEL:-не определена}${NET_KEY:+ ($NET_KEY)}"
    ZAPRET_NET_DIRTY=1
    # новая сеть — сторож проверит её стратегию через ~1.5 мин, а не через 15
    [ -n "$NET_KEY" ] && ZWD_LAST=$(( $(date +%s) - ZAPRET_WATCHDOG_MIN * 60 + 90 ))
    # и сайты со своей стратегией — через ~час (31.10: было ~10 мин — залп
    # проверки после каждой смены Wi-Fi/мобильной, а он, похоже, провоцирует ТСПУ)
    # В сети, где проверка уже была, срок только отодвигаем: иначе каждая смена сети ставила
    # её через час вместо суток. В другой сети — через час: ей своих стратегий ещё не подбирали
    _zs=$(( $(date +%s) - ZAPRET_ALT_MIN * 60 + 3600 ))
    if [ -n "$NET_KEY" ] && { [ "$NET_KEY" != "$ZSITES_NET" ] || [ "$_zs" -gt "$ZSITES_LAST" ]; }; then ZSITES_LAST=$_zs; fi
    phone_status_refresh
}

zapret_start() {
    local pid
    zapret_kill_all
    [ -f "$ZAPRET_LIST_AUTO" ] || { : > "$ZAPRET_LIST_AUTO"; chmod 600 "$ZAPRET_LIST_AUTO"; }
    [ -f "$ZAPRET_AUTO_LOG" ] || { : > "$ZAPRET_AUTO_LOG"; chmod 600 "$ZAPRET_AUTO_LOG"; }
    zapret_auto_clean_ru
    : > "$ZAPRET_LOG"
    # $1 без кавычек: это список аргументов, собранный zapret_args
    local bin="$NFQWS_BIN"
    [ "$ZAPRET_ENGINE_EFF" = nfqws2 ] && bin="$NFQWS2_BIN"
    "$bin" $1 >> "$ZAPRET_LOG" 2>&1 &
    pid=$!
    sleep 0.5
    if kill -0 "$pid" 2>/dev/null; then
        echo "$pid" > "$ZAPRET_PID_FILE"
        ZAPRET_ENGINE_RUN="$ZAPRET_ENGINE_EFF"
        if [ "$ZAPRET_ENGINE_EFF" = nfqws2 ]; then
            ZAPRET_ALT_N=$(zapret_alt_count "$1")
            yt_ramp_on && yt_ramp_kill
            log "zapret: nfqws2 запущен (pid $pid, стратегия $(zapret2_strat_label)$([ "$ZAPRET_ALT_N" -gt 0 ] && echo ", своя стратегия у $ZAPRET_ALT_N сайтов"), $([ "$ZAPRET_MODE" = all ] && echo "TLS всех сайтов, кроме .ru и Google не из списков; QUIC и HTTP — по спискам" || echo "свои списки и автосписок"))"
            return 0
        fi
        ZAPRET_ALT_N=$(zapret_alt_count "$1")
        [ "$ZAPRET_ALT_N" -gt 0 ] && log "zapret: своя стратегия у $ZAPRET_ALT_N сайтов (их основная не открывала)"
        if [ "$ZAPRET_NET_SRC" = "net" ] || [ "$ZAPRET_NET_SRC" = "label" ]; then
            log "zapret: nfqws запущен (pid $pid, стратегия сети «$NET_LABEL»$([ "$ZAPRET_NET_SRC" = label ] && echo " — взята у сети с тем же названием, своей у $NET_KEY нет"): $ZAPRET_EFF_STRATEGY${ZAPRET_EFF_ARGS:+ [$ZAPRET_EFF_ARGS]}${ZAPRET_EFF_YT:+, YouTube: [$ZAPRET_EFF_YT]}, режим $(zapret1_mode))"
        else
            log "zapret: nfqws запущен (pid $pid, стратегия $ZAPRET_EFF_STRATEGY — общая${NET_LABEL:+, для «$NET_LABEL» своей нет}, режим $(zapret1_mode))"
        fi
        return 0
    fi
    log "WARNING: zapret: $([ "$ZAPRET_ENGINE_EFF" = nfqws2 ] && echo nfqws2 || echo nfqws) не запустился: $(tail -n 2 "$ZAPRET_LOG" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    return 1
}

# QUIC раздачи — подделка вместо закрытия (ZAPRET_QUIC_FAKE). Пакеты раздачи
# без uid, приложение не отличить — весь UDP 443 мимо VPN/WARP: первые 9 пакетов
# в nfqws (профиль --filter-udp=443). Только если профиль уже у запущенного
# nfqws и есть connbytes — иначе QUIC ушёл бы голым и умер молча (ТСПУ, 29.10)
# Хук — в mangle POSTROUTING, как у TCP раздачи (VPN_ZAPRET), а не в FORWARD:
# mangle FORWARD идёт раньше filter FORWARD, где kill-switch (VPN_GUARD), —
# при отвалившемся VPN nfqws успел бы отправить подделки мимо туннеля
CHAIN_ZAPRET_QF="VPN_ZAPRET_QF"
ZAPRET_QF_ON=0                    # 1 — подделка QUIC раздачи стоит (iptables)
zapret_qf_off() {   # таблица
    local _n=0
    while [ $_n -lt 8 ] && $1 -t mangle -D POSTROUTING -p udp --dport 443 -j "$CHAIN_ZAPRET_QF" 2>/dev/null; do _n=$((_n + 1)); done
    # хук в FORWARD — от сборки до ревью (стояла на 13T)
    _n=0; while [ $_n -lt 8 ] && $1 -t mangle -D FORWARD -p udp --dport 443 -j "$CHAIN_ZAPRET_QF" 2>/dev/null; do _n=$((_n + 1)); done
    $1 -t mangle -F "$CHAIN_ZAPRET_QF" 2>/dev/null
    $1 -t mangle -X "$CHAIN_ZAPRET_QF" 2>/dev/null
}

zapret_qf_on() {   # таблица, локальные сети; 0 — подделка QUIC для раздачи стоит
    zapret_qf_off "$1"
    [ "$ZAPRET_QUIC_FAKE" = "1" ] && zapret_cap cb || return 1
    case "$ZAPRET_ARGS_RUN" in *quic_initial_www_google_com.bin*) ;; *) return 1 ;; esac
    $1 -t mangle -N "$CHAIN_ZAPRET_QF" 2>/dev/null
    $1 -t mangle -A "$CHAIN_ZAPRET_QF" -o tun+ -j RETURN 2>/dev/null
    $1 -t mangle -A "$CHAIN_ZAPRET_QF" -o warp+ -j RETURN 2>/dev/null
    $1 -t mangle -A "$CHAIN_ZAPRET_QF" -d "$2" -j RETURN 2>/dev/null
    # только раздача: у её пакетов нет локального сокета (телефон — VPN_QUIC_FAKE)
    $1 -t mangle -A "$CHAIN_ZAPRET_QF" -m owner --socket-exists -j RETURN 2>/dev/null || \
        { zapret_qf_off "$1"; return 1; }
    # shellcheck disable=SC2086
    $1 -t mangle -A "$CHAIN_ZAPRET_QF" $ZAPRET_CB_OUT -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null || \
        { zapret_qf_off "$1"; return 1; }
    $1 -t mangle -A POSTROUTING -p udp --dport 443 -j "$CHAIN_ZAPRET_QF" 2>/dev/null || \
        { zapret_qf_off "$1"; return 1; }
}

zapret_rules_on() {
    local excl="$1" t u lan rj
    for t in "$iptables" "$ip6tables"; do
        if [ "$t" = "$iptables" ]; then
            lan="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16"
            rj="icmp-port-unreachable"
        else
            lan="fc00::/7,fe80::/10,::1/128"
            rj="icmp6-port-unreachable"
        fi
        # исходящие
        $t -t mangle -N "$CHAIN_ZAPRET" 2>/dev/null
        $t -t mangle -F "$CHAIN_ZAPRET" 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET" -o tun+ -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET" -o warp+ -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET" -o lo -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET" -d "$lan" -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET" -m mark --mark "$ZAPRET_MARK/$ZAPRET_MARK" -j RETURN 2>/dev/null
        # метку выше на rmnet стирает qcom_qos_reset — дублируем по группе сокета.
        # own=0: любое такое правило забрало бы весь трафик до NFQUEUE
        zapret_cap own && $t -t mangle -A "$CHAIN_ZAPRET" -m owner --gid-owner "$ZAPRET_GID" -j RETURN 2>/dev/null
        # DoH через обход: dnsproxy — в очередь с любым портом TCP (443, :444 GeoHide, 853 DoT) и при
        # обходе только для раздачи. В nfqws его соединения ловят только профили DoH (имена,
        # адреса, порты), остальное nfqws пропускает как есть. Кроме порта 80: от этой группы идёт
        # проверка белых списков (zapret_http_ok, «мимо обхода»), а у nfqws2 порт 80 — в hardcorp74
        # shellcheck disable=SC2086
        # его пустые ACK без connbytes — мимо (zapret_ack_skip; общее правило ниже, после стоек малого окна, сюда не успевает)
        [ "$DNS_VIA_ZAPRET" = "1" ] && [ -n "$DNSPROXY_GID" ] && zapret_cap own && \
            zapret_ack_skip "$t" -m owner --gid-owner "$DNSPROXY_GID"
        [ "$DNS_VIA_ZAPRET" = "1" ] && [ -n "$DNSPROXY_GID" ] && zapret_cap own && \
            $t -t mangle -A "$CHAIN_ZAPRET" -p tcp ! --dport 80 -m owner --gid-owner "$DNSPROXY_GID" $ZAPRET_CB_OUT \
                -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null
        if [ "$ZAPRET_PHONE" = "1" ]; then
            if zapret_cap own; then
                for u in $excl; do
                    $t -t mangle -A "$CHAIN_ZAPRET" -m owner --uid-owner "$u" -j RETURN 2>/dev/null
                done
                # dnsproxy — мимо. С DoH через обход (DNS_VIA_ZAPRET) его TCP, кроме порта 80, уже
                # в очереди правилом выше; сюда доходят порт 80 (проверка белых списков) и UDP —
                # без этого у nfqws2 их забирали общие правила (порт 80 — в hardcorp74)
                [ -n "$DNSPROXY_GID" ] && \
                    $t -t mangle -A "$CHAIN_ZAPRET" -m owner --gid-owner "$DNSPROXY_GID" -j RETURN 2>/dev/null
                # opera-proxy: его TLS к серверам Opera обход не трогает
                $t -t mangle -A "$CHAIN_ZAPRET" -m owner --gid-owner "$OPERA_GID" -j RETURN 2>/dev/null
            fi
        else
            # только раздача: у её пакетов нет локального сокета
            $t -t mangle -A "$CHAIN_ZAPRET" -m owner --socket-exists -j RETURN 2>/dev/null
        fi
        # shellcheck disable=SC2086
        [ "$ZAPRET_ENGINE_RUN" = nfqws2 ] || zapret_ack_skip "$t"
        [ "$ZAPRET_ENGINE_RUN" = nfqws2 ] || $t -t mangle -A "$CHAIN_ZAPRET" -p tcp --dport 443 $ZAPRET_CB_OUT \
            -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null
        $t -t mangle -C POSTROUTING -j "$CHAIN_ZAPRET" 2>/dev/null || \
            $t -t mangle -A POSTROUTING -j "$CHAIN_ZAPRET" 2>/dev/null

        # ответы (автосписок, --wssize, autottl)
        $t -t mangle -N "$CHAIN_ZAPRET_IN" 2>/dev/null
        $t -t mangle -F "$CHAIN_ZAPRET_IN" 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET_IN" -i tun+ -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET_IN" -i warp+ -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET_IN" -i lo -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET_IN" -s "$lan" -j RETURN 2>/dev/null
        # без connbytes ответы не шлём: в nfqws ушла бы вся закачка
        [ "$ZAPRET_ENGINE_RUN" = nfqws2 ] && zapret2_rules "$t"
        [ "$ZAPRET_ENGINE_RUN" != nfqws2 ] && zapret_cap cb && $t -t mangle -A "$CHAIN_ZAPRET_IN" -p tcp --sport 443 \
            -m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:3 \
            -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null
        $t -t mangle -C PREROUTING -j "$CHAIN_ZAPRET_IN" 2>/dev/null || \
            $t -t mangle -A PREROUTING -j "$CHAIN_ZAPRET_IN" 2>/dev/null

        # QUIC раздачи мимо VPN: подделка (ZAPRET_QUIC_FAKE) главнее закрытия
        $t -N "$CHAIN_ZAPRET_QUIC" 2>/dev/null
        $t -F "$CHAIN_ZAPRET_QUIC" 2>/dev/null
        [ "$t" = "$iptables" ] && ZAPRET_QF_ON=0
        # nfqws2 берёт QUIC раздачи сам (профили UDP) — только с connbytes: без него UDP в очередь не идёт
        # (zapret2_rules), и QUIC ушёл бы голым — ни подделки, ни закрытия (ревью 17.11). И только при «пробивать»
        # (ZAPRET_QUIC_FAKE): раньше nfqws2 брал его всегда, и «закрыть» на nfqws2 не действовало (19.11) —
        # теперь закрытие ниже, в FORWARD до очереди nfqws2 (та в mangle POSTROUTING)
        if [ "$ZAPRET_ENGINE_RUN" = nfqws2 ] && zapret_cap cb && [ "$ZAPRET_QUIC_FAKE" = "1" ]; then
            zapret_qf_off "$t"
            while $t -D FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null; do :; done
        elif zapret_qf_on "$t" "$lan"; then
            [ "$t" = "$iptables" ] && ZAPRET_QF_ON=1
            while $t -D FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null; do :; done
        elif [ "$ZAPRET_QUIC_BLOCK" = "1" ]; then
            $t -A "$CHAIN_ZAPRET_QUIC" -o tun+ -j RETURN 2>/dev/null
            $t -A "$CHAIN_ZAPRET_QUIC" -o warp+ -j RETURN 2>/dev/null
            $t -A "$CHAIN_ZAPRET_QUIC" -p udp --dport 443 -j REJECT --reject-with "$rj" 2>/dev/null
            $t -C FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null || \
                $t -I FORWARD 1 -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null
        else
            while $t -D FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null; do :; done
        fi
    done
    zapret_ggc_on
    yt_dead_on
}

# --- сторож обхода: zapret/scan.sh check в фоне --------------------------
zapret_watchdog() {
    local now due n pid
    [ "$ZAPRET_WATCHDOG" = "1" ] && [ "$ZAPRET_STATE" = "on" ] && [ "$ZAPRET_PER_NET" = "1" ] && [ -n "$NET_KEY" ] || return 0
    vpn_up_now && return 0
    now=$(date +%s)
    # первая проверка — через интервал после старта (сеть успеет устояться)
    [ "$ZWD_LAST" -eq 0 ] && { ZWD_LAST=$now; return 0; }
    due=$((ZWD_LAST + ZAPRET_WATCHDOG_MIN * 60))
    n=$(echo $YT_STUCK | wc -w)
    # до журнала: пока идёт подбор, строка про застрявшие писалась раз в 2–3 с (06.11).
    # Счётчик в ноль: иначе сразу после подбора ещё один залп, по устаревшим данным
    zscan_running && { YT_STUCK=""; return 0; }
    if [ "$now" -lt "$due" ]; then
        # видео застревает на ClientHello — раньше срока, но не чаще раза в 3 мин.
        # Автоподбор выключен — чинить некому, и залп шёл бы каждые 3 мин без конца
        [ "$ZAPRET_AUTOPICK" = "1" ] && [ "$n" -ge 3 ] && [ $((now - ZWD_LAST)) -ge 180 ] || return 0
        log "zapret: $n соединений YouTube застряли на ClientHello — сторож проверяет стратегию"
    fi
    ZWD_LAST=$now
    YT_STUCK=""
    ZSCAN_JUST_TS=$now
    setsid sh "$ZAPRET_DIR/scan.sh" check </dev/null >/dev/null 2>&1 &
}

# --- сайты, которых основная стратегия не открывает: scan.sh sites в фоне ---
zapret_sites_check() {
    local now pid
    [ "$ZAPRET_ALT" = "1" ] && [ "$ZAPRET_STATE" = "on" ] && [ "$ZAPRET_PER_NET" = "1" ] && [ -n "$NET_KEY" ] || return 0
    now=$(date +%s)
    # прошлая сорвалась (scan.sh оставил метку) — повтор через ~час: сорвалась
    # часто как раз потому, что ТСПУ резал всё (31.10 14:23), через 15 мин — снова залп
    if [ -f "${ZSCAN_PID_FILE%.pid}.sitesfail" ]; then
        rm -f "${ZSCAN_PID_FILE%.pid}.sitesfail"
        ZSITES_LAST=$((now - ZAPRET_ALT_MIN * 60 + 3600))
        log "zapret: проверка сайтов сорвалась — повторю через ~час"
    fi
    # первая — через ~час после старта
    [ "$ZSITES_LAST" -eq 0 ] && { ZSITES_LAST=$((now - ZAPRET_ALT_MIN * 60 + 3600)); return 0; }
    [ "$now" -ge $((ZSITES_LAST + ZAPRET_ALT_MIN * 60)) ] || return 0
    # Ночью (01–06): сотни запросов к закрытым именам днём запускали волну Google (16.11: 15:38 — волна
    # с начала проверки; на Wi-Fi адрес не сменить). Не было ночного окна сутки сверх срока — в любое время
    case "$(date +%H)" in 0[1-5]) ;; *) [ "$now" -ge $((ZSITES_LAST + ZAPRET_ALT_MIN * 60 + 86400)) ] || return 0 ;; esac
    vpn_up_now && return 0
    zscan_running && return 0   # идёт подбор/сторож
    # сторож запустил scan.sh в этом же такте — его pid-файла ещё нет
    [ $((now - ZSCAN_JUST_TS)) -lt 10 ] && return 0
    ZSITES_LAST=$now
    ZSITES_NET="$NET_KEY"
    log "zapret: проверяю сайты из списков — кому нужна своя стратегия"
    # ZSCAN_AUTO — плановая (scan.sh: после волны час не запускается; из WebUI — всегда)
    ZSCAN_AUTO=1 setsid sh "$ZAPRET_DIR/scan.sh" sites </dev/null >/dev/null 2>&1 &
}

zapret_rules_off() {
    local t _n
    for t in "$iptables" "$ip6tables"; do
        _n=0; while [ $_n -lt 8 ] && $t -t mangle -D POSTROUTING -j "$CHAIN_ZAPRET" 2>/dev/null; do _n=$((_n + 1)); done
        _n=0; while [ $_n -lt 8 ] && $t -t mangle -D PREROUTING -j "$CHAIN_ZAPRET_IN" 2>/dev/null; do _n=$((_n + 1)); done
        _n=0; while [ $_n -lt 8 ] && $t -D FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null; do _n=$((_n + 1)); done
        $t -t mangle -F "$CHAIN_ZAPRET" 2>/dev/null;    $t -t mangle -X "$CHAIN_ZAPRET" 2>/dev/null
        $t -t mangle -F "$CHAIN_ZAPRET_IN" 2>/dev/null; $t -t mangle -X "$CHAIN_ZAPRET_IN" 2>/dev/null
        $t -F "$CHAIN_ZAPRET_QUIC" 2>/dev/null;         $t -X "$CHAIN_ZAPRET_QUIC" 2>/dev/null
        $t -t mangle -F "$CHAIN_YT_RAMP" 2>/dev/null;   $t -t mangle -X "$CHAIN_YT_RAMP" 2>/dev/null
        zapret_qf_off "$t"
    done
    ZAPRET_QF_ON=0
    zapret_ggc_off
    yt_dead_off
}

zapret_down() {
    zapret_rules_off
    zapret_kill_all
    [ "$ZAPRET_STATE" = "on" ] && log "zapret: выключен"
    ZAPRET_STATE="off"
    quic_block_apply    # nfqws нет — клиенты YouTube обратно на закрытие QUIC
    ZAPRET_ARGS_RUN=""
    ZAPRET_EXCL_RUN=""
    ZAPRET_ENGINE_RUN=""
    ZAPRET_RULES_ENGINE=""
    ZAPRET2_FAIL=0
    ZAPRET_RETRY=0
    ZAPRET_TICK=0
    ZAPRET_NETS_STAMP=""
    phone_status_refresh
}

# --- белые списки оператора: обход на паузу ---
# В белых списках открываются только разрешённые (российские) адреса: обход
# ничего не откроет, а сторож видит «стратегия не открывает» и каждые 15 мин
# гоняет подбор (~4 мин, сотни TLS), проверка сайтов срывается, отбой YouTube
# отбивает всё подряд. Признак дешёвый и только после отката DNS (DoH и
# запасные молчат): мимо обхода четыре зарубежных адреса из разных сетей по
# порту 80 не отвечают, а Яндекс отвечает. Раз в минуту; ожил любой зарубежный —
# обход обратно.
# 11.11 (YOTA): признаком были TLS до 1.1.1.1 и 9.9.9.9, а 1.1.1.1 и 8.8.8.8 на
# части адресов оператора в списке открыты (16 адресов из 35) — на них модуль
# решал «списков нет» и включал обход: за 20 минут пауза шесть раз снималась
# и ставилась. Порт 80 по адресу, без имени: ТСПУ его обычным сайтам не
# закрывает, а в списке он отбит или молчит (замер 23:11 — все четыре 000 за
# 25–57 мс, Яндекс 406). Адреса: Google, GitHub, Cloudflare, Apple
ZAPRET_WL_FOREIGN="216.239.38.120 140.82.121.4 104.16.124.96 17.253.144.10"
zapret_url_ok() {   # $1 — URL с адресом; мимо обхода и AdGuard (группа dnsproxy), через WAN
    local cmd c
    cmd="$CURL_BIN -sk -o /dev/null -m 3 --interface $LAST_WAN_IFACE -w %{http_code} $1"
    if [ "$DNSPROXY_SU_G" = "1" ]; then c=$($SUG_CMD "$DNSPROXY_GID" -c "$cmd" 2>/dev/null); else c=$(eval "$cmd" 2>/dev/null); fi
    [ -n "$c" ] && [ "$c" != "000" ]
}
zapret_http_ok() { zapret_url_ok "http://$1/"; }    # $1 — IP, порт 80
zapret_tls_ok() { zapret_url_ok "https://$1/"; }    # $1 — IP, TLS
ZAPRET_WL_HITS=0       # подряд проверок «похоже на белые списки» (вход — со второй)
zapret_whitelist_check() {
    local now f a p ps alive
    # дешёвое — первым: без отката DNS и без паузы делать нечего
    [ "$ZAPRET_WL" = "1" ] || [ "$DNS_DEGRADED" = "1" ] || { ZAPRET_WL_HITS=0; return 0; }
    [ "$ZAPRET_ENABLE" = "1" ] && [ -n "$NFQWS_BIN" ] && [ -n "$LAST_WAN_IFACE" ] || { ZAPRET_WL=0; ZAPRET_WL_HITS=0; return 0; }
    # VPN: прямой путь не проверить, и обход раздаче не нужен
    vpn_up_now && { ZAPRET_WL=0; ZAPRET_WL_HITS=0; return 0; }
    # DoH ожил — белых списков нет (в них молчат все DoH), даже если проверочные
    # адреса оператор закрыл отдельно (как 8.8.8.8 3 июля) — иначе пауза навсегда
    if [ "$ZAPRET_WL" = "1" ] && [ "$DNS_DEGRADED" != "1" ]; then
        log "zapret: DoH снова отвечает — белых списков нет, обход включаю"
        ZAPRET_WL=0; ZAPRET_WL_HITS=0; return 0
    fi
    # сменилась сеть — проверить сразу, а не через минуту
    [ "$LAST_WAN_IFACE" != "$ZAPRET_WL_WAN" ] && { ZAPRET_WL_WAN="$LAST_WAN_IFACE"; ZAPRET_WL_LAST=0; }
    now=$(date +%s)
    [ $((now - ZAPRET_WL_LAST)) -ge 60 ] || return 0
    ZAPRET_WL_LAST=$now
    # зарубежные — параллельно: цикл демона стоит, пока идёт проверка
    f="/data/local/tmp/vpn_tether_wl.$$"
    rm -f "$f".*
    ps=""
    for a in $ZAPRET_WL_FOREIGN; do
        ( zapret_http_ok "$a" && : > "$f.$a" ) </dev/null >/dev/null 2>&1 &
        ps="$ps $!"
    done
    # до конца, а не до сигнала: USR1 (Action, «Применить») прерывает wait, и
    # недоделанная проверка считалась провалом — ложная пауза обхода (ревью PR #19)
    for p in $ps; do while kill -0 "$p" 2>/dev/null; do wait "$p" 2>/dev/null; done; done
    alive=0
    for a in $ZAPRET_WL_FOREIGN; do [ -f "$f.$a" ] && alive=1; done
    if [ "$alive" = 1 ]; then
        [ "$ZAPRET_WL" = "1" ] && log "zapret: зарубежные адреса снова открываются — белых списков нет, обход включаю"
        ZAPRET_WL=0; ZAPRET_WL_HITS=0
    elif zapret_tls_ok 77.88.55.242; then
        ZAPRET_WL_HITS=$((ZAPRET_WL_HITS + 1))
        # вход — со второй проверки подряд (минута): одна неудача — не повод
        if [ "$ZAPRET_WL" != "1" ] && [ "$ZAPRET_WL_HITS" -ge 2 ]; then
            log "zapret: похоже, белые списки оператора (Яндекс открывается, четыре зарубежных адреса — нет, 2 проверки подряд) — обход на паузе, проверяю раз в минуту"
            ZAPRET_WL=1
        fi
    fi
    # не отвечает и Яндекс — нет связи вообще: состояние не меняем
    rm -f "$f".*
}

# Каждая итерация цикла. Дорогое (dumpsys, stat пакетов) — раз в ~30с.
zapret_reconcile() {
    local args excl
    # возможности ядра — и при выключенном zapret: по файлу их берут проверка
    # сайта и регистрация WARP (ядро без connbytes, ревью 27.10)
    [ -n "$ZAPRET_CAPS" ] || zapret_caps
    if [ "$ZAPRET_ENABLE" != "1" ] || { [ -z "$NFQWS_BIN" ] && [ -z "$NFQWS2_BIN" ]; }; then
        [ "$ZAPRET_STATE" != "off" ] && zapret_down
        return 0
    fi
    zapret_caps || return 0     # не удалось проверить сейчас — в следующем такте
    if ! zapret_cap nfq; then
        [ "$ZAPRET_STATE" = "nokernel" ] && return 0
        zapret_down
        ZAPRET_STATE="nokernel"
        phone_status_refresh
        return 0
    fi
    if [ "$ZAPRET_WL" = "1" ]; then
        [ "$ZAPRET_STATE" = "wl" ] && return 0
        zapret_down
        ZAPRET_STATE="wl"
        phone_status_refresh
        return 0
    fi
    if [ "$ZAPRET_RETRY" -gt 0 ]; then
        ZAPRET_RETRY=$((ZAPRET_RETRY - 1))
        return 0
    fi
    args="$ZAPRET_ARGS_RUN"
    excl="$ZAPRET_EXCL_RUN"
    net_identity_reconcile
    # файл стратегий сетей поменяли (WebUI, подбор) — подхватываем сразу
    local stamp=""
    # (и файл своих стратегий сайтов — scan.sh sites)
    [ "$ZAPRET_PER_NET" = "1" ] && stamp=$(stat -c '%Y %s %i' "$ZAPRET_NETS_FILE" "$ZALT_FILE" "$ZAPRET_QUIC_FILE" 2>/dev/null)
    [ "$stamp" != "$ZAPRET_NETS_STAMP" ] && ZAPRET_NET_DIRTY=1
    ZAPRET_TICK=$((ZAPRET_TICK + 1))
    if [ "$ZAPRET_TICK" -ge 15 ] || [ "$ZAPRET_STATE" != "on" ] || [ "$ZAPRET_NET_DIRTY" = "1" ]; then
        ZAPRET_TICK=0
        ZAPRET_NET_DIRTY=0
        zapret_auto_log_trim
        zapret_auto_age
        zapret_nfqws_log_trim
        ZAPRET_NETS_STAMP="$stamp"
        # dumpsys connectivity тяжёлый (system_server) — раз на каждый tun, а
        # не каждые 30с: владелец VPN за сессию не меняется
        if vpn_up_now; then
            local _ti; _ti=$(read_table_index "$TUN_NAME")
            [ "$_ti" != "$ZAPRET_OWNER_TUN" ] && { zapret_learn_vpn_owner; ZAPRET_OWNER_TUN="$_ti"; }
        fi
        local _qn="$QUIC_NET" _en
        _en=$(zapret_engine)
        [ "$_en" != "$ZAPRET_ENGINE" ] && [ "$_en" != "$ZAPRET_ENGINE_EFF" ] && \
            log "zapret: движок $ZAPRET_ENGINE недоступен ($([ -z "$NFQWS2_BIN" ] && echo "нет nfqws2" || { [ "$ZAPRET2_FAIL" = 1 ] && echo "не запустился"; } || echo "нет файлов Lua")) — работаю на $_en"
        ZAPRET_ENGINE_EFF="$_en"
        zapret_pick_strategy
        # итог проверки QUIC сменился: в WebUI он виден сразу, а не со следующим событием
        [ "$_qn" != "$QUIC_NET" ] && phone_status_refresh
        args=$(zapret_args)
        excl=$(zapret_vpn_uids)
        [ "$ZAPRET_STATE" = "on" ] && [ "$args" != "$ZAPRET_ARGS_RUN" ] && [ "$ZAPRET_ENGINE_EFF" != nfqws2 ] && \
            log "zapret: аргументы nfqws сменились (сеть «${NET_LABEL:-не определена}», стратегия $ZAPRET_EFF_STRATEGY — $(case "$ZAPRET_NET_SRC" in net) echo своя ;; label) echo "как у «$NET_LABEL»" ;; *) echo общая ;; esac)) — перезапускаю"
    fi

    # nfqws: не запущен / умер / сменились аргументы (свой список, другая сеть)
    if [ "$args" != "$ZAPRET_ARGS_RUN" ] || ! zapret_alive; then
        [ "$ZAPRET_STATE" = "on" ] && [ "$args" = "$ZAPRET_ARGS_RUN" ] && \
            log "WARNING: zapret: nfqws умер, перезапускаю"
        # nfqws2 упал при запуске (Lua, файлы, старое ядро) — не ждать минуту без обхода, а сразу nfqws1
        local _st=0
        if [ "$ZAPRET_ENGINE_EFF" = nfqws2 ]; then
            if zapret_start "$args"; then
                _st=1
            else
                ZAPRET2_FAIL=1
                ZAPRET_ENGINE_EFF=nfqws1
                log "WARNING: zapret: nfqws2 не запустился — работаю на nfqws1 до выключения обхода"
                args=$(zapret_args)
            fi
        fi
        if [ "$_st" = 0 ] && ! zapret_start "$args"; then
            zapret_rules_off
            ZAPRET_STATE="fail"
            ZAPRET_ARGS_RUN=""
            ZAPRET_EXCL_RUN=""
            ZAPRET_RETRY=30          # повтор через ~минуту
            quic_block_apply         # очередь без читателя — QUIC YouTube на закрытие
            phone_status_refresh
            return 0
        fi
        ZAPRET_ARGS_RUN="$args"
        # сменился движок — у nfqws2 другие правила очереди: пересобрать их ниже
        [ "$ZAPRET_STATE" = "on" ] && [ "$ZAPRET_ENGINE_RUN" != "$ZAPRET_RULES_ENGINE" ] && ZAPRET_STATE="starting"
        # Был включён (смена стратегии, nfqws умер) — правила на месте, их
        # не трогаем: пока nfqws перезапускался, --queue-bypass пропускал пакеты
        # (подделка QUIC — по новым аргументам: профиль UDP мог появиться или уйти)
        if [ "$ZAPRET_STATE" = "on" ]; then quic_block_apply; phone_status_refresh; else ZAPRET_STATE="starting"; fi
    fi

    # правила: впервые / сменились исключения / хук снесли (netd пересобрал
    # цепочки). iptables -C читает всю таблицу (у Android тысячи правил) —
    # хуки проверяем раз в ~10с: без хука zapret просто не работает, утечки нет
    local _hooks_bad=0
    ZAPRET_HOOK_TICK=$((ZAPRET_HOOK_TICK + 1))
    if [ "$ZAPRET_STATE" = "on" ] && [ "$ZAPRET_HOOK_TICK" -ge 5 ]; then
        ZAPRET_HOOK_TICK=0
        if ! $iptables -t mangle -C POSTROUTING -j "$CHAIN_ZAPRET" 2>/dev/null || \
           { [ "$ZAPRET_QF_ON" = "1" ] && ! $iptables -t mangle -C POSTROUTING -p udp --dport 443 -j "$CHAIN_ZAPRET_QF" 2>/dev/null; } || \
           { [ "$ZAPRET_QF_ON" != "1" ] && [ "$ZAPRET_QUIC_BLOCK" = "1" ] && { [ "$ZAPRET_ENGINE_RUN" != nfqws2 ] || ! zapret_cap cb || [ "$ZAPRET_QUIC_FAKE" != "1" ]; } && ! $iptables -C FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null; } || \
           { case "$GGC_STATE" in v4*) ! $iptables -C FORWARD $GGC_MATCH -j "$CHAIN_ZAPRET_GGC" 2>/dev/null ;; *) false ;; esac; } || \
           { [ "$YT_DEAD_STATE" = "on" ] && ! $iptables -t mangle -C FORWARD $YT_MARK_FWD 2>/dev/null; } || \
           { [ "$YT_GGC_BLOCK" = "1" ] && [ "$GGC_FAILS" -gt 0 ] && [ "$GGC_FAILS" -lt 3 ] && zapret_cap str; } || \
           { [ "$YT_DEAD_STATE" = "fail" ] && [ "$YT_DEAD_FAILS" -lt 3 ]; }; then
            _hooks_bad=1
            # повтор не вставших GGC/пометки видео — не «правила пропали»
            if [ "$GGC_FAILS" -gt 0 ] || [ "$YT_DEAD_STATE" = "fail" ]; then
                log "zapret: повторяю правила «мимо кэшей оператора»/повтора видеосоединений (попытка $((GGC_FAILS > YT_DEAD_FAILS ? GGC_FAILS + 1 : YT_DEAD_FAILS + 1)) из 3)"
                ZAPRET_RETRY_LOGGED=1
            fi
        fi
    fi
    if [ "$ZAPRET_STATE" != "on" ] || [ "$excl" != "$ZAPRET_EXCL_RUN" ] || [ "$_hooks_bad" = 1 ]; then
        zapret_rules_on "$excl"
        if [ "$ZAPRET_STATE" != "on" ]; then
            log "zapret: включён (режим $ZAPRET_MODE, телефон: $ZAPRET_PHONE, QUIC раздачи: $(if [ "$ZAPRET_ENGINE_RUN" = nfqws2 ] && zapret_cap cb && [ "$ZAPRET_QUIC_FAKE" = 1 ]; then echo "через nfqws2"; elif [ "$ZAPRET_QF_ON" = 1 ]; then echo подделка; elif [ "$ZAPRET_QUIC_BLOCK" = 1 ]; then echo закрыт; else echo открыт; fi); в исключениях (VPN-клиенты и «мимо обхода»): ${excl:-нет}$([ "$DNS_VIA_ZAPRET" = 1 ] && echo "; DoH через обход: $(zapret_doh_targets | cut -d'|' -f1,2 | tr ',|' '\n\n' | grep -c .) серверов, порты $(zapret_doh_targets | cut -d'|' -f3)"))"
        elif [ "$excl" != "$ZAPRET_EXCL_RUN" ]; then
            log "zapret: исключения (VPN-клиенты и «мимо обхода»): ${excl:-нет}"
        else
            [ "$ZAPRET_RETRY_LOGGED" = 1 ] || log "WATCHDOG: zapret: правила пропали, ставлю заново"
            ZAPRET_RETRY_LOGGED=0
        fi
        ZAPRET_EXCL_RUN="$excl"
        ZAPRET_RULES_ENGINE="$ZAPRET_ENGINE_RUN"
        ZAPRET_STATE="on"
        quic_block_apply    # подделка QUIC возможна только при работающем nfqws
        phone_status_refresh
    fi
}

