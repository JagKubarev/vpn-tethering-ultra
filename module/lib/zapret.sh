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
    for p in $QUIC_YT_PKGS; do
        case " $QUIC_BLOCK_APPS " in *" $p "*) continue ;; esac
        [ -d "/data/data/$p" ] && echo "$p"
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
        u=$(stat -c %u "/data/data/$p" 2>/dev/null)
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
        if [ -n "$1" ]; then
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
    QUIC_AG_UIDS="$QUIC_AG_UIDS $(quic_block_uids "$QUIC_YT_PKGS")"
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
#   нет connbytes — в nfqws все исходящие HTTPS-пакеты (не первые 9), ответы
#                   не идут (это была бы вся закачка): нет автосписка и
#                   подстройки по ответу сервера (autottl, --wssize);
#   нет string    — нет «мимо кэшей оператора» и отбоя мёртвых серверов YouTube.
# Итог — и в файл: проверка сайта, подбор и регистрация WARP ставят свои правила.
ZAPRET_CAPS=""                  # «cb=1 str=1 nfq=1», пусто — ещё не проверяли
ZAPRET_CAPS_FILE=/data/local/tmp/vpn_tether_zcaps
ZAPRET_CB_OUT="-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9"

ZAPRET_CAPS_TRIES=0
rm -f "$ZAPRET_CAPS_FILE" 2>/dev/null   # от прошлой загрузки: /data/local/tmp её переживает
# 0 — проверено (ZAPRET_CAPS заполнен), 1 — не сейчас (сбой не от ядра: замок
# xtables у netd/scan.sh, не создалась цепочка) — повтор в следующем такте.
# Иначе разовый сбой на загрузке выключал zapret до перезагрузки (ревью 27.10)
zapret_caps() {
    local c=VPN_ZCAP cb=0 str=0 nfq=0 e miss=""
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
    ZAPRET_CAPS="cb=$cb str=$str nfq=$nfq"
    printf '%s\n' $ZAPRET_CAPS > "$ZAPRET_CAPS_FILE" 2>/dev/null
    [ -n "$miss" ] && log "WARNING: zapret: ядро не умеет:$miss"
    if [ "$nfq" = 0 ]; then
        log "WARNING: zapret: без NFQUEUE обход невозможен — выключен до перезагрузки; нужен VPN или другое ядро"
    elif [ "$cb" = 0 ]; then
        ZAPRET_CB_OUT=""
        log "WARNING: zapret: упрощённый режим — в nfqws все исходящие HTTPS-пакеты (больше нагрузка), без подстройки по ответу сервера (autottl, --wssize); автосписок — только по зависаниям"
        # GGC и отбой мёртвых — по одной строке SNI, без «первых пакетов»
        GGC_MATCH="-p tcp --dport 443 -m string --string googlevideo.com --algo bm"
        GVT_MATCH="-p tcp --dport 443 -m string --string gvt1.com --algo bm"
        yt_match_build
        # хуки от убитого демона с этим совпадением: чистка при старте снимала
        # только вариант с connbytes
        zapret_ggc_hooks_off "$iptables"; zapret_ggc_hooks_off "$ip6tables"; yt_dead_hooks_off
    fi
    [ "$str" = 0 ] && log "WARNING: zapret: без string — «YouTube мимо кэшей оператора» и отбой мёртвых серверов недоступны"
    return 0
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

# uid VPN-клиентов: известные пакеты + владельцы VPN, замеченные раньше
zapret_vpn_uids() {
    local p u out=""
    for p in $VPN_CLIENT_PKGS; do
        u=$(stat -c %u "/data/data/$p" 2>/dev/null)
        case "$u" in ''|*[!0-9]*) continue ;; esac
        out="$out $u"
    done
    [ -f "$ZAPRET_VPN_UIDS_FILE" ] && out="$out $(tr -c '0-9' ' ' < "$ZAPRET_VPN_UIDS_FILE")"
    echo $out | tr ' ' '\n' | awk '$1 ~ /^[0-9]+$/ && $1 >= 10000' | sort -un | tr '\n' ' '
}

# Владелец поднятого VPN (любой клиент, даже не из списка) — запоминаем
zapret_learn_vpn_owner() {
    local u
    u=$(dumpsys connectivity 2>/dev/null | grep -A3 'VPN CONNECTED' | grep -oE 'OwnerUid: [0-9]+' | head -1 | grep -oE '[0-9]+$')
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
    local ex="$1" i=0 a f out=""
    if [ "$ZAPRET_ALT" = "1" ] && [ "$ZAPRET_PER_NET" = "1" ] && [ -n "$NET_KEY" ] && [ -f "$ZALT_FILE" ]; then
        K="$NET_KEY" L="$NET_LABEL" awk -F'|' '
            $1 == ENVIRON["K"] { k[++nk] = $4 "|" $3 }
            ENVIRON["L"] != "" && $2 == ENVIRON["L"] { l[++nl] = $4 "|" $3 }
            END { if (nk) { for (i = 1; i <= nk; i++) print k[i] } else for (i = 1; i <= nl; i++) print l[i] }' \
            "$ZALT_FILE" 2>/dev/null > "$ZALT_RUN.lst"
        cut -d'|' -f1 "$ZALT_RUN.lst" | awk '!s[$0]++' > "$ZALT_RUN.args"
        while IFS= read -r a <&3; do
            [ "$i" -lt 3 ] || break
            zapret_args_valid "$a" || continue
            i=$((i + 1)); f="$ZALT_RUN.$i"
            A="$a" awk -F'|' '$1 == ENVIRON["A"] && $2 ~ /^[a-z0-9.-]+$/ { print $2 }' "$ZALT_RUN.lst" | sort -u > "$f.new"
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

# .ru/.su/.рф-сайты, которые явно есть во встроенном или своём списке —
# им обход нужен (заблокированные СМИ); файл переписывается только при изменении
zapret_ru_listed() {
    { sed 's/#.*//' "$ZAPRET_LIST_DEFAULT"; sed 's/#.*//' "$ZAPRET_LIST_USER" 2>/dev/null; } | \
        tr -d ' \r' | tr 'A-Z' 'a-z' | grep -E '(^|\.)(ru|su|xn--p1ai)$' | sort -u > "$ZAPRET_RU_RUN.new"
    if cmp -s "$ZAPRET_RU_RUN.new" "$ZAPRET_RU_RUN"; then rm -f "$ZAPRET_RU_RUN.new"; else mv -f "$ZAPRET_RU_RUN.new" "$ZAPRET_RU_RUN"; fi
}
# российские зоны из автосписка — вон (попадали туда по случайным обрывам)
zapret_auto_clean_ru() {
    local n
    [ -s "$ZAPRET_LIST_AUTO" ] && [ -s "$ZAPRET_LIST_RUTLD" ] || return 0
    n=$(grep -cE '(^|\.)(ru|su|xn--p1ai)$' "$ZAPRET_LIST_AUTO")
    [ "${n:-0}" -gt 0 ] || return 0
    grep -vE '(^|\.)(ru|su|xn--p1ai)$' "$ZAPRET_LIST_AUTO" > "$ZAPRET_LIST_AUTO.tmp"
    cat "$ZAPRET_LIST_AUTO.tmp" > "$ZAPRET_LIST_AUTO"; rm -f "$ZAPRET_LIST_AUTO.tmp"
    log "zapret: из автосписка убраны российские сайты ($n): их обход не трогает"
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

zapret_args() {
    local a="--qnum=$ZAPRET_QNUM --uid=0:$ZAPRET_GID --bind-fix4 --bind-fix6" ex="" g alt rup="" rux="" q
    # банки и Госуслуги — мимо обхода в любом профиле (и в автосписок не попадут)
    grep -q '[a-z0-9]' "$ZAPRET_LIST_EXCL" 2>/dev/null && ex="--hostlist-exclude=$ZAPRET_LIST_EXCL"
    # .ru/.su/.рф: основной профиль их не трогает и в автосписок не берёт;
    # такие сайты из списков — своим профилем перед ним, с той же стратегией
    if grep -q '^[a-z]' "$ZAPRET_LIST_RUTLD" 2>/dev/null; then
        rux="--hostlist-exclude=$ZAPRET_LIST_RUTLD"
        zapret_ru_listed
        [ -s "$ZAPRET_RU_RUN" ] && rup="--filter-tcp=443 $ex --hostlist=$ZAPRET_RU_RUN $(zapret_strategy_args "$ZAPRET_DIR" "$ZAPRET_EFF_STRATEGY" "$ZAPRET_EFF_ARGS") --new "
    fi
    g="--filter-tcp=443 $ex $rux"
    if [ "$ZAPRET_MODE" = "list" ]; then
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
    # (quic_block_apply), по нему — 6 поддельных QUIC Initial google.com
    q=""
    { [ "$QUIC_BLOCK_YT" = "1" ] && [ "$QUIC_YT_FAKE" = "1" ]; } || [ "$ZAPRET_QUIC_FAKE" = "1" ] && \
        q="--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=$ZAPRET_DIR/quic_initial_www_google_com.bin --new "
    if [ -n "$ZAPRET_EFF_YT" ] && grep -q '[a-z0-9]' "$ZAPRET_LIST_YT" 2>/dev/null; then
        echo "$a $q$alt--filter-tcp=443 $ex --hostlist=$ZAPRET_LIST_YT $(zapret_strategy_args "$ZAPRET_DIR" custom "$ZAPRET_EFF_YT") --new $rup$g"
    else
        echo "$a $q$alt$rup$g"
    fi
}

# Какая стратегия для текущей сети: запомненная для неё или общая
zapret_pick_strategy() {
    local e rc
    ZAPRET_EFF_STRATEGY="$ZAPRET_STRATEGY"
    ZAPRET_EFF_ARGS="$ZAPRET_ARGS"
    ZAPRET_EFF_YT=""
    ZAPRET_NET_SRC="default"
    [ "$ZAPRET_PER_NET" = "1" ] && [ -n "$NET_KEY" ] || return 0
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
    ZAPRET_EFF_YT="${e#*"|"}"
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
    # и сайты со своей стратегией — через ~10 мин (сеть успеет устояться)
    [ -n "$NET_KEY" ] && ZSITES_LAST=$(( $(date +%s) - ZAPRET_ALT_MIN * 60 + 600 ))
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
    "$NFQWS_BIN" $1 >> "$ZAPRET_LOG" 2>&1 &
    pid=$!
    sleep 0.5
    if kill -0 "$pid" 2>/dev/null; then
        echo "$pid" > "$ZAPRET_PID_FILE"
        ZAPRET_ALT_N=$(zapret_alt_count "$1")
        [ "$ZAPRET_ALT_N" -gt 0 ] && log "zapret: своя стратегия у $ZAPRET_ALT_N сайтов (их основная не открывала)"
        if [ "$ZAPRET_NET_SRC" = "net" ] || [ "$ZAPRET_NET_SRC" = "label" ]; then
            log "zapret: nfqws запущен (pid $pid, стратегия сети «$NET_LABEL»$([ "$ZAPRET_NET_SRC" = label ] && echo " — взята у сети с тем же названием, своей у $NET_KEY нет"): $ZAPRET_EFF_STRATEGY${ZAPRET_EFF_ARGS:+ [$ZAPRET_EFF_ARGS]}${ZAPRET_EFF_YT:+, YouTube: [$ZAPRET_EFF_YT]}, режим $ZAPRET_MODE)"
        else
            log "zapret: nfqws запущен (pid $pid, стратегия $ZAPRET_EFF_STRATEGY — общая${NET_LABEL:+, для «$NET_LABEL» своей нет}, режим $ZAPRET_MODE)"
        fi
        return 0
    fi
    log "WARNING: zapret: nfqws не запустился: $(tail -n 2 "$ZAPRET_LOG" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    return 1
}

# QUIC раздачи — подделка вместо закрытия (ZAPRET_QUIC_FAKE). Пакеты раздачи
# без uid, приложение не отличить — весь UDP 443 мимо VPN/WARP: первые 9 пакетов
# в nfqws (профиль --filter-udp=443). Только если профиль уже у запущенного
# nfqws и есть connbytes — иначе QUIC ушёл бы голым и умер молча (ТСПУ, 29.10)
CHAIN_ZAPRET_QF="VPN_ZAPRET_QF"
zapret_qf_off() {   # таблица
    local _n=0
    while [ $_n -lt 8 ] && $1 -t mangle -D FORWARD -p udp --dport 443 -j "$CHAIN_ZAPRET_QF" 2>/dev/null; do _n=$((_n + 1)); done
    $1 -t mangle -F "$CHAIN_ZAPRET_QF" 2>/dev/null
    $1 -t mangle -X "$CHAIN_ZAPRET_QF" 2>/dev/null
}

zapret_qf_on() {   # таблица; 0 — подделка QUIC для раздачи стоит
    zapret_qf_off "$1"
    [ "$ZAPRET_QUIC_FAKE" = "1" ] && zapret_cap cb || return 1
    case "$ZAPRET_ARGS_RUN" in *quic_initial_www_google_com.bin*) ;; *) return 1 ;; esac
    $1 -t mangle -N "$CHAIN_ZAPRET_QF" 2>/dev/null
    $1 -t mangle -A "$CHAIN_ZAPRET_QF" -o tun+ -j RETURN 2>/dev/null
    $1 -t mangle -A "$CHAIN_ZAPRET_QF" -o warp+ -j RETURN 2>/dev/null
    # shellcheck disable=SC2086
    $1 -t mangle -A "$CHAIN_ZAPRET_QF" $ZAPRET_CB_OUT -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null || \
        { zapret_qf_off "$1"; return 1; }
    $1 -t mangle -A FORWARD -p udp --dport 443 -j "$CHAIN_ZAPRET_QF" 2>/dev/null
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
        # метку выше на rmnet стирает qcom_qos_reset — дублируем по группе сокета
        $t -t mangle -A "$CHAIN_ZAPRET" -m owner --gid-owner "$ZAPRET_GID" -j RETURN 2>/dev/null
        if [ "$ZAPRET_PHONE" = "1" ]; then
            for u in $excl; do
                $t -t mangle -A "$CHAIN_ZAPRET" -m owner --uid-owner "$u" -j RETURN 2>/dev/null
            done
            [ -n "$DNSPROXY_GID" ] && \
                $t -t mangle -A "$CHAIN_ZAPRET" -m owner --gid-owner "$DNSPROXY_GID" -j RETURN 2>/dev/null
        else
            # только раздача: у её пакетов нет локального сокета
            $t -t mangle -A "$CHAIN_ZAPRET" -m owner --socket-exists -j RETURN 2>/dev/null
        fi
        # shellcheck disable=SC2086
        $t -t mangle -A "$CHAIN_ZAPRET" -p tcp --dport 443 $ZAPRET_CB_OUT \
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
        zapret_cap cb && $t -t mangle -A "$CHAIN_ZAPRET_IN" -p tcp --sport 443 \
            -m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:3 \
            -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null
        $t -t mangle -C PREROUTING -j "$CHAIN_ZAPRET_IN" 2>/dev/null || \
            $t -t mangle -A PREROUTING -j "$CHAIN_ZAPRET_IN" 2>/dev/null

        # QUIC раздачи мимо VPN: подделка (ZAPRET_QUIC_FAKE) главнее закрытия
        $t -N "$CHAIN_ZAPRET_QUIC" 2>/dev/null
        $t -F "$CHAIN_ZAPRET_QUIC" 2>/dev/null
        if zapret_qf_on "$t"; then
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
    if [ "$now" -lt "$due" ]; then
        # видео застревает на ClientHello — раньше срока, но не чаще раза в 3 мин
        [ "$n" -ge 3 ] && [ $((now - ZWD_LAST)) -ge 180 ] || return 0
        log "zapret: $n соединений YouTube застряли на ClientHello — сторож проверяет стратегию"
    fi
    zscan_running && return 0   # уже идёт подбор/проверка
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
    # прошлая сорвалась (scan.sh оставил метку) — повтор через ~15 мин
    if [ -f "${ZSCAN_PID_FILE%.pid}.sitesfail" ]; then
        rm -f "${ZSCAN_PID_FILE%.pid}.sitesfail"
        ZSITES_LAST=$((now - ZAPRET_ALT_MIN * 60 + 900))
        log "zapret: проверка сайтов сорвалась — повторю через ~15 мин"
    fi
    # первая — через ~10 мин после старта
    [ "$ZSITES_LAST" -eq 0 ] && { ZSITES_LAST=$((now - ZAPRET_ALT_MIN * 60 + 600)); return 0; }
    [ "$now" -ge $((ZSITES_LAST + ZAPRET_ALT_MIN * 60)) ] || return 0
    vpn_up_now && return 0
    zscan_running && return 0   # идёт подбор/сторож
    # сторож запустил scan.sh в этом же такте — его pid-файла ещё нет
    [ $((now - ZSCAN_JUST_TS)) -lt 10 ] && return 0
    ZSITES_LAST=$now
    log "zapret: проверяю сайты из списков — кому нужна своя стратегия"
    setsid sh "$ZAPRET_DIR/scan.sh" sites </dev/null >/dev/null 2>&1 &
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
        zapret_qf_off "$t"
    done
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
# запасные молчат): мимо обхода TLS до 1.1.1.1 и 9.9.9.9 не проходит, а до
# Яндекса проходит. Раз в минуту; ожил любой зарубежный — обход обратно.
zapret_tls_ok() {   # $1 — IP; мимо обхода и AdGuard (группа dnsproxy), через WAN
    local cmd c
    cmd="curl -sk -o /dev/null -m 3 --interface $LAST_WAN_IFACE -w %{http_code} https://$1/"
    if [ "$DNSPROXY_SU_G" = "1" ]; then c=$(su -g "$DNSPROXY_GID" -c "$cmd" 2>/dev/null); else c=$(eval "$cmd" 2>/dev/null); fi
    [ -n "$c" ] && [ "$c" != "000" ]
}
ZAPRET_WL_HITS=0       # подряд проверок «похоже на белые списки» (вход — со второй)
zapret_whitelist_check() {
    local now f p1 p2
    # дешёвое — первым: без отката DNS и без паузы делать нечего
    [ "$ZAPRET_WL" = "1" ] || [ "$DNS_DEGRADED" = "1" ] || { ZAPRET_WL_HITS=0; return 0; }
    [ "$ZAPRET_ENABLE" = "1" ] && [ -n "$NFQWS_BIN" ] && [ -n "$LAST_WAN_IFACE" ] || { ZAPRET_WL=0; ZAPRET_WL_HITS=0; return 0; }
    # VPN: прямой путь не проверить, и обход раздаче не нужен
    vpn_up_now && { ZAPRET_WL=0; ZAPRET_WL_HITS=0; return 0; }
    # DoH ожил — белых списков нет (в них молчат все DoH), даже если 1.1.1.1 и
    # 9.9.9.9 оператор закрыл отдельно (как 8.8.8.8 3 июля) — иначе пауза навсегда
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
    rm -f "$f".1 "$f".2
    ( zapret_tls_ok 1.1.1.1 && : > "$f".1 ) </dev/null >/dev/null 2>&1 & p1=$!
    ( zapret_tls_ok 9.9.9.9 && : > "$f".2 ) </dev/null >/dev/null 2>&1 & p2=$!
    wait $p1 $p2
    if [ -f "$f".1 ] || [ -f "$f".2 ]; then
        [ "$ZAPRET_WL" = "1" ] && log "zapret: зарубежные адреса снова открываются — белых списков нет, обход включаю"
        ZAPRET_WL=0; ZAPRET_WL_HITS=0
    elif zapret_tls_ok 77.88.55.242; then
        ZAPRET_WL_HITS=$((ZAPRET_WL_HITS + 1))
        # вход — со второй проверки подряд (минута): одна неудача — не повод
        if [ "$ZAPRET_WL" != "1" ] && [ "$ZAPRET_WL_HITS" -ge 2 ]; then
            log "zapret: похоже, белые списки оператора (Яндекс открывается, 1.1.1.1 и 9.9.9.9 — нет, 2 проверки подряд) — обход на паузе, проверяю раз в минуту"
            ZAPRET_WL=1
        fi
    fi
    # не отвечает и Яндекс — нет связи вообще: состояние не меняем
    rm -f "$f".1 "$f".2
}

# Каждая итерация цикла. Дорогое (dumpsys, stat пакетов) — раз в ~30с.
zapret_reconcile() {
    local args excl
    # возможности ядра — и при выключенном zapret: по файлу их берут проверка
    # сайта и регистрация WARP (ядро без connbytes, ревью 27.10)
    [ -n "$ZAPRET_CAPS" ] || zapret_caps
    if [ "$ZAPRET_ENABLE" != "1" ] || [ -z "$NFQWS_BIN" ]; then
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
    [ "$ZAPRET_PER_NET" = "1" ] && stamp=$(stat -c '%Y %s %i' "$ZAPRET_NETS_FILE" "$ZALT_FILE" 2>/dev/null)
    [ "$stamp" != "$ZAPRET_NETS_STAMP" ] && ZAPRET_NET_DIRTY=1
    ZAPRET_TICK=$((ZAPRET_TICK + 1))
    if [ "$ZAPRET_TICK" -ge 15 ] || [ "$ZAPRET_STATE" != "on" ] || [ "$ZAPRET_NET_DIRTY" = "1" ]; then
        ZAPRET_TICK=0
        ZAPRET_NET_DIRTY=0
        zapret_auto_log_trim
        zapret_nfqws_log_trim
        ZAPRET_NETS_STAMP="$stamp"
        # dumpsys connectivity тяжёлый (system_server) — раз на каждый tun, а
        # не каждые 30с: владелец VPN за сессию не меняется
        if vpn_up_now; then
            local _ti; _ti=$(read_table_index "$TUN_NAME")
            [ "$_ti" != "$ZAPRET_OWNER_TUN" ] && { zapret_learn_vpn_owner; ZAPRET_OWNER_TUN="$_ti"; }
        fi
        zapret_pick_strategy
        args=$(zapret_args)
        excl=$(zapret_vpn_uids)
        [ "$ZAPRET_STATE" = "on" ] && [ "$args" != "$ZAPRET_ARGS_RUN" ] && \
            log "zapret: аргументы nfqws сменились (сеть «${NET_LABEL:-не определена}», стратегия $ZAPRET_EFF_STRATEGY — $(case "$ZAPRET_NET_SRC" in net) echo своя ;; label) echo "как у «$NET_LABEL»" ;; *) echo общая ;; esac)) — перезапускаю"
    fi

    # nfqws: не запущен / умер / сменились аргументы (свой список, другая сеть)
    if [ "$args" != "$ZAPRET_ARGS_RUN" ] || ! zapret_alive; then
        [ "$ZAPRET_STATE" = "on" ] && [ "$args" = "$ZAPRET_ARGS_RUN" ] && \
            log "WARNING: zapret: nfqws умер, перезапускаю"
        if ! zapret_start "$args"; then
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
           { [ "$ZAPRET_QUIC_BLOCK" = "1" ] && ! $iptables -C FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null && \
             ! $iptables -t mangle -C FORWARD -p udp --dport 443 -j "$CHAIN_ZAPRET_QF" 2>/dev/null; } || \
           { case "$GGC_STATE" in v4*) ! $iptables -C FORWARD $GGC_MATCH -j "$CHAIN_ZAPRET_GGC" 2>/dev/null ;; *) false ;; esac; } || \
           { [ "$YT_DEAD_STATE" = "on" ] && ! $iptables -C FORWARD $GGC_MATCH -j "$CHAIN_YT_DEAD" 2>/dev/null; } || \
           { [ "$YT_GGC_BLOCK" = "1" ] && [ "$GGC_FAILS" -gt 0 ] && [ "$GGC_FAILS" -lt 3 ] && zapret_cap str; } || \
           { [ "$YT_DEAD_STATE" = "fail" ] && [ "$YT_DEAD_FAILS" -lt 3 ]; }; then
            _hooks_bad=1
            # повтор не вставших GGC/отбоя — не «правила пропали»
            if [ "$GGC_FAILS" -gt 0 ] || [ "$YT_DEAD_STATE" = "fail" ]; then
                log "zapret: повторяю правила «мимо кэшей оператора»/отбоя мёртвых серверов (попытка $((GGC_FAILS > YT_DEAD_FAILS ? GGC_FAILS + 1 : YT_DEAD_FAILS + 1)) из 3)"
                ZAPRET_RETRY_LOGGED=1
            fi
        fi
    fi
    if [ "$ZAPRET_STATE" != "on" ] || [ "$excl" != "$ZAPRET_EXCL_RUN" ] || [ "$_hooks_bad" = 1 ]; then
        zapret_rules_on "$excl"
        if [ "$ZAPRET_STATE" != "on" ]; then
            log "zapret: включён (режим $ZAPRET_MODE, телефон: $ZAPRET_PHONE, QUIC раздачи: $(if $iptables -t mangle -C FORWARD -p udp --dport 443 -j "$CHAIN_ZAPRET_QF" 2>/dev/null; then echo подделка; elif [ "$ZAPRET_QUIC_BLOCK" = 1 ]; then echo закрыт; else echo открыт; fi); VPN-клиенты в исключениях: ${excl:-нет})"
        elif [ "$excl" != "$ZAPRET_EXCL_RUN" ]; then
            log "zapret: исключения VPN-клиентов: ${excl:-нет}"
        else
            [ "$ZAPRET_RETRY_LOGGED" = 1 ] || log "WATCHDOG: zapret: правила пропали, ставлю заново"
            ZAPRET_RETRY_LOGGED=0
        fi
        ZAPRET_EXCL_RUN="$excl"
        ZAPRET_STATE="on"
        quic_block_apply    # подделка QUIC возможна только при работающем nfqws
        phone_status_refresh
    fi
}

