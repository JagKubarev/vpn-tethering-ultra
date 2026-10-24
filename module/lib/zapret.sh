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
quic_block_uids() {
    local p u out=""
    for p in $QUIC_BLOCK_APPS; do
        u=$(stat -c %u "/data/data/$p" 2>/dev/null)
        case "$u" in ''|*[!0-9]*) continue ;; esac
        [ "$u" -ge 10000 ] && out="$out $u"
    done
    echo "${out# }"
}

quic_block_apply() {
    local uids t u rj
    [ -n "$QUIC_BLOCK_APPS" ] || return 0
    uids=$(quic_block_uids)
    if [ "$uids" = "$QUIC_UIDS" ] && [ "$QUIC_LOGGED" = "1" ] && \
       $iptables -C OUTPUT -j "$CHAIN_QUIC" 2>/dev/null; then
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
    done
    if [ "$uids" != "$QUIC_UIDS" ] || [ "$QUIC_LOGGED" != "1" ]; then
        log "QUIC (UDP 443) закрыт для: $QUIC_BLOCK_APPS (uid: ${uids:-не установлены})"
    fi
    QUIC_UIDS="$uids"
    QUIC_LOGGED=1
}

quic_block_down() {
    local t _n
    for t in "$iptables" "$ip6tables"; do
        _n=0
        while [ $_n -lt 8 ] && $t -D OUTPUT -j "$CHAIN_QUIC" 2>/dev/null; do _n=$((_n + 1)); done
        $t -F "$CHAIN_QUIC" 2>/dev/null
        $t -X "$CHAIN_QUIC" 2>/dev/null
    done
    QUIC_UIDS=""
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

zapret_alive() {
    local pid
    pid=$(cat "$ZAPRET_PID_FILE" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && grep -q nfqws "/proc/$pid/cmdline" 2>/dev/null
}

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

zapret_args() {
    local a="--qnum=$ZAPRET_QNUM --uid=0:$ZAPRET_GID --bind-fix4 --bind-fix6" ex="" g alt rup="" rux=""
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
    if [ -n "$ZAPRET_EFF_YT" ] && grep -q '[a-z0-9]' "$ZAPRET_LIST_YT" 2>/dev/null; then
        echo "$a $alt--filter-tcp=443 $ex --hostlist=$ZAPRET_LIST_YT $(zapret_strategy_args "$ZAPRET_DIR" custom "$ZAPRET_EFF_YT") --new $rup$g"
    else
        echo "$a $alt$rup$g"
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
        $t -t mangle -A "$CHAIN_ZAPRET" -o lo -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET" -d "$lan" -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET" -m mark --mark "$ZAPRET_MARK/$ZAPRET_MARK" -j RETURN 2>/dev/null
        # метку выше на rmnet стирает qcom_qos_reset — дублируем по группе сокета
        $t -t mangle -A "$CHAIN_ZAPRET" -m owner --gid-owner "$ZAPRET_GID" -j RETURN 2>/dev/null
        # opera-proxy (Telegram через Opera) — его TLS к серверам Opera обход не трогает
        [ -n "$OPERA_GID" ] && \
            $t -t mangle -A "$CHAIN_ZAPRET" -m owner --gid-owner "$OPERA_GID" -j RETURN 2>/dev/null
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
        $t -t mangle -A "$CHAIN_ZAPRET" -p tcp --dport 443 \
            -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 \
            -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null
        $t -t mangle -C POSTROUTING -j "$CHAIN_ZAPRET" 2>/dev/null || \
            $t -t mangle -A POSTROUTING -j "$CHAIN_ZAPRET" 2>/dev/null

        # ответы (автосписок, --wssize, autottl)
        $t -t mangle -N "$CHAIN_ZAPRET_IN" 2>/dev/null
        $t -t mangle -F "$CHAIN_ZAPRET_IN" 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET_IN" -i tun+ -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET_IN" -i lo -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET_IN" -s "$lan" -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET_IN" -p tcp --sport 443 \
            -m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:3 \
            -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null
        $t -t mangle -C PREROUTING -j "$CHAIN_ZAPRET_IN" 2>/dev/null || \
            $t -t mangle -A PREROUTING -j "$CHAIN_ZAPRET_IN" 2>/dev/null

        # QUIC раздачи мимо VPN
        $t -N "$CHAIN_ZAPRET_QUIC" 2>/dev/null
        $t -F "$CHAIN_ZAPRET_QUIC" 2>/dev/null
        if [ "$ZAPRET_QUIC_BLOCK" = "1" ]; then
            $t -A "$CHAIN_ZAPRET_QUIC" -o tun+ -j RETURN 2>/dev/null
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
    pid=$(cat "$ZSCAN_PID_FILE" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && return 0   # уже идёт подбор/проверка
    ZWD_LAST=$now
    YT_STUCK=""
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
    pid=$(cat "$ZSCAN_PID_FILE" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && return 0   # идёт подбор/сторож
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
    done
    zapret_ggc_off
    yt_dead_off
}

zapret_down() {
    zapret_rules_off
    zapret_kill_all
    [ "$ZAPRET_STATE" = "on" ] && log "zapret: выключен"
    ZAPRET_STATE="off"
    ZAPRET_ARGS_RUN=""
    ZAPRET_EXCL_RUN=""
    ZAPRET_RETRY=0
    ZAPRET_TICK=0
    ZAPRET_NETS_STAMP=""
    phone_status_refresh
}

# Каждая итерация цикла. Дорогое (dumpsys, stat пакетов) — раз в ~30с.
zapret_reconcile() {
    local args excl
    if [ "$ZAPRET_ENABLE" != "1" ] || [ -z "$NFQWS_BIN" ]; then
        [ "$ZAPRET_STATE" != "off" ] && zapret_down
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
            phone_status_refresh
            return 0
        fi
        ZAPRET_ARGS_RUN="$args"
        # Был включён (смена стратегии, nfqws умер) — правила на месте, их
        # не трогаем: пока nfqws перезапускался, --queue-bypass пропускал пакеты
        if [ "$ZAPRET_STATE" = "on" ]; then phone_status_refresh; else ZAPRET_STATE="starting"; fi
    fi

    # правила: впервые / сменились исключения / хук снесли (netd пересобрал
    # цепочки). iptables -C читает всю таблицу (у Android тысячи правил) —
    # хуки проверяем раз в ~10с: без хука zapret просто не работает, утечки нет
    local _hooks_bad=0
    ZAPRET_HOOK_TICK=$((ZAPRET_HOOK_TICK + 1))
    if [ "$ZAPRET_STATE" = "on" ] && [ "$ZAPRET_HOOK_TICK" -ge 5 ]; then
        ZAPRET_HOOK_TICK=0
        if ! $iptables -t mangle -C POSTROUTING -j "$CHAIN_ZAPRET" 2>/dev/null || \
           { [ "$ZAPRET_QUIC_BLOCK" = "1" ] && ! $iptables -C FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null; } || \
           { [ -n "$GGC_STATE" ] && ! $iptables -C FORWARD $GGC_MATCH -j "$CHAIN_ZAPRET_GGC" 2>/dev/null; } || \
           { [ "$YT_DEAD_STATE" = "on" ] && ! $iptables -C FORWARD $GGC_MATCH -j "$CHAIN_YT_DEAD" 2>/dev/null; }; then
            _hooks_bad=1
        fi
    fi
    if [ "$ZAPRET_STATE" != "on" ] || [ "$excl" != "$ZAPRET_EXCL_RUN" ] || [ "$_hooks_bad" = 1 ]; then
        zapret_rules_on "$excl"
        if [ "$ZAPRET_STATE" != "on" ]; then
            log "zapret: включён (режим $ZAPRET_MODE, телефон: $ZAPRET_PHONE, QUIC раздачи: $([ "$ZAPRET_QUIC_BLOCK" = 1 ] && echo закрыт || echo открыт); VPN-клиенты в исключениях: ${excl:-нет})"
        elif [ "$excl" != "$ZAPRET_EXCL_RUN" ]; then
            log "zapret: исключения VPN-клиентов: ${excl:-нет}"
        else
            log "WATCHDOG: zapret: правила пропали, ставлю заново"
        fi
        ZAPRET_EXCL_RUN="$excl"
        ZAPRET_STATE="on"
        phone_status_refresh
    fi
}

