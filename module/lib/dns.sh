# shellcheck shell=sh
# lib/dns.sh — DNS: перехват DNS клиентов, dnsproxy (запуск, проверки, откат,
# запасные DoH), Meta «из Европы», DNS самого телефона.
# Часть демона service.sh: подключается из него через ".", сам не запускается.
# Настройки (USER CONFIG) и общие переменные — в service.sh.

cleanup_dns_redirect() {
    $iptables -t nat -D PREROUTING -j "$CHAIN_DNS" 2>/dev/null
    $iptables -t nat -F "$CHAIN_DNS" 2>/dev/null
    $iptables -t nat -X "$CHAIN_DNS" 2>/dev/null
    
    $ip6tables -t nat -D PREROUTING -j "$CHAIN_DNS6" 2>/dev/null
    $ip6tables -t nat -F "$CHAIN_DNS6" 2>/dev/null
    $ip6tables -t nat -X "$CHAIN_DNS6" 2>/dev/null
}

# Старые DNS-потоки раздачи из conntrack — после смены правил DNS. NAT
# решается на первом пакете потока: запрос, пришедший до новых правил (в
# окне между flush_conntrack и установкой — 25.10 при выключении VPN, или
# ещё в прежнем режиме), так и ходит по старому пути. Windows шлёт DNS из
# пула постоянных портов — такая запись продлевается каждым запросом
# (25.10: порт 61415, 7 запросов, 155 с из 180) и DNS ноутбука «как от VPN»,
# пока не переподключишь его или не переключишь DoH. Только порт 53 и только
# подсети раздачи — остальные потоки не трогаем.
dns_conntrack_flush() {
    local iface net p
    [ -n "$CONNTRACK_BIN" ] || return 0
    for iface in "$@"; do
        net=$($ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet /{print $2; exit}')
        case "$net" in */*) ;; *) continue ;; esac
        for p in udp tcp; do
            "$CONNTRACK_BIN" -D -p $p --orig-src "$net" --orig-port-dst 53 >/dev/null 2>&1
        done
    done
}

setup_dns_redirect() {
    local dns_servers=$1
    local dns4="${dns_servers%%"|"*}"
    local dns6="${dns_servers##*"|"}"
    shift
    local tether_ifaces="$*"
    [ -z "$tether_ifaces" ] && return

    cleanup_dns_redirect
    
    local valid_dns4=""
    [ -n "$dns4" ] && [ "$dns4" != "null" ] && valid_dns4=$(_parse_ip4_safe "$dns4" 2>/dev/null)
    
    if [ -n "$valid_dns4" ]; then
        $iptables -t nat -N "$CHAIN_DNS" 2>/dev/null
        $iptables -t nat -F "$CHAIN_DNS"
        $iptables -t nat -C PREROUTING -j "$CHAIN_DNS" 2>/dev/null || \
            $iptables -t nat -I PREROUTING 1 -j "$CHAIN_DNS" 2>/dev/null
        
        local added=0
        for iface in $tether_ifaces; do
            $iptables -t nat -A "$CHAIN_DNS" -i "$iface" -p udp --dport 53 -j DNAT --to-destination "$valid_dns4" 2>/dev/null && added=$((added + 1))
            $iptables -t nat -A "$CHAIN_DNS" -i "$iface" -p tcp --dport 53 -j DNAT --to-destination "$valid_dns4" 2>/dev/null && added=$((added + 1))
        done
        log "DNS IPv4 redirect to $valid_dns4 ($added rules)"
    else
        log "WARNING: No valid IPv4 DNS, using fallback 1.1.1.1"
        $iptables -t nat -N "$CHAIN_DNS" 2>/dev/null
        $iptables -t nat -F "$CHAIN_DNS"
        $iptables -t nat -C PREROUTING -j "$CHAIN_DNS" 2>/dev/null || \
            $iptables -t nat -I PREROUTING 1 -j "$CHAIN_DNS" 2>/dev/null
        for iface in $tether_ifaces; do
            $iptables -t nat -A "$CHAIN_DNS" -i "$iface" -p udp --dport 53 -j DNAT --to-destination "1.1.1.1" 2>/dev/null
            $iptables -t nat -A "$CHAIN_DNS" -i "$iface" -p tcp --dport 53 -j DNAT --to-destination "1.1.1.1" 2>/dev/null
        done
        log "DNS IPv4 redirect to 1.1.1.1 (fallback)"
    fi
    
    local valid_dns6=""
    [ -n "$dns6" ] && [ "$dns6" != "null" ] && [ "$dns6" != "::" ] && valid_dns6=$(_parse_ip6_safe "$dns6" 2>/dev/null)
    
    if [ -n "$valid_dns6" ] && $ip6tables -t nat -L >/dev/null 2>&1; then
        $ip6tables -t nat -N "$CHAIN_DNS6" 2>/dev/null
        $ip6tables -t nat -F "$CHAIN_DNS6"
        $ip6tables -t nat -C PREROUTING -j "$CHAIN_DNS6" 2>/dev/null || \
            $ip6tables -t nat -I PREROUTING 1 -j "$CHAIN_DNS6" 2>/dev/null
        
        local added6=0
        for iface in $tether_ifaces; do
            $ip6tables -t nat -A "$CHAIN_DNS6" -i "$iface" -p udp --dport 53 -j DNAT --to-destination "$valid_dns6" 2>/dev/null && added6=$((added6 + 1))
            $ip6tables -t nat -A "$CHAIN_DNS6" -i "$iface" -p tcp --dport 53 -j DNAT --to-destination "$valid_dns6" 2>/dev/null && added6=$((added6 + 1))
        done
        log "DNS IPv6 redirect to $valid_dns6 ($added6 rules)"
    fi
    dns_conntrack_flush $tether_ifaces
}

# ============================================================================
# DNS через dnsproxy
# ============================================================================
dnsproxy_alive() {
    local pid
    pid=$(cat "$DNSPROXY_PID_FILE" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && \
        grep -q dnsproxy "/proc/$pid/cmdline" 2>/dev/null
}

# dnsproxy слушает 0.0.0.0 (адрес раздачи меняется при каждом старте
# хотспота), поэтому доступ режем фаерволом: только tether-ифейсы и lo.
# Go слушает 0.0.0.0 как dual-stack ([::]:порт), поэтому режем и в ip6tables:
# иначе у оператора с глобальным IPv6 порт был бы открытым резолвером.
dnsproxy_port_guard() {
    local iface t
    for t in "$iptables" "$ip6tables"; do
        $t -N "$CHAIN_DNSP" 2>/dev/null
        $t -F "$CHAIN_DNSP" 2>/dev/null
        $t -A "$CHAIN_DNSP" -i lo -j RETURN 2>/dev/null
        for iface in "$@"; do
            $t -A "$CHAIN_DNSP" -i "$iface" -j RETURN 2>/dev/null
        done
        $t -A "$CHAIN_DNSP" -j DROP 2>/dev/null
        $t -C INPUT -p udp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null || \
            $t -I INPUT 1 -p udp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null
        $t -C INPUT -p tcp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null || \
            $t -I INPUT 1 -p tcp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null
    done
}

dnsproxy_port_guard_down() {
    local _n t
    for t in "$iptables" "$ip6tables"; do
        _n=0
        while [ $_n -lt 8 ] && $t -D INPUT -p udp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null; do _n=$((_n + 1)); done
        _n=0
        while [ $_n -lt 8 ] && $t -D INPUT -p tcp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null; do _n=$((_n + 1)); done
        $t -F "$CHAIN_DNSP" 2>/dev/null
        $t -X "$CHAIN_DNSP" 2>/dev/null
    done
}

dnsproxy_stop() {
    local pid i
    pid=$(cat "$DNSPROXY_PID_FILE" 2>/dev/null)
    if [ -n "$pid" ] && grep -q dnsproxy "/proc/$pid/cmdline" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        i=0
        while [ $i -lt 10 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
        kill -9 "$pid" 2>/dev/null
        log "dnsproxy остановлен (pid $pid)"
    fi
    # и всё, что могло остаться от прошлых запусков (обёртка su, гонки)
    for pid in $(dnsproxy_pids); do kill -9 "$pid" 2>/dev/null; done
    rm -f "$DNSPROXY_PID_FILE"
    DNSPROXY_SIG=""
    meta_eu_stop
    dnsproxy_exempt_down
}

# PID-ы процессов, чей argv[0] — наш dnsproxy (grep и обёртки su/sh не в счёт)
# $1 — порт экземпляра (по умолчанию основной)
dnsproxy_pids() {
    local f port="${1:-$DNSPROXY_PORT}"
    for f in $(grep -l "$MODULE_DIR/bin/dnsproxy" /proc/[0-9]*/cmdline 2>/dev/null); do
        # только наш экземпляр (наш порт): чужие dnsproxy с этим же бинарём
        # (тесты, второй модуль) не трогаем и не принимаем за свой pid
        case "$(tr '\0' ' ' 2>/dev/null < "$f")" in
            "$MODULE_DIR/bin/dnsproxy"*" -p $port "*) f="${f#/proc/}"; echo "${f%/cmdline}" ;;
        esac
    done
}

# Осиротевшие экземпляры от убитого демона (pid-файл мог потеряться)
dnsproxy_kill_strays() {
    local pid
    for pid in $(dnsproxy_pids) $(dnsproxy_pids "$META_EU_PORT"); do
        kill -9 "$pid" 2>/dev/null && log "Убит осиротевший dnsproxy $pid"
    done
}

# Запуск dnsproxy от root:DNSPROXY_GID (мимо перехвата AdGuard).
# dnsproxy_spawn "<аргументы>" <лог>
dnsproxy_spawn() {
    # Статический Go не находит CA Android 14+ (лежат в APEX conscrypt) ->
    # "x509: certificate signed by unknown authority". Только системные CA:
    # пользовательские (cacerts-added, напр. AdGuard HTTPS-фильтр) не берём.
    local certs="SSL_CERT_DIR=/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts"
    if [ "$DNSPROXY_SU_G" = "1" ]; then
        dnsproxy_exempt force
        su -g "$DNSPROXY_GID" -c "$certs exec $DNSPROXY_BIN $1 -o $2" >/dev/null 2>&1 < /dev/null &
    else
        env "$certs" $DNSPROXY_BIN $1 -o "$2" >/dev/null 2>&1 < /dev/null &
    fi
}

# ----------------------------------------------------------------------------
# DNS_META_EU: домены Meta основной dnsproxy отдаёт второму экземпляру
# (127.0.0.1:META_EU_PORT), а тот спрашивает Google с EDNS Client Subnet
# DNS_META_ECS — ответы "как для Европы". Второй живёт и умирает вместе с
# основным (dnsproxy_start/stop). Упал — основной для этих доменов уходит на
# фолбэки: Meta резолвится как обычно, без чёрной дыры.
# Список апстримов — файлом: в аргументах "[/домены/]адрес" — скобки, а
# строка аргументов разбивается шеллом (и ещё раз в su -c).
# ----------------------------------------------------------------------------
META_EU_PORT=5355
META_EU_LOG="/data/local/tmp/vpn_tether_dnsproxy_meta.log"
META_EU_UPS_FILE="/data/local/tmp/vpn_tether_meta_upstreams"
META_DOMAINS="instagram.com cdninstagram.com instagr.am ig.me facebook.com fbcdn.net fbsbx.com facebook.net fb.com fb.me messenger.com threads.net threads.com meta.com"
DNSPROXY_META_ON=0

meta_eu_stop() {
    local pid
    for pid in $(dnsproxy_pids "$META_EU_PORT"); do kill -9 "$pid" 2>/dev/null; done
    DNSPROXY_META_ON=0
}

meta_eu_start() {
    local args u i
    meta_eu_stop
    args="-l 127.0.0.1 -p $META_EU_PORT --edns --edns-addr=$DNS_META_ECS --timeout=3s --refuse-any"
    for u in $DNS_META_UPSTREAMS; do args="$args -u $u"; done
    for u in $DNS_FALLBACKS; do args="$args -f $u"; done
    for u in $DNS_BOOTSTRAP $DNS_BOOTSTRAP_ENC; do args="$args -b $u"; done
    : > "$META_EU_LOG"
    dnsproxy_spawn "$args" "$META_EU_LOG"
    i=0
    while [ $i -lt 25 ]; do
        sleep 0.2
        if [ -n "$(dnsproxy_pids "$META_EU_PORT")" ] && \
           ss -lun 2>/dev/null | grep -qE "[:.]$META_EU_PORT[[:space:]]"; then
            DNSPROXY_META_ON=1
            return 0
        fi
        i=$((i + 1))
    done
    log "WARNING: dnsproxy для Meta (ECS) не поднялся: $(tail -n 2 "$META_EU_LOG" 2>/dev/null | tr '\n' ' ' | cut -c1-160) — Meta резолвится как обычно"
    meta_eu_stop
    return 1
}

# Из цикла, раз в ~30с: второй экземпляр умер при живом основном
meta_eu_watchdog() {
    [ "$DNSPROXY_META_ON" = "1" ] || return 0
    dnsproxy_alive || return 0
    [ -n "$(dnsproxy_pids "$META_EU_PORT")" ] && return 0
    log "WATCHDOG: dnsproxy для Meta (ECS) умер, перезапускаю"
    meta_eu_start && log "dnsproxy для Meta (ECS) снова поднят"
}

# Исключение dnsproxy из перехвата AdGuard: RETURN по GID первым в nat OUTPUT.
# AdGuard при перезапуске вставляет свой jump в позицию 1 — поэтому проверяем
# именно позицию, а не наличие.
dnsproxy_exempt() {   # [force] — без него не чаще раза в ~10с (зовут 2 раза за цикл)
    local t want
    [ "$DNSPROXY_SU_G" = "1" ] || return 0
    if [ "$1" != "force" ]; then
        DNS_EXEMPT_TICK=$((DNS_EXEMPT_TICK + 1))
        [ "$DNS_EXEMPT_TICK" -ge 10 ] || return 0
    fi
    DNS_EXEMPT_TICK=0
    want="-A OUTPUT -m owner --gid-owner $DNSPROXY_GID -j RETURN"
    for t in "$iptables" "$ip6tables"; do
        [ "$($t -t nat -S OUTPUT 2>/dev/null | sed -n 2p)" = "$want" ] && continue
        local _n=0
        while [ $_n -lt 8 ] && $t -t nat -D OUTPUT -m owner --gid-owner "$DNSPROXY_GID" -j RETURN 2>/dev/null; do _n=$((_n + 1)); done
        $t -t nat -I OUTPUT 1 -m owner --gid-owner "$DNSPROXY_GID" -j RETURN 2>/dev/null
    done
}

dnsproxy_exempt_down() {
    local t _n
    [ -n "$DNSPROXY_GID" ] || return 0
    for t in "$iptables" "$ip6tables"; do
        _n=0
        while [ $_n -lt 8 ] && $t -t nat -D OUTPUT -m owner --gid-owner "$DNSPROXY_GID" -j RETURN 2>/dev/null; do _n=$((_n + 1)); done
    done
}

# Настоящий DNS-запрос к dnsproxy, ~5с максимум. 0 = апстрим ответил.
# Имя случайное (p<9 цифр>.example.com): cache-optimistic отдаёт из кэша даже
# протухшее, и запрос example.com "проходил" при мёртвом апстриме.
# NOERROR и NXDOMAIN = апстрим живой; SERVFAIL/тишина = нет.
#
# Медленный ответ = отказ. Замер (comss режется, Google жив): dnsproxy отвечал
# через фолбэк за ~9с — "успех" для проверки, но клиенты (Android ~5с) к тому
# времени уже сдаются. Порог DNS_PROBE_SLOW_MS включает ~1с, которую nc
# ждёт после ответа.
#
# Время меряется до ПРИХОДА ответа, а не до выхода nc: busybox nc сам по себе
# добавляет ~2с (ждёт -w и при подключении, и после ответа) — замер на
# кэшированном имени = ровно 2000мс. nc пишет в файл в фоне, мы раз в 50мс
# смотрим, появился ли ответ. Часы — /proc/uptime (сотые доли секунды):
# маленькие числа, считаются и в 32-битной арифметике (mksh), в отличие
# от date +%s%N.
DNS_PROBE_LAST_MS=""
uptime_ms() {
    local u
    read -r u _ < /proc/uptime
    u="${u%.*}${u#*.}"
    u="${u#${u%%[!0]*}}"
    echo $(( ${u:-0} * 10 ))
}

dnsproxy_probe() {   # [адрес] — по умолчанию dnsproxy; с адресом — :53 от группы dnsproxy
    local lbl f nc_pid t0 now out nc
    [ -n "$BUSYBOX" ] || return 0   # нечем проверить — не блокируем запуск
    lbl=$(printf 'p%09d' $(( ($(date +%s) % 100000) * 10000 + RANDOM % 10000 )))
    f="/data/local/tmp/vpn_tether_probe.$$"
    : > "$f"
    nc="$BUSYBOX nc -u -w $DNS_PROBE_TIMEOUT 127.0.0.1 $DNSPROXY_PORT"
    if [ -n "$1" ]; then
        # мимо перехвата DNS телефона: от root он ушёл бы в тот же dnsproxy
        nc="$BUSYBOX nc -u -w $DNS_PROBE_TIMEOUT $1 53"
        [ "$DNSPROXY_SU_G" = "1" ] && nc="su -g $DNSPROXY_GID -c '$nc'"
    fi
    printf '\022\064\001\000\000\001\000\000\000\000\000\000\012%s\007example\003com\000\000\001\000\001' "$lbl" | \
        eval "$nc" > "$f" 2>/dev/null &
    nc_pid=$!
    t0=$(uptime_ms)
    while :; do
        [ -s "$f" ] && break
        now=$(uptime_ms)
        [ $((now - t0)) -ge $((DNS_PROBE_TIMEOUT * 1000)) ] && break
        sleep 0.05
    done
    now=$(uptime_ms)
    kill "$nc_pid" 2>/dev/null
    out=$($BUSYBOX od -An -tx1 -N4 "$f" 2>/dev/null)
    rm -f "$f"
    # " 12 34 81 83": id, флаги (rcode = младшие 4 бита 4-го байта)
    set -- $out
    if [ "$1$2" != "1234" ]; then
        DNS_PROBE_LAST_MS="нет ответа за ${DNS_PROBE_TIMEOUT}с"
        return 1
    fi
    case $(( 0x${4:-ff} & 15 )) in
        0|3) ;;                                   # NOERROR / NXDOMAIN — апстрим жив
        *) DNS_PROBE_LAST_MS="rcode $(( 0x$4 & 15 ))"; return 1 ;;
    esac
    DNS_PROBE_LAST_MS=$((now - t0))
    [ "$DNS_PROBE_LAST_MS" -le "$DNS_PROBE_SLOW_MS" ] && return 0
    return 2
}

# Первое соединение холодное (bootstrap + TLS) — "медленно" ещё не приговор:
# повторяем один раз по уже прогретому. Нет ответа вовсе — без повтора.
dnsproxy_probe_cold() {
    dnsproxy_probe
    case $? in
        0) return 0 ;;
        2) dnsproxy_probe; return $? ;;
        *) return 1 ;;
    esac
}

# dnsproxy_start <тег режима> <апстримы...>
# Перезапускает только при смене режима/апстримов. 0 = порт слушается.
dnsproxy_start() {
    local tag="$1"; shift
    local ups="$*" sig args u i

    [ -n "$DNSPROXY_BIN" ] || { log "WARNING: нет bin/dnsproxy, DNS по-старому"; return 1; }
    sig="$tag|$ups"
    local route_now
    route_now=$(route_id)
    if [ "$sig" = "$DNSPROXY_SIG" ] && dnsproxy_alive; then
        [ "$DNSPROXY_STARTED_ROUTE" = "$route_now" ] && return 0
        # Тот же режим, но у root другой маршрут (VPN поднялся/пропал, или без
        # VPN сменился WAN), а DoH-соединение dnsproxy осталось на прежнем.
        # Раньше перезапуск делал только phone_dns_reconcile — уже ПОСЛЕ
        # apply_state, и проверка в apply_dns_mode шла через старое
        # соединение -> ложный откат на 30с (лог 1.3.2, 09:24:30-09:25:06).
        log "dnsproxy: маршрут сменился ($DNSPROXY_STARTED_ROUTE -> $route_now) — перезапуск"
        dns_route_changed
    fi
    dnsproxy_stop

    # timeout 3с: при "молчащем" апстриме (белые списки) запрос висел ~15с.
    # cache-max-ttl: comss отдаёт TTL ~2,5 ч вместо 20-60 с у оригинала (CDN
    # Авито, Google и т.п.) — смена узла CDN доезжала бы до клиентов часами.
    args="-l 0.0.0.0 -p $DNSPROXY_PORT --cache --cache-optimistic --cache-max-ttl=600 --timeout=3s --refuse-any"
    for u in $ups; do args="$args -u $u"; done
    local fb="$DNS_FALLBACKS"
    if [ -n "$DNS_ALT_UPS" ] && [ "$ups" = "$DNS_ALT_UPS" ]; then
        # на запасном: остальные запасные и сам основной — его фолбэки
        fb=$(for u in $DNS_FALLBACKS $DNS_UPSTREAMS; do [ "$u" = "$DNS_ALT_UPS" ] || echo "$u"; done | awk '!s[$0]++')
        fb=$(echo $fb)
    fi
    # фолбэком не повторяем то, что уже основное (comss есть и в DNS_FALLBACKS)
    for u in $fb; do case " $ups " in *" $u "*) continue ;; esac; args="$args -f $u"; done
    for u in $DNS_BOOTSTRAP $DNS_BOOTSTRAP_ENC; do args="$args -b $u"; done

    : > "$DNSPROXY_LOG"

    if [ -z "$DNSPROXY_SU_G" ]; then
        DNSPROXY_SU_G=0
        [ -n "$DNSPROXY_GID" ] && su -g "$DNSPROXY_GID" -c true >/dev/null 2>&1 && DNSPROXY_SU_G=1
        [ -n "$DNSPROXY_GID" ] && [ "$DNSPROXY_SU_G" = "0" ] && \
            log "WARNING: su -g не работает — dnsproxy без своего GID, HTTPS-фильтр AdGuard сломает DoH"
    fi

    # Meta "как из Европы" — только у экземпляра без VPN (direct-doh: раздача
    # напрямую и DNS телефона). Через VPN Meta и так открывается, а ECS
    # Амстердама с выходом VPN в другой стране только запутал бы CDN.
    local meta=""
    if [ "$DNS_META_EU" = "1" ] && [ "$tag" = "direct-doh" ]; then
        if meta_eu_start; then
            printf '[/%s/]127.0.0.1:%s\n' "$(echo $META_DOMAINS | tr ' ' '/')" "$META_EU_PORT" > "$META_EU_UPS_FILE"
            args="$args -u $META_EU_UPS_FILE"
            meta=" + Meta через ECS $DNS_META_ECS"
        fi
    fi

    dnsproxy_spawn "$args" "$DNSPROXY_LOG"

    # $! тут — su/env, а не сам dnsproxy: ищем по argv[0]
    i=0
    while [ $i -lt 25 ]; do
        sleep 0.2
        u=$(dnsproxy_pids | head -1)
        [ -n "$u" ] && echo "$u" > "$DNSPROXY_PID_FILE"
        if [ -n "$u" ] && ss -lun 2>/dev/null | grep -qE "[:.]$DNSPROXY_PORT[[:space:]]"; then
            DNSPROXY_SIG="$sig"
            DNSPROXY_STARTED_ROUTE="$route_now"
            log "dnsproxy запущен (pid $u, gid ${DNSPROXY_GID:-0}, $tag): $ups$meta"
            return 0
        fi
        i=$((i + 1))
    done
    log "ERROR: dnsproxy не поднялся: $(tail -n 3 "$DNSPROXY_LOG" 2>/dev/null | tr '\n' ' ')"
    dnsproxy_stop
    # сигнатуру — обратно: перезапуски обнуляют её перед стартом, и сторож
    # с пустой поднимал бы dnsproxy без апстримов — DNAT навсегда (ревью DNS)
    DNSPROXY_SIG="$sig"
    return 1
}

# VPN сейчас поднят (у tun есть адрес)
vpn_up_now() {
    $ip addr show "$TUN_NAME" 2>/dev/null | grep -q "inet "
}

# Каким путём сейчас ходит трафик root (а значит, DoH-соединение dnsproxy):
# "vpn" — через tun; "wan:<ифейс>" — напрямую. При VPN смена WAN dnsproxy не
# касается (это забота VPN-клиента), без VPN — касается (Wi-Fi <-> мобилка).
route_id() {
    if vpn_up_now; then echo vpn; else echo "wan:$LAST_WAN_IFACE"; fi
}

# Трафик root (dnsproxy) идёт в tun? Если VPN-приложение в per-app режиме
# или исключает системные uid, cache/doh в VPN-режиме ушли бы мимо VPN.
root_routed_via_tun() {
    $ip route get 1.1.1.1 uid 0 2>/dev/null | grep -q "dev $TUN_NAME"
}

dns_redirect_to_proxy() {
    local iface added=0
    cleanup_dns_redirect
    $iptables -t nat -N "$CHAIN_DNS" 2>/dev/null
    $iptables -t nat -F "$CHAIN_DNS"
    $iptables -t nat -C PREROUTING -j "$CHAIN_DNS" 2>/dev/null || \
        $iptables -t nat -I PREROUTING 1 -j "$CHAIN_DNS" 2>/dev/null
    # REDIRECT = на основной адрес входящего ифейса (адрес раздачи):порт
    for iface in "$@"; do
        $iptables -t nat -A "$CHAIN_DNS" -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSPROXY_PORT" 2>/dev/null && added=$((added + 1))
        $iptables -t nat -A "$CHAIN_DNS" -i "$iface" -p tcp --dport 53 -j REDIRECT --to-ports "$DNSPROXY_PORT" 2>/dev/null && added=$((added + 1))
    done
    log "DNS -> dnsproxy :$DNSPROXY_PORT ($added rules)"
    dns_conntrack_flush "$@"
}

direct_dns_servers() {
    local sys_dns=$(getprop net.dns1 2>/dev/null)
    [ -z "$sys_dns" ] && sys_dns="1.1.1.1"
    echo "${sys_dns}|2606:4700:4700::1111"
}

# apply_dns_mode <vpn|direct> <"v4|v6"> <ifaces...>
# Ставит DNS для клиентов. Любой сбой dnsproxy -> старый DNAT.
apply_dns_mode() {
    local mode="$1" servers="$2"
    # ошибка shift в mksh прерывает функцию, а не уходит в ||
    if [ $# -ge 2 ]; then shift 2; else shift $#; fi
    local ifaces="$*" want="" ups="" dns4

    if [ -z "$ifaces" ]; then
        dnsproxy_release
        DNS_STATE=""
        return 0
    fi
    dns4="${servers%%"|"*}"

    if [ "$mode" = "direct" ]; then
        [ "$DNS_DIRECT" = "doh" ] && { want="doh"; ups="${DNS_ALT_UPS:-$DNS_UPSTREAMS}"; }
    else
        case "$DNS_VPN" in
            cache) want="cache"; ups="$dns4:53" ;;
            doh)   want="doh";   ups="$DNS_VPN_UPSTREAMS" ;;
        esac
        if [ -n "$want" ] && ! root_routed_via_tun; then
            log "WARNING: трафик root идёт мимо $TUN_NAME (per-app VPN?) — DNS_VPN=$DNS_VPN выключен, DNAT в DNS VPN"
            want=""
        fi
        # Каждая пересборка VPN = новый экземпляр: keep-alive DoH-соединение
        # могло открыться через WAN, пока tun пропадал, и так бы и осталось.
        # Только если dnsproxy нужен раздаче: иначе (dnat) затёртая сигнатура
        # ломала dnsproxy_restart для экземпляра телефона.
        [ -n "$want" ] && DNSPROXY_SIG=""
    fi

    if [ -n "$want" ] && [ -n "$ups" ]; then
        dnsproxy_port_guard $ifaces
        # Редирект ставим СРАЗУ после старта, проверку — после: иначе на всё
        # время проверки клиенты без редиректа спрашивали dnsmasq раздачи
        # (= DNS оператора). Не прошла — setup_dns_redirect ниже его заменит.
        if dnsproxy_start "$mode-$want" $ups; then
            dns_redirect_to_proxy $ifaces
            DNS_STATE="dnsproxy $want"
            DNS_STATE_MODE="$mode"
            DNS_STATE_IFACES="$ifaces"
            # Апстрим недоступен (белые списки, блокировка) — dnsproxy НЕ гасим:
            # DNS временно на обычный, dns_health вернёт DoH, когда оживёт.
            if dnsproxy_probe_cold || dns_try_alt "проверка при настройке"; then
                DNS_DEGRADED=0
            else
                dns_degrade "проверка при настройке"
            fi
            return 0
        fi
        log "WARNING: dnsproxy не запустился ($(tail -n 2 "$DNSPROXY_LOG" 2>/dev/null | tr '\n' ' ' | cut -c1-160)), откат на обычный DNAT"
        dnsproxy_stop
        dnsproxy_port_guard_down
    fi
    if [ -n "$want" ] && [ -n "$ups" ] && [ -n "$DNSPROXY_BIN" ]; then
        # сторож повторит раз в ~минуту (раньше — только до пересборки)
        DNS_FAIL_SIG="$mode-$want|$ups"
        DNS_FAIL_WANT="$want"
        DNS_FAIL_RETRY=0
        DNS_STATE_MODE="$mode"
        DNS_STATE_IFACES="$ifaces"
        if [ "$mode" = "direct" ]; then
            # как dns_degrade: DNS раздачи (оператор), а не DNAT на 1.1.1.1 —
            # net.dns1 с Android 8 пустой, а 1.1.1.1:53 ТСПУ отдаёт НСДИ, в
            # белых списках он не отвечает вовсе
            cleanup_dns_redirect
            dns_conntrack_flush $ifaces
        else
            setup_dns_redirect "$servers" $ifaces
        fi
        DNS_STATE="DNAT (dnsproxy упал)"
        return 0
    else
        dnsproxy_release
    fi

    setup_dns_redirect "$servers" $ifaces
    DNS_STATE="DNAT ${dns4:-?}"
    DNS_STATE_MODE="$mode"
    DNS_STATE_IFACES="$ifaces"
    return 0
}

# dnsproxy пишет в лог только старт и ошибки, но за недели набегает.
# Зовётся из dns_health — то есть и когда dnsproxy нужен только телефону.
dnsproxy_log_rotate() {
    if [ "$(wc -c < "$DNSPROXY_LOG" 2>/dev/null || echo 0)" -gt 1048576 ]; then
        tail -c 262144 "$DNSPROXY_LOG" > "$DNSPROXY_LOG.tmp" 2>/dev/null && \
            cat "$DNSPROXY_LOG.tmp" > "$DNSPROXY_LOG"
        rm -f "$DNSPROXY_LOG.tmp"
        DNS_LOG_SEEN=0
    fi
}

# Из цикла: dnsproxy умер -> поднять; не поднялся -> DNAT, клиенты не без DNS,
# и раз в ~минуту пробуем вернуть dnsproxy (раньше DNAT оставался до
# следующей пересборки правил, то есть часто до перезагрузки).
DNS_FAIL_SIG=""
DNS_FAIL_WANT=""
DNS_FAIL_RETRY=0
dns_watchdog() {
    local saved_sig
    case "$DNS_STATE" in
        "DNAT (dnsproxy упал)")
            DNS_FAIL_RETRY=$((DNS_FAIL_RETRY + 1))
            [ "$DNS_FAIL_RETRY" -ge 30 ] || return 0
            DNS_FAIL_RETRY=0
            [ -n "$DNS_FAIL_SIG" ] || return 0
            if dnsproxy_start "${DNS_FAIL_SIG%%"|"*}" ${DNS_FAIL_SIG#*"|"}; then
                dnsproxy_port_guard $DNS_STATE_IFACES
                dns_redirect_to_proxy $DNS_STATE_IFACES
                DNS_STATE="dnsproxy $DNS_FAIL_WANT"
                DNS_HEALTH_LAST=0       # dns_health проверит апстрим сразу
                log "WATCHDOG: dnsproxy снова поднят, DNS клиентов -> dnsproxy"
            fi
            return 0 ;;
        dnsproxy*) ;;
        *) return 0 ;;
    esac
    dnsproxy_exempt
    dnsproxy_alive && return 0

    log "WATCHDOG: dnsproxy умер, перезапускаю"
    saved_sig="$DNSPROXY_SIG"
    DNSPROXY_SIG=""
    dnsproxy_start "${saved_sig%%"|"*}" ${saved_sig#*"|"} && return 0

    log "WATCHDOG: dnsproxy не поднялся, DNS клиентов -> DNAT (повтор раз в ~минуту)"
    if [ "$DNS_STATE_MODE" = "direct" ]; then
        # DNS раздачи (оператор), как dns_degrade, — не DNAT на 1.1.1.1
        cleanup_dns_redirect
        dns_conntrack_flush $DNS_STATE_IFACES
    else
        setup_dns_redirect "$(get_vpn_dns)" $DNS_STATE_IFACES
    fi
    dnsproxy_port_guard_down
    DNS_FAIL_SIG="$saved_sig"
    DNS_FAIL_WANT="${DNS_STATE#dnsproxy }"
    DNS_FAIL_RETRY=0
    DNS_STATE="DNAT (dnsproxy упал)"
}

# Раздаче dnsproxy больше не нужен. Если им пользуется телефон — не гасим,
# только сужаем доступ к порту до lo.
dnsproxy_release() {
    if [ "$PHONE_DNS_ON" = "1" ] && dnsproxy_alive; then
        dnsproxy_port_guard
        return 0
    fi
    dnsproxy_stop
    dnsproxy_port_guard_down
}

# dnsproxy_restart <причина> [quiet]
dnsproxy_restart() {
    local sig="$DNSPROXY_SIG"
    [ -n "$sig" ] || return 0
    DNSPROXY_SIG=""
    # Новый маршрут (только что поднятый VPN) первые секунды может не возить
    # трафик: проверка сразу после перезапуска ложно решала "DoH недоступен"
    # (лог 1.3, 07:42:55 -> 07:43:03). Первая проверка — через интервал.
    DNS_HEALTH_LAST=$(date +%s)
    if dnsproxy_start "${sig%%"|"*}" ${sig#*"|"}; then
        [ "$2" = "quiet" ] || log "dnsproxy перезапущен ($1)"
    else
        log "WARNING: dnsproxy не перезапустился ($1)"
    fi
}

# ============================================================================
# Здоровье DoH: апстрим недоступен -> обычный DNS, ожил -> обратно на DoH.
# Без этого при "молчащем" comss (белые списки) клиенты сидели без DNS:
# dnsproxy ждал апстрим ~15с, до фолбэков не доходил (context deadline).
# ============================================================================
# Идемпотентно: правила применяются всегда (пересборка могла заново поставить
# редирект на dnsproxy), в лог — только на переходе.
dns_degrade() {
    if [ "$DNS_DEGRADED" != "1" ]; then
        # Только что сменился маршрут (VPN поднялся/пропал) или стартовал демон:
        # новый путь может заработать не сразу. На обычный DNS всё равно
        # уходим (это безопасно), но перепроверяем через INTERVAL, а не через
        # RECOVER и без условия "нужна активность" — иначе 30с без DoH зря.
        if [ $(( $(date +%s) - DNS_ROUTE_CHANGED_TS )) -lt 15 ]; then
            DNS_FAST_RECHECK=1
            log "WARNING: DoH не ответил сразу после смены маршрута ($1) — DNS временно обычный, перепроверю через ${DNS_HEALTH_INTERVAL}с"
        else
            log "WARNING: DoH-апстрим не отвечает ($1) — DNS временно обычный (оператор/VPN), проверяю раз в ${DNS_HEALTH_RECOVER}с"
        fi
    fi
    DNS_DEGRADED=1
    case "$DNS_STATE" in
        dnsproxy*)
            if [ "$DNS_STATE_MODE" = "vpn" ]; then
                setup_dns_redirect "$(get_vpn_dns)" $DNS_STATE_IFACES
            else
                # Без перехвата клиенты спрашивают DNS раздачи (dnsmasq ->
                # DNS оператора), а он в белых списках как раз работает.
                cleanup_dns_redirect
                # потоки, уже закреплённые за dnsproxy (у Windows — постоянные
                # порты), иначе так и ходили бы в него с мёртвым апстримом
                dns_conntrack_flush $DNS_STATE_IFACES
            fi ;;
    esac
    [ "$PHONE_DNS_ON" = "1" ] && phone_dns_rules_off
    phone_status_refresh
}

# Маршрут root сменился (VPN поднялся/пропал, сменился WAN). Если мы в откате,
# то, возможно, как раз из-за старого пути: перепроверяем через INTERVAL и без
# условия активности, а не через RECOVER (лог 1.4: 15:24:02 rmnet появился,
# а DoH вернулся только в 15:24:36).
dns_route_changed() {
    DNS_ROUTE_CHANGED_TS=$(date +%s)
    [ "$DNS_DEGRADED" = "1" ] && DNS_FAST_RECHECK=1
}

# Сброс кэша dnsproxy (3.17): кэш живёт в памяти процесса — перезапуск с теми
# же режимом и апстримами (порт свободен ~1с). $1 — причина, для журнала.
# 0 — перезапущен; 1 — dnsproxy не запущен (VPN с DNAT, DNSPROXY_ENABLE=0).
dnsproxy_flush() {
    local tag ups
    [ -n "$DNSPROXY_SIG" ] && dnsproxy_alive || return 1
    tag="${DNSPROXY_SIG%%"|"*}"; ups="${DNSPROXY_SIG#*"|"}"
    log "DNS: сбрасываю кэш dnsproxy ($1)"
    dnsproxy_stop
    # не поднялся — сигнатуру вернуть: dnsproxy_stop её обнулил, и сторож
    # иначе не знал бы, с чем перезапускать
    dnsproxy_start "$tag" $ups || { DNSPROXY_SIG="$tag|$ups"; return 1; }
}

dns_restore() {
    [ "$DNS_DEGRADED" = "1" ] || return 0
    DNS_DEGRADED=0
    log "DoH-апстрим снова отвечает — DNS обратно через dnsproxy"
    case "$DNS_STATE" in dnsproxy*) dns_redirect_to_proxy $DNS_STATE_IFACES ;; esac
    [ "$PHONE_DNS_ON" = "1" ] && phone_dns_rules_on
    phone_status_refresh
}

# Сколько DNS-запросов прошло через наши редиректы (раздача + телефон).
# nat-счётчик растёт на каждый новый поток, а у DNS каждый запрос — новый
# порт = новый поток. Проверка dnsproxy (127.0.0.1, -o lo -> RETURN) и
# собственные запросы dnsproxy (gid-исключение) сюда не попадают.
dns_activity() {
    local n=0 c
    for c in "$CHAIN_DNS" "$CHAIN_PHONE_DNS"; do
        n=$(( n + $($iptables -t nat -L "$c" -v -x -n 2>/dev/null | awk '/REDIRECT/ {s += $1} END {print s + 0}') ))
    done
    echo "$n"
}

# Байты rx+tx на текущем WAN: грубый признак "модем сейчас и так работает"
wan_bytes() {
    local w="$LAST_WAN_IFACE" rx tx
    # без раздачи apply_state зовётся редко и WAN мог ещё не попасть сюда:
    # тогда счётчик стоял на 0 и проверка восстановления не шла вовсе
    [ -n "$w" ] || w=$(get_wan_iface)
    [ -n "$w" ] || { echo 0; return; }
    rx=$(cat "/sys/class/net/$w/statistics/rx_bytes" 2>/dev/null || echo 0)
    tx=$(cat "/sys/class/net/$w/statistics/tx_bytes" 2>/dev/null || echo 0)
    echo $((rx + tx))
}

# --- ступенька между comss и оператором ------------------------------------
# 20.10: comss ответил за 3680мс (это уже "comss молчит, ответил фолбэк"), и
# модуль увёл DNS к оператору — а тот для заблокированных сайтов может отдать
# заглушку, которая потом сидит в кэше Android/Windows. Теперь: основной
# DoH молчит -> тот же dnsproxy, но основными становятся DNS_FALLBACKS
# (с 3.17 — только DoH с обходом гео-блока). К оператору — только если молчат и они (белые
# списки). Ожил ли основной — проверяем curl-ом раз в DNS_HEALTH_RECOVER,
# не трогая dnsproxy (его кэш не теряется).
# DoH молчит — а DNS оператора? Спрашиваем его напрямую (адреса — из
# LinkProperties WAN, dumpsys; от группы dnsproxy — мимо перехвата DNS
# телефона: dnsmasq раздачи и root ушли бы в тот же dnsproxy, тест 29.10 —
# «оператор молчит» при живом операторе). Молчат все — сети нет вовсе
# (метро 29.10: откат каждые ~2 мин, 3 перезапуска dnsproxy, потом ответы
# оператора). Белые списки: оператор отвечает -> откат, как раньше.
# 0 = «оператор мёртв»; только напрямую, адресов не нашли — 1 (откат как раньше).
DNS_OP_CACHE=""        # «WAN|адреса» — dumpsys тяжёлый: пока оператор отвечает
dns_operator_dead() {
    local w s old="" ms="$DNS_PROBE_LAST_MS" r=1
    [ "$DNS_STATE_MODE" != "vpn" ] || return 1
    w="$LAST_WAN_IFACE"; [ -n "$w" ] || return 1
    [ "${DNS_OP_CACHE%%|*}" = "$w" ] && old="${DNS_OP_CACHE#*|}"
    for s in $old; do
        dnsproxy_probe "$s"; r=$?
        [ "$r" = 1 ] || break
    done
    if [ "$r" = 1 ]; then
        # нет в кэше или из кэша молчат: адреса могли смениться при том же WAN
        # (другая точка на wlan0, переподключение мобильной) — старый адрес
        # роутера молчал бы, и при живом операторе откат не делался бы
        s=$(dumpsys connectivity 2>/dev/null | grep -oE "InterfaceName: [^ ]+|DnsAddresses: \[[^]]*\]" | \
            awk -v w="$w" '$0 == "InterfaceName: " w {f = 1; next} f && /^DnsAddresses/ {print; exit} /^InterfaceName/ {f = 0}' | \
            grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -2 | tr '\n' ' ')
        if [ -z "$s" ]; then DNS_OP_CACHE=""; DNS_PROBE_LAST_MS="$ms"; return 1; fi
        DNS_OP_CACHE="$w|$s"
        if [ "$s" != "$old" ]; then
            for s in $s; do
                dnsproxy_probe "$s"; r=$?
                [ "$r" = 1 ] || break
            done
        fi
    fi
    DNS_PROBE_LAST_MS="$ms"
    [ "$r" = 1 ]
}

dns_hosts_of() { echo $* | sed -E 's#[a-z0-9]+://([^/: ]+)[^ ]*#\1#g'; }

dns_try_alt() {     # 0 = перешли на запасные DoH и они отвечают
    [ -z "$DNS_ALT_UPS" ] || return 1
    [ -n "$DNS_FALLBACKS" ] || return 1
    case "$DNSPROXY_SIG" in "direct-doh|"*) ;; *) return 1 ;; esac
    # основным — только первый запасной (dns.zapret.moe): несколько -u dnsproxy
    # опрашивает по очереди, и часть ответов пришла бы от Google без
    # "разблокирующих" адресов
    # первый запасной, которого нет среди основных (выбран zapret.moe основным —
    # тогда запасной не он же, а следующий)
    DNS_ALT_UPS=$(for u in $DNS_FALLBACKS; do case " $DNS_UPSTREAMS " in *" $u "*) ;; *) echo "$u"; break ;; esac; done)
    [ -n "$DNS_ALT_UPS" ] || return 1
    if dnsproxy_start "direct-doh" $DNS_ALT_UPS && dnsproxy_probe_cold; then
        local now t keep="" hold="$DNS_ALT_HOLD"
        now=$(date +%s)
        for t in $DNS_ALT_TRIPS; do [ $((now - t)) -lt 1800 ] && keep="$keep $t"; done
        DNS_ALT_TRIPS="$keep $now"
        [ "$(echo $DNS_ALT_TRIPS | wc -w)" -ge 2 ] && hold="$DNS_ALT_HOLD_FLAP"
        log "WARNING: DoH-апстрим не отвечает ($1) — DNS через запасные DoH ($(dns_hosts_of $DNS_ALT_UPS)); на $(dns_hosts_of $DNS_UPSTREAMS) вернусь не раньше чем через $((hold / 60)) мин$([ "$hold" = "$DNS_ALT_HOLD_FLAP" ] && echo ' (он дёргается)')"
        DNS_ALT_LAST=$now
        DNS_ALT_SINCE=$now
        DNS_ALT_OKS=0
        phone_status_refresh
        return 0
    fi
    # запасные тоже молчат — обратно на основной, дальше откат к оператору
    DNS_ALT_UPS=""
    dnsproxy_start "direct-doh" $DNS_UPSTREAMS
    return 1
}

# Основной DoH отвечает? Напрямую curl-ом, от группы dnsproxy (мимо AdGuard).
dns_primary_alive() {
    local u code
    set -- $DNS_UPSTREAMS
    u="$1"
    # проверить нечем (не https / нет curl) — «не жив»: запасной работает, а
    # «жив» гонял бы на мёртвый основной раз в ~30 мин (сценарное ревью)
    case "$u" in https://*) ;; *) return 1 ;; esac
    command -v curl >/dev/null 2>&1 || return 1
    case "$u" in *\?*) u="$u&" ;; *) u="$u?" ;; esac
    u="${u}dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"
    if [ "$DNSPROXY_SU_G" = "1" ]; then
        code=$(su -g "$DNSPROXY_GID" -c "curl -s -o /dev/null -m 4 --capath /apex/com.android.conscrypt/cacerts -H 'accept: application/dns-message' -w '%{http_code}' '$u'" 2>/dev/null)
    else
        code=$(curl -s -o /dev/null -m 4 --capath /apex/com.android.conscrypt/cacerts -H 'accept: application/dns-message' -w '%{http_code}' "$u" 2>/dev/null)
    fi
    [ "$code" = "200" ]
}

dns_alt_recheck() {
    local hold="$DNS_ALT_HOLD"
    [ -n "$DNS_ALT_UPS" ] && [ "$DNS_DEGRADED" = "0" ] || return 1
    # только экземпляр direct: VPN-режим (cache/doh) затёрся бы wlrus
    case "$DNSPROXY_SIG" in "direct-doh|"*) ;; *) return 1 ;; esac
    [ $(( $1 - DNS_ALT_LAST )) -ge "$DNS_HEALTH_RECOVER" ] || return 1
    DNS_ALT_LAST=$1
    # основной должен ответить 2 проверки подряд, и не раньше срока: иначе
    # при "дёргающемся" comss dnsproxy перезапускался туда-обратно каждые 30-40с
    if dns_primary_alive; then DNS_ALT_OKS=$((DNS_ALT_OKS + 1)); else DNS_ALT_OKS=0; return 1; fi
    [ "$(echo $DNS_ALT_TRIPS | wc -w)" -ge 2 ] && hold="$DNS_ALT_HOLD_FLAP"
    [ "$DNS_ALT_OKS" -ge 2 ] && [ $(( $1 - DNS_ALT_SINCE )) -ge "$hold" ] || return 1
    DNS_ALT_UPS=""
    DNS_ALT_OKS=0
    if dnsproxy_start "direct-doh" $DNS_UPSTREAMS; then
        log "DoH-апстрим $(dns_hosts_of $DNS_UPSTREAMS) снова отвечает — DNS обратно через него (dnsproxy перезапущен, кэш пустой)"
    fi
    DNS_HEALTH_LAST=0
    phone_status_refresh
    return 0
}

# Из цикла. Пока DoH работает — проверка раз в DNS_HEALTH_INTERVAL, при
# неудаче сразу вторая (одна медленная секунда в автобусе — не повод).
# В деградации — раз в DNS_HEALTH_RECOVER. И то и другое — только если
# DNS/сеть реально используются (см. ниже).
dns_health() {
    local now period sz
    case "$DNS_STATE" in dnsproxy*) ;; *) [ "$PHONE_DNS_ON" = "1" ] || { DNS_DEGRADED=0; return 0; } ;; esac
    dnsproxy_alive || return 0
    dnsproxy_log_rotate
    now=$(date +%s)
    dns_alt_recheck "$now" && return 0

    # Пассивный сигнал: в логе dnsproxy появились "exchange failed" — у
    # клиентов уже сыпятся ошибки, проверяем сейчас, не ждём интервал.
    sz=$(wc -c < "$DNSPROXY_LOG" 2>/dev/null || echo 0)
    # «сети нет» (DNS_NONET) — «exchange failed» сыплются на каждый запрос клиентов:
    # не повод проверять в каждом проходе цикла (проверка там до ~17 с)
    if [ "$DNS_DEGRADED" = "0" ] && [ "$DNS_NONET" != 1 ] && [ "$sz" -gt "$DNS_LOG_SEEN" ] 2>/dev/null; then
        tail -c $((sz - DNS_LOG_SEEN)) "$DNSPROXY_LOG" 2>/dev/null | grep -q "exchange failed" && DNS_HEALTH_LAST=0
    fi
    DNS_LOG_SEEN="$sz"

    period="$DNS_HEALTH_INTERVAL"
    [ "$DNS_DEGRADED" = "1" ] && [ "$DNS_FAST_RECHECK" != "1" ] && period="$DNS_HEALTH_RECOVER"
    # сети нет: вернётся — dnsproxy заработает и без нас, ждём только белые
    # списки (оператор отвечает) — с периодом отката
    # (до правки метро и было откатом с этим периодом)
    [ "$DNS_NONET" = 1 ] && period="$DNS_HEALTH_RECOVER"
    [ $((now - DNS_HEALTH_LAST)) -lt "$period" ] && return 0

    # Проверяем только при реальном использовании: иначе DoH-запрос раз в
    # несколько секунд круглосуточно не даёт модему уснуть (батарея) и
    # тратит трафик, даже когда телефон лежит с погашенным экраном.
    #  - DoH работает: счётчики наших DNS-редиректов не изменились = за это
    #    время никто DNS не спрашивал -> защищать нечего, пропускаем;
    #  - откат: редиректов нет, смотрим трафик на WAN — почти ноль = модем
    #    простаивает, будить его ради проверки не будем.
    # DNS_HEALTH_LAST не трогаем: при первом же запросе проверка пойдёт сразу.
    if [ "$DNS_DEGRADED" = "0" ]; then
        local act
        act=$(dns_activity)
        [ "$act" = "$DNS_ACT_LAST" ] && return 0
        DNS_ACT_LAST="$act"
    elif [ "$DNS_FAST_RECHECK" = "1" ]; then
        # быстрая перепроверка после смены маршрута — без условия активности
        DNS_FAST_RECHECK=0
    else
        local wb
        wb=$(wan_bytes)
        if [ $((wb - DNS_WAN_LAST)) -lt "$DNS_HEALTH_IDLE_BYTES" ] && [ $((wb - DNS_WAN_LAST)) -ge 0 ]; then
            return 0
        fi
        DNS_WAN_LAST="$wb"
    fi
    DNS_HEALTH_LAST=$now

    # В откате dnsproxy никто не пользуется, а его DoH-соединение, пока
    # апстрим резали, зависло: первая проверка после возврата comss всё равно
    # получала "context deadline", и возврат на DoH опаздывал на целый цикл
    # (тест на демоне: 60с вместо ≤30с). Свежий экземпляр — свежее соединение.
    if [ "$DNS_DEGRADED" = "1" ]; then
        # Откат после запасных: перезапуск шёл бы снова на запасных, и основной
        # не проверялся бы вовсе, пока не оживут они (23.10: оператор 22:55-23:03,
        # wlrus мог ожить раньше). Основной отвечает (curl) — пробуем через него.
        if [ -n "$DNS_ALT_UPS" ] && case "$DNSPROXY_SIG" in "direct-doh|"*) true ;; *) false ;; esac && dns_primary_alive; then
            DNS_ALT_UPS=""
            DNS_ALT_OKS=0
            dnsproxy_start "direct-doh" $DNS_UPSTREAMS
        else
            dnsproxy_restart "проверка восстановления" quiet
        fi
        dnsproxy_alive || { DNS_HEALTH_LAST=$(date +%s); return 0; }
    fi

    if dnsproxy_probe_cold; then
        [ "$DNS_NONET" = 1 ] && log "DoH снова отвечает (сеть вернулась)"
        DNS_NONET=0
        dns_restore
    elif [ "$DNS_DEGRADED" = "0" ]; then
        # одна неудача — не повод (одна плохая секунда в автобусе), сразу вторая
        if ! dnsproxy_probe; then
            local why="2 проверки подряд: $DNS_PROBE_LAST_MS$(case "$DNS_PROBE_LAST_MS" in [0-9]*) echo 'мс, медленно' ;; esac)"
            if dns_operator_dead; then
                # сети нет вовсе (метро): оператор тоже молчит — откат ничего не даст,
                # а стоил бы кэша dnsproxy (3 перезапуска) и ответов оператора потом
                [ "$DNS_NONET" = 1 ] || log "DoH молчит ($why), но и DNS оператора молчит — сети нет, DNS не трогаю"
                DNS_NONET=1
            else
                DNS_NONET=0
                dns_try_alt "$why" || dns_degrade "$why"
            fi
        else
            [ "$DNS_NONET" = 1 ] && log "DoH снова отвечает (сеть вернулась)"
            DNS_NONET=0
        fi
    else
        # в откате основной не ожил — может, ожили запасные
        dns_try_alt "проверка восстановления" && dns_restore
    fi
    DNS_HEALTH_LAST=$(date +%s)
}

# ============================================================================
# DNS самого телефона (DNS_PHONE)
# ============================================================================
phone_dns_rules_on() {
    local t
    PHONE_DNS_V6=0
    for t in "$iptables" "$ip6tables"; do
        # ip6 nat есть не во всех ядрах (на OnePlus 13T, A15 — нет)
        if ! $t -t nat -L "$CHAIN_PHONE_DNS" -n >/dev/null 2>&1; then
            $t -t nat -N "$CHAIN_PHONE_DNS" 2>/dev/null || continue
        fi
        $t -t nat -F "$CHAIN_PHONE_DNS" 2>/dev/null
        # сам dnsproxy (bootstrap :53) — мимо, иначе петля
        [ -n "$DNSPROXY_GID" ] && \
            $t -t nat -A "$CHAIN_PHONE_DNS" -m owner --gid-owner "$DNSPROXY_GID" -j RETURN 2>/dev/null
        [ "$DNSPROXY_SU_G" = "1" ] || \
            $t -t nat -A "$CHAIN_PHONE_DNS" -m owner --uid-owner 0 -j RETURN 2>/dev/null
        $t -t nat -A "$CHAIN_PHONE_DNS" -o lo -j RETURN 2>/dev/null
        $t -t nat -A "$CHAIN_PHONE_DNS" -p udp --dport 53 -j REDIRECT --to-ports "$DNSPROXY_PORT" 2>/dev/null
        $t -t nat -A "$CHAIN_PHONE_DNS" -p tcp --dport 53 -j REDIRECT --to-ports "$DNSPROXY_PORT" 2>/dev/null
        $t -t nat -C OUTPUT -j "$CHAIN_PHONE_DNS" 2>/dev/null || \
            $t -t nat -I OUTPUT 1 -j "$CHAIN_PHONE_DNS" 2>/dev/null
        [ "$t" = "$ip6tables" ] && PHONE_DNS_V6=1
    done
    # исключение dnsproxy из AdGuard обратно на первое место
    dnsproxy_exempt force
}

phone_dns_rules_off() {
    local t _n
    for t in "$iptables" "$ip6tables"; do
        _n=0
        while [ $_n -lt 8 ] && $t -t nat -D OUTPUT -j "$CHAIN_PHONE_DNS" 2>/dev/null; do _n=$((_n + 1)); done
        $t -t nat -F "$CHAIN_PHONE_DNS" 2>/dev/null
        $t -t nat -X "$CHAIN_PHONE_DNS" 2>/dev/null
    done
}

# Каждая итерация цикла (и при выключенном хотспоте). Состояние VPN берём
# сами: apply_state при пустой раздаче вызывается редко. Сглаживание —
# только на появление VPN (см. ниже), пропажа принимается сразу:
# два одинаковых "VPN есть" подряд, чтобы реконнект VPN не дёргал правила.
phone_dns_reconcile() {
    local up=0 want=0
    $ip addr show "$TUN_NAME" 2>/dev/null | grep -q "inet " && up=1
    # VPN поднялся/упал = у root другой маршрут. Keep-alive DoH-соединение
    # dnsproxy остаётся на старом пути и висит до таймаута — в логе 1.2 это
    # ~16с SERVFAIL у клиентов на переключении Incy. Перезапуск сразу, без
    # сглаживания (сглаживание — только для включения/снятия правил ниже).
    # По состоянию, при котором dnsproxy запущен, а не по "переходу между
    # двумя замерами": если apply_state уже перезапустил его под новый
    # маршрут, второй раз не перезапускаем.
    local route
    route=$(route_id)
    if dnsproxy_alive && [ -n "$DNSPROXY_STARTED_ROUTE" ] &&        [ "$route" != "$DNSPROXY_STARTED_ROUTE" ] && [ "$route" != "wan:" ]; then
        dns_route_changed
        case "$DNS_STATE" in
            dnsproxy*) dnsproxy_restart "маршрут: $DNSPROXY_STARTED_ROUTE -> $route" ;;
            *)
                if [ "$up" = "1" ]; then
                    # VPN поднялся, раздача dnsproxy не пользуется: DNS телефона
                    # сейчас уйдёт в VPN, и dnsproxy остановится. Раньше его
                    # перезапускали под VPN и через 2с всё равно гасили.
                    PHONE_VPN_SEEN=1
                else
                    dnsproxy_restart "маршрут: $DNSPROXY_STARTED_ROUTE -> $route"
                fi ;;
        esac
    fi
    # "VPN пропал" — принимаем сразу, "VPN появился" — только 2 раза подряд.
    # Пока ждали второго замера (~2-4с), DNS телефона шёл к оператору, и
    # Android кэшировал настоящие адреса заблокированных/гео-сервисов на их
    # TTL (claude.ai — ~47 мин), обходя comss. Ошибиться в эту сторону
    # безопасно: если VPN тут же вернётся, правило просто снимется.
    if [ "$up" = "0" ] || [ "$up" = "$PHONE_VPN_SEEN" ]; then
        PHONE_VPN_STABLE="$up"
    fi
    PHONE_VPN_SEEN="$up"
    [ -z "$PHONE_VPN_STABLE" ] && return 0

    [ "$DNS_PHONE" = "1" ] && [ "$PHONE_VPN_STABLE" = "0" ] && [ -n "$DNSPROXY_BIN" ] && want=1

    if [ "$want" = "0" ]; then
        if [ "$PHONE_DNS_ON" = "1" ]; then
            phone_dns_rules_off
            PHONE_DNS_ON=0
            log "DNS телефона: как обычно (VPN поднят)"
            case "$DNS_STATE" in dnsproxy*) dnsproxy_port_guard $DNS_STATE_IFACES ;; *) dnsproxy_stop; dnsproxy_port_guard_down ;; esac
            phone_status_refresh
        fi
        PHONE_DNS_RETRY=0
        return 0
    fi

    if [ "$PHONE_DNS_ON" = "1" ]; then
        if dnsproxy_alive; then
            # держим хук и исключение на месте (AdGuard/netd могли перетряхнуть);
            # в деградации хука как раз быть не должно
            if [ "$DNS_DEGRADED" = "0" ]; then
                $iptables -t nat -C OUTPUT -j "$CHAIN_PHONE_DNS" 2>/dev/null || phone_dns_rules_on
            fi
            dnsproxy_exempt
            return 0
        fi
        # dnsproxy умер — не держим DNS телефона в чёрной дыре
        log "WARNING: dnsproxy умер, DNS телефона -> обычный"
        phone_dns_rules_off
        PHONE_DNS_ON=0
        phone_status_refresh
    fi

    if [ "$PHONE_DNS_RETRY" -gt 0 ]; then
        PHONE_DNS_RETRY=$((PHONE_DNS_RETRY - 1))
        return 0
    fi

    # Сети ещё нет (загрузка, авиарежим): проверка DoH заведомо провалится и
    # уведёт в откат — после загрузки 1.4 это давало ~50с "comss не отвечает"
    # (лог 15:23:44 -> 15:24:36). Ждём, пока появится WAN.
    if [ "$route" = "wan:" ]; then
        LAST_WAN_IFACE=$(get_wan_iface)
        [ -n "$LAST_WAN_IFACE" ] || return 0
    fi

    # Экземпляр с DNS_UPSTREAMS и тегом direct-doh — общий с раздачей в direct
    case "$DNS_STATE" in dnsproxy*) ;; *) dnsproxy_port_guard ;; esac
    if dnsproxy_start "direct-doh" ${DNS_ALT_UPS:-$DNS_UPSTREAMS}; then
        PHONE_DNS_ON=1
        if [ "$DNS_DEGRADED" = "0" ] && { dnsproxy_probe_cold || dns_try_alt "DNS телефона, проверка при включении"; }; then
            phone_dns_rules_on
            log "DNS телефона -> dnsproxy :$DNSPROXY_PORT (VPN не поднят; IPv6: $([ "$PHONE_DNS_V6" = 1 ] && echo да || echo 'нет ip6 nat'))"
            phone_status_refresh
        else
            # апстрим молчит: правила не ставим, dns_health включит их сам
            dns_degrade "DNS телефона, проверка при включении"
            DNS_HEALTH_LAST=$(date +%s)
        fi
    else
        log "WARNING: dnsproxy не запустился, DNS телефона оставляю обычным (повтор через ~1 мин)"
        PHONE_DNS_RETRY=30
        case "$DNS_STATE" in dnsproxy*) ;; *) dnsproxy_stop; dnsproxy_port_guard_down ;; esac
    fi
}

