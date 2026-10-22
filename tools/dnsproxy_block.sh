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
dnsproxy_port_guard() {
    local iface
    $iptables -N "$CHAIN_DNSP" 2>/dev/null
    $iptables -F "$CHAIN_DNSP" 2>/dev/null
    $iptables -A "$CHAIN_DNSP" -i lo -j RETURN 2>/dev/null
    for iface in "$@"; do
        $iptables -A "$CHAIN_DNSP" -i "$iface" -j RETURN 2>/dev/null
    done
    $iptables -A "$CHAIN_DNSP" -j DROP 2>/dev/null
    $iptables -C INPUT -p udp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null || \
        $iptables -I INPUT 1 -p udp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null
    $iptables -C INPUT -p tcp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null || \
        $iptables -I INPUT 1 -p tcp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null
}

dnsproxy_port_guard_down() {
    local _n=0
    while [ $_n -lt 8 ] && $iptables -D INPUT -p udp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null; do _n=$((_n + 1)); done
    _n=0
    while [ $_n -lt 8 ] && $iptables -D INPUT -p tcp --dport "$DNSPROXY_PORT" -j "$CHAIN_DNSP" 2>/dev/null; do _n=$((_n + 1)); done
    $iptables -F "$CHAIN_DNSP" 2>/dev/null
    $iptables -X "$CHAIN_DNSP" 2>/dev/null
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
    rm -f "$DNSPROXY_PID_FILE"
    DNSPROXY_SIG=""
}

# Осиротевшие экземпляры от убитого демона (pid-файл мог потеряться)
dnsproxy_kill_strays() {
    local f pid
    for f in $(grep -l "$MODULE_DIR/bin/dnsproxy" /proc/[0-9]*/cmdline 2>/dev/null); do
        pid="${f#/proc/}"; pid="${pid%/cmdline}"
        [ "$pid" = "$$" ] && continue
        kill -9 "$pid" 2>/dev/null && log "Убит осиротевший dnsproxy $pid"
    done
}

# dnsproxy_start <тег режима> <апстримы...>
# Перезапускает только при смене режима/апстримов. 0 = порт слушается.
dnsproxy_start() {
    local tag="$1"; shift
    local ups="$*" sig args u i

    [ -n "$DNSPROXY_BIN" ] || { log "WARNING: нет bin/dnsproxy, DNS по-старому"; return 1; }
    sig="$tag|$ups"
    if [ "$sig" = "$DNSPROXY_SIG" ] && dnsproxy_alive; then
        return 0
    fi
    dnsproxy_stop

    args="-l 0.0.0.0 -p $DNSPROXY_PORT --cache --cache-optimistic --timeout=5s --refuse-any"
    for u in $ups; do args="$args -u $u"; done
    for u in $DNS_FALLBACKS; do args="$args -f $u"; done
    for u in $DNS_BOOTSTRAP; do args="$args -b $u"; done

    : > "$DNSPROXY_LOG"
    $DNSPROXY_BIN $args -o "$DNSPROXY_LOG" >/dev/null 2>&1 < /dev/null &
    echo $! > "$DNSPROXY_PID_FILE"

    i=0
    while [ $i -lt 25 ]; do
        sleep 0.2
        dnsproxy_alive || break
        if ss -lun 2>/dev/null | grep -qE "[:.]$DNSPROXY_PORT[[:space:]]"; then
            DNSPROXY_SIG="$sig"
            log "dnsproxy запущен (pid $(cat "$DNSPROXY_PID_FILE"), $tag): $ups"
            return 0
        fi
        i=$((i + 1))
    done
    log "ERROR: dnsproxy не поднялся: $(tail -n 3 "$DNSPROXY_LOG" 2>/dev/null | tr '\n' ' ')"
    dnsproxy_stop
    return 1
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
    shift 2 2>/dev/null || shift $#
    local ifaces="$*" want="" ups="" dns4

    if [ -z "$ifaces" ]; then
        dnsproxy_stop
        dnsproxy_port_guard_down
        DNS_STATE=""
        return 0
    fi
    dns4="${servers%%|*}"

    if [ "$mode" = "direct" ]; then
        [ "$DNS_DIRECT" = "doh" ] && { want="doh"; ups="$DNS_UPSTREAMS"; }
    else
        case "$DNS_VPN" in
            cache) want="cache"; ups="$dns4:53" ;;
            doh)   want="doh";   ups="$DNS_UPSTREAMS" ;;
        esac
        if [ -n "$want" ] && ! root_routed_via_tun; then
            log "WARNING: трафик root идёт мимо $TUN_NAME (per-app VPN?) — DNS_VPN=$DNS_VPN выключен, DNAT в DNS VPN"
            want=""
        fi
    fi

    if [ -n "$want" ] && [ -n "$ups" ]; then
        dnsproxy_port_guard $ifaces
        if dnsproxy_start "$mode-$want" $ups; then
            dns_redirect_to_proxy $ifaces
            DNS_STATE="dnsproxy $want"
            DNS_STATE_MODE="$mode"
            DNS_STATE_IFACES="$ifaces"
            return 0
        fi
        log "WARNING: dnsproxy недоступен, откат на обычный DNAT"
    fi

    dnsproxy_stop
    dnsproxy_port_guard_down
    setup_dns_redirect "$servers" $ifaces
    DNS_STATE="DNAT ${dns4:-?}"
    DNS_STATE_MODE="$mode"
    DNS_STATE_IFACES="$ifaces"
    return 0
}

# Из цикла: dnsproxy умер -> поднять; не поднялся -> DNAT, клиенты не без DNS.
dns_watchdog() {
    local saved_sig
    case "$DNS_STATE" in dnsproxy*) ;; *) return 0 ;; esac
    if dnsproxy_alive; then
        # dnsproxy пишет в лог только старт и ошибки, но за недели набегает
        if [ "$(wc -c < "$DNSPROXY_LOG" 2>/dev/null || echo 0)" -gt 1048576 ]; then
            tail -c 262144 "$DNSPROXY_LOG" > "$DNSPROXY_LOG.tmp" 2>/dev/null && \
                cat "$DNSPROXY_LOG.tmp" > "$DNSPROXY_LOG"
            rm -f "$DNSPROXY_LOG.tmp"
        fi
        return 0
    fi

    log "WATCHDOG: dnsproxy умер, перезапускаю"
    saved_sig="$DNSPROXY_SIG"
    DNSPROXY_SIG=""
    dnsproxy_start "${saved_sig%%|*}" ${saved_sig#*|} && return 0

    log "WATCHDOG: dnsproxy не поднялся, DNS клиентов -> DNAT"
    if [ "$DNS_STATE_MODE" = "direct" ]; then
        setup_dns_redirect "$(direct_dns_servers)" $DNS_STATE_IFACES
    else
        setup_dns_redirect "$(get_vpn_dns)" $DNS_STATE_IFACES
    fi
    dnsproxy_port_guard_down
    DNS_STATE="DNAT (dnsproxy упал)"
}
