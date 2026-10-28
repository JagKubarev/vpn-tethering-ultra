# shellcheck shell=sh
# lib/loop.sh — главный цикл: handle_change, перечитывание настроек
# (reload_config), USR1, выход, monitor_loop.
# Часть демона service.sh: подключается из него через ".", сам не запускается.
# Настройки (USER CONFIG) и общие переменные — в service.sh.

handle_change() {
    local now=$(date +%s)
    local ack_token=""

    # Тоггл из action.sh. Обрабатываем здесь, а не в trap: trap может
    # сработать посреди apply_state, и "FORCE_UPDATE=0" после него терял сигнал.
    if [ "$USR1_PENDING" -eq 1 ]; then
        USR1_PENDING=0
        local _force=1
        if [ -f "$RELOAD_FILE" ]; then
            rm -f "$RELOAD_FILE"
            reload_config
            [ "$RELOAD_NEED_REBUILD" = "1" ] || _force=0
        fi
        refresh_vpn_target
        FORCE_UPDATE=$_force
        ack_token=$(cat "$REQ_FILE" 2>/dev/null)
        [ -z "$ack_token" ] && ack_token="noreq"
    fi

    # с ack_token — не выходить: токен локальный, ack потерялся бы
    [ "$FORCE_UPDATE" -eq 0 ] && [ -z "$ack_token" ] && [ $((now - LAST_HANDLE_TS)) -lt $DEBOUNCE_SECS ] && { _NEED_UPDATE=1; return 0; }

    LAST_HANDLE_TS=$now
    IP_RULE_CACHE=$($ip rule show 2>/dev/null)

    if [ "$LAST_VPN_ACTIVE" = "false" ] || ! $ip link show "$TUN_NAME" >/dev/null 2>&1; then
        local new_tun=$(detect_tun_name)
        [ "$new_tun" != "$TUN_NAME" ] && { log "TUN: $TUN_NAME → $new_tun"; TUN_NAME="$new_tun"; ORIGINAL_TUN_MTU=""; }
    fi

    local current_wan=$(get_wan_iface)
    local current_wan_ip=""
    local current_gw=""

    if [ -n "$current_wan" ]; then
        current_wan_ip=$($ip -4 addr show "$current_wan" 2>/dev/null | \
            awk '/inet / {print $2; exit}' | cut -d'/' -f1)
        current_gw=$($ip route get 1.1.1.1 oif "$current_wan" 2>/dev/null | \
            awk '{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}')
    fi

    local net_diff=false
    if [ -z "$current_wan" ]; then
        # WAN временно отсутствует (мобилка моргнула). Раньше это считалось
        # "сменой сети": net_diff=true, а LAST_WAN_IFACE не обновлялся (он
        # пишется только при непустом значении) — и модуль долбил полный
        # teardown+rebuild каждые ~12 секунд подряд (см. лог 01:09:27-01:10:04).
        # Каждая такая пересборка = окно, в котором клиент шёл напрямую.
        if [ "$WAN_DOWN_LOGGED" -eq 0 ]; then
            log "WAN пропал (был $LAST_WAN_IFACE), держу текущее состояние"
            WAN_DOWN_LOGGED=1
        fi
    else
        if [ "$WAN_DOWN_LOGGED" -eq 1 ]; then
            WAN_DOWN_LOGGED=0
            log "WAN вернулся: $current_wan"
            net_diff=true
        fi
        if [ -n "$LAST_WAN_IFACE" ]; then
            [ "$current_wan" != "$LAST_WAN_IFACE" ] && net_diff=true
            [ -n "$current_wan_ip" ] && [ -n "$LAST_WAN_IP" ] && \
                [ "$current_wan_ip" != "$LAST_WAN_IP" ] && net_diff=true
            [ -n "$current_gw" ] && [ -n "$LAST_WAN_GW" ] && \
                [ "$current_gw" != "$LAST_WAN_GW" ] && net_diff=true
        fi
    fi

    if $net_diff && { [ "$VPN_TETHER_MODE" = "on" ] || [ "$VPN_TETHER_MODE" = "blocked" ]; }; then
        # VPN-режим от WAN не зависит: маршрут — в таблицу tun, NAT — в tun.
        # Раньше тут был flush conntrack (обрыв всех соединений клиентов) +
        # FORCE_UPDATE (полная пересборка с hard-окном) на КАЖДЫЙ переход
        # Wi-Fi <-> мобилка. Смену tun (реконнект VPN) ловит apply_state.
        log "Network change (VPN mode, без пересборки): iface=$LAST_WAN_IFACE→$current_wan ip=$LAST_WAN_IP→$current_wan_ip"
        $ip route flush cache 2>/dev/null || true
        VPN_DNS_CACHE=""
        VPN_DNS_CACHE_TIME=0
    elif $net_diff; then
        log "Network change: iface=$LAST_WAN_IFACE→$current_wan ip=$LAST_WAN_IP→$current_wan_ip gw=$LAST_WAN_GW→$current_gw"
        WARP_CHECK_TS=0     # WARP: проверить туннель на новой сети сразу
        flush_conntrack
        $ip route flush cache 2>/dev/null || true
        ndc resolver flushdefaultif 2>/dev/null || true
        VPN_DNS_CACHE=""
        VPN_DNS_CACHE_TIME=0

        local wait_count=0
        while [ $wait_count -lt 4 ]; do
            sleep 2
            local new_ip=$($ip -4 addr show "$current_wan" 2>/dev/null | \
                awk '/inet / {print $2; exit}' | cut -d'/' -f1)
            if [ -n "$new_ip" ]; then
                current_wan_ip="$new_ip"
                break
            fi
            wait_count=$((wait_count + 1))
        done

        FORCE_UPDATE=1
    fi

    [ -n "$current_wan" ] && LAST_WAN_IFACE="$current_wan"
    [ -n "$current_wan_ip" ] && LAST_WAN_IP="$current_wan_ip"
    [ -n "$current_gw" ] && LAST_WAN_GW="$current_gw"
    [ -z "$LAST_WAN_IFACE" ] && LAST_WAN_IFACE="$current_wan"
    # В VPN-режиме смена сети обходится без пересборки -> update_status не
    # звался, и в status оставался старый wan= (WebUI-проверки шли через
    # интерфейс без адреса). Обновляем статус на любой смене сети.
    # Другая сеть -> zapret_reconcile пересчитает её имя и стратегию
    $net_diff && NET_ID_FORCE=1
    $net_diff && phone_status_refresh

    local tun_idx=$(read_table_index "$TUN_NAME")
    refresh_tether_ifaces
    # дальше правила меняются (setup_*), кэш ip rule больше не верен
    IP_RULE_CACHE=""
    local tether_ifaces="$TETHER_NOW"
    
    if [ -z "$tether_ifaces" ]; then
        EMPTY_IFACE_DELAY=$((EMPTY_IFACE_DELAY + 1))
        # Было: [ $((now % 10)) -ne 0 ] && return 0
        # now — это epoch-секунды, а цикл спит по 2с. Стоит фазе сползти на
        # нечётную (ping с timeout 3 это делает регулярно) — now%10 никогда
        # не станет нулём, и apply_state не вызывается ВООБЩЕ. Считаем итерации.
        if [ $EMPTY_IFACE_DELAY -gt 5 ] && [ "$FORCE_UPDATE" -eq 0 ] && [ -z "$ack_token" ]; then
            [ $((EMPTY_IFACE_DELAY % 5)) -ne 0 ] && return 0
        fi
    else
        EMPTY_IFACE_DELAY=0
    fi

    # Watchdog: правила могли снести снаружи (netd/TetheringService при
    # реконнекте клиента). Модуль этого не видел — LAST_* не менялись,
    # apply_state ничего не делал, а клиент тем временем шёл напрямую.
    if [ "$FORCE_UPDATE" -eq 0 ] && [ "$VPN_TETHER_MODE" = "on" ]; then
        WATCHDOG_TICK=$((WATCHDOG_TICK + 1))
        # каждую итерацию (~2с): проверка дешёвая, а окно "netd снёс и маршрут,
        # и guard" = время до проверки (тест: снесли оба — до ~6с при -ge 3)
        if [ $WATCHDOG_TICK -ge 1 ]; then
            WATCHDOG_TICK=0
            verify_active_rules || {
                log "WATCHDOG: пересобираю правила VPN"
                guard_apply hard $tether_ifaces
                FORCE_UPDATE=1
            }
        fi
    elif [ "$FORCE_UPDATE" -eq 0 ] && [ "$VPN_TETHER_MODE" = "blocked" ] && [ "$KILL_SWITCH" = "1" ]; then
        # В blocked вся защита — это guard; netd мог перетряхнуть FORWARD
        $iptables -C FORWARD -j "$CHAIN_GUARD" 2>/dev/null || {
            log "WATCHDOG: guard в blocked пропал, ставлю заново"
            guard_apply hard $tether_ifaces
        }
    fi

    apply_state "$tun_idx" $tether_ifaces || log "ERROR: apply_state failed"

    dns_watchdog

    FORCE_UPDATE=0

    local pending=0
    [ "$_NEED_UPDATE" -eq 1 ] && pending=1
    _NEED_UPDATE=0

    if [ "$pending" -eq 1 ]; then
        log "Pending update..."
        sleep 1
        LAST_HANDLE_TS=0
        tun_idx=$(read_table_index "$TUN_NAME")
        refresh_tether_ifaces
        tether_ifaces="$TETHER_NOW"
        apply_state "$tun_idx" $tether_ifaces || log "ERROR: apply_state failed"
        FORCE_UPDATE=0
    fi

    # Подтверждаем action.sh, что тоггл отработан и статус актуален
    if [ -n "$ack_token" ]; then
        echo "$ack_token" > "$ACK_FILE" 2>/dev/null
        log "Toggle done (ack $ack_token)"
    fi
    return 0
}

# Перечитать vpn_tether.conf без перезагрузки (кнопка "Применить" в WebUI).
# Зовётся из handle_change перед полной пересборкой (FORCE_UPDATE): здесь
# только сбрасываем то, что пересборка сама не переставит, — DNS-состояние,
# DNS телефона, QUIC, kill-switch при выключении, описание модуля.
# Группы настроек для reload_config: что пересобирать при смене.
# DNS и kill-switch живут в правилах раздачи -> полная пересборка (с ней —
# сброс соединений клиентов). zapret, QUIC приложений и прочее — точечно:
# 20.10 каждое "Применить" (переключение zapret) рвало все соединения
# ноутбука и перезапускало dnsproxy с пустым кэшем.
CONF_GRP_DNS="DNSPROXY_ENABLE DNS_DIRECT DNS_VPN DNS_PHONE DNS_UPSTREAMS DNS_FALLBACKS DNS_VPN_UPSTREAMS DNS_BOOTSTRAP DNS_META_EU DNS_META_ECS DNS_META_UPSTREAMS"
CONF_GRP_KS="KILL_SWITCH KILL_SWITCH_STRICT"
CONF_GRP_QUIC="QUIC_BLOCK_APPS"
CONF_GRP_STEALTH="TETHER_STEALTH TETHER_TTL_STRICT"
CONF_GRP_WARP="WARP_ENABLE WARP_CONF"
CONF_GRP_WARPR="WARP_GOOGLE WARP_TELEGRAM WARP_APPS WARP_DOMAINS WARP_PHONE"
CONF_GRP_ZAPRET="ZAPRET_ENABLE ZAPRET_MODE ZAPRET_PHONE ZAPRET_STRATEGY ZAPRET_ARGS ZAPRET_QUIC_BLOCK ZAPRET_PER_NET YT_GGC_BLOCK YT_DEAD_FAILFAST"
_conf_grp_sig() {   # $1 = имя переменной-результата, дальше ключи
    local _v="$1" _k _o=""; shift
    for _k in "$@"; do eval "_o=\"\$_o|\$$_k\""; done
    eval "$_v=\"\$_o\""
}
RELOAD_NEED_REBUILD=1

reload_config() {
    local old_ks="$KILL_SWITCH" s_dns0 s_ks0 s_quic0 s_zap0 s_dns1 s_ks1 s_quic1 s_zap1 s_st0 s_st1 s_wp0 s_wp1 s_wr0 s_wr1 what=""
    _conf_grp_sig s_dns0 $CONF_GRP_DNS
    _conf_grp_sig s_ks0 $CONF_GRP_KS
    _conf_grp_sig s_quic0 $CONF_GRP_QUIC
    _conf_grp_sig s_zap0 $CONF_GRP_ZAPRET
    _conf_grp_sig s_st0 $CONF_GRP_STEALTH
    _conf_grp_sig s_wp0 $CONF_GRP_WARP
    _conf_grp_sig s_wr0 $CONF_GRP_WARPR
    conf_restore_defaults
    USER_CONF_NOTE=""
    load_user_conf
    conf_apply_overrides
    DNSPROXY_BIN="$DNSPROXY_BIN_FOUND"
    [ "$DNSPROXY_ENABLE" = "1" ] || DNSPROXY_BIN=""
    _conf_grp_sig s_dns1 $CONF_GRP_DNS
    _conf_grp_sig s_ks1 $CONF_GRP_KS
    _conf_grp_sig s_quic1 $CONF_GRP_QUIC
    _conf_grp_sig s_zap1 $CONF_GRP_ZAPRET
    _conf_grp_sig s_st1 $CONF_GRP_STEALTH
    _conf_grp_sig s_wp1 $CONF_GRP_WARP
    _conf_grp_sig s_wr1 $CONF_GRP_WARPR
    RELOAD_NEED_REBUILD=0
    [ "$s_dns0" != "$s_dns1" ] && { what="$what DNS"; RELOAD_NEED_REBUILD=1; }
    [ "$s_ks0" != "$s_ks1" ] && { what="$what kill-switch"; RELOAD_NEED_REBUILD=1; }
    [ "$s_quic0" != "$s_quic1" ] && what="$what QUIC-приложений"
    [ "$s_zap0" != "$s_zap1" ] && what="$what zapret"
    [ "$s_st0" != "$s_st1" ] && what="$what скрытие-раздачи"
    [ "$s_wp0" != "$s_wp1" ] && what="$what WARP"
    [ "$s_wr0" != "$s_wr1" ] && what="$what что-идёт-в-WARP"
    log "Настройки перечитаны:${USER_CONF_NOTE:- (всё по умолчанию)}"
    log "Применяю:${what:- ничего не поменялось}$([ "$RELOAD_NEED_REBUILD" = 1 ] && echo ' — пересборка правил раздачи' || echo ' — без пересборки раздачи')"
    log "Config: DNSPROXY=$DNSPROXY_ENABLE KILL_SWITCH=$KILL_SWITCH STRICT=$KILL_SWITCH_STRICT DNS_DIRECT=$DNS_DIRECT DNS_VPN=$DNS_VPN DNS_PHONE=$DNS_PHONE UPSTREAMS=[$DNS_UPSTREAMS] QUIC_BLOCK=[$QUIC_BLOCK_APPS] ZAPRET=$ZAPRET_ENABLE/$ZAPRET_MODE/$ZAPRET_STRATEGY/phone=$ZAPRET_PHONE/quic=$ZAPRET_QUIC_BLOCK/per_net=$ZAPRET_PER_NET META_EU=$DNS_META_EU/$DNS_META_ECS HEALTH=${DNS_HEALTH_INTERVAL}/${DNS_HEALTH_RECOVER}s"

    if [ "$s_dns0" != "$s_dns1" ]; then
        # DNS: всё с нуля — пересборка поставит заново под новые настройки
        if [ "$PHONE_DNS_ON" = "1" ]; then phone_dns_rules_off; fi
        PHONE_DNS_ON=0
        PHONE_DNS_RETRY=0
        PHONE_VPN_SEEN=""
        PHONE_VPN_STABLE=""
        dnsproxy_stop
        dnsproxy_port_guard_down
        DNSPROXY_SIG=""
        DNSPROXY_STARTED_ROUTE=""
        DNS_STATE=""
        DNS_DEGRADED=0
        DNS_ALT_UPS=""
        DNS_FAST_RECHECK=0
        DNS_FAIL_SIG=""
        DNS_HEALTH_LAST=0
        DNS_ROUTE_CHANGED_TS=$(date +%s)
    fi

    # guard_apply при KILL_SWITCH=0 ничего не делает — старый guard остался бы
    [ "$old_ks" = "1" ] && [ "$KILL_SWITCH" != "1" ] && guard_down

    if [ "$s_quic0" != "$s_quic1" ]; then
        quic_block_down
        quic_block_apply
    fi

    [ "$s_st0" != "$s_st1" ] && stealth_apply

    if [ "$s_wp0" != "$s_wp1" ]; then
        # WARP: снять, сторож поднимет заново с новым конфигом (~2с)
        warp_down "настройки"
        WARP_BAD=""; WARP_EP_FULL=0; WARP_RETRY_TS=0; WARP_ENSURE_DONE=0
        warp_set_state off ""
    fi
    if [ "$s_wr0" != "$s_wr1" ]; then
        # группы: туннель не трогаем, правила пересоберёт сторож (~2с)
        WARP_RT_SIG=""; WARP_DOM_TS=0; WARP_DOM_IPS=""; WARP_APP_TS=0
    fi

    if [ "$s_zap0" != "$s_zap1" ]; then
        # zapret: снять всё, цикл поднимет заново под новые настройки (~2с)
        zapret_down
        NET_ID_FORCE=1
        ZAPRET_NET_BAD=""
    fi

    [ "$STATUS_IN_DESCRIPTION" = "1" ] || set_description "$MODULE_DESC_DEFAULT"
    phone_status_refresh
}

# Только помечаем: вся работа — в handle_change, в основном потоке цикла
handle_usr1() {
    USR1_PENDING=1
    LAST_HANDLE_TS=0
    if [ -f "$RELOAD_FILE" ]; then log "Сигнал: применить настройки (WebUI)"; else log "Toggle signal received"; fi
}

cleanup_on_exit() {
    log "Exiting, cleaning up..."
    cleanup_all_rules
    phone_dns_rules_off
    PHONE_DNS_ON=0
    quic_block_down
    zapret_down
    stealth_off
    dnsproxy_stop
    dnsproxy_port_guard_down
    guard_down
    restore_hw_offload
    block_down
    warp_down "выход"
    # в конце: zapret_down -> phone_status_refresh -> update_status писал
    # описание заново («Раздача через VPN…» после выхода демона)
    [ "$STATUS_IN_DESCRIPTION" = "1" ] && set_description "$MODULE_DESC_DEFAULT"
    rm -f "$PID_FILE" "$RULES_FILE"
    rm -f "$PID_LOCK/pid"
    rmdir "$PID_LOCK" 2>/dev/null || rm -rf "$PID_LOCK" 2>/dev/null
    # Без exit trap возвращался в while true: цикл жил дальше и через 2с
    # заново ставил правила, которые только что снесли.
    exit 0
}

monitor_loop() {
    trap 'handle_usr1' USR1
    trap 'cleanup_on_exit' TERM INT

    set +e
    log "Adaptive monitor started (RTT threshold: ${RTT_THRESHOLD_STABLE}ms, hysteresis: 2 checks)"
    local _loop_count=0
    while true; do
        # sleep в фоне + wait: wait прерывается сигналом, и тоггл
        # обрабатывается сразу, а не после окончания sleep
        if [ "$USR1_PENDING" -eq 0 ]; then
            sleep 2 &
            wait $! 2>/dev/null
        fi
        handle_change || log "ERROR: handle_change failed, continuing anyway"
        # отдельно от handle_change: тот рано выходит, когда хотспот выключен
        phone_dns_reconcile
        # WebUI: сбросить кэш DNS (webctl dnsflush ждёт, пока файл исчезнет)
        if [ -f "$DNS_FLUSH_FILE" ]; then
            dnsproxy_flush "кнопка в WebUI" || log "DNS: сброс кэша — dnsproxy сейчас не запущен"
            rm -f "$DNS_FLUSH_FILE"
        fi
        dns_health
        [ $((_loop_count % 15)) -eq 0 ] && quic_block_apply
        [ $((_loop_count % 15)) -eq 7 ] && meta_eu_watchdog
        [ $((_loop_count % 15)) -eq 3 ] && stealth_reconcile
        # Tethering перевешивает BPF-фильтры при смене аплинка: раздача и WAN —
        # каждый цикл (1-2 вызова tc), все интерфейсы — раз в ~30с
        if [ $((_loop_count % 15)) -eq 11 ]; then
            bpf_offload_detach
        elif [ -n "$LAST_TETHER_IFACES$LAST_WAN_IFACE" ]; then
            bpf_offload_detach $LAST_TETHER_IFACES $LAST_WAN_IFACE
        fi
        block_reconcile
        zapret_whitelist_check
        zapret_reconcile
        [ $((_loop_count % 2)) -eq 1 ] && yt_dead_scan
        [ $((_loop_count % 30)) -eq 17 ] && yt_dead_recheck
        [ $((_loop_count % 5)) -eq 4 ] && yt_slow_reconcile
        zapret_watchdog
        zapret_sites_check
        warp_reconcile
        _loop_count=$(( _loop_count + 1 ))
    done
}
