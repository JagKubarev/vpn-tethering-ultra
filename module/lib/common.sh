# shellcheck shell=sh
# lib/common.sh — общее: журнал (log), режим из кэша, sysctl, статус и описание
# модуля, ip rule из файла правил.
# Часть демона service.sh: подключается из него через ".", сам не запускается.
# Настройки (USER CONFIG) и общие переменные — в service.sh.

log() {
    local msg="$*"
    
    if [ "$msg" = "$LAST_LOG_MSG" ]; then
        LAST_LOG_COUNT=$((LAST_LOG_COUNT + 1))
        if [ $LAST_LOG_COUNT -eq $LOG_REPEAT_THRESHOLD ]; then
            echo "[$(date '+%H:%M:%S')] (previous message repeated $LOG_REPEAT_THRESHOLD times)" >> "$LOG_FILE"
        fi
        if [ $LAST_LOG_COUNT -gt $LOG_REPEAT_THRESHOLD ]; then
            echo "vpn_tether: $*" > /dev/kmsg 2>/dev/null || true
            return
        fi
    else
        if [ $LAST_LOG_COUNT -gt $LOG_REPEAT_THRESHOLD ]; then
            echo "[$(date '+%H:%M:%S')] (previous message repeated total $LAST_LOG_COUNT times)" >> "$LOG_FILE"
        fi
        LAST_LOG_MSG="$msg"
        LAST_LOG_COUNT=1
    fi
    
    if [ -f "$LOG_FILE" ]; then
        local _sz
        _sz=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$_sz" -gt 512000 ]; then
            [ -f "${LOG_FILE}.old" ] && rm -f "${LOG_FILE}.old" 2>/dev/null
            mv "$LOG_FILE" "${LOG_FILE}.old" 2>/dev/null
        fi
    fi
    local full_msg="[$(date '+%H:%M:%S')] $msg"
    echo "$full_msg" >> "$LOG_FILE"
    echo "vpn_tether: $msg" > /dev/kmsg 2>/dev/null || true
    $ANDROID_LOG -t vpn_tether "$msg" 2>/dev/null || true
}

# Режим берётся из кэша, а не из файла: action.sh меняет файл ДО сигнала, и
# итерация, попавшая между ними, перестраивала всё без ack (а потом ещё раз).
# Кэш обновляется только при обработке USR1 и на старте.
VPN_TARGET=""
refresh_vpn_target() { if [ -f "$FLAG_FILE" ]; then VPN_TARGET=1; else VPN_TARGET=0; fi; }
is_vpn_tether_enabled() { [ "$VPN_TARGET" = "1" ]; }

is_excluded_iface() {
    case "$1" in
        tun*|wg*|awg*|vpn*|warp*|ppp*|lo|rmnet*|r_rmnet*|ccmni*|wwan*|pdp*|stnet*|epdg*|dummy*|sit*|ip6*|ifb*|v4-*|clat*|ipsec*|bond*|bridge*|pan*|bt-*|veth*|docker*|lxc*|virbr*|macvlan*|ipvlan*|vlan*|p2p*)
            # p2p* — Wi-Fi Direct / Quick Share (свой DHCP), не раздача
            return 0 ;;
    esac
    return 1
}

set_sysctl() {
    local key="$1" val="$2"
    [ -z "$key" ] && return 0
    sysctl -w "$key=$val" >/dev/null 2>&1 || \
    echo "$val" > "/proc/sys/$(echo "$key" | tr . /)" 2>/dev/null || return 1
}

update_status() {
    local mode=$1 ifaces=$2 profile=$3
    local tun0_mtu=$($ip link show "$TUN_NAME" 2>/dev/null | awk '/mtu/{for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1);exit}}')
    local status_line=""
    
    if [ "$mode" = "vpn" ]; then
        status_line="✅ VPN ON"
    elif [ "$mode" = "blocked" ]; then
        status_line="⛔ VPN выбран, но не поднят — раздача заблокирована (kill-switch)"
    else
        status_line="🔴 VPN OFF"
    fi
    [ -n "$profile" ] && status_line="$status_line [$profile]"
    [ -n "$tun0_mtu" ] && status_line="$status_line | tun0 MTU: $tun0_mtu"
    [ $CURRENT_MSS -gt 0 ] && status_line="$status_line | MSS: $CURRENT_MSS ($MSS_METHOD)"
    [ "$mode" != "blocked" ] && [ -n "$DNS_STATE" ] && status_line="$status_line | DNS: $DNS_STATE"
    if [ "$DNS_DEGRADED" = "1" ]; then
        status_line="$status_line | ⚠️ DoH недоступен — DNS обычный"
    elif [ "$PHONE_DNS_ON" = "1" ]; then
        status_line="$status_line | DNS телефона: dnsproxy"
    fi
    LAST_STATUS_MODE="$mode"
    LAST_STATUS_IFACES="$ifaces"

    # Строки 1-2 — как раньше (совместимость), дальше КЛЮЧ=значение для
    # action.sh: он собирает из них понятный человеку текст.
    local vpn_up=0 up_host
    vpn_up_now && vpn_up=1
    up_host=$(echo "${DNS_ALT_UPS:-$DNS_UPSTREAMS}" | awk '{print $1}' | sed -E 's#^[a-z0-9]+://##; s#[/:].*##')
    {
        printf '%s\n%s\n' "$status_line" "$ifaces"
        echo "mode=$mode"
        echo "target=$(is_vpn_tether_enabled && echo vpn || echo direct)"
        echo "ifaces=$(echo "$ifaces" | tr '/' ' ' | sed 's/no-tether//')"
        echo "vpn_up=$vpn_up"
        echo "dns_state=$DNS_STATE"
        echo "dns_degraded=$DNS_DEGRADED"
        echo "dns_alt=$([ -n "$DNS_ALT_UPS" ] && echo 1 || echo 0)"
        echo "ggc=$([ -n "$GGC_STATE" ] && echo on || echo off)"
        echo "yt_dead=$([ "$YT_DEAD_STATE" = on ] && cat "$YT_DEAD_FILE" 2>/dev/null | awk 'END {print NR}' || echo off)"
        echo "yt_dead_hits=$(yt_dead_hits)"
        if [ -n "$YT_SLOW_PID" ]; then
            echo "yt_slow=$(sed -n 's/^state=//p' "$YT_SLOW_STAT" 2>/dev/null || echo on)"
            echo "yt_slow_kills=$(sed -n 's/^kills=//p' "$YT_SLOW_STAT" 2>/dev/null)"
            echo "yt_slow_fast=$(sed -n 's/^fast=//p' "$YT_SLOW_STAT" 2>/dev/null)"
            echo "yt_slow_degr=$(sed -n 's/^degr=//p' "$YT_SLOW_STAT" 2>/dev/null)"
        else
            echo "yt_slow=off"
        fi
        echo "zwd=$ZAPRET_WATCHDOG"
        echo "stealth=$([ "$STEALTH_STATE" = on ] && echo on || echo off)"
        echo "stealth_strict=$TETHER_TTL_STRICT"
        echo "ttl_foreign=$(stealth_foreign)"
        echo "stealth_rivals=$STEALTH_RIVALS"
        echo "stealth_rival_rules=$STEALTH_RIVAL_RULES"
        echo "phone_dns=$PHONE_DNS_ON"
        echo "dns_phone_enabled=$DNS_PHONE"
        echo "dnsproxy_enable=$DNSPROXY_ENABLE"
        echo "dns_upstream=$up_host"
        echo "kill_switch=$KILL_SWITCH"
        echo "mtu=$tun0_mtu"
        echo "mss=$CURRENT_MSS"
        echo "quic_uids=$QUIC_UIDS"
        echo "zapret=$ZAPRET_STATE"
        echo "zapret_auto=$(cat "$ZAPRET_LIST_AUTO" 2>/dev/null | grep -c '[a-z0-9]')"
        echo "zapret_per_net=$ZAPRET_PER_NET"
        echo "zapret_strategy=$ZAPRET_EFF_STRATEGY"
        echo "zapret_eff_args=$ZAPRET_EFF_ARGS"
        echo "zapret_eff_yt=$ZAPRET_EFF_YT"
        echo "zapret_alt_n=$ZAPRET_ALT_N"
        echo "zapret_src=$ZAPRET_NET_SRC"
        echo "net_key=$NET_KEY"
        echo "net_label=$NET_LABEL"
        echo "meta_eu=$DNS_META_EU"
        echo "meta_eu_on=$DNSPROXY_META_ON"
        echo "meta_ecs=$DNS_META_ECS"
        echo "wan=$LAST_WAN_IFACE"
        echo "warp=$([ "$WARP_ENABLE" = 1 ] && echo "$WARP_STATE" || echo disabled)"
        echo "warp_conf=$WARP_CUR"
        echo "warp_note=$WARP_NOTE"
        echo "conf_note=$USER_CONF_NOTE"
        echo "updated=$(date '+%H:%M:%S')"
    } > "$STATUS_FILE.tmp" 2>/dev/null && mv -f "$STATUS_FILE.tmp" "$STATUS_FILE"

    update_description "$mode" "$ifaces"
}

# wlan2/rndis0 -> "Wi-Fi, USB"
friendly_ifaces() {
    local out="" i n
    for i in $(echo "$*" | tr '/' ' '); do
        case "$i" in
            wlan*|ap*|swlan*|softap*|hotspot*) n="Wi-Fi" ;;
            rndis*|ncm*|usb*)                 n="USB" ;;
            bt-pan|bnep*)                     n="Bluetooth" ;;
            eth*)                             n="Ethernet" ;;
            no-tether|"")                     continue ;;
            *)                                n="$i" ;;
        esac
        case ", $out, " in *", $n, "*) ;; *) out="${out:+$out, }$n" ;; esac
    done
    echo "$out"
}

# Текущее состояние — в описание модуля (список модулей KernelSU/Magisk).
# Пишем только при изменении; на выходе демона возвращаем обычное описание.
MODULE_DESC_DEFAULT="Раздача Wi-Fi/USB через VPN или напрямую: защита от утечек, зашифрованный DNS (DoH), обход блокировок. Action — переключить VPN/напрямую."
update_description() {
    [ "$STATUS_IN_DESCRIPTION" = "1" ] || return 0
    local mode="$1" ifaces="$2" f="$MODULE_DIR/module.prop" names d up_host
    [ -f "$f" ] || return 0
    names=$(friendly_ifaces "$ifaces")
    up_host=$(echo "$DNS_UPSTREAMS" | awk '{print $1}' | sed -E 's#^[a-z0-9]+://##; s#[/:].*##')
    case "$mode" in
        vpn)     d="Раздача через VPN${names:+ · $names}" ;;
        blocked) d="VPN не подключён — раздача приостановлена" ;;
        *)
            if [ -z "$names" ]; then
                d="Раздача выключена · режим: $(is_vpn_tether_enabled && echo VPN || echo напрямую)"
            else
                d="Раздача напрямую · $names"
            fi ;;
    esac
    if [ "$DNS_DEGRADED" = "1" ]; then
        d="$d · DoH не отвечает, DNS обычный"
    elif [ "$mode" = "direct" ] && [ -n "$names" ]; then
        case "$DNS_STATE" in dnsproxy*) d="$d · DNS: $up_host" ;; esac
    fi
    [ "$mode" = "direct" ] && [ -n "$names" ] && [ "$ZAPRET_STATE" = "on" ] && d="$d · обход DPI"
    d="$d · Action — переключить"
    set_description "$d"
}
set_description() {
    local f="$MODULE_DIR/module.prop"
    [ -f "$f" ] || return 0
    [ "$(sed -n 's/^description=//p' "$f")" = "$1" ] && return 0
    awk -v d="$1" '/^description=/ {print "description=" d; next} {print}' "$f" > "$f.tmp" 2>/dev/null && \
        grep -q '^id=' "$f.tmp" && cat "$f.tmp" > "$f"
    rm -f "$f.tmp"
}

save_rule() { printf '%s\n' "$*" >> "$RULES_FILE"; }
clear_rules_file() { rm -f "$RULES_FILE"; touch "$RULES_FILE"; }

ip_rule_add() {
    if $ip rule add "$@" 2>/dev/null; then
        save_rule "$*"
        log "Added ip rule: $*"
        return 0
    fi
    return 1
}

ip_rule_del_all() {
    [ -f "$RULES_FILE" ] || return 0
    while IFS= read -r rule || [ -n "$rule" ]; do
        rule="${rule## }"
        rule="${rule%% }"
        [ -z "$rule" ] && continue
        $ip rule del $rule 2>/dev/null || log "Failed to delete rule: $rule"
    done < "$RULES_FILE"
    rm -f "$RULES_FILE"
}

phone_status_refresh() {
    [ -n "$LAST_STATUS_MODE" ] && update_status "$LAST_STATUS_MODE" "$LAST_STATUS_IFACES" "$CURRENT_NET_PROFILE"
}

