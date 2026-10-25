# shellcheck shell=sh
# lib/rules.sh — правила раздачи: conntrack, HW offload, kill-switch (guard),
# правила direct / blocked / VPN, apply_state.
# Часть демона service.sh: подключается из него через ".", сам не запускается.
# Настройки (USER CONFIG) и общие переменные — в service.sh.

# --- перенесено из ветки B (без изменений логики) ---
flush_conntrack() {
    if [ "$TARGETED_CT_FLUSH" != "1" ]; then
        # поведение 0.7.3: на большинстве ядер это no-op (файл read-only)
        echo f > /proc/net/nf_conntrack 2>/dev/null || true
        return 0
    fi
    if [ -n "$CONNTRACK_BIN" ]; then
        # ТОЛЬКО подсети реальных tether-ифейсов. Блэнкет по RFC1918 сносил
        # NAT-маппинги AdGuard transparent proxy и живые потоки телефона.
        local ok=0 skipped=1 out net iface
        for iface in $(get_active_tether_ifaces) $LAST_TETHER_IFACES; do
            net=$($ip -4 addr show dev "$iface" 2>/dev/null | \
                  awk '/inet /{print $2; exit}')
            case "$net" in
                */*)
                    skipped=0
                    out=$("$CONNTRACK_BIN" -D --orig-src "$net" 2>&1)
                    case "$out" in
                        *"flow entries"*) ok=1 ;;
                    esac
                    ;;
            esac
        done
        [ "$ok" -eq 1 ] && log "conntrack: tether-subnet flows flushed (targeted)"
        # Нет tether-подсетей — флашить нечего. Фолбэка на -F нет намеренно.
        return 0
    fi
    if [ "$CONNTRACK_WARNED" -eq 0 ]; then
        log "WARNING: no conntrack binary, stale NAT entries live until timeout"
        CONNTRACK_WARNED=1
    fi
    return 1
}

disable_hw_offload() {
    [ "$DISABLE_HW_OFFLOAD" = "1" ] || return 0
    if ! command -v settings >/dev/null 2>&1; then
        log "WARNING: no settings binary, HW offload left as-is"
        return 1
    fi
    if [ ! -f "$OFFLOAD_SAVE_FILE" ]; then
        {
            echo "setting=$(settings get global tether_offload_disabled 2>/dev/null)"
            command -v device_config >/dev/null 2>&1 && \
                echo "bpf=$(device_config get tethering override_bpf_offload 2>/dev/null)"
        } > "$OFFLOAD_SAVE_FILE" 2>/dev/null
    fi
    settings put global tether_offload_disabled 1 2>/dev/null
    command -v device_config >/dev/null 2>&1 && \
        device_config put tethering override_bpf_offload false 2>/dev/null
    # На A13+ BPF offload этим не выключается (A15: mIsBpfEnabled: true) —
    # его снимает bpf_offload_detach. Раньше здесь был dumpsys-чек, но при
    # загрузке раздача ещё не поднята, и в логе было ложное "HAL + BPF".
    log "HW tethering offload disabled (HAL); BPF offload: снимаю tc-фильтры Tethering"
    bpf_offload_detach
    return 0
}

# --- BPF tethering offload (Android 13+) ---
# tc-программы Tethering (schedcls_tether_*) на ingress раздачи и аплинка
# форвардят потоки МИМО netfilter: их не видят ни kill-switch, ни ip rule,
# ни conntrack flush. Правила в BPF-картах переживают удаление conntrack:
# 20.10 после переключения direct -> VPN ноут ещё 10+ минут гнал старые
# соединения напрямую через rmnet_data1 (~1 МБ/мин с реальным IP), хотя в
# conntrack их уже не было, а guard не дропнул ни пакета. То же для IPv6:
# ip6tables FORWARD DROP BPF-форвард не видит.
# Снимаем сами фильтры — так же, как это делает Tethering (protocol + pref).
# Без них форвард идёт обычным путём ядра, как при выключенном HAL offload.
# Tethering вешает их заново при смене аплинка, поэтому проверка — каждый
# цикл. Обратно не вешаем: offload вернётся после перезапуска точки доступа.
TC_BIN="/system/bin/tc"
BPF_DETACH_WARNED=0

bpf_offload_detach() {   # [iface...]; без аргументов — все интерфейсы
    [ "$DISABLE_HW_OFFLOAD" = "1" ] || return 0
    [ -x "$TC_BIN" ] || return 0
    local ifaces="$*" d out spec detached="" failed=""
    [ -z "$ifaces" ] && ifaces=$(ls /sys/class/net 2>/dev/null)
    for d in $ifaces; do
        out=$($TC_BIN filter show dev "$d" ingress 2>/dev/null)
        case "$out" in *schedcls_tether_*) ;; *) continue ;; esac
        for spec in $(printf '%s\n' "$out" | awk '/schedcls_tether_/ {
                p = ""; r = ""
                for (i = 1; i < NF; i++) { if ($i == "protocol") p = $(i+1); if ($i == "pref") r = $(i+1) }
                if (p != "" && r != "") print p ":" r }' | sort -u); do
            if $TC_BIN filter del dev "$d" ingress protocol "${spec%%:*}" pref "${spec#*:}" 2>/dev/null; then
                detached="$detached $d/${spec%%:*}"
            else
                failed="$failed $d/${spec%%:*}"
            fi
        done
    done
    [ -n "$detached" ] && log "BPF offload: сняты tc-фильтры Tethering [$detached ] — форвард раздачи только через netfilter"
    if [ -n "$failed" ] && [ "$BPF_DETACH_WARNED" -eq 0 ]; then
        log "WARNING: BPF offload: не снялись tc-фильтры [$failed ] — старые потоки могут идти мимо VPN"
        BPF_DETACH_WARNED=1
    fi
    return 0
}

restore_hw_offload() {
    [ -f "$OFFLOAD_SAVE_FILE" ] || return 0
    local line key val
    while IFS= read -r line || [ -n "$line" ]; do
        key="${line%%=*}"
        val="${line#*=}"
        case "$key" in
            setting)
                case "$val" in
                    ""|null) settings delete global tether_offload_disabled 2>/dev/null ;;
                    *)       settings put global tether_offload_disabled "$val" 2>/dev/null ;;
                esac ;;
            bpf)
                case "$val" in
                    ""|null) device_config delete tethering override_bpf_offload 2>/dev/null ;;
                    *)       device_config put tethering override_bpf_offload "$val" 2>/dev/null ;;
                esac ;;
        esac
    done < "$OFFLOAD_SAVE_FILE"
    rm -f "$OFFLOAD_SAVE_FILE"
    log "HW offload settings restored"
}

# ============================================================================
# KILL-SWITCH (fail-closed guard)
# Отдельная цепочка в самом начале FORWARD. Два режима:
#   hard  — режем ВЕСЬ форвард с tether-ифейсов (на время пересборки правил
#           и на время подозрения, что VPN отвалился)
#   armed — режем только то, что уходит МИМО tun (штатный kill-switch)
# Смысл: при любом сбое (stale таблица, netd снёс ip rule, окно между
# cleanup и setup) клиент теряет интернет, а НЕ уходит напрямую с реальным IP.
# ============================================================================
guard_apply() {
    local mode="$1"; shift
    local ifaces="$*" iface
    [ "$KILL_SWITCH" = "1" ] || return 0
    [ -z "$ifaces" ] && return 0

    $iptables -N "$CHAIN_GUARD" 2>/dev/null
    $iptables -F "$CHAIN_GUARD" 2>/dev/null
    for iface in $ifaces; do
        if [ "$mode" = "hard" ]; then
            $iptables -A "$CHAIN_GUARD" -i "$iface" -j DROP 2>/dev/null
        else
            $iptables -A "$CHAIN_GUARD" -i "$iface" ! -o "$TUN_NAME" -j DROP 2>/dev/null
        fi
    done
    # гарантированно первым: сначала снимаем хук, потом ставим в позицию 1
    $iptables -D FORWARD -j "$CHAIN_GUARD" 2>/dev/null
    $iptables -I FORWARD 1 -j "$CHAIN_GUARD" 2>/dev/null || {
        # занят xtables lock и т.п. — не делать вид, что kill-switch стоит
        log "ERROR: Kill-switch: хук FORWARD -> $CHAIN_GUARD не встал ($mode [$ifaces])"
        return 1; }

    # DNS к самому телефону. В armed его ловит DNAT в DNS VPN, а в hard
    # (пересборка / VPN не поднят) DNAT снят, и запросы клиента уходили
    # в dnsmasq раздачи -> к DNS оператора. DHCP (67) не трогаем.
    $iptables -N "$CHAIN_GUARD_IN" 2>/dev/null
    $iptables -F "$CHAIN_GUARD_IN" 2>/dev/null
    if [ "$mode" = "hard" ]; then
        for iface in $ifaces; do
            $iptables -A "$CHAIN_GUARD_IN" -i "$iface" -p udp --dport 53 -j DROP 2>/dev/null
            $iptables -A "$CHAIN_GUARD_IN" -i "$iface" -p tcp --dport 53 -j DROP 2>/dev/null
            $iptables -A "$CHAIN_GUARD_IN" -i "$iface" -p udp --dport "$DNSPROXY_PORT" -j DROP 2>/dev/null
            $iptables -A "$CHAIN_GUARD_IN" -i "$iface" -p tcp --dport "$DNSPROXY_PORT" -j DROP 2>/dev/null
        done
    fi
    $iptables -C INPUT -j "$CHAIN_GUARD_IN" 2>/dev/null || \
        $iptables -I INPUT 1 -j "$CHAIN_GUARD_IN" 2>/dev/null

    [ "$GUARD_STATE" != "$mode" ] && log "Kill-switch: $mode [$ifaces]"
    GUARD_STATE="$mode"
    return 0
}

guard_down() {
    _n=0
    while [ $_n -lt 8 ] && $iptables -D FORWARD -j "$CHAIN_GUARD" 2>/dev/null; do _n=$((_n + 1)); done
    $iptables -F "$CHAIN_GUARD" 2>/dev/null
    $iptables -X "$CHAIN_GUARD" 2>/dev/null
    _n=0
    while [ $_n -lt 8 ] && $iptables -D INPUT -j "$CHAIN_GUARD_IN" 2>/dev/null; do _n=$((_n + 1)); done
    $iptables -F "$CHAIN_GUARD_IN" 2>/dev/null
    $iptables -X "$CHAIN_GUARD_IN" 2>/dev/null
    [ "$GUARD_STATE" != "none" ] && log "Kill-switch: off"
    GUARD_STATE="none"
    return 0
}

# Зомби-правила от убитого демона: RULES_FILE мог не сохраниться,
# поэтому сносим всё по нашему маркеру pref 3000.
sweep_zombie_rules() {
    local n=0
    while [ $n -lt 32 ] && $ip rule del pref 3000 2>/dev/null; do
        n=$((n + 1))
    done
    [ $n -gt 0 ] && log "Swept $n stale ip rule(s) pref 3000"
    return 0
}

# Проверка, что то, что мы поставили, всё ещё на месте.
# netd/TetheringService регулярно перетряхивают правила при реконнекте
# клиента, смене диапазона, IPv6 provisioning и т.п.
verify_active_rules() {
    [ "$RULE_WATCHDOG" = "1" ] || return 0
    [ "$VPN_TETHER_MODE" = "on" ] || return 0
    [ -n "$LAST_TETHER_IFACES" ] || return 0
    [ -n "$LAST_TUN_INDEX" ] || return 0

    local iface rules
    # tun пропал (VPN переподключается или выключен) — это работа гистерезиса
    # в apply_state: hard на 1-м и 2-м промахе, direct — на 3-м. Иначе
    # «таблица пустая» ставила FORCE_UPDATE, и на первом же промахе раздача
    # уходила напрямую (25.10: 18:20:09, 19:03:38 — «упал (1 промахов подряд)»).
    $ip addr show "$TUN_NAME" 2>/dev/null | grep -q "inet " || return 0
    rules=$($ip rule show 2>/dev/null)

    for iface in $LAST_TETHER_IFACES; do
        case "$rules" in
            *"iif $iface lookup $LAST_TUN_INDEX"*|*"iif $iface lookup $TUN_NAME"*) ;;
            *) log "WATCHDOG: ip rule iif $iface -> $LAST_TUN_INDEX пропало"; return 1 ;;
        esac
    done

    $ip route show table "$LAST_TUN_INDEX" 2>/dev/null | grep -q . || {
        log "WATCHDOG: таблица $LAST_TUN_INDEX пустая (stale)"; return 1; }

    $iptables -C FORWARD -j "$CHAIN_FWD" 2>/dev/null || {
        log "WATCHDOG: хук FORWARD -> $CHAIN_FWD пропал"; return 1; }

    $iptables -t nat -C POSTROUTING -j "$CHAIN_POST" 2>/dev/null || {
        log "WATCHDOG: хук nat POSTROUTING -> $CHAIN_POST пропал"; return 1; }

    # DNS клиентов в VPN-режиме всегда через нашу цепочку (DNAT или dnsproxy);
    # без хука клиенты спрашивали бы DNS раздачи — мимо VPN
    # цепочка цела — хватит вернуть хук, без полной пересборки
    if ! $iptables -t nat -C PREROUTING -j "$CHAIN_DNS" 2>/dev/null; then
        if $iptables -t nat -L "$CHAIN_DNS" -n >/dev/null 2>&1 && \
           $iptables -t nat -I PREROUTING 1 -j "$CHAIN_DNS" 2>/dev/null; then
            log "WATCHDOG: хук nat PREROUTING -> $CHAIN_DNS пропал — вернул"
        else
            log "WATCHDOG: хук nat PREROUTING -> $CHAIN_DNS пропал"; return 1
        fi
    fi

    if [ "$KILL_SWITCH" = "1" ]; then
        $iptables -C FORWARD -j "$CHAIN_GUARD" 2>/dev/null || {
            log "WATCHDOG: kill-switch снят, переставляю"; return 1; }
    fi

    return 0
}

cleanup_all_rules() {
    log "Full cleanup..."

    # Восстанавливаем оригинальный MTU перед сбросом
    # только тому же tun: если VPN-приложение пересоздало tun0 (смена
    # приложения без паузы), MTU прошлого (NekoBox 9000) встал бы на новый (AWG 1280)
    if [ -n "$ORIGINAL_TUN_MTU" ] && [ "$ORIGINAL_TUN_MTU" -gt 0 ] 2>/dev/null && \
       [ "$(cat "/sys/class/net/$TUN_NAME/ifindex" 2>/dev/null)" = "$ORIGINAL_TUN_IFINDEX" ]; then
        $ip link set dev "$TUN_NAME" mtu "$ORIGINAL_TUN_MTU" 2>/dev/null || true
    fi
    # файл — только если оригинал наш (вернули или tun уже другой); у нового
    # демона после kill -9 ORIGINAL_TUN_MTU пуст — файл нужен setup_vpn_rules
    [ -n "$ORIGINAL_TUN_MTU" ] && rm -f "$TUN_MTU_FILE"
    ORIGINAL_TUN_MTU=""

    ip_rule_del_all
    sweep_zombie_rules

    # Блэнкетный "-A FORWARD -j ACCEPT" раньше НЕ удалялся никогда и жил
    # сквозь все cleanup. Именно он превращал любой сбой маршрутизации
    # в рабочий direct-выход для клиента. Сносим; direct-режим ставит заново.
    _n=0
    while [ $_n -lt 8 ] && $iptables -D FORWARD -j ACCEPT 2>/dev/null; do _n=$((_n + 1)); done

    $iptables -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    $iptables -D FORWARD -j "$CHAIN_FWD" 2>/dev/null
    $iptables -F "$CHAIN_FWD" 2>/dev/null
    $iptables -X "$CHAIN_FWD" 2>/dev/null

    $iptables -D FORWARD -j "$CHAIN_MSS" 2>/dev/null
    $iptables -F "$CHAIN_MSS" 2>/dev/null
    $iptables -X "$CHAIN_MSS" 2>/dev/null

    $iptables -t nat -D POSTROUTING -j "$CHAIN_POST" 2>/dev/null
    $iptables -t nat -F "$CHAIN_POST" 2>/dev/null
    $iptables -t nat -X "$CHAIN_POST" 2>/dev/null

    $iptables -t mangle -D PREROUTING -j "VPN_TETHER_MARK" 2>/dev/null
    $iptables -t mangle -F "VPN_TETHER_MARK" 2>/dev/null
    $iptables -t mangle -X "VPN_TETHER_MARK" 2>/dev/null
    
    cleanup_dns_redirect

    $ip6tables -D FORWARD -j DROP 2>/dev/null
    $ip6tables -D FORWARD -j REJECT --reject-with icmp6-no-route 2>/dev/null

    $iptables -D FORWARD -m conntrack --ctstate INVALID -j DROP 2>/dev/null || true

    $ip route flush cache 2>/dev/null

    # Сбрасываем conntrack при каждом cleanup.
    # При VPN reconnect MASQUERADE IP меняется -> старые conntrack записи
    # содержат неверный NAT-адрес и дропают пакеты (Telegram "соединение...")
    # ВАЖНО: до обнуления LAST_TETHER_IFACES (flush_conntrack их использует)
    flush_conntrack

    LAST_TUN_INDEX=""
    LAST_TETHER_IFACES=""
    LAST_TETHER_IFACES_STABLE=""
    LAST_VPN_ACTIVE="false"
    VPN_TETHER_MODE="off"
    CURRENT_MSS=0
    MSS_METHOD="static"
}

# Хвосты «Telegram через Opera» (3.13–3.15.1, убрано в 3.16): демон
# перезапущен без перезагрузки — цепочки, ip rule, процессы и файлы старой
# версии могли остаться. TPROXY без слушателя дропает Telegram. Раз при старте.
opera_leftovers_cleanup() {
    local _n f p c t found=0
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D PREROUTING -j VPN_OPERA_IN 2>/dev/null; do _n=$((_n + 1)); found=1; done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D OUTPUT -j VPN_OPERA_OUT 2>/dev/null; do _n=$((_n + 1)); found=1; done
    for c in VPN_OPERA_IN VPN_OPERA_OUT VPN_OPERA_TP; do
        for t in mangle nat; do
            $iptables -t $t -F "$c" 2>/dev/null && { $iptables -t $t -X "$c" 2>/dev/null; found=1; }
        done
    done
    # исключение opera-proxy (группа 3997) из перехвата AdGuard
    _n=0; while [ $_n -lt 8 ] && $iptables -t nat -D OUTPUT -m owner --gid-owner 3997 -j RETURN 2>/dev/null; do _n=$((_n + 1)); found=1; done
    _n=0; while [ $_n -lt 8 ] && $ip rule del pref 2990 lookup 3997 2>/dev/null; do _n=$((_n + 1)); found=1; done
    $ip route flush table 3997 2>/dev/null
    # фоновая проверка сайтов (подоболочка старого service.sh)
    p=$(cat /data/local/tmp/vpn_tether_opera_sites.pid 2>/dev/null)
    case "$p" in ''|*[!0-9]*) ;; *)
        [ "$p" != "$$" ] && case "$(tr '\0' ' ' 2>/dev/null < "/proc/$p/cmdline")" in
            *service.sh*) kill "$p" 2>/dev/null && found=1 ;;
        esac ;;
    esac
    # opera-proxy и hev: argv[0] — путь бинаря модуля (обёртки su/sh и сам grep не в счёт)
    for f in $(grep -lE 'bin/(opera-proxy|hev-socks5-tproxy)' /proc/[0-9]*/cmdline 2>/dev/null); do
        case "$(tr '\0' ' ' 2>/dev/null < "$f")" in
            "$MODULE_DIR/bin/opera-proxy"*|"$MODULE_DIR/bin/hev-socks5-tproxy"*)
                f="${f#/proc/}"; kill -9 "${f%/cmdline}" 2>/dev/null && found=1 ;;
        esac
    done
    for f in /data/adb/vpn_tether_opera* /data/local/tmp/vpn_tether_opera* /data/local/tmp/vpn_tether_hev*; do
        [ -e "$f" ] && { rm -rf "$f"; found=1; }
    done
    [ "$found" = 1 ] && log "Убраны хвосты Telegram через Opera (до 3.16)"
    return 0
}

apply_iface_optimizations() {
    local tun_mtu=""
    case "$1" in
        [0-9]*) tun_mtu="$1"; shift ;;
    esac
    local tether_ifaces="$*"

    for iface in $tether_ifaces; do
        $ip link show "$iface" >/dev/null 2>&1 || continue

        [ -f "/proc/sys/net/ipv4/conf/$iface/rp_filter" ] && \
            echo 2 > "/proc/sys/net/ipv4/conf/$iface/rp_filter" 2>/dev/null || true

        case "$iface" in
            rndis*|usb*)
                $ip link set "$iface" txqueuelen 1000 2>/dev/null || true
                ;;
            *)
                $ip link set "$iface" txqueuelen 1000 2>/dev/null || true
                ;;
        esac
    done

    apply_rps_xps $tether_ifaces
}

setup_direct_rules() {
    local tether_ifaces="$*"
    log "Setup DIRECT mode for: [$tether_ifaces]"

    cleanup_all_rules
    clear_rules_file

    # Direct — осознанный режим, kill-switch снимаем
    guard_down
    # и здесь: BPF-правила direct-потоков иначе переживут переход в VPN
    bpf_offload_detach

    # Базовые FORWARD-правила для direct mode (на случай DROP-политики)
    $iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
        $iptables -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $iptables -C FORWARD -j ACCEPT 2>/dev/null || $iptables -A FORWARD -j ACCEPT

    if [ -z "$tether_ifaces" ]; then
        apply_dns_mode direct ""
        update_status "direct" "no-tether" "$CURRENT_NET_PROFILE"
        return 0
    fi

    apply_iface_optimizations $tether_ifaces || log "WARNING: Interface optimization failed"
    apply_sysctl_optimizations
    apply_advanced_speed_tweaks
    
    apply_dns_mode direct "$(direct_dns_servers)" $tether_ifaces
    
    CURRENT_MSS=0
    MSS_METHOD="none"
    update_status "direct" "$(echo $tether_ifaces | tr ' ' '/')" "$CURRENT_NET_PROFILE"
    $ip route flush cache 2>/dev/null
    log "Direct mode done (DNS: $DNS_STATE)"
    return 0
}

# Strict kill-switch: пользователь выбрал VPN, а VPN нет. Клиенты остаются
# подключёнными к раздаче, но без форварда и без DNS — до появления VPN
# (apply_state сам поднимет setup_vpn_rules) или переключения в direct.
setup_blocked_rules() {
    local tether_ifaces="$*"
    log "Setup BLOCKED (VPN выбран, но не поднят) for: [$tether_ifaces]"

    guard_apply hard $tether_ifaces
    bpf_offload_detach
    cleanup_all_rules
    clear_rules_file

    $ip6tables -C FORWARD -j DROP 2>/dev/null || $ip6tables -I FORWARD -j DROP 2>/dev/null
    # cleanup_all_rules сносит хуки, но не цепочку guard — подтверждаем её
    guard_apply hard $tether_ifaces

    # Раздаче в blocked DNS не нужен. Телефону (VPN не поднят) — может быть
    # нужен, поэтому release, а не stop.
    dnsproxy_release
    DNS_STATE=""

    CURRENT_MSS=0
    update_status "blocked" "$(echo $tether_ifaces | tr ' ' '/')" "$CURRENT_NET_PROFILE"
    return 0
}

setup_vpn_rules() {
    local tun_table_index=$1; shift
    local tether_ifaces="$*"

    [ -z "$tether_ifaces" ] && { log "No tether ifaces, skipping VPN setup"; return 1; }
    [ -z "$tun_table_index" ] && { log "No tun table index!"; return 1; }

    local tun_fwmark=$(get_tun_fwmark)
    log "Setup VPN: table=$tun_table_index fwmark=$tun_fwmark ifaces=[$tether_ifaces]"

    # Fail-closed НА ВРЕМЯ ПЕРЕСБОРКИ. cleanup_all_rules сносит ip rule и
    # цепочки, а дальше идут sysctl/MTU/conntrack — это ~1-2 секунды, в
    # которые форвард с wlan2 спокойно уходил в main table (= напрямую).
    guard_apply hard $tether_ifaces
    # BPF-форвард guard не видит — снимаем до пересборки (все интерфейсы:
    # программы висят и на аплинке, который мог смениться)
    bpf_offload_detach

    cleanup_all_rules
    clear_rules_file

    # IPv6-форвард режем СРАЗУ, а не в конце после dumpsys (тот может
    # висеть до 3-6с на таймауте — всё это время был v6-леак).
    $ip6tables -D FORWARD -j REJECT --reject-with icmp6-no-route 2>/dev/null
    $ip6tables -D FORWARD -j DROP 2>/dev/null
    $ip6tables -I FORWARD -j DROP 2>/dev/null
    
    # Сохраняем оригинальный MTU в родительском процессе, а не в подоболочке
    if [ -z "$ORIGINAL_TUN_MTU" ]; then
        ORIGINAL_TUN_IFINDEX=$(cat "/sys/class/net/$TUN_NAME/ifindex" 2>/dev/null)
        # демона убили (kill -9) после того, как он занизил MTU: у того же tun
        # «оригинал» — из файла, иначе каждый крах опускал бы MTU ещё на 40
        # (каскад из «Уроков»)
        local _fi="" _fm=""
        read -r _fi _fm < "$TUN_MTU_FILE" 2>/dev/null
        if [ -n "$ORIGINAL_TUN_IFINDEX" ] && [ "$_fi" = "$ORIGINAL_TUN_IFINDEX" ] && [ -n "$_fm" ]; then
            ORIGINAL_TUN_MTU="$_fm"
        else
            ORIGINAL_TUN_MTU=$($ip link show "$TUN_NAME" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}')
            [ -n "$ORIGINAL_TUN_IFINDEX" ] && echo "$ORIGINAL_TUN_IFINDEX $ORIGINAL_TUN_MTU" > "$TUN_MTU_FILE" 2>/dev/null
        fi
        log "Original TUN MTU saved: $ORIGINAL_TUN_MTU"
    fi
    
    local tun_mtu
    tun_mtu=$(get_tun_mtu)
    log "Original TUN MTU: $ORIGINAL_TUN_MTU -> safe MTU: $tun_mtu"

    apply_sysctl_optimizations
    apply_iface_optimizations "$tun_mtu" $tether_ifaces || log "WARNING: Interface optimization failed"
    apply_advanced_speed_tweaks

# Принудительно ставим safe_mtu на tun0 (нужно для UDP)
$ip link set dev "$TUN_NAME" mtu "$tun_mtu" 2>/dev/null && \
    log "tun0 MTU set to $tun_mtu (was $ORIGINAL_TUN_MTU)" || \
    log "WARNING: failed to set tun0 MTU (VPN app owns it)"

    # --- FORWARD: порядок ESTABLISHED → MSS → разрешение ---
    # 1. Пропускаем уже установленные соединения (короткий путь, снижает нагрузку)
    $iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
        $iptables -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # 2. MSS clamping — до разрешающих правил, чтобы SYN обработался первым
    $iptables -N "$CHAIN_MSS" 2>/dev/null
    $iptables -F "$CHAIN_MSS"

    local tcp_mss=$(( tun_mtu - 40 ))
    $iptables -A "$CHAIN_MSS" -o "$TUN_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$tcp_mss"
    $iptables -A "$CHAIN_MSS" -i "$TUN_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$tcp_mss"

    $iptables -C FORWARD -j "$CHAIN_MSS" 2>/dev/null || $iptables -I FORWARD 2 -j "$CHAIN_MSS"

    # 3. Разрешающие правила — ACCEPT (не RETURN: на Android политика FORWARD=DROP,
    #    RETURN вернёт пакет в цепочку и он дропнется без явного ACCEPT)
    $iptables -N "$CHAIN_FWD" 2>/dev/null
    $iptables -F "$CHAIN_FWD"
    $iptables -C FORWARD -j "$CHAIN_FWD" 2>/dev/null || $iptables -I FORWARD 3 -j "$CHAIN_FWD"
    $iptables -A "$CHAIN_FWD" -s 10.0.0.0/8     -o "$TUN_NAME" -j ACCEPT
    $iptables -A "$CHAIN_FWD" -s 172.16.0.0/12  -o "$TUN_NAME" -j ACCEPT
    $iptables -A "$CHAIN_FWD" -s 192.168.0.0/16 -o "$TUN_NAME" -j ACCEPT
    $iptables -A "$CHAIN_FWD" -i "$TUN_NAME"                    -j ACCEPT

    # 4. Явный ACCEPT в конце FORWARD — защита от DROP-политики других модулей
    $iptables -C FORWARD -j ACCEPT 2>/dev/null || $iptables -A FORWARD -j ACCEPT

    CURRENT_MSS=$tcp_mss
    MSS_METHOD="static"
    log "TCP MSS clamped to $tcp_mss (tun_mtu=$tun_mtu, method=$MSS_METHOD)"

    $iptables -t nat -N "$CHAIN_POST" 2>/dev/null
    $iptables -t nat -F "$CHAIN_POST"
    $iptables -t nat -I POSTROUTING 1 -j "$CHAIN_POST"
    $iptables -t nat -A "$CHAIN_POST" -s 10.0.0.0/8     -o "$TUN_NAME" -j MASQUERADE
    $iptables -t nat -A "$CHAIN_POST" -s 172.16.0.0/12  -o "$TUN_NAME" -j MASQUERADE
    $iptables -t nat -A "$CHAIN_POST" -s 192.168.0.0/16 -o "$TUN_NAME" -j MASQUERADE

    local rules_ok=1
    for iface in $tether_ifaces; do
        ip_rule_add iif "$iface" lookup "$tun_table_index" pref 3000 || {
            rules_ok=0
            log "ERROR: не удалось добавить ip rule для $iface -> $tun_table_index"
        }
    done

    if [ "$rules_ok" -eq 0 ]; then
        # Без правила маршрутизации VPN-режим невозможен. Оставляем hard guard
        # (клиент без интернета) и выходим с ошибкой — apply_state попробует
        # снова. Раньше здесь молча получался рабочий direct.
        log "ERROR: VPN routing rules не встали, держу kill-switch (hard)"
        # без kill-switch guard не ставится, а общий ACCEPT уже стоит — напрямую
        if [ "$KILL_SWITCH" = "1" ]; then _m=blocked; else _m=direct; fi
        update_status "$_m" "$(echo $tether_ifaces | tr ' ' '/')" "$CURRENT_NET_PROFILE"
        return 1
    fi

    if [ -n "$tun_fwmark" ]; then
        local clean_mark=$(normalize_fwmark "$tun_fwmark")
        $iptables -t mangle -N "VPN_TETHER_MARK" 2>/dev/null
        $iptables -t mangle -F "VPN_TETHER_MARK"
        $iptables -t mangle -I PREROUTING 1 -j "VPN_TETHER_MARK"
        # Не перезаписываем mark, уже установленный VPN-приложением
        $iptables -t mangle -A "VPN_TETHER_MARK" -m mark ! --mark 0x0/0xFFFFFFFF -j RETURN
        for iface in $tether_ifaces; do
            $iptables -t mangle -A "VPN_TETHER_MARK" -i "$iface" -j MARK --set-mark "$clean_mark" 2>/dev/null || \
            $iptables -t mangle -A "VPN_TETHER_MARK" -i "$iface" -j MARK --set-mark "$tun_fwmark" 2>/dev/null
        done
        log "fwmark $tun_fwmark -> $tether_ifaces"
    fi

    local vpn_dns=$(get_vpn_dns)
    apply_dns_mode vpn "$vpn_dns" $tether_ifaces

    # IPv6 уже заблокирован в начале функции, здесь только подтверждаем хук
    $ip6tables -C FORWARD -j DROP 2>/dev/null || $ip6tables -I FORWARD -j DROP 2>/dev/null
    log "IPv6 forwarding blocked for tethered clients"

    # Из ветки B: INVALID (out-of-window после реконнекта) дропаем до всего —
    # иначе такие пакеты проваливаются в глобальный ACCEPT и утекают напрямую.
    # Вставляем ПОСЛЕДНИМ с -I 1, чтобы гарантированно встать первым.
    $iptables -C FORWARD -m conntrack --ctstate INVALID -j DROP 2>/dev/null || \
        $iptables -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP


    # Правила встали — переводим kill-switch из hard в armed:
    # разрешено всё, что уходит в tun, режется всё, что мимо.
    guard_apply armed $tether_ifaces

    update_status "vpn" "$(echo $tether_ifaces | tr ' ' '/')" "$CURRENT_NET_PROFILE"
    $ip route flush cache 2>/dev/null
    log "VPN setup complete"
    return 0
}

apply_state() {
    local tun_idx=$1; shift
    local tether_ifaces="$*"
    local now=$(date +%s)

    if [ "$FORCE_UPDATE" -eq 1 ]; then
        tun_idx=$(read_table_index "$TUN_NAME")
    fi

    _norm_words $tether_ifaces; tether_ifaces="$NORM_OUT"
    local _clean
    _clean_ifaces $tether_ifaces; _clean="$CLEAN_OUT"
    if [ "$_clean" != "$tether_ifaces" ]; then
        log "WARNING: странные имена раздачи [$tether_ifaces] -> [$_clean] (discovery: $DISCOVERY_SRC, last: [$LAST_TETHER_IFACES])"
        tether_ifaces="$_clean"
    fi
    LAST_TETHER_IFACES_STABLE="${LAST_TETHER_IFACES_STABLE:-$tether_ifaces}"
    
    local sorted_current sorted_stable
    _norm_words $tether_ifaces; sorted_current="$NORM_OUT"
    _norm_words $LAST_TETHER_IFACES_STABLE; sorted_stable="$NORM_OUT"
    
    if [ -z "$tether_ifaces" ]; then
        EMPTY_TETHER_COUNT=$((EMPTY_TETHER_COUNT + 1))
        if [ $EMPTY_TETHER_COUNT -lt 3 ] && [ -n "$LAST_TETHER_IFACES" ]; then
            tether_ifaces="$LAST_TETHER_IFACES"
            log "tether=[] transient, keeping [$tether_ifaces] (empty_count=$EMPTY_TETHER_COUNT)"
        elif [ $EMPTY_TETHER_COUNT -ge 3 ]; then
            TETHER_CHANGE_COUNT=0
            LAST_TETHER_IFACES_STABLE=""
        fi
    else
        EMPTY_TETHER_COUNT=0
        
        if [ "$sorted_current" != "$sorted_stable" ]; then
            TETHER_CHANGE_COUNT=$((TETHER_CHANGE_COUNT + 1))
            if [ $TETHER_CHANGE_COUNT -ge 3 ] && [ $((now - TETHER_STABLE_TIME)) -lt 30 ]; then
                # объединение, а не прежний набор: новый (USB ncm0) иначе до
                # 30 с вне guard и ip rule — напрямую. С прошлым набором, чтобы
                # не пересобирать на каждом такте дребезга (A / A+B / A …)
                _norm_words $LAST_TETHER_IFACES_STABLE $LAST_TETHER_IFACES $tether_ifaces
                tether_ifaces="$NORM_OUT"
                log "WARNING: Tether interfaces flapping, keeping union: [$tether_ifaces]"
                TETHER_CHANGE_COUNT=3
            else
                LAST_TETHER_IFACES_STABLE="$tether_ifaces"
                TETHER_STABLE_TIME=$now
            fi
        else
            TETHER_CHANGE_COUNT=0
        fi
    fi

    local vpn_active=false
    [ -n "$tun_idx" ] && $ip addr show "$TUN_NAME" 2>/dev/null | grep -q "inet " && vpn_active=true

    # Гистерезис на падение VPN. В логе видно (23:27:57) "tun=1043 vpn=false"
    # с мгновенным возвратом через 3 секунды: приложение переподключалось,
    # а модуль успевал сделать полный teardown -> DIRECT. Это и есть окно,
    # в которое клиент уезжает напрямую. Ждём 3 подряд промаха, всё это
    # время держим hard-guard (клиент без сети, но и без утечки).
    if [ "$vpn_active" = "false" ] && [ "$LAST_VPN_ACTIVE" = "true" ] && is_vpn_tether_enabled; then
        VPN_DOWN_COUNT=$((VPN_DOWN_COUNT + 1))
        if [ $VPN_DOWN_COUNT -lt 3 ] && [ "$FORCE_UPDATE" -eq 0 ]; then
            log "VPN down transient (count=$VPN_DOWN_COUNT), держу правила"
            guard_apply hard $tether_ifaces
            return 0
        fi
        log "VPN действительно упал ($VPN_DOWN_COUNT промахов подряд)"
    fi
    [ "$vpn_active" = "true" ] && VPN_DOWN_COUNT=0

    if [ "$vpn_active" != "$LAST_VPN_ACTIVE" ] || [ "$tether_ifaces" != "$LAST_TETHER_IFACES" ] || [ "$FORCE_UPDATE" -eq 1 ]; then
        VPN_DNS_CACHE=""
        VPN_DNS_CACHE_TIME=0
        log "Network state changed or force update, DNS cache flushed"
    fi

    check_network_quality

    local vpn_just_restored=false
    if [ "$LAST_VPN_ACTIVE" = "false" ] && [ "$vpn_active" = "true" ]; then
        vpn_just_restored=true
        ORIGINAL_TUN_MTU=""
    fi

    if [ "$vpn_active" != "$LAST_VPN_ACTIVE" ] || [ "$tether_ifaces" != "$LAST_TETHER_IFACES" ] || [ "$FORCE_UPDATE" -eq 1 ]; then
        log "State: tun=$tun_idx vpn=$vpn_active tether=[$tether_ifaces] target=$(is_vpn_tether_enabled && echo vpn || echo direct) profile=$CURRENT_NET_PROFILE"
    fi

    if ! $vpn_active; then
        if is_vpn_tether_enabled && [ "$KILL_SWITCH" = "1" ] && \
           [ "$KILL_SWITCH_STRICT" = "1" ] && [ -n "$tether_ifaces" ]; then
            if [ "$VPN_TETHER_MODE" != "blocked" ] || \
               [ "$tether_ifaces" != "$LAST_TETHER_IFACES" ] || [ "$FORCE_UPDATE" -eq 1 ]; then
                log "VPN не поднят, режим VPN выбран -> блокирую клиентов (strict kill-switch)"
                setup_blocked_rules $tether_ifaces
                VPN_TETHER_MODE="blocked"
            fi
        elif [ "$VPN_TETHER_MODE" != "off" ] || [ "$tether_ifaces" != "$LAST_TETHER_IFACES" ] || [ "$FORCE_UPDATE" -eq 1 ]; then
            log "VPN down or disabled, switching to direct..."
            setup_direct_rules $tether_ifaces || log "ERROR: Direct setup failed"
            VPN_TETHER_MODE="off"
        fi
        LAST_VPN_ACTIVE="false"
        LAST_TETHER_IFACES="$tether_ifaces"
        LAST_TUN_INDEX="$tun_idx"
        return 0
    fi

    if is_vpn_tether_enabled; then
        # GUARD_STATE=hard при mode=on = был кратковременный обрыв VPN
        # (гистерезис поставил hard и вышел). Если tun вернулся тот же, ни
        # одно другое условие не срабатывало, и раздача навсегда оставалась
        # без интернета под hard-guard. Пересобираем — setup вернёт armed.
        if { [ "$VPN_TETHER_MODE" != "on" ] && [ "$VPN_TETHER_MODE" != "degraded" ]; } || \
           { [ "$VPN_TETHER_MODE" = "on" ] && [ "$GUARD_STATE" = "hard" ]; } || \
           [ "$tun_idx" != "$LAST_TUN_INDEX" ] || \
           [ "$tether_ifaces" != "$LAST_TETHER_IFACES" ] || [ "$vpn_just_restored" = "true" ] || [ "$FORCE_UPDATE" -eq 1 ]; then
            if [ -n "$tether_ifaces" ] && [ -n "$tun_idx" ]; then
                if setup_vpn_rules "$tun_idx" $tether_ifaces; then
                    VPN_TETHER_MODE="on"
                else
                    # Раньше здесь безусловно ставилось "on" — модуль считал,
                    # что всё хорошо, и больше не пытался. Теперь "retry":
                    # условие входа выше сработает на следующей итерации.
                    log "ERROR: VPN setup failed, повтор на следующей итерации"
                    VPN_TETHER_MODE="retry"
                fi
            else
                # ФИКС 0.7.3: раньше здесь ставился "off", условие выше
                # проверяло != "on" — и цикл direct+cleanup молотил вечно.
                # "degraded" = осели без тетеринга, ждём реального изменения
                # (появление tether, смена tun_idx, реконнект, FORCE_UPDATE).
                if [ "$VPN_TETHER_MODE" != "degraded" ]; then
                    log "VPN enabled but missing tether/tun, settling in degraded (no rules) until state change"
                    setup_direct_rules $tether_ifaces
                fi
                VPN_TETHER_MODE="degraded"
            fi
        fi
    else
        if [ "$VPN_TETHER_MODE" != "off" ] || [ "$tether_ifaces" != "$LAST_TETHER_IFACES" ] || \
           [ "$vpn_just_restored" = "true" ] || [ "$FORCE_UPDATE" -eq 1 ]; then
            log "VPN mode disabled by user, switching to direct..."
            setup_direct_rules $tether_ifaces || log "ERROR: Direct setup failed"
            VPN_TETHER_MODE="off"
        fi
    fi

    LAST_TUN_INDEX="$tun_idx"
    LAST_TETHER_IFACES="$tether_ifaces"
    LAST_VPN_ACTIVE="$vpn_active"
    return 0
}

