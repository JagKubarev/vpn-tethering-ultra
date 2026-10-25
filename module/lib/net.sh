# shellcheck shell=sh
# lib/net.sh — сеть: имена интерфейсов, tun и VPN (DNS, fwmark, MTU, таблица),
# WAN, поиск раздачи; профили сети, sysctl-оптимизации, RPS/XPS.
# Часть демона service.sh: подключается из него через ".", сам не запускается.
# Настройки (USER CONFIG) и общие переменные — в service.sh.

# Уникальные слова по алфавиту -> NORM_OUT, без внешних команд (было
# echo|tr|sort|grep|tr|sed = 6 процессов, и так 3-4 раза за цикл).
_norm_words() {
    local w o out=""
    for w in $*; do
        case " $out " in *" $w "*) continue ;; esac
        local done_=0 res=""
        for o in $out; do
            if [ "$done_" = 0 ] && [ "$w" \< "$o" ]; then res="$res $w"; done_=1; fi
            res="$res $o"
        done
        [ "$done_" = 0 ] && res="$res $w"
        out="${res# }"
    done
    NORM_OUT="$out"
}
normalize_tether_ifaces() {
    _norm_words "$@"
    echo "$NORM_OUT"
}

# Только настоящие имена интерфейсов. 2.2.1, 20.10: после ребута в файле
# правил нашлось "iif netd|wlan2 lookup 1032" — строка discovery целиком
# ("источник|ифейсы") попала в ip rule, и раздача осталась без своего
# правила. Откуда — не поймали (лог до ребута затёрт); теперь мусор
# отбрасывается с записью в лог, а прошлый лог сохраняется (.prev).
clean_iface_list() {
    _clean_ifaces "$@"
    echo "$CLEAN_OUT"
}
_clean_ifaces() {   # -> CLEAN_OUT, без подоболочек
    local i out="" IFS=" 	|
"
    for i in $*; do
        case "$i" in netd|heuristic|*[!A-Za-z0-9_.-]*) continue ;; esac
        case " $out " in *" $i "*) ;; *) out="$out $i" ;; esac
    done
    CLEAN_OUT="${out# }"
}

normalize_iface_name() {
    echo "${1%%@*}"
}

_parse_ip4_safe() {
    local ip="$1"
    ip=$(echo "$ip" | tr -d '[:space:]')
    
    case "$ip" in
        [0-9]*.[0-9]*.[0-9]*.[0-9]*) ;;
        *) return 1 ;;
    esac
    
    local IFS='.'
    set -- $ip
    [ "$#" -ne 4 ] && return 1
    
    for octet; do
        case "$octet" in ''|*[!0-9]*) return 1 ;; esac
        [ "$octet" -gt 255 ] 2>/dev/null && return 1
    done
    
    case "$ip" in
        0.*|127.*|255.*|169.254.*) return 1 ;;
    esac
    
    echo "$ip"
    return 0
}

_parse_ip6_safe() {
    local ip="$1"
    
    case "$ip" in
        fe80:*|fe81:*|fe[89ab][0-9a-fA-F]:*) return 1 ;;
        ff0*:*|ff1*:*|ff2*:*) return 1 ;;
        ::|::1|::ffff:*) return 1 ;;
        0:0:0:0:0:0:0:0|0::0) return 1 ;;
        *[!.0-9a-fA-F:]*) return 1 ;;
    esac

    local colon_count
    colon_count=$(echo "$ip" | tr -cd ':' | wc -c)
    [ "$colon_count" -eq 2 ] && case "$ip" in *::*) ;; *) return 1 ;; esac

    local blocks=$(echo "$ip" | tr ':' '\n' | grep -c '[0-9a-fA-F]')
    [ "$blocks" -lt 2 ] && return 1

    echo "$ip"
    return 0
}

detect_tun_name() {
    local iface default_iface=""
    
    default_iface=$($ip route get 8.8.8.8 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
    
    case "$default_iface" in
        tun*|wg*|awg*|vpn*)
            if $ip addr show "$default_iface" 2>/dev/null | grep -q "inet "; then
                echo "$default_iface"
                return 0
            fi
            ;;
    esac
    
    for iface in $($ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^(tun|wg|awg|vpn)'); do
        if $ip addr show "$iface" 2>/dev/null | grep -q "inet "; then
            echo "$iface"
            return 0
        fi
    done
    
    for iface in $($ip -o addr show 2>/dev/null | awk '/inet / {print $2}' | sort -u); do
        iface="${iface%%@*}"
        iface="${iface%%:*}"
        
        case "$iface" in
            lo|wlan*|rmnet*|rndis*|eth*|usb*|ccmni*|pdp*|swlan*|ap*|hotspot*|bond*|bridge*|dummy*|sit*|ip6*|ifb*|v4-*|clat*|ipsec*|p2p*|ppp*|pan*|bt-*)
                continue ;;
            # раздача USB (CDC-NCM на 13T) и прочие точки, мобильный Unisoc:
            # без VPN третий проход брал ncm0 за tun — он выпадал из раздачи
            ncm*|softap*|tether*|bnep*|qmi*|seth_*|sipa_*|tunl*)
                continue ;;
        esac
        
        if $ip addr show "$iface" 2>/dev/null | grep -q "inet "; then
            echo "$iface"
            return 0
        fi
    done
    
    echo "tun0"
    return 1
}

# ----------------------------------------------------------------------------
# Источник правды — netd. Для каждой раздачи с аплинком Android ставит
#   "from all iif <downstream> lookup <upstream>"   (pref 21000 на A15)
# а для дефолтной сети — "from all fwmark 0x0/0xffff iif lo lookup <iface>".
# Эвристика по RFC1918 ниже — только фолбэк: при VPN "ip route get" от root
# уходит в tun0, и wlan0 (клиент Wi-Fi) принимался за раздачу.
# ----------------------------------------------------------------------------
ip_rules() {   # кэш на проход handle_change (там же и сбрасывается)
    if [ -n "$IP_RULE_CACHE" ]; then printf '%s\n' "$IP_RULE_CACHE"; else $ip rule show 2>/dev/null; fi
}

netd_tether_pairs() {
    ip_rules | awk '
        /^3000:/ { next }
        /fwmark|uidrange|oif / { next }
        {
            iif = ""; tbl = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "iif") iif = $(i + 1)
                if ($i == "lookup") tbl = $(i + 1)
            }
            if (iif == "" || tbl == "" || iif == "lo") next
            if (iif ~ /^(tun|wg|awg|vpn|ppp)/) next
            if (tbl ~ /^(local_network|local|main|default|legacy_system|legacy_network)$/) next
            print iif, tbl
        }' | sort -u
}

netd_default_iface() {
    ip_rules | awk '
        /fwmark 0x0\/0xffff iif lo lookup/ && !/uidrange/ {
            for (i = 1; i <= NF; i++) if ($i == "lookup") { print $(i + 1); exit }
        }' | sed 's/_local$//'
}

# Интерфейсы, на которых висит DHCP-сервер (раздача без аплинка тоже видна)
dhcp_server_ifaces() {
    # раз в ~3 вызова: точку доступа и USB netd и так показывает в ip rule,
    # это — запасной признак для раздач без правила netd
    DHCP_IFACES_TICK=$((DHCP_IFACES_TICK + 1))
    if [ "$DHCP_IFACES_TICK" -lt 3 ] && [ -n "$DHCP_IFACES_CACHE" ]; then
        echo "$DHCP_IFACES_CACHE"
        return
    fi
    DHCP_IFACES_TICK=0
    DHCP_IFACES_CACHE=$(_dhcp_server_ifaces_live | tr '\n' ' ')
    [ -n "$DHCP_IFACES_CACHE" ] || DHCP_IFACES_CACHE=" "
    echo "$DHCP_IFACES_CACHE"
}
_dhcp_server_ifaces_live() {
    ss -lun 2>/dev/null | grep -oE '%[A-Za-z0-9_.-]+:67([^0-9]|$)' | \
        sed -E 's/^%//; s/:67.*//' | sort -u
}

has_private_ip4() {
    $ip -4 addr show "$1" 2>/dev/null | \
        grep -qE 'inet (10|172\.1[6-9]|172\.2[0-9]|172\.3[01]|192\.168)\.'
}

get_wan_iface() {
    local iface
    iface=$(netd_tether_pairs | awk 'NR == 1 { print $2 }')
    [ -z "$iface" ] && iface=$(netd_default_iface)
    case "$iface" in tun*|wg*|awg*|vpn*) iface="" ;; esac
    if [ -n "$iface" ] && $ip -4 addr show "$iface" 2>/dev/null | grep -q "inet "; then
        echo "$iface"
        return
    fi

    iface=$($ip route get 8.8.8.8 2>/dev/null | \
        awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' | \
        grep -vE "^(tun|wg|awg|vpn|clat|v4-|rmnet_ipa|rmnet_usb)[0-9]")
    [ -n "$iface" ] && echo "$iface" && return

    iface=$($ip route show table main 2>/dev/null | awk '/^default/ && /dev/ {
        for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}
    }' | grep -vE "^(tun|wg|awg|vpn|clat|v4-|rmnet_ipa|rmnet_usb)[0-9]" | head -1)
    [ -n "$iface" ] && echo "$iface" && return

    for i in $($ip link show 2>/dev/null | \
               grep -oE '(rmnet_data|rmnet|r_rmnet_data|ccmni|wwan|pdp)[0-9]+' | sort -u); do
        $ip addr show "$i" 2>/dev/null | grep -q "inet " && echo "$i" && return
    done
}

# Печатает "<источник>|<ифейсы>". Чистая функция — можно звать в $(...).
get_tether_discovery() {
    local ifaces="" iface src

    for iface in $(netd_tether_pairs | awk '{ print $1 }') $(dhcp_server_ifaces); do
        iface="${iface%%@*}"
        is_excluded_iface "$iface" && continue
        [ "$iface" = "$TUN_NAME" ] && continue
        has_private_ip4 "$iface" || continue
        case " $ifaces " in *" $iface "*) continue ;; esac
        ifaces="$ifaces $iface"
    done

    if [ -n "$ifaces" ]; then
        src="netd"
    else
        ifaces=$(get_active_tether_ifaces_heuristic)
        src="heuristic"
    fi
    echo "$src|$(normalize_tether_ifaces $ifaces)"
}

get_active_tether_ifaces() {
    local d
    d=$(get_tether_discovery)
    echo "${d#*"|"}"
}

# Вызывать НЕ через $(...): пишет глобальные TETHER_NOW и DISCOVERY_SRC
refresh_tether_ifaces() {
    local d src
    d=$(get_tether_discovery)
    src="${d%%"|"*}"
    TETHER_NOW="${d#*"|"}"
    case "$TETHER_NOW" in
        *[!A-Za-z0-9_.\ -]*)
            log "WARNING: discovery вернул странное: [$d] — оставляю только имена интерфейсов"
            TETHER_NOW=$(clean_iface_list $TETHER_NOW) ;;
    esac
    if [ -n "$TETHER_NOW" ] && [ "$src" != "$DISCOVERY_SRC" ]; then
        log "Tether discovery: $src [$TETHER_NOW]"
        DISCOVERY_SRC="$src"
    fi
}

# Интерфейс — подключение телефона к сети (клиент Wi-Fi), а не раздача: адрес
# получен по DHCP (флаг dynamic) или в его таблице есть маршрут по умолчанию.
# 24.10 20:28:55: телефон подключился к Wi-Fi, WAN ещё был мобильным, и
# эвристика на 20с приняла wlan0 (клиент) за раздачу.
is_uplink_iface() {
    $ip -4 addr show "$1" 2>/dev/null | grep -q " dynamic" && return 0
    $ip route show table all 2>/dev/null | grep -qE "^default via [0-9.]+ dev $1( |\$)"
}

get_active_tether_ifaces_heuristic() {
    local wan_iface=$(get_wan_iface)
    local def_iface=$(netd_default_iface)
    local ifaces=""

    local all_ifaces=$($ip -4 addr show 2>/dev/null | awk '/^[0-9]+:/ {iface=$2; gsub(/:$/,"",iface)}
        /inet (10|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)/ {print iface}')

    for iface in $all_ifaces; do
        iface=$(normalize_iface_name "$iface")
        is_excluded_iface "$iface" && continue
        [ "$iface" = "$TUN_NAME" ] && continue
        [ -n "$wan_iface" ] && [ "$iface" = "$wan_iface" ] && continue
        [ -n "$def_iface" ] && [ "$iface" = "$def_iface" ] && continue
        is_uplink_iface "$iface" && continue
        case " $ifaces " in *" $iface "*) continue ;; esac
        ifaces="$ifaces $iface"
    done

    for iface in $TETHER_IFACES; do
        iface=$(normalize_iface_name "$iface")
        is_excluded_iface "$iface" && continue
        case " $ifaces " in *" $iface "*) continue ;; esac
        [ "$iface" = "$TUN_NAME" ] && continue
        [ -n "$wan_iface" ] && [ "$iface" = "$wan_iface" ] && continue
        [ -n "$def_iface" ] && [ "$iface" = "$def_iface" ] && continue
        is_uplink_iface "$iface" && continue

        if $ip link show "$iface" >/dev/null 2>&1; then
            local ipaddr=$($ip addr show "$iface" 2>/dev/null | \
                grep -oE 'inet (10|172\.1[6-9]|172\.2[0-9]|172\.3[01]|192\.168)\.[0-9.]+' | head -1)
            [ -n "$ipaddr" ] && ifaces="$ifaces $iface"
        fi
    done

    local result="${ifaces# }"
    normalize_tether_ifaces $result
}

get_vpn_dns() {
    local now=$(date +%s)
    if [ -n "$VPN_DNS_CACHE" ] && [ "$VPN_DNS_CACHE" != "|" ] && [ $((now - VPN_DNS_CACHE_TIME)) -lt 30 ]; then
        echo "$VPN_DNS_CACHE"
        return
    fi
    
    if [ "$FORCE_PUBLIC_DNS" -eq 1 ]; then
        log "FORCE_PUBLIC_DNS=1, using public DNS"
        VPN_DNS_CACHE="1.1.1.1|2606:4700:4700::1111"
        VPN_DNS_CACHE_TIME=$now
        echo "$VPN_DNS_CACHE"
        return
    fi
    
    log "Detecting VPN DNS..."
    local dns4="" dns6=""
    
    if command -v dumpsys >/dev/null 2>&1; then
        local dumpsys_out
        # без запасного второго dumpsys: тот шёл без таймаута (код возврата —
        # от grep, «блок не найден» = повтор) и мог повесить демон
        dumpsys_out=$($TIMEOUT_CMD sh -c "dumpsys connectivity 2>/dev/null" | grep -A200 "VPN CONNECTED" | grep -B5 -A5 "InterfaceName: $TUN_NAME")
        
        if [ -n "$dumpsys_out" ]; then
            log "VPN block found (first 80 chars): $(echo "$dumpsys_out" | head -1 | cut -b1-80)..."
            
            local dns_block=$(echo "$dumpsys_out" | grep -o 'DnsAddresses: \[[^]]*\]' | head -1)
            log "Raw DNS block: ${dns_block:-<none>}"
            
            if [ -n "$dns_block" ]; then
                local dns_content=$(echo "$dns_block" | sed 's/.*DnsAddresses: \[//' | sed 's/\].*//' | tr -d ' ')
                log "DNS content: $dns_content"
                
                local raw_dns4=$(echo "$dns_content" | tr ',' '\n' | sed 's/^\///' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
                log "IPv4 candidates: $(echo $raw_dns4 | tr '\n' ' ')"
                
                # не $ip: это путь к /system/bin/ip
                for _a in $raw_dns4; do
                    [ -n "$dns4" ] && break
                    dns4=$(_parse_ip4_safe "$_a")
                    [ -n "$dns4" ] && log "Valid IPv4 DNS: $dns4"
                done
                
                local raw_dns6=$(echo "$dns_content" | tr ',' '\n' | sed 's/^\///' | grep -E ':' | grep -v '^/$')
                log "IPv6 candidates: $(echo $raw_dns6 | tr '\n' ' ')"
                
                for _a in $raw_dns6; do
                    [ -n "$dns6" ] && break
                    dns6=$(_parse_ip6_safe "$_a")
                    [ -n "$dns6" ] && log "Valid IPv6 DNS: $dns6"
                done
            fi
        else
            log "WARNING: VPN block not found in dumpsys"
        fi
    fi
    
    [ -z "$dns4" ] && { dns4="1.1.1.1"; log "No valid IPv4 DNS, using fallback 1.1.1.1"; }
    [ -z "$dns6" ] && { dns6="2606:4700:4700::1111"; log "No valid IPv6 DNS, using fallback 2606:4700:4700::1111"; }
    
    VPN_DNS_CACHE="${dns4}|${dns6}"
    VPN_DNS_CACHE_TIME=$now
    echo "$VPN_DNS_CACHE"
}

get_tun_fwmark() {
    $ip rule show 2>/dev/null | awk -v tun="$TUN_NAME" '
        $0 ~ "lookup " tun {
            for(i=1; i<=NF; i++) {
                if ($i == "fwmark") {
                    gsub("/.*", "", $(i+1))
                    print $(i+1)
                    exit
                }
            }
        }
    ' | head -1
}

normalize_fwmark() {
    local mark="$1"
    case "$mark" in
        0x*|0X*)
            mark="${mark#0x}"
            mark="${mark#0X}"
            printf "%d" "0x$mark" 2>/dev/null || echo "$mark"
            ;;
        *)
            echo "$mark"  # Уже десятичное
            ;;
    esac
}

get_tun_mtu() {
    local tun_raw_mtu wan_mtu safe_mtu
    
    if [ -n "$ORIGINAL_TUN_MTU" ]; then
        tun_raw_mtu="$ORIGINAL_TUN_MTU"
    else
        tun_raw_mtu=$($ip link show "$TUN_NAME" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}')
    fi
    [ -z "$tun_raw_mtu" ] && tun_raw_mtu=1500

    if [ "$tun_raw_mtu" -le 1500 ] 2>/dev/null; then
        safe_mtu=$(( tun_raw_mtu - 40 ))
        log "MTU calc: tun=${tun_raw_mtu} (WG-style) -> safe=${safe_mtu}"
    else
        local wan_iface
        wan_iface=$(get_wan_iface)
        wan_mtu=1500
        if [ -n "$wan_iface" ]; then
            wan_mtu=$($ip link show "$wan_iface" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}')
            [ -z "$wan_mtu" ] && wan_mtu=1500
        fi
        safe_mtu=$(( wan_mtu - 120 ))
        log "MTU calc: tun=${tun_raw_mtu} (jumbo), wan=${wan_iface}/${wan_mtu} -> safe=${safe_mtu}"
    fi

    [ "$safe_mtu" -lt 1200 ] && safe_mtu=1200
    [ "$safe_mtu" -gt 1420 ] && safe_mtu=1420

    echo "$safe_mtu"
}

read_table_index() {
    local iface=$1 attempts=15 delay_ms=100 index name cand last live

    [ -s /data/misc/net/rt_tables ] || { sleep 1; return 1; }
    # Нет самого ифейса (VPN выключен) — ждать строку в rt_tables бессмысленно.
    # Ретраи нужны только сразу после появления tun, пока netd не дописал таблицу.
    $ip link show "$iface" >/dev/null 2>&1 || return 1

    while [ $attempts -gt 0 ]; do
        # ВАЖНО: раньше бралось ПЕРВОЕ совпадение. При реконнекте VPN Android
        # заводит новую сеть с новым индексом, а старая строка "tun0" может
        # ещё висеть в rt_tables. Первое совпадение = мёртвая таблица =
        # ip rule ведёт в пустоту -> пакеты проваливаются в main -> ноут
        # уходит напрямую мимо VPN. Берём самое свежее И живое.
        cand=""
        while read -r index name; do
            [ "$name" = "$iface" ] && cand="$cand $index"
        done < /data/misc/net/rt_tables 2>/dev/null

        live=""; last=""
        for index in $cand; do
            last="$index"
            $ip route show table "$index" 2>/dev/null | grep -q . && live="$index"
        done

        [ -n "$live" ] && { echo "$live"; return 0; }

        if [ -n "$last" ] && [ $attempts -le 1 ]; then
            # ни одна таблица не отдала маршруты — отдаём последнюю, но
            # честно предупреждаем: kill-switch не даст утечь, а watchdog
            # переставит правила, когда таблица наполнится.
            log "WARNING: table(s) [$cand] for $iface без маршрутов, беру $last"
            echo "$last"
            return 0
        fi

        attempts=$((attempts - 1))
        [ $attempts -gt 0 ] && { sleep 0.$(printf "%03d" $delay_ms); delay_ms=$((delay_ms * 3 / 2)); [ $delay_ms -gt 999 ] && delay_ms=999; }
    done
    return 1
}

apply_network_profile() {
    local profile=$1

    # Сравниваем с тем, что РЕАЛЬНО применено. Раньше — с CURRENT_NET_PROFILE,
    # который изначально "FAST": на загрузке (без FORCE) профиль не применялся
    # вовсе, и до первого тоггла оставался системный cc (обычно cubic).
    if [ "$profile" = "$NET_PROFILE_APPLIED" ] && [ "$FORCE_UPDATE" -eq 0 ]; then
        return
    fi
    
    log "Switching to $profile profile..."
    
    if [ "$profile" = "STABLE" ]; then
        # Было: cubic + ECN=2 + slow_start_after_idle=1 — "стабильнее" на
        # плохой связи. Замер на телефоне (veth, RTT 300мс, 10 Мбит, отдача
        # с телефона — так ходит TCP-туннель VPN): без потерь cubic 8.7 vs bbr
        # 8.1 Мбит, но при 1% потерь 1.8-2.5 vs 7.2-7.4, при 3% 0.3-1.3 vs
        # 6.7-7.8. Плохая мобильная связь = потери, то есть "STABLE" резал
        # скорость в разы ровно тогда, когда включался. Оставляем BBR, на
        # плохой связи меняем только число SYN-ретраев.
        if grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
            echo bbr > /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || true
        fi
        # ECN=2 (как у Android): принимаем, но сами не просим — на мобильных
        # сетях встречаются узлы, которые режут или портят ECN-пакеты
        echo 2 > /proc/sys/net/ipv4/tcp_ecn 2>/dev/null || true
        echo 1 > /proc/sys/net/ipv4/tcp_ecn_fallback 2>/dev/null || true
        set_sysctl net.ipv4.tcp_syn_retries 5
        set_sysctl net.ipv4.tcp_slow_start_after_idle 0
        log "STABLE profile: BBR + больше SYN-ретраев"
    else
        if grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
            echo bbr > /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || true
        else
            echo cubic > /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || true
        fi
        echo 2 > /proc/sys/net/ipv4/tcp_ecn 2>/dev/null || true
        echo 1 > /proc/sys/net/ipv4/tcp_ecn_fallback 2>/dev/null || true
        set_sysctl net.ipv4.tcp_syn_retries 3
        set_sysctl net.ipv4.tcp_slow_start_after_idle 0
        log "FAST profile: BBR/cubic + ECN по запросу сервера"
    fi
    
    CURRENT_NET_PROFILE=$profile
    NET_PROFILE_APPLIED=$profile
    # Не вызываем update_status здесь — правильный статус ставится в конце setup
}

check_network_quality() {
    # По умолчанию выключено: профили теперь отличаются только SYN-ретраями,
    # а ради этого пинговать 1.1.1.1 мимо VPN каждые ~20с (оператор это
    # видит; 6000+ строк в логе) смысла нет.
    [ "$NET_PROFILE_ADAPTIVE" = "1" ] || return 0
    [ -z "$LAST_TETHER_IFACES" ] && return 0

    # На FORCE_UPDATE (тоггл, смена сети) не пингуем: ping -W 3 блокировал
    # пересборку на 3с, а action.sh за это время успевал показать старый
    # статус — пользователи жали ещё раз, и режим откатывался обратно.
    [ "$FORCE_UPDATE" -eq 1 ] && return 0

    QUALITY_CHECK_COUNTER=$((QUALITY_CHECK_COUNTER + 1))

    if [ $QUALITY_CHECK_COUNTER -lt 10 ]; then
        return
    fi
    QUALITY_CHECK_COUNTER=0
    
    local wan=$(get_wan_iface)
    [ -z "$wan" ] && return 0
    
    local gw=$($ip route show table main 2>/dev/null | awk '/^default/ && !/tun|wg|awg/ {print $3; exit}')
    local ping_target="${gw:-1.1.1.1}"
    
    local rtt_min=""
    local ping_out
    ping_out=$($TIMEOUT_CMD ping -I "$wan" -c 1 -W 3 "$ping_target" 2>/dev/null)
    
    if [ -n "$ping_out" ]; then
        rtt_min=$(echo "$ping_out" | awk -F'[ /=]+' \
            '/^rtt|^round-trip/ {for(i=1;i<=NF;i++) if($i~/^[0-9]+\.[0-9]+$/) {print int($i); break}}')
    fi
    
    if [ -z "$rtt_min" ]; then
        # Потеря = плохая связь. Раньше счётчики сбрасывались, и на самой
        # плохой связи (потери) профиль не менялся никогда.
        log "Network quality check: no response from $ping_target via $wan (считаю как плохую связь)"
        rtt_min=$((RTT_THRESHOLD_STABLE + 1))
    else
        log "Network RTT to $ping_target via $wan: ${rtt_min}ms (threshold: ${RTT_THRESHOLD_STABLE}ms)"
    fi

    if [ "$rtt_min" -gt "$RTT_THRESHOLD_STABLE" ]; then
        STABLE_COUNT=$((STABLE_COUNT + 1))
        FAST_COUNT=0
        if [ $STABLE_COUNT -ge 2 ]; then
            apply_network_profile "STABLE"
            STABLE_COUNT=0
        fi
    else
        FAST_COUNT=$((FAST_COUNT + 1))
        STABLE_COUNT=0
        if [ $FAST_COUNT -ge 2 ]; then
            apply_network_profile "FAST"
            FAST_COUNT=0
        fi
    fi
}

apply_sysctl_optimizations() {
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    echo 1 > /proc/sys/net/ipv4/conf/all/forwarding 2>/dev/null || true
    
    echo 500 > /proc/sys/net/core/netdev_budget 2>/dev/null || true
    echo 50 > /proc/sys/net/core/netdev_budget_usecs 2>/dev/null || true
    
    for f in /proc/sys/net/ipv4/conf/all/rp_filter /proc/sys/net/ipv4/conf/default/rp_filter; do
        [ -f "$f" ] && echo 2 > "$f" 2>/dev/null || true
    done
    
    echo 2 > "/proc/sys/net/ipv4/conf/$TUN_NAME/rp_filter" 2>/dev/null || true
    
    if [ -e /proc/sys/net/netfilter/nf_conntrack_max ]; then
        echo 65536 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true
        [ -f /sys/module/nf_conntrack/parameters/hashsize ] && \
            echo 16384 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
    fi

    echo 5000 > /proc/sys/net/core/netdev_max_backlog 2>/dev/null || true
    echo 1024 > /proc/sys/net/core/somaxconn 2>/dev/null || true
    
    local buf=8388608
    echo $buf > /proc/sys/net/core/rmem_max 2>/dev/null || true
    echo $buf > /proc/sys/net/core/wmem_max 2>/dev/null || true
    echo "4096 87380 $buf" > /proc/sys/net/ipv4/tcp_rmem 2>/dev/null || true
    echo "4096 65536 $buf" > /proc/sys/net/ipv4/tcp_wmem 2>/dev/null || true
    
    echo 524288 > /proc/sys/net/core/rmem_default 2>/dev/null || true
    echo 524288 > /proc/sys/net/core/wmem_default 2>/dev/null || true

    set_sysctl net.ipv4.tcp_mtu_probing 1
    set_sysctl net.ipv4.tcp_sack 1
    set_sysctl net.ipv4.tcp_window_scaling 1
    set_sysctl net.ipv4.tcp_no_metrics_save 1
    
    # Очередь TUN интерфейса — снижает задержку при высоком трафике
    $ip link set "$TUN_NAME" txqueuelen 1500 2>/dev/null || true

    apply_network_profile "$CURRENT_NET_PROFILE"
    
    log "Network engine: TCP-настройки применены"
}

apply_advanced_speed_tweaks() {
    log "Applying advanced TCP tweaks..."
    
    set_sysctl net.ipv4.tcp_autocorking 1
    set_sysctl net.ipv4.tcp_limit_output_bytes 2097152
    # UDP: быстро чистим мёртвые записи YouTube/QUIC чтобы не мешали Telegram
    set_sysctl net.netfilter.nf_conntrack_udp_timeout 20
    set_sysctl net.netfilter.nf_conntrack_udp_timeout_stream 180
    # Пара к INVALID->DROP: не помечать out-of-window ретрансмиты как INVALID
    # (иначе после реконнекта легитимные хвосты потоков попадут под DROP)
    set_sysctl net.netfilter.nf_conntrack_tcp_be_liberal 1
    # TCP: ускоряем уборку закрытых соединений
    set_sysctl net.netfilter.nf_conntrack_tcp_timeout_time_wait 15
    set_sysctl net.netfilter.nf_conntrack_tcp_timeout_syn_sent 15
    set_sysctl net.netfilter.nf_conntrack_tcp_timeout_close_wait 15
    set_sysctl net.netfilter.nf_conntrack_tcp_timeout_fin_wait 15
    # ESTABLISHED: по умолчанию 432000 (5 дней) — слишком много для мобильного VPN.
    # После смены VPN конфига старые записи с неверным NAT-IP живут вечно и мешают.
    # 3600 (1 час) — достаточно для Telegram keepalive (он переподключается через минуты).
    set_sysctl net.netfilter.nf_conntrack_tcp_timeout_established 7200
    
    [ -f /proc/sys/net/ipv4/tcp_tsq ] && echo 1 > /proc/sys/net/ipv4/tcp_tsq 2>/dev/null || true
    [ -f /proc/sys/net/ipv4/tcp_pacing ] && echo 1 > /proc/sys/net/ipv4/tcp_pacing 2>/dev/null || true
    
    echo 4194304 > /proc/sys/net/ipv4/ipfrag_high_thresh 2>/dev/null || true
    echo 3145728 > /proc/sys/net/ipv4/ipfrag_low_thresh 2>/dev/null || true
    echo 30 > /proc/sys/net/ipv4/ipfrag_time 2>/dev/null || true
    set_sysctl net.ipv4.tcp_fin_timeout 15
    # Быстрое обнаружение мёртвых TCP соединений.
    # При смене VPN конфига сервер перестаёт отвечать на старые соединения,
    # но TG на телефоне не знает об этом пока не истечёт keepalive.
    # 15 + 5*3 = 30 сек до обнаружения (было 60 + 10*3 = 90 сек).
    set_sysctl net.ipv4.tcp_keepalive_time 60
    set_sysctl net.ipv4.tcp_keepalive_intvl 10
    set_sysctl net.ipv4.tcp_keepalive_probes 4
    # Быстрее сдаёмся при потере пакетов (8 вместо 15 ретрансмиссий -> ~51 сек вместо минут)
    set_sysctl net.ipv4.tcp_retries2 12
    
    log "Advanced TCP tweaks applied"
}

apply_rps_xps() {
    local ifaces="$*"
    local cpus=$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 4)
    
    local mask="f"
    [ "$cpus" -gt 4 ] && mask="ff"
    [ "$cpus" -gt 8 ] && mask="ffff"
    
    for iface in $ifaces; do
        case "$iface" in tun*|wg*|awg*|vpn*) continue ;; esac
        [ -d "/sys/class/net/$iface/queues" ] || continue
        
        for rx_queue in /sys/class/net/$iface/queues/rx-*; do
            [ -f "$rx_queue/rps_cpus" ] && echo "$mask" > "$rx_queue/rps_cpus" 2>/dev/null || true
            [ -f "$rx_queue/rps_flow_cnt" ] && echo 4096 > "$rx_queue/rps_flow_cnt" 2>/dev/null || true
        done
        
        for tx_queue in /sys/class/net/$iface/queues/tx-*; do
            [ -f "$tx_queue/xps_cpus" ] && echo "$mask" > "$tx_queue/xps_cpus" 2>/dev/null || true
        done
    done
    log "RPS/XPS applied to all tether interfaces"
}

