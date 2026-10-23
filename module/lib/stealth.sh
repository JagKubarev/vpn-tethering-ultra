# shellcheck shell=sh
# lib/stealth.sh — скрыть раздачу от оператора (TETHER_STEALTH): TTL, чужие модули.
# Часть демона service.sh: подключается из него через ".", сам не запускается.
# Настройки (USER CONFIG) и общие переменные — в service.sh.

# ============================================================================
# TETHER_STEALTH — скрыть раздачу от оператора
# ============================================================================
CHAIN_TTL="VPN_TETHER_TTL"   # filter FORWARD -o <мобильная сеть>: TTL раздачи
STEALTH_STATE=""             # "" | on
STEALTH_TICK=0
STEALTH_FOREIGN_LOGGED=0     # сколько чужих пакетов было, когда писали в лог
STEALTH_IFS="rmnet+ ccmni+ rev_rmnet+"
RESETPROP=""
for _r in /data/adb/ksu/bin/resetprop /data/adb/magisk/resetprop /data/adb/ap/bin/resetprop; do
    [ -x "$_r" ] && RESETPROP="$_r" && break
done
[ -z "$RESETPROP" ] && command -v resetprop >/dev/null 2>&1 && RESETPROP=resetprop
STEALTH_RIVALS=""           # другие включённые модули, которые трогают TTL/раздачу
STEALTH_RIVAL_RULES=0       # чужие правила TTL в iptables (вне нашей цепочки)
STEALTH_RIVALS_LOGGED="-"

# Кто ещё скрывает раздачу — не по имени модуля, а по тому, что он делает:
# в его скриптах/system.prop TTL, hop limit или проверка раздачи у оператора.
# Два таких модуля мешают друг другу (21.10: tether_unblock на каждом пакете
# с TTL≠63 писал CONNMARK 0x40/0xffffffff и стирал наши метки раздачи).
stealth_find_rivals() {
    local d f n out=""
    for d in /data/adb/modules/*; do
        [ -d "$d" ] || continue
        [ "$d" = "$MODULE_DIR" ] && continue
        [ -f "$d/disable" ] && continue
        [ -f "$d/remove" ] && continue
        for f in "$d/service.sh" "$d/post-fs-data.sh" "$d/system.prop" "$d/late_start.sh" "$d/boot-completed.sh"; do
            [ -f "$f" ] || continue
            if grep -qE 'ip_default_ttl|--ttl-set|-j TTL|--hl-set|hop_limit|noprovisioning|tether_dun_required' "$f" 2>/dev/null; then
                n=$(sed -n 's/^name=//p' "$d/module.prop" 2>/dev/null | head -n 1 | tr -d '\r|')
                out="${out:+$out, }${n:-${d##*/}}"
                break
            fi
        done
    done
    STEALTH_RIVALS="$out"
    # правила с TTL не из нашей цепочки (модуль мог уже не значиться, а правила — остаться)
    STEALTH_RIVAL_RULES=$({ $iptables -S 2>/dev/null; $iptables -t mangle -S 2>/dev/null; } | \
        grep -E -- '-m ttl|-j TTL' | grep -vc -- "$CHAIN_TTL")
    if [ "$STEALTH_RIVALS|$STEALTH_RIVAL_RULES" != "$STEALTH_RIVALS_LOGGED" ]; then
        STEALTH_RIVALS_LOGGED="$STEALTH_RIVALS|$STEALTH_RIVAL_RULES"
        if [ -n "$STEALTH_RIVALS" ]; then
            log "WARNING: TTL/раздачу меняет ещё и модуль: $STEALTH_RIVALS — с включённым «Скрыть раздачу» он лишний и мешает (стирает метки соединений раздачи). Отключи или удали его"
        elif [ "$STEALTH_RIVAL_RULES" -gt 0 ]; then
            log "WARNING: в iptables чужие правила TTL ($STEALTH_RIVAL_RULES) — их ставит другой модуль или приложение"
        fi
    fi
}

stealth_rules_on() {
    local o
    $iptables -N "$CHAIN_TTL" 2>/dev/null
    $iptables -F "$CHAIN_TTL" 2>/dev/null
    $iptables -A "$CHAIN_TTL" -m ttl --ttl-eq 63 -j RETURN 2>/dev/null
    if [ "$TETHER_TTL_STRICT" = "1" ]; then
        $iptables -A "$CHAIN_TTL" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
    else
        # только счётчик: сколько пакетов раздачи выдали бы её оператору
        $iptables -A "$CHAIN_TTL" -j RETURN 2>/dev/null
    fi
    for o in $STEALTH_IFS; do
        $iptables -C FORWARD -o "$o" -j "$CHAIN_TTL" 2>/dev/null || \
            $iptables -I FORWARD 1 -o "$o" -j "$CHAIN_TTL" 2>/dev/null
    done
}

stealth_rules_off() {
    local o _n
    for o in $STEALTH_IFS; do
        _n=0; while [ $_n -lt 8 ] && $iptables -D FORWARD -o "$o" -j "$CHAIN_TTL" 2>/dev/null; do _n=$((_n + 1)); done
    done
    $iptables -F "$CHAIN_TTL" 2>/dev/null; $iptables -X "$CHAIN_TTL" 2>/dev/null
}

# сколько пакетов раздачи ушло в мобильную сеть с TTL не 63
stealth_foreign() {
    [ "$STEALTH_STATE" = "on" ] || { echo 0; return; }
    $iptables -L "$CHAIN_TTL" -v -x -n 2>/dev/null | awk 'NR > 2 && !/TTL match/ {s += $1} END {print s + 0}'
}

stealth_apply() {
    if [ "$TETHER_STEALTH" = "1" ]; then
        echo 63 > /proc/sys/net/ipv4/ip_default_ttl 2>/dev/null
        echo 63 > /proc/sys/net/ipv6/conf/all/hop_limit 2>/dev/null
        echo 63 > /proc/sys/net/ipv6/conf/default/hop_limit 2>/dev/null
        [ -n "$RESETPROP" ] && "$RESETPROP" net.tethering.noprovisioning true >/dev/null 2>&1
        if [ "$STEALTH_STATE" != "on" ]; then
            settings put global tether_dun_required 0 >/dev/null 2>&1
            log "Скрытие раздачи: TTL телефона 63, проверка раздачи у оператора отключена$([ -n "$RESETPROP" ] || echo ' (НЕТ resetprop — проверка не отключена)'), чужой TTL раздачи: $([ "$TETHER_TTL_STRICT" = 1 ] && echo отбиваю || echo считаю)"
        fi
        stealth_rules_on
        STEALTH_STATE="on"
        stealth_find_rivals
    elif [ "$STEALTH_STATE" = "on" ]; then
        stealth_off
        log "Скрытие раздачи выключено: TTL 64, проверка раздачи у оператора — как в системе"
    fi
}

stealth_off() {
    stealth_rules_off
    [ "$STEALTH_STATE" = "on" ] || return 0
    STEALTH_STATE=""
    # то же делает другой модуль — пока он включён, его настройки не трогаем
    stealth_find_rivals
    [ -n "$STEALTH_RIVALS" ] && return 0
    echo 64 > /proc/sys/net/ipv4/ip_default_ttl 2>/dev/null
    echo 64 > /proc/sys/net/ipv6/conf/all/hop_limit 2>/dev/null
    echo 64 > /proc/sys/net/ipv6/conf/default/hop_limit 2>/dev/null
    [ -n "$RESETPROP" ] && "$RESETPROP" --delete net.tethering.noprovisioning >/dev/null 2>&1
    settings delete global tether_dun_required >/dev/null 2>&1
}

# из цикла раз в ~30с: хук на месте (netd пересобирает FORWARD), чужой TTL — в лог
stealth_reconcile() {
    local n
    [ "$STEALTH_STATE" = "on" ] || return 0
    $iptables -C FORWARD -o rmnet+ -j "$CHAIN_TTL" 2>/dev/null || { log "WATCHDOG: скрытие раздачи: хук пропал, ставлю заново"; stealth_rules_on; }
    # модули стартуют параллельно с нами — чужие ищем ещё и раз в ~5 мин
    STEALTH_TICK=$((STEALTH_TICK + 1))
    if [ "$STEALTH_TICK" -ge 10 ]; then
        STEALTH_TICK=0
        n="$STEALTH_RIVALS|$STEALTH_RIVAL_RULES"
        stealth_find_rivals
        [ "$n" != "$STEALTH_RIVALS|$STEALTH_RIVAL_RULES" ] && phone_status_refresh
    fi
    n=$(stealth_foreign)
    if [ "$n" -gt $((STEALTH_FOREIGN_LOGGED + 100)) ]; then
        [ "$STEALTH_FOREIGN_LOGGED" = 0 ] && \
            log "WARNING: раздача: устройство выходит в мобильную сеть с TTL не 64 (Windows?) — оператор может заметить раздачу. На нём: Set-NetIPv4Protocol -DefaultHopLimit 64$([ "$TETHER_TTL_STRICT" = 1 ] && echo ' (сейчас такие пакеты отбиваются)')"
        STEALTH_FOREIGN_LOGGED=$n
        phone_status_refresh
    fi
}

