"""v2.2 -> v2.3: DNS для раздачи через dnsproxy. Запуск из папки module/."""
import sys

p = 'service.sh'
s = open(p, encoding='utf-8').read()


def rep(old, new, count=1):
    global s
    n = s.count(old)
    if n != count:
        sys.exit(f'PATCH FAIL ({n} matches): {old[:80]!r}')
    s = s.replace(old, new)


# ---------- header ----------
rep('''#   6. Честный лог про BPF offload; umask 022 для файлов в /data/local/tmp.
# ============================================================================
''', '''#   6. Честный лог про BPF offload; umask 022 для файлов в /data/local/tmp.
# ============================================================================
# v3.9.6-hybrid.5 — свой DNS для раздачи через dnsproxy (AdGuard, bin/):
#   - direct: DNS клиентов (любой :53) -> REDIRECT на локальный dnsproxy ->
#     DoH/DoT (по умолчанию dns.comss.one), с кэшем и шифрованными фолбэками.
#     Оператор видит только TLS до DNS-сервера, а не сами запросы.
#   - VPN: по умолчанию как раньше (DNAT в DNS VPN). Опционально cache/doh —
#     только если трафик root реально идёт в tun (иначе DNS утёк бы мимо VPN).
#   - Порт dnsproxy закрыт для всего, кроме tether и lo; в hard/blocked режется.
#   - Смена режима = перезапуск dnsproxy (keep-alive DoH-соединения не должны
#     пережить переход direct <-> VPN на старом маршруте).
#   - dnsproxy упал и не поднялся -> откат на обычный DNAT, клиенты не без DNS.
# ============================================================================
''')

# ---------- config ----------
rep('''RULE_WATCHDOG=1        # 1 = каждые ~6с проверять, что ip rule/цепочки живы,
                       #     и пересобирать их, если netd их снёс.
# =====================================================================
''', '''RULE_WATCHDOG=1        # 1 = каждые ~6с проверять, что ip rule/цепочки живы,
                       #     и пересобирать их, если netd их снёс.

# ---------------------------- DNS (dnsproxy) ----------------------------
DNS_DIRECT="doh"       # direct-режим: doh   = DNS_UPSTREAMS через dnsproxy
                       #               plain = как раньше, DNAT на 1.1.1.1
DNS_VPN="dnat"         # VPN-режим:    dnat  = DNAT в DNS из VPN (как раньше)
                       #               cache = DNS из VPN через dnsproxy + кэш
                       #               doh   = DNS_UPSTREAMS через туннель
# Основные апстримы (DoH https://, DoT tls://, DoQ quic://, обычный ip:53)
DNS_UPSTREAMS="https://dns.comss.one/dns-query tls://dns.comss.one"
# Если основные недоступны. Только шифрованные — иначе запросы ушли бы
# оператору открытым текстом.
DNS_FALLBACKS="https://dns.google/dns-query tls://1.1.1.1"
# Чем резолвить имена самих апстримов (dns.comss.one). Подмена тут не
# страшна: TLS-сертификат апстрима всё равно проверяется.
DNS_BOOTSTRAP="77.88.8.8:53 1.1.1.1:53 8.8.8.8:53"
DNSPROXY_PORT=5354
# =====================================================================
''')

# ---------- binary detection ----------
rep('''[ -z "$CONNTRACK_BIN" ] && command -v conntrack >/dev/null 2>&1 && CONNTRACK_BIN="conntrack"
CONNTRACK_WARNED=0
''', '''[ -z "$CONNTRACK_BIN" ] && command -v conntrack >/dev/null 2>&1 && CONNTRACK_BIN="conntrack"
CONNTRACK_WARNED=0

case "$(uname -m 2>/dev/null)" in
    aarch64|arm64) _DP_CANDIDATES="$MODULE_DIR/bin/dnsproxy-arm64" ;;
    armv*|arm)     _DP_CANDIDATES="$MODULE_DIR/bin/dnsproxy-arm" ;;
    *)             _DP_CANDIDATES="$MODULE_DIR/bin/dnsproxy-arm64 $MODULE_DIR/bin/dnsproxy-arm" ;;
esac
DNSPROXY_BIN=""
for _c in $_DP_CANDIDATES; do
    [ -x "$_c" ] && DNSPROXY_BIN="$_c" && break
done
DNSPROXY_PID_FILE="/data/local/tmp/vpn_tether_dnsproxy.pid"
DNSPROXY_LOG="/data/local/tmp/vpn_tether_dnsproxy.log"
CHAIN_DNSP="VPN_TETHER_DNSP"
DNSPROXY_SIG=""        # "<режим>|<апстримы>" запущенного экземпляра
DNS_STATE=""           # что сейчас обслуживает DNS клиентов (для статуса)
DNS_STATE_MODE=""      # vpn | direct — для какого режима поставлен DNS
DNS_STATE_IFACES=""
''')

# ---------- status ----------
rep('''    [ $CURRENT_MSS -gt 0 ] && status_line="$status_line | MSS: $CURRENT_MSS ($MSS_METHOD)"
''', '''    [ $CURRENT_MSS -gt 0 ] && status_line="$status_line | MSS: $CURRENT_MSS ($MSS_METHOD)"
    [ "$mode" != "blocked" ] && [ -n "$DNS_STATE" ] && status_line="$status_line | DNS: $DNS_STATE"
''')

# ---------- DnsAddresses дублируется в dumpsys (видно в логе 2.2) ----------
rep('''local dns_block=$(echo "$dumpsys_out" | grep -o 'DnsAddresses: \\[[^]]*\\]')''',
    '''local dns_block=$(echo "$dumpsys_out" | grep -o 'DnsAddresses: \\[[^]]*\\]' | head -1)''')

# ---------- блок dnsproxy ----------
marker = '''# --- перенесено из 3.9.11 (без изменений логики) ---
flush_conntrack() {'''
block = open('../tools/dnsproxy_block.sh', encoding='utf-8').read()
rep(marker, block + '\n' + marker)

# ---------- hard guard режет и порт dnsproxy ----------
rep('''            $iptables -A "$CHAIN_GUARD_IN" -i "$iface" -p udp --dport 53 -j DROP 2>/dev/null
            $iptables -A "$CHAIN_GUARD_IN" -i "$iface" -p tcp --dport 53 -j DROP 2>/dev/null
''', '''            $iptables -A "$CHAIN_GUARD_IN" -i "$iface" -p udp --dport 53 -j DROP 2>/dev/null
            $iptables -A "$CHAIN_GUARD_IN" -i "$iface" -p tcp --dport 53 -j DROP 2>/dev/null
            $iptables -A "$CHAIN_GUARD_IN" -i "$iface" -p udp --dport "$DNSPROXY_PORT" -j DROP 2>/dev/null
            $iptables -A "$CHAIN_GUARD_IN" -i "$iface" -p tcp --dport "$DNSPROXY_PORT" -j DROP 2>/dev/null
''')

# ---------- direct ----------
rep('''    local sys_dns=$(getprop net.dns1 2>/dev/null)
    [ -z "$sys_dns" ] && sys_dns="1.1.1.1"
    setup_dns_redirect "${sys_dns}|2606:4700:4700::1111" $tether_ifaces
''', '''    apply_dns_mode direct "$(direct_dns_servers)" $tether_ifaces
''')
rep('log "Direct mode done (DNS: $sys_dns)"', 'log "Direct mode done (DNS: $DNS_STATE)"')
rep('''    if [ -z "$tether_ifaces" ]; then
        update_status "direct" "no-tether" "$CURRENT_NET_PROFILE"
        return 0
    fi
''', '''    if [ -z "$tether_ifaces" ]; then
        apply_dns_mode direct ""
        update_status "direct" "no-tether" "$CURRENT_NET_PROFILE"
        return 0
    fi
''')

# ---------- vpn ----------
rep('''    local vpn_dns=$(get_vpn_dns)
    setup_dns_redirect "$vpn_dns" $tether_ifaces''', '''    local vpn_dns=$(get_vpn_dns)
    apply_dns_mode vpn "$vpn_dns" $tether_ifaces''')

# ---------- blocked ----------
rep('''    CURRENT_MSS=0
    update_status "blocked"''', '''    # В blocked DNS не нужен; dnsproxy гасим, чтобы при выходе из blocked
    # он стартовал заново уже на правильном маршруте
    dnsproxy_stop
    dnsproxy_port_guard_down
    DNS_STATE=""

    CURRENT_MSS=0
    update_status "blocked"''')

# ---------- watchdog в цикле ----------
rep('''    apply_state "$tun_idx" $tether_ifaces || log "ERROR: apply_state failed"

    FORCE_UPDATE=0
''', '''    apply_state "$tun_idx" $tether_ifaces || log "ERROR: apply_state failed"

    dns_watchdog

    FORCE_UPDATE=0
''')

# ---------- выход и старт ----------
rep('''    log "Exiting, cleaning up..."
    cleanup_all_rules
    guard_down''', '''    log "Exiting, cleaning up..."
    cleanup_all_rules
    dnsproxy_stop
    dnsproxy_port_guard_down
    guard_down''')
rep('''TUN_NAME=$(detect_tun_name)
log "TUN: $TUN_NAME"

cleanup_all_rules''', '''TUN_NAME=$(detect_tun_name)
log "TUN: $TUN_NAME"

dnsproxy_kill_strays
rm -f "$DNSPROXY_PID_FILE"
dnsproxy_port_guard_down

cleanup_all_rules''')

rep('echo "=== VPN Tether v3.9.5-hybrid.4 Started $(date) ===" > "$LOG_FILE"',
    'echo "=== VPN Tether v3.9.6-hybrid.5 Started $(date) ===" > "$LOG_FILE"')
rep('WATCHDOG=$RULE_WATCHDOG ct_bin=${CONNTRACK_BIN:-none}"',
    'WATCHDOG=$RULE_WATCHDOG DNS_DIRECT=$DNS_DIRECT DNS_VPN=$DNS_VPN ct_bin=${CONNTRACK_BIN:-none} dnsproxy=${DNSPROXY_BIN:-none}"')
rep('log "Network engine: v3.9.5"', 'log "Network engine: v3.9.6"')

open(p, 'w', encoding='utf-8', newline='\n').write(s)
print('patched OK')
