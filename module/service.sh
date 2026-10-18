#!/system/bin/sh

# ============================================================================
# VPN Tether v3.9.3 - AI review patches (FORWARD order, fwmark, zombie rules)
# - База: v3.8.5
# - ИСПРАВЛЕНО:
#   - Каскад MTU (сохраняем оригинальный MTU при первом чтении)
#   - Принудительная установка safe_mtu на tun0 (нужна для UDP)
#   - Инвертированный статус (убрана гонка с action.sh)
# - УБРАНО:
#   - Power save off (не влияет на скорость)
#   - advmss (вызывал нестабильность)
# - ОСТАВЛЕНО:
#   - normalize_fwmark()
#   - MSS logging
#   - Transient tether
#   - Умный расчёт MTU для VLESS/WireGuard
# ============================================================================
# v3.9.3-hybrid.2: стабильная база 3.9.3 + точечные фиксы из 3.9.11:
#   - таргетированный conntrack flush (только tether-подсети, bin/conntrack)
#     вместо no-op "echo f" — фикс затупов AdGuard после reconnect
#   - INVALID -> DROP первым в FORWARD + be_liberal=1 (анти-утечка на реконнекте)
#   - отключение HW tethering offload (клиенты не прибиваются к прямому пути)
# Фикс болячки 3.9.3: при vpn=true и tether=[] state-машина зацикливалась
#   "direct для [] -> Full cleanup" каждые 10-30с всю сессию (мода ставилась
#   в "off", условие входа проверяло != "on"). Введено состояние "degraded":
#   без тетеринга модуль оседает и молчит до реального изменения состояния.
# ============================================================================
# v3.9.4-hybrid.3 — устранение тихих утечек в direct:
#   1. KILL-SWITCH (VPN_TETHER_GUARD): fail-closed. Раньше блэнкетный
#      "-A FORWARD -j ACCEPT" НИКОГДА не удалялся, и любой сбой маршрутизации
#      превращался в рабочий direct-выход с реальным IP.
#   2. read_table_index брал ПЕРВОЕ совпадение "tun0" в rt_tables — при
#      реконнекте это могла быть мёртвая таблица -> провал в main -> direct.
#      Теперь берётся самая свежая таблица С МАРШРУТАМИ.
#   3. Порядок старта: clear_rules_file шёл ДО cleanup_all_rules, поэтому
#      зомби-правила от убитого демона не удалялись никогда.
#   4. WATCHDOG: раз в ~6с проверяем, что ip rule и хуки цепочек живы.
#      netd/TetheringService их сносят, а модуль этого не замечал.
#   5. Пустой WAN больше не считается "сменой сети" (шторм teardown+rebuild
#      каждые 12с, см. лог 01:09:27-01:10:04 — каждая пересборка = окно).
#   6. Гистерезис на падение VPN (3 промаха), IPv6 DROP до dumpsys,
#      счётчик итераций вместо now%10 (мог залипнуть навсегда).
# ============================================================================
# v3.9.5-hybrid.4 — сценарий "телефон на Wi-Fi + раздача", strict kill-switch:
#   1. Tether/WAN берутся из правил netd ("iif <downstream> lookup <upstream>")
#      и DHCP-сокетов :67, а не из эвристики по RFC1918. Раньше при VPN
#      "ip route get" от root уходит в tun0, WAN не находился, и wlan0
#      (клиент Wi-Fi, 192.168.x) записывался в tether: ip rule/fwmark/guard
#      на wlan0 + conntrack flush собственных потоков телефона (туннель VPN).
#   2. Смена WAN в VPN-режиме больше не вызывает flush+пересборку: правила
#      от WAN не зависят (NAT в tun). Было: 2 лишних hard-окна и обрыв всех
#      соединений клиентов на каждый переход Wi-Fi <-> мобилка.
#   3. KILL_SWITCH_STRICT: режим VPN выбран, а VPN нет (упал / ещё не поднялся
#      после загрузки) -> клиенты блокируются, а не уходят в direct.
#   4. hard-guard режет и DNS к самому телефону (dnsmasq), иначе в окне
#      пересборки запросы шли к DNS оператора.
#   5. Тоггл: USR1 будит цикл сразу (sleep & wait), без 3с ping на FORCE,
#      демон подтверждает выполнение через ack-файл — action.sh ждёт его,
#      а не спит 3с (из-за этого жали повторно и режим откатывался).
#   6. Честный лог про BPF offload; umask 022 для файлов в /data/local/tmp.
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
#   - CA для Go-бинаря берутся из APEX conscrypt (Android 14+), только системные.
#   - ФИКС (жил с 3.9.4): после кратковременного обрыва VPN без смены tun
#     guard оставался в hard навсегда — раздача без интернета до ребута/тоггла.
# ============================================================================
# v3.9.7-hybrid.6 — DoH реально работает на устройстве с AdGuard:
#   - AdGuard (root, HTTPS-фильтр) REDIRECT-ит ВЕСЬ TCP root на свой MITM-
#     прокси -> dnsproxy видел сертификат AdGuard -> "unknown authority",
#     все запросы SERVFAIL. Теперь dnsproxy = root:DNSPROXY_GID (su -g), и
#     правило "nat OUTPUT -m owner --gid-owner GID -j RETURN" стоит ПЕРВЫМ
#     (watchdog возвращает его наверх, если AdGuard перевставил свою цепочку).
#   - DoT (853) к comss режется по дороге (EOF) — по умолчанию только DoH.
#   - После старта — настоящий DNS-запрос к dnsproxy (nc). Не ответил ->
#     откат на DNAT, а не "клиенты без DNS".
#   - 3.9.7.1: редирект на dnsproxy до проверки (не было окна с DNS оператора),
#     проверка ~1-2с вместо 8-10с (nc -w 1 x5).
#   - 3.9.7.2: тоггл в direct шёл 20-28с -> action.sh "демон не подтвердил":
#     * флаг режима читается только при обработке USR1. Раньше action.sh
#       менял файл, текущая итерация уже перестраивала всё по новому флагу
#       (без ack), а следующая — ещё раз с FORCE (с ack). Две настройки.
#     * read_table_index при выключенном VPN гонял 15 попыток (~3с на вызов,
#       2 вызова на итерацию); теперь нет tun-ифейса -> сразу выход.
#       Заодно: "sleep 0.1138" вместо 1.138с (printf %03d от 1138).
# ============================================================================

umask 022

# ==================== USER CONFIG (0=выкл, 1=вкл) ====================
DISABLE_HW_OFFLOAD=1   # выключать аппаратный tethering offload
TARGETED_CT_FLUSH=1    # 1 = таргетированный flush через bin/conntrack;
                       # 0 = поведение 3.9.3 (echo f, фактически no-op)
KILL_SWITCH=1          # 1 = fail-closed: если правила VPN не встали/отвалились,
                       #     трафик клиентов ДРОПАЕТСЯ, а не уходит напрямую.
                       # 0 = старое поведение (при сбое клиент уходит в direct
                       #     мимо VPN — то самое, из-за чего ноут светил IP).
KILL_SWITCH_STRICT=1   # 1 = выбран режим VPN, а VPN не поднят -> клиенты без сети
                       #     (до появления VPN или ручного переключения в direct).
                       # 0 = как в 3.9.4: после 3 промахов уходим в direct.
RULE_WATCHDOG=1        # 1 = каждые ~6с проверять, что ip rule/цепочки живы,
                       #     и пересобирать их, если netd их снёс.

# ---------------------------- DNS (dnsproxy) ----------------------------
DNS_DIRECT="doh"       # direct-режим: doh   = DNS_UPSTREAMS через dnsproxy
                       #               plain = как раньше, DNAT на 1.1.1.1
DNS_VPN="dnat"         # VPN-режим:    dnat  = DNAT в DNS из VPN (как раньше; нужен,
                       #                       если VPN-клиент роутит по доменам/fakeip)
                       #               cache = DNS из VPN через dnsproxy + кэш
                       #               doh   = DNS_VPN_UPSTREAMS через туннель + кэш
                       #                       (замер: ~200мс вместо ~550мс, кэш ~5мс)
# Основные апстримы (DoH https://, DoT tls://, DoQ quic://, обычный ip:53)
DNS_UPSTREAMS="https://dns.comss.one/dns-query"
# Если основные недоступны. Только шифрованные — иначе запросы ушли бы
# оператору открытым текстом.
DNS_FALLBACKS="https://dns.google/dns-query https://cloudflare-dns.com/dns-query"
# Апстримы для DNS_VPN=doh (идут через туннель)
DNS_VPN_UPSTREAMS="https://dns.google/dns-query https://cloudflare-dns.com/dns-query"
# Чем резолвить имена самих апстримов (dns.comss.one). Подмена тут не
# страшна: TLS-сертификат апстрима всё равно проверяется.
DNS_BOOTSTRAP="77.88.8.8:53 1.1.1.1:53 8.8.8.8:53"
DNSPROXY_PORT=5354
# dnsproxy запускается как root:DNSPROXY_GID; по этому GID его трафик
# исключается из перехвата AdGuard и прочих transparent-proxy (nat OUTPUT).
# Пусто = без исключения (DoH сломается, если HTTPS-фильтр AdGuard включён).
DNSPROXY_GID=3999
# =====================================================================

FORCE_PUBLIC_DNS=0

# Адаптивные профили сети
RTT_THRESHOLD_STABLE=250

TIMEOUT_CMD="timeout 3"
if command -v timeout >/dev/null 2>&1; then
    if timeout --help 2>&1 | grep -q -- '-k'; then
        TIMEOUT_CMD="timeout -k 5 3"
    fi
fi

PID_FILE="/data/local/tmp/vpn_tether.pid"
PID_LOCK="/data/local/tmp/vpn_tether.lock"

is_our_daemon() {
    local pid="$1"
    kill -0 "$pid" 2>/dev/null || return 1
    
    local cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
    case "$cmd" in
        *sh*|*magisk*|*ksu*) ;; 
        *) return 1 ;;
    esac

    if ls -l "/proc/$pid/fd" 2>/dev/null | grep -qE "vpn_tether.log|status"; then
        return 0
    fi
    
    local cwd=$(ls -l "/proc/$pid/cwd" 2>/dev/null | awk '{print $NF}')
    if [ "$cwd" = "$MODULE_DIR" ]; then
        return 0
    fi
    
    return 1
}

if ! mkdir "$PID_LOCK" 2>/dev/null; then
    if [ -f "$PID_LOCK/pid" ]; then
        lock_pid=$(cat "$PID_LOCK/pid" 2>/dev/null)
        if [ -n "$lock_pid" ] && is_our_daemon "$lock_pid"; then
            echo "[$(date '+%H:%M:%S')] Already running (PID $lock_pid). Exiting."
            exit 1
        else
            rm -f "$PID_LOCK/pid" 2>/dev/null
            rmdir "$PID_LOCK" 2>/dev/null
            if ! mkdir "$PID_LOCK" 2>/dev/null; then
                echo "[$(date '+%H:%M:%S')] Failed to acquire lock. Exiting."
                exit 1
            fi
        fi
    else
        rmdir "$PID_LOCK" 2>/dev/null
        if ! mkdir "$PID_LOCK" 2>/dev/null; then
            echo "[$(date '+%H:%M:%S')] Failed to acquire lock. Exiting."
            exit 1
        fi
    fi
fi

echo $$ > "$PID_LOCK/pid"
trap 'rm -f "$PID_LOCK/pid" 2>/dev/null; rmdir "$PID_LOCK" 2>/dev/null || rm -rf "$PID_LOCK" 2>/dev/null' EXIT
echo $$ > "$PID_FILE"

TUN_NAME=tun0
DEBOUNCE_SECS=1
FORCE_UPDATE=0
LAST_HANDLE_TS=0
EMPTY_IFACE_DELAY=0
EMPTY_TETHER_COUNT=0

# Сохраняем оригинальный MTU при первом чтении (защита от каскада)
ORIGINAL_TUN_MTU=""

TETHER_IFACES="wlan2 wlan1 wlan0 ap0 hotspot swlan0 swlan1 swlan2 rndis0 usb0 eth0 bt-pan bnep0 ncm0 wwan0 tether0 qmi0"

CHAIN_FWD="VPN_TETHER_FWD"
CHAIN_POST="VPN_TETHER_POST"
CHAIN_MSS="VPN_BASE_MSS"
CHAIN_DNS="VPN_TETHER_DNS"
CHAIN_DNS6="VPN_TETHER_DNS6"
CHAIN_GUARD="VPN_TETHER_GUARD"
CHAIN_GUARD_IN="VPN_TETHER_GUARD_IN"

VPN_DOWN_COUNT=0
WATCHDOG_TICK=0
WAN_DOWN_LOGGED=0
GUARD_STATE="none"

MODDIR="${0%/*}"
if [ -f "$MODDIR/module.prop" ]; then
    MODULE_DIR="$MODDIR"
else
    for _d in /data/adb/modules/vpn-to-hotspot-usb /data/adb/ksu/modules/vpn-to-hotspot-usb; do
        if [ -f "$_d/module.prop" ]; then
            MODULE_DIR="$_d"
            break
        fi
    done
fi
: "${MODULE_DIR:=/data/adb/modules/vpn-to-hotspot-usb}"

FLAG_FILE="$MODULE_DIR/vpn_tether_enabled"
STATUS_FILE="$MODULE_DIR/status"
REQ_FILE="$MODULE_DIR/toggle_req"
ACK_FILE="$MODULE_DIR/toggle_ack"
USR1_PENDING=0
DISCOVERY_SRC=""
LOG_FILE="/data/local/tmp/vpn_tether.log"
RULES_FILE="/data/local/tmp/vpn_tether_rules"

ip="/system/bin/ip"
iptables="/system/bin/iptables -w 2"
ip6tables="/system/bin/ip6tables -w 2"
ANDROID_LOG="/system/bin/log"

# --- перенесено из 3.9.11: статический conntrack + сохранение offload ---
OFFLOAD_SAVE_FILE="/data/local/tmp/vpn_tether_offload_orig"
_CT_CANDIDATES=""
case "$(uname -m 2>/dev/null)" in
    aarch64|arm64) _CT_CANDIDATES="$MODULE_DIR/bin/conntrack-arm64" ;;
    armv*|arm)     _CT_CANDIDATES="$MODULE_DIR/bin/conntrack-arm" ;;
    *)             _CT_CANDIDATES="$MODULE_DIR/bin/conntrack-arm64 $MODULE_DIR/bin/conntrack-arm" ;;
esac
CONNTRACK_BIN=""
for _c in $_CT_CANDIDATES; do
    [ -x "$_c" ] && CONNTRACK_BIN="$_c" && break
done
[ -z "$CONNTRACK_BIN" ] && command -v conntrack >/dev/null 2>&1 && CONNTRACK_BIN="conntrack"
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
DNSPROXY_SU_G=""       # "" = не проверяли, 1 = su -g работает, 0 = нет
BUSYBOX=""
for _b in /data/adb/ksu/bin/busybox /data/adb/magisk/busybox /data/adb/ap/bin/busybox; do
    [ -x "$_b" ] && BUSYBOX="$_b" && break
done

LAST_TUN_INDEX=""
LAST_TETHER_IFACES=""
LAST_WAN_IFACE=""
LAST_WAN_GW=""
LAST_WAN_IP=""
LAST_TETHER_IFACES_STABLE=""
LAST_VPN_ACTIVE="false"
VPN_TETHER_MODE="off"
_NEED_UPDATE=0
VPN_DNS_CACHE=""
VPN_DNS_CACHE_TIME=0
TETHER_CHANGE_COUNT=0
TETHER_STABLE_TIME=0

# Состояние качества сети
CURRENT_NET_PROFILE="FAST"
QUALITY_CHECK_COUNTER=0
STABLE_COUNT=0
FAST_COUNT=0

# MSS tracking
CURRENT_MSS=0
MSS_METHOD="static"

# Rate limiting для логов
LAST_LOG_MSG=""
LAST_LOG_COUNT=0
LOG_REPEAT_THRESHOLD=5

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
        tun*|wg*|awg*|vpn*|ppp*|lo|rmnet*|r_rmnet*|ccmni*|wwan*|pdp*|stnet*|epdg*|dummy*|sit*|ip6*|ifb*|v4-*|clat*|ipsec*|bond*|bridge*|pan*|bt-*|veth*|docker*|lxc*|virbr*|macvlan*|ipvlan*|vlan*)
            return 0 ;;
    esac
    return 1
}

set_sysctl() {
    local key="$1" val="$2"
    [ -z "$key" ] && return 0
    sysctl -w "$key=$val" >/dev/null 2>&1 || \
    echo "$val" > "/proc/sys/${key//./\/}" 2>/dev/null || return 1
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
    
    printf '%s\n%s' "$status_line" "$ifaces" > "$STATUS_FILE"
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

normalize_tether_ifaces() {
    echo "$*" | tr -s '[:space:]' '\n' | sort -u | grep -v '^$' | tr '\n' ' ' | sed 's/ $//'
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
netd_tether_pairs() {
    $ip rule show 2>/dev/null | awk '
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
    $ip rule show 2>/dev/null | awk '
        /fwmark 0x0\/0xffff iif lo lookup/ && !/uidrange/ {
            for (i = 1; i <= NF; i++) if ($i == "lookup") { print $(i + 1); exit }
        }' | sed 's/_local$//'
}

# Интерфейсы, на которых висит DHCP-сервер (раздача без аплинка тоже видна)
dhcp_server_ifaces() {
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
        iface=$(normalize_iface_name "$iface")
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
    echo "${d#*|}"
}

# Вызывать НЕ через $(...): пишет глобальные TETHER_NOW и DISCOVERY_SRC
refresh_tether_ifaces() {
    local d src
    d=$(get_tether_discovery)
    src="${d%%|*}"
    TETHER_NOW="${d#*|}"
    if [ -n "$TETHER_NOW" ] && [ "$src" != "$DISCOVERY_SRC" ]; then
        log "Tether discovery: $src [$TETHER_NOW]"
        DISCOVERY_SRC="$src"
    fi
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
        dumpsys_out=$($TIMEOUT_CMD sh -c "dumpsys connectivity 2>/dev/null" | grep -A200 "VPN CONNECTED" | grep -B5 -A5 "InterfaceName: $TUN_NAME") || \
        dumpsys_out=$(dumpsys connectivity 2>/dev/null | grep -A200 "VPN CONNECTED" | grep -B5 -A5 "InterfaceName: $TUN_NAME")
        
        if [ -n "$dumpsys_out" ]; then
            log "VPN block found (first 80 chars): $(echo "$dumpsys_out" | head -1 | cut -b1-80)..."
            
            local dns_block=$(echo "$dumpsys_out" | grep -o 'DnsAddresses: \[[^]]*\]' | head -1)
            log "Raw DNS block: ${dns_block:-<none>}"
            
            if [ -n "$dns_block" ]; then
                local dns_content=$(echo "$dns_block" | sed 's/.*DnsAddresses: \[//' | sed 's/\].*//' | tr -d ' ')
                log "DNS content: $dns_content"
                
                local raw_dns4=$(echo "$dns_content" | tr ',' '\n' | sed 's/^\///' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
                log "IPv4 candidates: $(echo $raw_dns4 | tr '\n' ' ')"
                
                for ip in $raw_dns4; do
                    [ -n "$dns4" ] && break
                    dns4=$(_parse_ip4_safe "$ip")
                    [ -n "$dns4" ] && log "Valid IPv4 DNS: $dns4"
                done
                
                local raw_dns6=$(echo "$dns_content" | tr ',' '\n' | sed 's/^\///' | grep -E ':' | grep -v '^/$')
                log "IPv6 candidates: $(echo $raw_dns6 | tr '\n' ' ')"
                
                for ip in $raw_dns6; do
                    [ -n "$dns6" ] && break
                    dns6=$(_parse_ip6_safe "$ip")
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
    
    if [ "$profile" = "$CURRENT_NET_PROFILE" ] && [ "$FORCE_UPDATE" -eq 0 ]; then
        return
    fi
    
    log "Switching to $profile profile..."
    
    if [ "$profile" = "STABLE" ]; then
        echo cubic > /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || true
        echo 2 > /proc/sys/net/ipv4/tcp_ecn 2>/dev/null || true
        echo 1 > /proc/sys/net/ipv4/tcp_ecn_fallback 2>/dev/null || true
        set_sysctl net.ipv4.tcp_syn_retries 4
        set_sysctl net.ipv4.tcp_slow_start_after_idle 1
        log "STABLE profile: Cubic + Safe-ECN + High Retries"
    else
        if grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
            echo bbr > /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || true
        else
            echo cubic > /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || true
        fi
        echo 1 > /proc/sys/net/ipv4/tcp_ecn 2>/dev/null || true
        echo 1 > /proc/sys/net/ipv4/tcp_ecn_fallback 2>/dev/null || true
        set_sysctl net.ipv4.tcp_syn_retries 3
        set_sysctl net.ipv4.tcp_slow_start_after_idle 0
        log "FAST profile: BBR/cubic + Full-ECN + Low Latency"
    fi
    
    CURRENT_NET_PROFILE=$profile
    # Не вызываем update_status здесь — правильный статус ставится в конце setup
}

check_network_quality() {
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
        log "Network quality check: no response from $ping_target via $wan, keeping $CURRENT_NET_PROFILE"
        STABLE_COUNT=0
        FAST_COUNT=0
        return
    fi
    
    log "Network RTT to $ping_target via $wan: ${rtt_min}ms (threshold: ${RTT_THRESHOLD_STABLE}ms)"
    
    if [ "$FORCE_UPDATE" -eq 1 ]; then
        STABLE_COUNT=0
        FAST_COUNT=0
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
    
    log "Network engine: v3.9.7"
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

cleanup_dns_redirect() {
    $iptables -t nat -D PREROUTING -j "$CHAIN_DNS" 2>/dev/null
    $iptables -t nat -F "$CHAIN_DNS" 2>/dev/null
    $iptables -t nat -X "$CHAIN_DNS" 2>/dev/null
    
    $ip6tables -t nat -D PREROUTING -j "$CHAIN_DNS6" 2>/dev/null
    $ip6tables -t nat -F "$CHAIN_DNS6" 2>/dev/null
    $ip6tables -t nat -X "$CHAIN_DNS6" 2>/dev/null
}

setup_dns_redirect() {
    local dns_servers=$1
    local dns4="${dns_servers%%|*}"
    local dns6="${dns_servers##*|}"
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
    # и всё, что могло остаться от прошлых запусков (обёртка su, гонки)
    for pid in $(dnsproxy_pids); do kill -9 "$pid" 2>/dev/null; done
    rm -f "$DNSPROXY_PID_FILE"
    DNSPROXY_SIG=""
    dnsproxy_exempt_down
}

# PID-ы процессов, чей argv[0] — наш dnsproxy (grep и обёртки su/sh не в счёт)
dnsproxy_pids() {
    local f
    for f in $(grep -l "$MODULE_DIR/bin/dnsproxy" /proc/[0-9]*/cmdline 2>/dev/null); do
        case "$(tr '\0' ' ' 2>/dev/null < "$f")" in
            "$MODULE_DIR/bin/dnsproxy"*) f="${f#/proc/}"; echo "${f%/cmdline}" ;;
        esac
    done
}

# Осиротевшие экземпляры от убитого демона (pid-файл мог потеряться)
dnsproxy_kill_strays() {
    local pid
    for pid in $(dnsproxy_pids); do
        kill -9 "$pid" 2>/dev/null && log "Убит осиротевший dnsproxy $pid"
    done
}

# Исключение dnsproxy из перехвата AdGuard: RETURN по GID первым в nat OUTPUT.
# AdGuard при перезапуске вставляет свой jump в позицию 1 — поэтому проверяем
# именно позицию, а не наличие.
dnsproxy_exempt() {
    local t want
    [ "$DNSPROXY_SU_G" = "1" ] || return 0
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

# Настоящий DNS-запрос (example.com A) к dnsproxy. 0 = NOERROR и есть ответы.
dnsproxy_probe() {
    local out i
    [ -n "$BUSYBOX" ] || return 0   # нечем проверить — не блокируем запуск
    # busybox nc после ответа ещё ждёт -w секунд тишины, поэтому -w 1 и
    # несколько попыток: холодный старт (bootstrap + TLS) ~1.5с промахнётся
    # в первую попытку, вторая уже ответит из готового соединения/кэша.
    for i in 1 2 3 4 5; do
        out=$(printf '\022\064\001\000\000\001\000\000\000\000\000\000\007example\003com\000\000\001\000\001' | \
              $BUSYBOX nc -u -w 1 127.0.0.1 "$DNSPROXY_PORT" 2>/dev/null | \
              $BUSYBOX od -An -tx1 -N8 2>/dev/null)
        # " 12 34 81 80 00 01 00 01": id, флаги (rcode = младшие 4 бита 4-го), qd, an
        set -- $out
        if [ "$1$2" = "1234" ] && [ $(( 0x${4:-ff} & 15 )) -eq 0 ] && [ "$7$8" != "0000" ]; then
            return 0
        fi
    done
    return 1
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
    # Статический Go не находит CA Android 14+ (лежат в APEX conscrypt) ->
    # "x509: certificate signed by unknown authority". Только системные CA:
    # пользовательские (cacerts-added, напр. AdGuard HTTPS-фильтр) не берём.
    local certs="SSL_CERT_DIR=/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts"

    if [ -z "$DNSPROXY_SU_G" ]; then
        DNSPROXY_SU_G=0
        [ -n "$DNSPROXY_GID" ] && su -g "$DNSPROXY_GID" -c true >/dev/null 2>&1 && DNSPROXY_SU_G=1
        [ -n "$DNSPROXY_GID" ] && [ "$DNSPROXY_SU_G" = "0" ] && \
            log "WARNING: su -g не работает — dnsproxy без своего GID, HTTPS-фильтр AdGuard сломает DoH"
    fi

    if [ "$DNSPROXY_SU_G" = "1" ]; then
        dnsproxy_exempt
        su -g "$DNSPROXY_GID" -c "$certs exec $DNSPROXY_BIN $args -o $DNSPROXY_LOG" >/dev/null 2>&1 < /dev/null &
    else
        env "$certs" $DNSPROXY_BIN $args -o "$DNSPROXY_LOG" >/dev/null 2>&1 < /dev/null &
    fi

    # $! тут — su/env, а не сам dnsproxy: ищем по argv[0]
    i=0
    while [ $i -lt 25 ]; do
        sleep 0.2
        u=$(dnsproxy_pids | head -1)
        [ -n "$u" ] && echo "$u" > "$DNSPROXY_PID_FILE"
        if [ -n "$u" ] && ss -lun 2>/dev/null | grep -qE "[:.]$DNSPROXY_PORT[[:space:]]"; then
            DNSPROXY_SIG="$sig"
            log "dnsproxy запущен (pid $u, gid ${DNSPROXY_GID:-0}, $tag): $ups"
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
            doh)   want="doh";   ups="$DNS_VPN_UPSTREAMS" ;;
        esac
        # Каждая пересборка VPN = новый экземпляр: keep-alive DoH-соединение
        # могло открыться через WAN, пока tun пропадал, и так бы и осталось.
        DNSPROXY_SIG=""
        if [ -n "$want" ] && ! root_routed_via_tun; then
            log "WARNING: трафик root идёт мимо $TUN_NAME (per-app VPN?) — DNS_VPN=$DNS_VPN выключен, DNAT в DNS VPN"
            want=""
        fi
    fi

    if [ -n "$want" ] && [ -n "$ups" ]; then
        dnsproxy_port_guard $ifaces
        # Редирект ставим СРАЗУ после старта, проверку — после: иначе на всё
        # время проверки клиенты без редиректа спрашивали dnsmasq раздачи
        # (= DNS оператора). Не прошла — setup_dns_redirect ниже его заменит.
        if dnsproxy_start "$mode-$want" $ups; then
            dns_redirect_to_proxy $ifaces
            if dnsproxy_probe; then
                DNS_STATE="dnsproxy $want"
                DNS_STATE_MODE="$mode"
                DNS_STATE_IFACES="$ifaces"
                return 0
            fi
        fi
        log "WARNING: dnsproxy не отвечает ($(grep ERROR "$DNSPROXY_LOG" 2>/dev/null | tail -1 | cut -c1-160)), откат на обычный DNAT"
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
    dnsproxy_exempt
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

# --- перенесено из 3.9.11 (без изменений логики) ---
flush_conntrack() {
    if [ "$TARGETED_CT_FLUSH" != "1" ]; then
        # поведение 3.9.3: на большинстве ядер это no-op (файл read-only)
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
    # На A13+ BPF offload этим не выключается (проверено на A15: в dumpsys
    # остаётся mIsBpfEnabled: true). Это не утечка: BpfCoordinator офлоадит
    # только потоки, NAT-нутые на адрес аплинка, а VPN-потоки NAT-ятся в tun.
    # Direct-потоки, пережившие переключение, убирает conntrack flush.
    if dumpsys tethering 2>/dev/null | grep -q "mIsBpfEnabled: true"; then
        log "HW offload disabled; BPF offload остаётся включённым (A13+), VPN-потоки он не трогает"
    else
        log "HW tethering offload disabled (HAL + BPF)"
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
    $iptables -I FORWARD 1 -j "$CHAIN_GUARD" 2>/dev/null

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

    if [ "$KILL_SWITCH" = "1" ]; then
        $iptables -C FORWARD -j "$CHAIN_GUARD" 2>/dev/null || {
            log "WATCHDOG: kill-switch снят, переставляю"; return 1; }
    fi

    return 0
}

cleanup_all_rules() {
    log "Full cleanup..."

    # Восстанавливаем оригинальный MTU перед сбросом
    if [ -n "$ORIGINAL_TUN_MTU" ] && [ "$ORIGINAL_TUN_MTU" -gt 0 ] 2>/dev/null; then
        $ip link set dev "$TUN_NAME" mtu "$ORIGINAL_TUN_MTU" 2>/dev/null || true
    fi
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
    cleanup_all_rules
    clear_rules_file

    $ip6tables -C FORWARD -j DROP 2>/dev/null || $ip6tables -I FORWARD -j DROP 2>/dev/null
    # cleanup_all_rules сносит хуки, но не цепочку guard — подтверждаем её
    guard_apply hard $tether_ifaces

    # В blocked DNS не нужен; dnsproxy гасим, чтобы при выходе из blocked
    # он стартовал заново уже на правильном маршруте
    dnsproxy_stop
    dnsproxy_port_guard_down
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

    cleanup_all_rules
    clear_rules_file

    # IPv6-форвард режем СРАЗУ, а не в конце после dumpsys (тот может
    # висеть до 3-6с на таймауте — всё это время был v6-леак).
    $ip6tables -D FORWARD -j REJECT --reject-with icmp6-no-route 2>/dev/null
    $ip6tables -D FORWARD -j DROP 2>/dev/null
    $ip6tables -I FORWARD -j DROP 2>/dev/null
    
    # Сохраняем оригинальный MTU в родительском процессе, а не в подоболочке
    if [ -z "$ORIGINAL_TUN_MTU" ]; then
        ORIGINAL_TUN_MTU=$($ip link show "$TUN_NAME" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}')
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
        update_status "direct" "$(echo $tether_ifaces | tr ' ' '/')" "$CURRENT_NET_PROFILE"
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

    # Из 3.9.11: INVALID (out-of-window после реконнекта) дропаем до всего —
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

    tether_ifaces=$(normalize_tether_ifaces $tether_ifaces)
    LAST_TETHER_IFACES_STABLE="${LAST_TETHER_IFACES_STABLE:-$tether_ifaces}"
    
    local sorted_current=$(echo "$tether_ifaces" | tr -s '[:space:]' '\n' | sort | tr '\n' ' ' | sed 's/ $//')
    local sorted_stable=$(echo "$LAST_TETHER_IFACES_STABLE" | tr -s '[:space:]' '\n' | sort | tr '\n' ' ' | sed 's/ $//')
    
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
                log "WARNING: Tether interfaces flapping, keeping stable set: [$LAST_TETHER_IFACES_STABLE]"
                tether_ifaces="$LAST_TETHER_IFACES_STABLE"
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
                # ФИКС 3.9.3: раньше здесь ставился "off", условие выше
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

handle_change() {
    local now=$(date +%s)
    local ack_token=""

    # Тоггл из action.sh. Обрабатываем здесь, а не в trap: trap может
    # сработать посреди apply_state, и "FORCE_UPDATE=0" после него терял сигнал.
    if [ "$USR1_PENDING" -eq 1 ]; then
        USR1_PENDING=0
        refresh_vpn_target
        FORCE_UPDATE=1
        ack_token=$(cat "$REQ_FILE" 2>/dev/null)
        [ -z "$ack_token" ] && ack_token="noreq"
    fi

    [ "$FORCE_UPDATE" -eq 0 ] && [ $((now - LAST_HANDLE_TS)) -lt $DEBOUNCE_SECS ] && { _NEED_UPDATE=1; return 0; }

    LAST_HANDLE_TS=$now

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

    local tun_idx=$(read_table_index "$TUN_NAME")
    refresh_tether_ifaces
    local tether_ifaces="$TETHER_NOW"
    
    if [ -z "$tether_ifaces" ]; then
        EMPTY_IFACE_DELAY=$((EMPTY_IFACE_DELAY + 1))
        # Было: [ $((now % 10)) -ne 0 ] && return 0
        # now — это epoch-секунды, а цикл спит по 2с. Стоит фазе сползти на
        # нечётную (ping с timeout 3 это делает регулярно) — now%10 никогда
        # не станет нулём, и apply_state не вызывается ВООБЩЕ. Считаем итерации.
        if [ $EMPTY_IFACE_DELAY -gt 5 ] && [ "$FORCE_UPDATE" -eq 0 ]; then
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
        if [ $WATCHDOG_TICK -ge 3 ]; then
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

# Только помечаем: вся работа — в handle_change, в основном потоке цикла
handle_usr1() {
    USR1_PENDING=1
    LAST_HANDLE_TS=0
    log "Toggle signal received"
}

cleanup_on_exit() {
    log "Exiting, cleaning up..."
    cleanup_all_rules
    dnsproxy_stop
    dnsproxy_port_guard_down
    guard_down
    restore_hw_offload
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
        _loop_count=$(( _loop_count + 1 ))
    done
}

echo "=== VPN Tether v3.9.7-hybrid.6 Started $(date) ===" > "$LOG_FILE"

log "Daemon started with PID $$"
log "Config: HW_OFFLOAD_OFF=$DISABLE_HW_OFFLOAD CT_FLUSH=$TARGETED_CT_FLUSH KILL_SWITCH=$KILL_SWITCH STRICT=$KILL_SWITCH_STRICT WATCHDOG=$RULE_WATCHDOG DNS_DIRECT=$DNS_DIRECT DNS_VPN=$DNS_VPN ct_bin=${CONNTRACK_BIN:-none} dnsproxy=${DNSPROXY_BIN:-none}"

disable_hw_offload

[ ! -f "$FLAG_FILE" ] && { touch "$FLAG_FILE"; log "VPN mode ENABLED by default after reboot"; }
refresh_vpn_target

# ВНИМАНИЕ: clear_rules_file здесь БЫЛ и стирал список правил ДО того, как
# cleanup_all_rules успевал их удалить (ip_rule_del_all читает этот файл).
# Итог: после жёсткого убийства демона в системе оставались зомби-правила
# "iif wlan2 lookup <мёртвая таблица> pref 3000". Новое правило вставало
# рядом с тем же pref 3000, порядок недетерминирован — и клиент мог
# постоянно уходить в мёртвую таблицу и проваливаться в main (= напрямую).
# Теперь чистим сначала, стираем файл после.
guard_down

RT_WAIT=0
while [ ! -f /data/misc/net/rt_tables ] && [ $RT_WAIT -lt 30 ]; do
    sleep 2
    RT_WAIT=$((RT_WAIT + 1))
done
[ -f /data/misc/net/rt_tables ] && log "rt_tables found" || log "WARNING: rt_tables not found, continuing anyway"

TUN_NAME=$(detect_tun_name)
log "TUN: $TUN_NAME"

dnsproxy_kill_strays
rm -f "$DNSPROXY_PID_FILE"
dnsproxy_port_guard_down

cleanup_all_rules
clear_rules_file
sleep 2

tun_idx=$(read_table_index "$TUN_NAME")
refresh_tether_ifaces
tether_ifaces="$TETHER_NOW"
log "Initial: tun_idx=$tun_idx tether=[$tether_ifaces]"
apply_state "$tun_idx" $tether_ifaces || log "ERROR: Initial apply_state failed"

set +e
monitor_loop