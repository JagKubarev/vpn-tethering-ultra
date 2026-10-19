#!/system/bin/sh

# ============================================================================
# VPN Tether Action Script v2.0
# - Переключение VPN / напрямую с подтверждением от демона (ack, не sleep)
# - Понятный человеку вывод: что сейчас происходит и что будет при нажатии
# - Статус берётся из полей КЛЮЧ=значение, которые пишет service.sh
# ============================================================================

# Определяем путь модуля
for _d in /data/adb/modules/vpn-to-hotspot-usb \
          /data/adb/ksu/modules/vpn-to-hotspot-usb \
          /data/adb/magisk/vpn-to-hotspot-usb; do
    [ -d "$_d" ] && MODULE_DIR="$_d" && break
done
: "${MODULE_DIR:=/data/adb/modules/vpn-to-hotspot-usb}"

FLAG_FILE="$MODULE_DIR/vpn_tether_enabled"
STATUS_FILE="$MODULE_DIR/status"
REQ_FILE="$MODULE_DIR/toggle_req"
ACK_FILE="$MODULE_DIR/toggle_ack"
PID_FILE="/data/local/tmp/vpn_tether.pid"
LOG_FILE="/data/local/tmp/vpn_tether.log"
USER_CONF="/data/adb/vpn_tether.conf"

LINE="━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ----------------------------------------------------------------------------
# Проверка, что демон — наш и живой
# ----------------------------------------------------------------------------
is_our_daemon() {
    local pid="$1"
    kill -0 "$pid" 2>/dev/null || return 1
    local cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
    case "$cmd" in
        *sh*|*magisk*|*ksu*) ;;
        *) return 1 ;;
    esac
    ls -l "/proc/$pid/fd" 2>/dev/null | grep -qE "$LOG_FILE|$STATUS_FILE" && return 0
    [ "$(ls -l "/proc/$pid/cwd" 2>/dev/null | awk '{print $NF}')" = "$MODULE_DIR" ] && return 0
    ls -l "/proc/$pid/fd" 2>/dev/null | grep -q "service.sh" && return 0
    return 1
}

# Значение поля из status (КЛЮЧ=значение)
st() { sed -n "s/^$1=//p" "$STATUS_FILE" 2>/dev/null | head -1; }

# rndis0 wlan2 -> "Wi-Fi, USB"
friendly_ifaces() {
    local out="" i n
    for i in $*; do
        case "$i" in
            wlan*|ap*|swlan*|softap*|hotspot*) n="Wi-Fi" ;;
            rndis*|ncm*|usb*)                 n="USB" ;;
            bt-pan|bnep*)                     n="Bluetooth" ;;
            eth*)                             n="Ethernet" ;;
            *)                                n="$i" ;;
        esac
        case ", $out, " in *", $n, "*) ;; *) out="${out:+$out, }$n" ;; esac
    done
    echo "$out"
}

# ----------------------------------------------------------------------------
# Красивый вывод текущего состояния
# ----------------------------------------------------------------------------
show_status() {
    local mode target ifaces names vpn_up dns degraded phone phone_en dp up ks mtu mss upd
    mode=$(st mode); target=$(st target); ifaces=$(st ifaces); vpn_up=$(st vpn_up)
    dns=$(st dns_state); degraded=$(st dns_degraded); phone=$(st phone_dns)
    phone_en=$(st dns_phone_enabled); dp=$(st dnsproxy_enable); up=$(st dns_upstream)
    ks=$(st kill_switch); mtu=$(st mtu); mss=$(st mss); upd=$(st updated)
    names=$(friendly_ifaces $ifaces)

    if [ -z "$mode" ]; then
        # старый формат status (демон ещё не обновлён) — показываем как есть
        { read -r l1; read -r l2; } < "$STATUS_FILE" 2>/dev/null
        echo "$LINE"; echo "${l1:-❓ Статус неизвестен}"; [ -n "$l2" ] && echo "📡 $l2"; echo "$LINE"
        return
    fi

    echo "$LINE"
    if [ -z "$names" ]; then
        echo "💤  РАЗДАЧА СЕЙЧАС ВЫКЛЮЧЕНА"
        echo "    Включи точку доступа или USB-модем."
        echo "    Режим при включении: $([ "$target" = "vpn" ] && echo "через VPN 🛡" || echo "напрямую 🌍")"
    elif [ "$mode" = "vpn" ]; then
        echo "🛡  РАЗДАЧА ЧЕРЕЗ VPN"
        echo "    Устройства выходят в интернет"
        echo "    только через VPN."
    elif [ "$mode" = "blocked" ]; then
        echo "⛔  VPN НЕ ПОДКЛЮЧЁН"
        echo "    Раздача на паузе, чтобы не"
        echo "    засветить твой настоящий IP."
        echo ""
        echo "👉 Включи VPN-клиент — раздача"
        echo "   заработает сама."
    else
        echo "🌍  РАЗДАЧА НАПРЯМУЮ"
        echo "    Без VPN, через оператора."
    fi
    echo "$LINE"

    [ -n "$names" ] && echo "📡 Раздаю на:  $names"

    # DNS раздачи
    if [ -n "$names" ] && [ "$mode" != "blocked" ]; then
        local dline=""
        if [ "$degraded" = "1" ]; then
            if [ "$mode" = "vpn" ]; then
                dline="⚠️ $up не ответил,
              пока DNS VPN (проверяю снова)"
            else
                dline="⚠️ $up не ответил,
              пока DNS оператора (проверяю снова)"
            fi
        else
            case "$dns" in
                "dnsproxy doh")
                    if [ "$mode" = "vpn" ]; then dline="через VPN, зашифрован 🔒"
                    else dline="$up, зашифрован 🔒"; fi ;;
                "dnsproxy cache") dline="DNS VPN + кэш" ;;
                "DNAT (dnsproxy упал)") dline="⚠️ обычный (dnsproxy не запустился)" ;;
                DNAT*)
                    if [ "$mode" = "vpn" ]; then dline="через VPN (${dns#DNAT })"
                    else dline="обычный (${dns#DNAT })"; fi ;;
            esac
        fi
        [ -n "$dline" ] && echo "🌐 DNS:        $dline"
    fi

    # DNS самого телефона
    if [ "$dp" = "1" ] && [ "$phone_en" = "1" ]; then
        if [ "$vpn_up" = "1" ]; then
            echo "📱 DNS телефона: через VPN"
        elif [ "$phone" = "1" ] && [ "$degraded" = "1" ]; then
            echo "📱 DNS телефона: пока обычный —"
            echo "   $up не ответил, проверяю снова"
        elif [ "$phone" = "1" ]; then
            echo "📱 DNS телефона: $up 🔒"
        fi
    fi

    if [ "$mode" = "vpn" ] && [ "$ks" = "1" ]; then
        echo "🧱 Kill-switch: если VPN упадёт,"
        echo "   раздача встанет, но IP не утечёт."
    fi
    [ "$mode" = "vpn" ] && [ -n "$mtu" ] && [ "${mss:-0}" -gt 0 ] 2>/dev/null && \
        echo "⚙️  MTU $mtu · MSS $mss"

    echo "$LINE"
    if [ "$target" = "vpn" ]; then
        echo "▶ Нажми ещё раз → раздавать напрямую"
    else
        echo "▶ Нажми ещё раз → раздавать через VPN"
    fi
    [ -n "$upd" ] && echo "   (статус на $upd)"
}

# ----------------------------------------------------------------------------
# Демон не запущен
# ----------------------------------------------------------------------------
PID=$(cat "$PID_FILE" 2>/dev/null)

if [ -z "$PID" ] || ! is_our_daemon "$PID"; then
    echo "$LINE"
    echo "❌  МОДУЛЬ НЕ ЗАПУЩЕН"
    echo "$LINE"
    if [ ! -f /data/misc/net/rt_tables ]; then
        echo "⏳ Телефон ещё загружается."
        echo "   Подожди минуту и нажми снова."
    else
        echo "Попробуй перезагрузить телефон."
        echo "Если не поможет — пришли лог:"
        echo "   $LOG_FILE"
    fi
    if [ -f "$LOG_FILE" ]; then
        echo ""
        echo "📋 Последние строки лога:"
        tail -n 5 "$LOG_FILE" 2>/dev/null | while read -r line; do
            echo "   $line"
        done
    fi
    exit 0
fi

# ----------------------------------------------------------------------------
# Защита от двойного нажатия: предыдущий тоггл ещё не подтверждён демоном
# ----------------------------------------------------------------------------
_req=$(cat "$REQ_FILE" 2>/dev/null)
_ack=$(cat "$ACK_FILE" 2>/dev/null)
if [ -n "$_req" ] && [ "$_req" != "$_ack" ]; then
    _age=$(( $(date +%s) - ${_req%%-*} ))
    if [ "$_age" -ge 0 ] 2>/dev/null && [ "$_age" -lt 20 ]; then
        echo "⏳ Предыдущее переключение ещё"
        echo "   применяется (${_age} с). Подожди"
        echo "   пару секунд и нажми снова."
        exit 0
    fi
fi

# ----------------------------------------------------------------------------
# Переключение
# ----------------------------------------------------------------------------
if [ -f "$FLAG_FILE" ]; then
    rm -f "$FLAG_FILE"
    echo "🔄 Переключаю: VPN → напрямую"
else
    touch "$FLAG_FILE"
    echo "🔄 Переключаю: напрямую → VPN"
fi

# Демон пишет в ACK_FILE токен запроса, когда закончил (а не "sleep 3").
TOKEN="$(date +%s)-$$"
echo "$TOKEN" > "$REQ_FILE"
kill -USR1 "$PID" 2>/dev/null

echo -n "⏳ Применяю"
i=0
done_ok=0
while [ $i -lt 40 ]; do
    sleep 0.5
    i=$((i + 1))
    [ $((i % 2)) -eq 0 ] && echo -n "."
    if [ "$(cat "$ACK_FILE" 2>/dev/null)" = "$TOKEN" ]; then
        done_ok=1
        break
    fi
done
if [ "$done_ok" -eq 1 ]; then
    echo " готово ($(( (i + 1) / 2 )) с)"
else
    echo ""
    echo "⚠️ Модуль не ответил за 20 с —"
    echo "   статус ниже может быть старым."
fi
echo ""

show_status
exit 0
