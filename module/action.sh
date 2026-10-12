#!/system/bin/sh

# ============================================================================
# VPN Tether Action Script v1.4 (ack от демона вместо sleep 3)
# - Ослаблена проверка cmdline (исправляет ложное "Демон не запущен")
# - Добавлена проверка по открытым файлам (лог и статус)
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

# ----------------------------------------------------------------------------
# Функция проверки демона
# ----------------------------------------------------------------------------
is_our_daemon() {
    local pid="$1"
    
    # 1. Процесс вообще существует?
    kill -0 "$pid" 2>/dev/null || return 1
    
    # 2. Проверяем, что это shell-процесс (sh/dash/bash/magisk/ksu)
    local cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
    case "$cmd" in
        *sh*|*magisk*|*ksu*) ;; 
        *) return 1 ;;
    esac

    # 3. Решающая проверка: открыт ли наш лог-файл или статус-файл?
    if ls -l "/proc/$pid/fd" 2>/dev/null | grep -qE "$LOG_FILE|$STATUS_FILE"; then
        return 0
    fi
    
    # 4. Fallback: проверяем рабочую директорию процесса
    local cwd=$(ls -l "/proc/$pid/cwd" 2>/dev/null | awk '{print $NF}')
    if [ "$cwd" = "$MODULE_DIR" ]; then
        return 0
    fi
    
    # 5. Последний fallback: ищем скрипт в открытых файлах
    if ls -l "/proc/$pid/fd" 2>/dev/null | grep -q "service.sh"; then
        return 0
    fi

    return 1
}

# ----------------------------------------------------------------------------
# Основная логика
# ----------------------------------------------------------------------------
PID=$(cat "$PID_FILE" 2>/dev/null)

if [ -z "$PID" ] || ! is_our_daemon "$PID"; then
    echo "━━━━━━━━━━━━━━━━━━━━"
    echo "❌ Демон не запущен"
    echo "━━━━━━━━━━━━━━━━━━━━"
    
    if [ -f "$LOG_FILE" ]; then
        echo ""
        echo "📋 Последние строки лога:"
        tail -n 5 "$LOG_FILE" 2>/dev/null | while read -r line; do
            echo "   $line"
        done
    fi
    
    # Дополнительная диагностика
    if [ ! -f /data/misc/net/rt_tables ]; then
        echo ""
        echo "⏳ Система ещё загружается (нет rt_tables)"
    fi
    
    if [ -f "$PID_FILE" ] && [ -n "$PID" ]; then
        echo ""
        echo "🔍 PID $PID существует, но это не наш демон"
        echo "   (возможно, старый PID после перезагрузки)"
    fi
    
    echo ""
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
        echo "⏳ Предыдущее переключение ещё применяется (${_age}с), подожди пару секунд"
        exit 0
    fi
fi

# ----------------------------------------------------------------------------
# Переключение флага
# ----------------------------------------------------------------------------
if [ -f "$FLAG_FILE" ]; then
    rm -f "$FLAG_FILE"
    echo "🔄 Переключение в DIRECT режим..."
else
    touch "$FLAG_FILE"
    echo "🔄 Переключение в VPN режим..."
fi

# ----------------------------------------------------------------------------
# Сигнал демону
# ----------------------------------------------------------------------------
# Раньше: sleep 3 и читаем status. Пересборка идёт 2-8с, поэтому часто
# показывался СТАРЫЙ статус, пользователь жал ещё раз — и режим откатывался.
# Теперь демон пишет в ACK_FILE токен запроса, когда закончил.
TOKEN="$(date +%s)-$$"
echo "$TOKEN" > "$REQ_FILE"
kill -USR1 "$PID" 2>/dev/null

echo -n "⏳ Применяем правила"
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
echo ""
[ "$done_ok" -eq 1 ] || echo "⚠️ Демон не подтвердил за 20с — статус ниже может быть устаревшим"

# ----------------------------------------------------------------------------
# Чтение статуса
# ----------------------------------------------------------------------------
{ read -r status_line1; read -r status_line2; } < "$STATUS_FILE" 2>/dev/null

echo ""
echo "━━━━━━━━━━━━━━━━━━━━"
echo "${status_line1:-❓ Статус неизвестен}"
if [ -n "$status_line2" ] && [ "$status_line2" != "no-tether" ]; then
    echo "📱 Интерфейсы: $status_line2"
elif [ "$status_line2" = "no-tether" ]; then
    echo "⚠️ Нет активных интерфейсов раздачи"
fi
echo "━━━━━━━━━━━━━━━━━━━━"

exit 0