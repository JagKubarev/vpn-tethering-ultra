#!/system/bin/sh
# ============================================================================
# Мост WebUI -> модуль. Страница (webroot/index.html) зовёт только этот
# скрипт и только с фиксированными командами; значения настроек проверяет
# сам service.sh (--check), записываются они как данные, не как код.
#
#   webctl.sh status           статус демона (КЛЮЧ=значение)
#   webctl.sh conf             D КЛЮЧ=умолчание / U КЛЮЧ=из файла
#   webctl.sh set КЛЮЧ ЗНАЧ    записать в vpn_tether.conf (с проверкой)
#   webctl.sh unset КЛЮЧ       вернуть к умолчанию (строка комментируется)
#   webctl.sh apply            демону: перечитать настройки -> токен
#   webctl.sh toggle           VPN <-> напрямую -> токен
#   webctl.sh ack              последний подтверждённый токен
#   webctl.sh log [N]          хвост лога
#   webctl.sh apps             пакеты пользователя (если нет API менеджера)
#   webctl.sh doh              проверка DoH через запущенный dnsproxy
# ============================================================================

MODDIR="${0%/*}"
[ -f "$MODDIR/service.sh" ] || MODDIR=/data/adb/modules/vpn-to-hotspot-usb

CONF="${VPN_TETHER_CONF:-/data/adb/vpn_tether.conf}"   # переменная — только для тестов
STATUS_FILE="$MODDIR/status"
FLAG_FILE="$MODDIR/vpn_tether_enabled"
REQ_FILE="$MODDIR/toggle_req"
ACK_FILE="$MODDIR/toggle_ack"
RELOAD_FILE="$MODDIR/reload_req"
PID_FILE=/data/local/tmp/vpn_tether.pid
LOG_FILE=/data/local/tmp/vpn_tether.log
DNSPROXY_PID_FILE=/data/local/tmp/vpn_tether_dnsproxy.pid
DNSPROXY_PORT=5354
BB=/data/adb/ksu/bin/busybox
[ -x "$BB" ] || BB=/data/adb/magisk/busybox
[ -x "$BB" ] || BB=/data/adb/ap/bin/busybox

daemon_pid() {
    local pid
    pid=$(cat "$PID_FILE" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && echo "$pid"
}

# Токен, по которому страница ждёт подтверждения от демона
signal_daemon() {
    local pid token
    pid=$(daemon_pid)
    [ -n "$pid" ] || { echo "ERR демон не запущен"; return 1; }
    token="$(date +%s)-$$"
    echo "$token" > "$REQ_FILE"
    kill -USR1 "$pid" 2>/dev/null || { echo "ERR сигнал не доставлен"; return 1; }
    echo "OK $token"
}

case "$1" in
    status)
        if [ -n "$(daemon_pid)" ]; then echo "daemon=1"; else echo "daemon=0"; fi
        sed -n 's/^version=/module_version=/p' "$MODDIR/module.prop"
        # строки 1-2 — старый формат, страница читает только КЛЮЧ=значение
        sed '1,2d' "$STATUS_FILE" 2>/dev/null
        ;;

    conf)
        sh "$MODDIR/service.sh" --defaults 2>/dev/null | sed 's/^/D /'
        [ -f "$CONF" ] && tr -d '\r' < "$CONF" | awk '
            { sub(/#.*/, "") }
            /=/ {
                k = $0; sub(/=.*/, "", k); gsub(/[ \t]/, "", k)
                v = $0; sub(/^[^=]*=/, "", v)
                sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
                if (v ~ /^".*"$/ || v ~ /^\x27.*\x27$/) v = substr(v, 2, length(v) - 2)
                if (k != "") print "U " k "=" v
            }'
        ;;

    set)
        key="$2"; val="$3"
        sh "$MODDIR/service.sh" --check "$key" "$val" 2>/dev/null
        case $? in
            0) ;;
            2) echo "ERR неизвестный ключ"; exit 1 ;;
            *) echo "ERR недопустимое значение"; exit 1 ;;
        esac
        [ -f "$CONF" ] || { : > "$CONF"; chmod 600 "$CONF"; }
        # Первая строка с этим ключом (рабочая или закомментированная
        # подсказка) становится КЛЮЧ=значение, остальные рабочие —
        # комментируются. Значение идёт через ENVIRON: awk его не разбирает.
        K="$key" V="$val" awk '
            BEGIN { k = ENVIRON["K"]; v = ENVIRON["V"]; done = 0 }
            {
                line = $0; t = line; sub(/\r$/, "", t)
                s = t; sub(/^[ \t]*/, "", s)
                c = s; sub(/^#[ \t]*/, "", c)
                if (index(c, k "=") == 1 || index(c, k " =") == 1) {
                    if (!done) { print k "=" v; done = 1; next }
                    if (s !~ /^#/) { print "#" t; next }
                }
                print line
            }
            END { if (!done) print k "=" v }' "$CONF" > "$CONF.tmp" && \
            cat "$CONF.tmp" > "$CONF"
        rm -f "$CONF.tmp"
        echo "OK"
        ;;

    unset)
        key="$2"
        case "$key" in ''|*[!A-Z_]*) echo "ERR ключ"; exit 1 ;; esac
        [ -f "$CONF" ] || { echo "OK"; exit 0; }
        K="$key" awk '
            BEGIN { k = ENVIRON["K"] }
            {
                t = $0; sub(/\r$/, "", t); s = t; sub(/^[ \t]*/, "", s)
                if (s !~ /^#/ && (index(s, k "=") == 1 || index(s, k " =") == 1)) { print "#" t; next }
                print
            }' "$CONF" > "$CONF.tmp" && cat "$CONF.tmp" > "$CONF"
        rm -f "$CONF.tmp"
        echo "OK"
        ;;

    apply)
        : > "$RELOAD_FILE"
        signal_daemon || rm -f "$RELOAD_FILE"
        ;;

    toggle)
        [ -n "$(daemon_pid)" ] || { echo "ERR демон не запущен"; exit 1; }
        if [ -f "$FLAG_FILE" ]; then rm -f "$FLAG_FILE"; else touch "$FLAG_FILE"; fi
        signal_daemon
        ;;

    ack)
        cat "$ACK_FILE" 2>/dev/null
        ;;

    log)
        n="${2:-200}"
        case "$n" in ''|*[!0-9]*) n=200 ;; esac
        tail -n "$n" "$LOG_FILE" 2>/dev/null
        ;;

    apps)
        pm list packages -3 2>/dev/null | sed 's/^package://' | sort
        ;;

    doh)
        pid=$(cat "$DNSPROXY_PID_FILE" 2>/dev/null)
        if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
            echo "off"; exit 0
        fi
        [ -x "$BB" ] || { echo "fail нет busybox"; exit 0; }
        # Случайное имя — мимо кэша dnsproxy, как проверка в демоне
        lbl=$(printf 'w%09d' $(( ($(date +%s) % 100000) * 10000 + $$ % 10000 )))
        f="/data/local/tmp/vpn_tether_webprobe.$$"
        : > "$f"
        # nc -w ждёт тишины и после ответа — поэтому nc в фоне, файл опрашиваем
        printf '\022\064\001\000\000\001\000\000\000\000\000\000\012%s\007example\003com\000\000\001\000\001' "$lbl" | \
            "$BB" nc -u -w 5 127.0.0.1 "$DNSPROXY_PORT" > "$f" 2>/dev/null &
        nc_pid=$!
        read -r u0 _ < /proc/uptime
        while :; do
            [ -s "$f" ] && break
            read -r u1 _ < /proc/uptime
            [ "$("$BB" awk -v a="$u0" -v b="$u1" 'BEGIN { print (b - a >= 5) }')" = 1 ] && break
            sleep 0.05
        done
        read -r u1 _ < /proc/uptime
        kill "$nc_pid" 2>/dev/null
        out=$("$BB" od -An -tx1 -N4 "$f" 2>/dev/null)
        rm -f "$f"
        ms=$("$BB" awk -v a="$u0" -v b="$u1" 'BEGIN { printf "%d", (b - a) * 1000 }')
        set -- $out
        if [ "$1$2" != "1234" ]; then
            echo "fail нет ответа за 5 с"
        else
            case $(( 0x${4:-ff} & 15 )) in
                0|3) echo "ok $ms" ;;
                *)   echo "fail ошибка сервера (rcode $(( 0x$4 & 15 )))" ;;
            esac
        fi
        ;;

    *)
        echo "ERR команда"; exit 1 ;;
esac
