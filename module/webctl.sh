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
#   webctl.sh zlist|zdefault|zauto    списки zapret: свой / встроенный / авто
#   webctl.sh zlist-set 'д1 д2'       записать свой список (с проверкой)
#   webctl.sh zauto-clear             очистить автосписок
#   webctl.sh sitetest ДОМЕН          открывается ли сайт мимо VPN без/с обходом
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
ZLIST_USER=/data/adb/vpn_tether_zapret.txt
ZLIST_AUTO=/data/adb/vpn_tether_zapret_auto.txt
ZSCAN=/data/local/tmp/vpn_tether_zscan
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

    # --- zapret ------------------------------------------------------------
    zlist)      cat "$ZLIST_USER" 2>/dev/null ;;
    zdefault)   cat "$MODDIR/zapret/list-default.txt" 2>/dev/null ;;
    zauto)      cat "$ZLIST_AUTO" 2>/dev/null ;;
    zauto-clear)
        [ -f "$ZLIST_AUTO" ] && : > "$ZLIST_AUTO"
        echo "OK" ;;
    zlist-set)
        # $2 — домены через пробел/перевод строки. Каждый проверяем.
        out=""
        for d in $(printf '%s' "$2" | tr 'A-Z' 'a-z' | tr ',;' '  '); do
            d=${d#http://}; d=${d#https://}; d=${d%%/*}; d=${d#.}
            case "$d" in
                ''|*[!a-z0-9.-]*|*..*|.*|*.|-*) echo "ERR неверный домен: $d"; exit 1 ;;
                *.*) ;;
                *) echo "ERR неверный домен: $d"; exit 1 ;;
            esac
            case " $out " in *" $d "*) ;; *) out="$out $d" ;; esac
        done
        printf '%s\n' $out > "$ZLIST_USER.tmp" && mv -f "$ZLIST_USER.tmp" "$ZLIST_USER"
        chmod 600 "$ZLIST_USER"
        echo "OK $(echo $out | wc -w)" ;;

    # --- подбор стратегии (zapret/scan.sh в фоне) ----------------------------
    zscan-start)
        mode="$2"; case "$mode" in quick|full) ;; *) echo "ERR режим"; exit 1 ;; esac
        sites=""
        for d in $(printf '%s' "$3" | tr 'A-Z' 'a-z' | tr ',;' '  '); do
            d=${d#http://}; d=${d#https://}; d=${d%%/*}
            case "$d" in ''|*[!a-z0-9.-]*|*..*|.*|*.|-*) echo "ERR неверный адрес: $d"; exit 1 ;; *.*) ;; *) echo "ERR неверный адрес: $d"; exit 1 ;; esac
            sites="$sites $d"
        done
        pid=$(cat "$ZSCAN.pid" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then echo "ERR подбор уже идёт"; exit 1; fi
        rm -f "$ZSCAN.status" "$ZSCAN.results"
        # отдельная сессия: страница может закрыться, подбор продолжится
        setsid sh "$MODDIR/zapret/scan.sh" "$mode" "${sites# }" </dev/null >/dev/null 2>&1 &
        # ждём, пока сканер реально стартует (pid + статус), иначе первый
        # опрос страницы видел "не запущен" и переставал обновляться
        i=0
        while [ $i -lt 30 ] && ! { [ -s "$ZSCAN.pid" ] && [ -s "$ZSCAN.status" ]; }; do sleep 0.1; i=$((i + 1)); done
        echo "OK" ;;
    zscan-stop)
        pid=$(cat "$ZSCAN.pid" 2>/dev/null)
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
        echo "OK" ;;
    zscan-status)
        cat "$ZSCAN.status" 2>/dev/null
        pid=$(cat "$ZSCAN.pid" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then echo "alive=1"; else echo "alive=0"; fi ;;
    zscan-results)
        cat "$ZSCAN.results" 2>/dev/null ;;

    sitetest)
        # Открывается ли сайт мимо VPN: без обхода и с текущей стратегией.
        h=$(printf '%s' "$2" | tr 'A-Z' 'a-z')
        h=${h#http://}; h=${h#https://}; h=${h%%/*}
        case "$h" in ''|*[!a-z0-9.-]*|*..*|.*) echo "ERR адрес"; exit 1 ;; esac
        wan=$(sed -n 's/^wan=//p' "$STATUS_FILE" 2>/dev/null)
        [ -n "$wan" ] || { echo "ERR не знаю интерфейс оператора — модуль ещё не видел сеть"; exit 1; }
        ip -4 addr show "$wan" 2>/dev/null | grep -q "inet " || { echo "ERR у $wan нет адреса — сеть только что сменилась? Повтори через полминуты"; exit 1; }
        case "$(uname -m)" in aarch64|arm64) nq="$MODDIR/bin/nfqws-arm64" ;; *) nq="$MODDIR/bin/nfqws-arm" ;; esac
        [ -x "$nq" ] || { echo "ERR нет nfqws"; exit 1; }
        CA=/apex/com.android.conscrypt/cacerts
        [ -d "$CA" ] || CA=/system/etc/security/cacerts
        Q=202
        RULE_NFQ="-o $wan -m owner --uid-owner 0 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
        st_cleanup() {
            [ -n "$nqpid" ] && kill "$nqpid" 2>/dev/null
            iptables -w 2 -t mangle -D POSTROUTING $RULE_NFQ 2>/dev/null
            iptables -w 2 -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
            iptables -w 2 -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null
        }
        trap st_cleanup EXIT INT TERM
        # мимо AdGuard (его прокси подменяет сертификаты) и мимо основного zapret
        iptables -w 2 -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
        iptables -w 2 -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null
        # адрес — через DoH (обычный DNS мимо VPN оператор может подменить)
        ip=$(curl -s -m 6 --capath "$CA" -H 'accept: application/dns-json' \
            "https://1.1.1.1/dns-query?name=$h&type=A" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | head -1 | grep -oE '[0-9.]+')
        [ -n "$ip" ] || ip=$("$BB" nslookup "$h" 1.1.1.1 2>/dev/null | sed -n '/^Name/,$p' | grep -oE 'Address 1: [0-9.]+' | awk '{print $3}')
        [ -n "$ip" ] || { echo "ERR не удалось узнать адрес $h"; exit 1; }
        one() {
            curl -s -o /dev/null -m 8 --interface "$wan" --capath "$CA" --resolve "$h:443:$ip" \
                -w '%{http_code} %{time_total}' "https://$h/" 2>/dev/null
            echo " $?"
        }
        echo "ip $ip"
        echo "direct $(one)"
        iptables -w 2 -t mangle -I POSTROUTING 1 $RULE_NFQ
        "$nq" --qnum=$Q --uid=0:0 --bind-fix4 $(sh "$MODDIR/service.sh" --zapret-strategy) >/dev/null 2>&1 &
        nqpid=$!
        sleep 0.7
        if kill -0 "$nqpid" 2>/dev/null; then echo "zapret $(one)"; else echo "zapret 000 0 nfqws"; fi
        ;;

    *)
        echo "ERR команда"; exit 1 ;;
esac
