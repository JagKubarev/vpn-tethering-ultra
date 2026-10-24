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
#   webctl.sh zauto-info              автосписок с причинами: домен|когда|сбросы/зависания/редиректы|phone/tether
#   webctl.sh zauto-del ДОМЕН         убрать один домен из автосписка
#   webctl.sh logs-send               логи одним файлом в «Загрузки» + окно «Поделиться»
#   webctl.sh sitetest ДОМЕН          открывается ли сайт мимо VPN без/с обходом
#   webctl.sh ytspeed                 скорость "видео YouTube" мимо VPN без/с обходом
#   webctl.sh znet                    текущая сеть + стратегии, запомненные для сетей
#   webctl.sh znet-set СТР 'АРГ' [ЗАМЕТКА] ['АРГ_YT']   запомнить стратегию для текущей сети
#   webctl.sh diag                    диагностика сети: DNS, обрыв 16 КБ, белые списки, Telegram
#   webctl.sh znet-del КЛЮЧ           забыть стратегию сети
#   webctl.sh zevents [N]             журнал сторожа обхода (последние N)
#   webctl.sh zhist                   прежние стратегии текущей сети (для сторожа)
#   webctl.sh metatest                какие адреса Meta отдаёт DNS "как из Европы"
#   webctl.sh zalt                    сайты со своей стратегией в текущей сети: сайт|аргументы|дата
#   webctl.sh zalt-clear              забыть их (и «не открылись ничем»)
#   webctl.sh zscan-start sites ['сайты']  подобрать своё сайтам (без списка — из списков zapret)
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
ZAUTO_LOG=/data/adb/vpn_tether_zapret_auto.log   # причины (nfqws --hostlist-auto-debug)
ZSCAN=/data/local/tmp/vpn_tether_zscan
ZNETS=/data/adb/vpn_tether_zapret_nets
ZHIST=/data/adb/vpn_tether_zapret_hist      # ключ|стратегия|аргументы|дата|заметка|аргументы_YouTube — прежние стратегии сетей
ZEVENTS=/data/adb/vpn_tether_zapret_events  # дата|сеть|событие — журнал сторожа и подбора
ZALT=/data/adb/vpn_tether_zapret_alt        # ключ|название|сайт|аргументы|дата — своя стратегия сайтов
ZSKIP=/data/adb/vpn_tether_zapret_altskip   # ключ|сайт|epoch — не открылись ничем
BB=/data/adb/ksu/bin/busybox
[ -x "$BB" ] || BB=/data/adb/magisk/busybox
[ -x "$BB" ] || BB=/data/adb/ap/bin/busybox

daemon_pid() {
    local pid
    pid=$(cat "$PID_FILE" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && echo "$pid"
}

# Текущая сеть: "<ключ>|<название>" (zapret/netid.sh по WAN из status)
cur_net() {
    local wan
    wan=$(sed -n 's/^wan=//p' "$STATUS_FILE" 2>/dev/null)
    [ -n "$wan" ] || return 0
    sh "$MODDIR/zapret/netid.sh" "$wan" 2>/dev/null | head -1
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
        # без демона: секунды с загрузки — страница отличит «запускается» от «не запущен»
        echo "uptime=$(cut -d. -f1 /proc/uptime)"
        sed -n 's/^version=/module_version=/p' "$MODDIR/module.prop"
        # строки 1-2 — старый формат, страница читает только КЛЮЧ=значение
        sed '1,2d' "$STATUS_FILE" 2>/dev/null
        # счётчики обрыва медленных видео — свежие (статус демон пишет только при событиях)
        if ! grep -q '^yt_slow=off' "$STATUS_FILE" 2>/dev/null && [ -f /data/local/tmp/vpn_tether_ytslow.stat ]; then
            sed -n 's/^state=/yt_slow=/p; s/^kills=/yt_slow_kills=/p; s/^fast=/yt_slow_fast=/p; s/^degr=/yt_slow_degr=/p' /data/local/tmp/vpn_tether_ytslow.stat
        fi
        # итог последней проверки сторожа (пишет zapret/scan.sh check)
        w=$(head -n 1 "$ZSCAN.wd" 2>/dev/null | tr -d '\r')
        [ -n "$w" ] && echo "zwd_last=$w"
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
    logs-send)
        # Один текстовый файл для разбора проблемы: в «Загрузки», затем окно
        # «Поделиться». Файл виден приложениям через MediaStore (scan_file),
        # поэтому его можно отправить в мессенджер. Не вышло — файл всё равно
        # в «Загрузках» (ответ «OK путь nosend»).
        F=/storage/emulated/0/Download/vpn_tether_logs_$(date '+%Y%m%d_%H%M').txt
        {
            echo "=== VPN Tethering Ultra — логи для разбора, $(date '+%d.%m.%Y %H:%M:%S')"
            sed -n 's/^version=/модуль: /p' "$MODDIR/module.prop"
            echo "телефон: $(getprop ro.product.manufacturer) $(getprop ro.product.model), Android $(getprop ro.build.version.release), ядро $(uname -r)"
            echo; echo "=== состояние"; sed '1,2d' "$STATUS_FILE" 2>/dev/null
            echo; echo "=== настройки (vpn_tether.conf, без комментариев)"; grep -v '^[[:space:]]*#' "$CONF" 2>/dev/null | grep .
            echo; echo "=== журнал модуля (последние 3000 строк)"; tail -n 3000 "$LOG_FILE" 2>/dev/null
            echo; echo "=== журнал прошлого запуска (последние 500 строк)"; tail -n 500 "$LOG_FILE.prev" 2>/dev/null
            echo; echo "=== сторож и подбор (последние 100)"; tail -n 100 "$ZEVENTS" 2>/dev/null
            echo; echo "=== стратегии сетей"; cat "$ZNETS" 2>/dev/null
            echo; echo "=== свои стратегии сайтов"; cat "$ZALT" 2>/dev/null
            echo; echo "=== автосписок: домен|когда|сбросы/зависания/редиректы|кто"; sh "$MODDIR/webctl.sh" zauto-info 2>/dev/null
            echo; echo "=== nfqws (последние 50 строк)"; tail -n 50 /data/local/tmp/vpn_tether_nfqws.log 2>/dev/null
            echo; echo "=== opera-proxy (последние 80 строк)"; tail -n 80 /data/local/tmp/vpn_tether_opera.log 2>/dev/null
            echo; echo "=== hev-socks5-tproxy (последние 30 строк)"; tail -n 30 /data/local/tmp/vpn_tether_hev.log 2>/dev/null
            echo; echo "=== ip rule"; ip rule 2>/dev/null
            echo; echo "=== цепочки модуля (filter / nat / mangle)"
            for t in filter nat mangle; do iptables -w 2 -t $t -S 2>/dev/null | grep -E 'VPN_|ZAPRET' | sed "s/^/$t: /"; done
        } > "$F" 2>&1
        [ -s "$F" ] || { echo "ERR не удалось записать файл"; exit 1; }
        chmod 644 "$F" 2>/dev/null
        content call --uri content://media --method scan_file --arg "$F" >/dev/null 2>&1
        id=$(content query --uri content://media/external/file --projection _id --where "_data='$F'" 2>/dev/null | grep -oE '_id=[0-9]+' | head -1 | cut -d= -f2)
        # am — от uid 2000 (shell): разрешение на чтение, выданное от root,
        # система отбрасывает («the system cannot issue a Uri permission grant»),
        # и мессенджер пишет «вложение не поддерживается». Ссылка ещё и в -d:
        # am не переносит EXTRA_STREAM в ClipData, разрешение выдаётся только на
        # данные интента. Флаги одним -f: он заменяет, а не дополняет
        # --grant-read-uri-permission (0x1 = FLAG_GRANT_READ_URI_PERMISSION).
        U="content://media/external/file/$id"
        # подпись к файлу в мессенджере: версия и время сбора логов
        V=$(sed -n 's/^version=//p' "$MODDIR/module.prop"); T=$(date '+%d.%m.%Y %H:%M')
        if [ -n "$id" ] && su 2000 -c "am start -a android.intent.action.SEND -t text/plain -d '$U' \
                --eu android.intent.extra.STREAM '$U' \
                --es android.intent.extra.SUBJECT 'VPN Tethering Ultra $V: логи от $T' \
                -f 0x10000001" >/dev/null 2>&1; then
            echo "OK $F"
        else
            echo "OK $F nosend"
        fi
        ;;
    log-prev)   # лог прошлого запуска демона (до ребута/перезапуска)
        tail -n 400 "$LOG_FILE.prev" 2>/dev/null
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
    zauto-info)
        # строки журнала: "ДД.ММ.ГГГГ ЧЧ:ММ:СС : домен : profile N : client IP:порт : proto P : событие".
        # Сбои считаем с последнего «website is working» до «adding to»; клиент —
        # адрес телефона в сети оператора (в т.ч. через AdGuard) или раздача.
        [ -f "$ZLIST_AUTO" ] || exit 0
        wan=$(sed -n 's/^wan=//p' "$STATUS_FILE" 2>/dev/null)
        wip=$(ip -4 addr show "$wan" 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')
        lg="$ZAUTO_LOG"; [ -f "$lg" ] || lg=/dev/null
        W="$wip" awk -F' : ' '
            FILENAME == ARGV[1] {
                if (NF < 6) next
                h = $2; ev = $6; split($4, c, " "); cl = c[2]; sub(/:[0-9]+$/, "", cl)
                if (ev ~ /^incoming RST/) rst[h]++
                else if (ev ~ /^retrans/) rt[h]++
                else if (ev ~ /^redirect/) rd[h]++
                else if (ev ~ /website is working/) { rst[h] = 0; rt[h] = 0; rd[h] = 0 }
                else if (ev ~ /^adding to/) {
                    when[h] = $1; who[h] = (cl == ENVIRON["W"]) ? "phone" : "tether"
                    n[h] = (rst[h] + 0) "/" (rt[h] + 0) "/" (rd[h] + 0); rst[h] = 0; rt[h] = 0; rd[h] = 0
                }
                next
            }
            { h = $1; sub(/\r$/, "", h); if (h == "" || (h in seen)) next; seen[h] = 1
              if (h in when) print h "|" when[h] "|" n[h] "|" who[h]; else print h "|||" }
        ' "$lg" "$ZLIST_AUTO"
        ;;
    zauto-del)
        d=$(printf '%s' "$2" | tr 'A-Z' 'a-z')
        case "$d" in ''|*[!a-z0-9.-]*|*..*|.*|*.|-*) echo "ERR неверный домен"; exit 1 ;; esac
        [ -f "$ZLIST_AUTO" ] || { echo "OK"; exit 0; }
        # тот же файл (cat, а не mv): nfqws сам перечитает изменившийся список
        grep -vxF "$d" "$ZLIST_AUTO" > "$ZLIST_AUTO.tmp"; cat "$ZLIST_AUTO.tmp" > "$ZLIST_AUTO"; rm -f "$ZLIST_AUTO.tmp"
        echo "OK" ;;
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
        mode="$2"; case "$mode" in quick|full|sites) ;; *) echo "ERR режим"; exit 1 ;; esac
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
        ip -4 addr show "$wan" 2>/dev/null | grep -q "inet " || { echo "ERR у $wan нет адреса — сеть только что сменилась? Повторите через полминуты"; exit 1; }
        case "$(uname -m)" in aarch64|arm64) nq="$MODDIR/bin/nfqws-arm64" ;; *) nq="$MODDIR/bin/nfqws-arm" ;; esac
        [ -x "$nq" ] || { echo "ERR нет nfqws"; exit 1; }
        CA=/apex/com.android.conscrypt/cacerts
        [ -d "$CA" ] || CA=/system/etc/security/cacerts
        Q=202
        RULE_NFQ="-o $wan -m owner --uid-owner 0 ! --gid-owner 3999 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
        st_cleanup() {
            [ -n "$nqpid" ] && kill "$nqpid" 2>/dev/null
            iptables -w 2 -t mangle -D POSTROUTING $RULE_NFQ 2>/dev/null
            iptables -w 2 -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
            iptables -w 2 -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null
        }
        # по сигналу — выход (снимет EXIT): обработчик без exit продолжал
        # проверку, и правила снимались второй раз — чужие (scan.sh) тоже
        trap st_cleanup EXIT
        trap 'exit 1' INT TERM HUP
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
        nk=$(cur_net); nl=${nk#*"|"}; nk=${nk%%"|"*}
        # группа 3998 (ZAPRET_GID): основной zapret пропускает её пакеты, даже
        # если наше uid-0 исключение в VPN_ZAPRET пропадёт при пересборке.
        # full — оба профиля (своя стратегия YouTube для его доменов)
        "$nq" --qnum=$Q --uid=0:3998 --bind-fix4 $(sh "$MODDIR/service.sh" --zapret-strategy "$nk" "$nl" full) >/dev/null 2>&1 &
        nqpid=$!
        sleep 0.7
        if kill -0 "$nqpid" 2>/dev/null; then echo "zapret $(one)"; else echo "zapret 000 0 nfqws"; fi
        ;;

    ytspeed)
        # Скорость видео мимо VPN. ТСПУ режет по имени видеосервера в TLS (SNI),
        # а у настоящих видеосерверов нет большого файла без подписанной ссылки.
        # Поэтому: сервер Google (dl.google.com), имя в SNI — googlevideo.com,
        # файл — по заголовку Host. Так видно и замедление, и помогает ли обход.
        wan=$(sed -n 's/^wan=//p' "$STATUS_FILE" 2>/dev/null)
        [ -n "$wan" ] || { echo "ERR не знаю интерфейс оператора — модуль ещё не видел сеть"; exit 1; }
        ip -4 addr show "$wan" 2>/dev/null | grep -q "inet " || { echo "ERR у $wan нет адреса — сеть только что сменилась? Повторите через полминуты"; exit 1; }
        case "$(uname -m)" in aarch64|arm64) nq="$MODDIR/bin/nfqws-arm64" ;; *) nq="$MODDIR/bin/nfqws-arm" ;; esac
        [ -x "$nq" ] || { echo "ERR нет nfqws"; exit 1; }
        CA=/apex/com.android.conscrypt/cacerts
        [ -d "$CA" ] || CA=/system/etc/security/cacerts
        Q=202
        RULE_NFQ="-o $wan -m owner --uid-owner 0 ! --gid-owner 3999 -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
        yt_cleanup() {
            [ -n "$nqpid" ] && kill "$nqpid" 2>/dev/null
            iptables -w 2 -t mangle -D POSTROUTING $RULE_NFQ 2>/dev/null
            iptables -w 2 -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
            iptables -w 2 -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null
        }
        # по сигналу — выход (снимет EXIT): обработчик без exit продолжал
        # проверку, и правила снимались второй раз — чужие (scan.sh) тоже
        trap yt_cleanup EXIT
        trap 'exit 1' INT TERM HUP
        iptables -w 2 -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
        iptables -w 2 -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null
        ip=$(curl -s -m 6 --capath "$CA" -H 'accept: application/dns-json' \
            "https://1.1.1.1/dns-query?name=dl.google.com&type=A" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | head -1 | grep -oE '[0-9.]+')
        [ -n "$ip" ] || { echo "ERR не удалось узнать адрес сервера Google"; exit 1; }
        H="rr1---sn-gvnuxaxjvh-n8vz.googlevideo.com"
        yt_one() {
            curl -s -k -o /dev/null -m 6 --interface "$wan" --connect-to "$H:443:$ip:443" -H 'Host: dl.google.com' \
                -w '%{http_code} %{speed_download}' "https://$H/linux/direct/google-chrome-stable_current_amd64.deb" 2>/dev/null
            echo " $?"
        }
        echo "ip $ip"
        echo "direct $(yt_one)"
        iptables -w 2 -t mangle -I POSTROUTING 1 $RULE_NFQ
        nk=$(cur_net); nl=${nk#*"|"}; nk=${nk%%"|"*}
        "$nq" --qnum=$Q --uid=0:3998 --bind-fix4 $(sh "$MODDIR/service.sh" --zapret-strategy "$nk" "$nl" yt) >/dev/null 2>&1 &
        nqpid=$!
        sleep 0.7
        if kill -0 "$nqpid" 2>/dev/null; then echo "zapret $(yt_one)"; else echo "zapret 000 0 nfqws"; fi
        ;;

    # --- стратегия для каждой сети ----------------------------------------
    znet)
        d=$(cur_net)
        echo "C ${d%%"|"*}|${d#*"|"}"
        [ -f "$ZNETS" ] && grep '|' "$ZNETS" | sed 's/^/N /'
        ;;
    znet-set)
        st="$2"; a="$3"; yt="$5"
        # WebUI зовёт без 5-го аргумента — своя стратегия YouTube сети
        # остаётся прежней (раньше молча стиралась); подбор передаёт его всегда
        keep_yt=0; [ $# -lt 5 ] && keep_yt=1
        note=$(printf '%s' "$4" | tr -d '\r\n|' | cut -c1-120)
        [ -z "$yt" ] || sh "$MODDIR/service.sh" --check ZAPRET_ARGS "$yt" 2>/dev/null || { echo "ERR недопустимые параметры YouTube"; exit 1; }
        [ "$yt" = "$a" ] && yt=""
        sh "$MODDIR/service.sh" --check ZAPRET_STRATEGY "$st" 2>/dev/null || { echo "ERR стратегия"; exit 1; }
        sh "$MODDIR/service.sh" --check ZAPRET_ARGS "$a" 2>/dev/null || { echo "ERR недопустимые параметры"; exit 1; }
        if [ "$st" = custom ]; then [ -n "$a" ] || { echo "ERR нет параметров"; exit 1; }; else a=""; fi
        d=$(cur_net); k=${d%%"|"*}; l=${d#*"|"}
        [ -n "$k" ] || { echo "ERR не понял, что за сеть (нет Wi-Fi/мобильной сети или модуль её ещё не видел)"; exit 1; }
        if [ "$keep_yt" = 1 ] && [ -f "$ZNETS" ]; then
            yt=$(K="$k" awk -F'|' '$1 == ENVIRON["K"] { y = $7 } END { print y }' "$ZNETS")
            [ "$yt" = "$a" ] && yt=""
        fi
        {
            [ -f "$ZNETS" ] && K="$k" awk -F'|' '$1 != ENVIRON["K"]' "$ZNETS"
            printf '%s|%s|%s|%s|%s|%s|%s\n' "$k" "$st" "$a" "$l" "$note" "$(date '+%Y-%m-%d %H:%M')" "$yt"
        } > "$ZNETS.tmp" && chmod 600 "$ZNETS.tmp" && mv -f "$ZNETS.tmp" "$ZNETS"
        # история сети: сторож при поломке сначала пробует прежние стратегии
        # (та же запись — переносим в конец, держим 8 последних на сеть)
        {
            [ -f "$ZHIST" ] && K="$k" S="$st" A="$a" Y="$yt" awk -F'|' '!($1 == ENVIRON["K"] && $2 == ENVIRON["S"] && $3 == ENVIRON["A"] && $6 == ENVIRON["Y"])' "$ZHIST"
            printf '%s|%s|%s|%s|%s|%s\n' "$k" "$st" "$a" "$(date '+%Y-%m-%d %H:%M')" "$note" "$yt"
        } | K="$k" awk -F'|' '{ l[NR] = $0; key[NR] = $1 } END { for (i = NR; i >= 1; i--) if (key[i] != ENVIRON["K"] || ++n <= 8) keep[i] = 1; for (i = 1; i <= NR; i++) if (keep[i]) print l[i] }' > "$ZHIST.tmp" && \
            chmod 600 "$ZHIST.tmp" && mv -f "$ZHIST.tmp" "$ZHIST"
        echo "OK $l"
        ;;
    zalt)
        # своих записей у сети нет — как у демона, записи сети с тем же названием
        d=$(cur_net); k=${d%%"|"*}; l=${d#*"|"}
        [ -n "$k" ] && [ -f "$ZALT" ] && K="$k" L="$l" awk -F'|' '
            $1 == ENVIRON["K"] { a[++n] = $3 "|" $4 "|" $5 }
            ENVIRON["L"] != "" && $2 == ENVIRON["L"] { b[++m] = $3 "|" $4 "|" $5 }
            END { if (n) { for (i = 1; i <= n; i++) print a[i] } else for (i = 1; i <= m; i++) print b[i] }' "$ZALT"
        ;;
    zalt-clear)
        d=$(cur_net); k=${d%%"|"*}; l=${d#*"|"}
        [ -n "$k" ] || { echo "ERR не понял, что за сеть"; exit 1; }
        for f in "$ZALT" "$ZSKIP"; do
            [ -f "$f" ] || continue
            K="$k" L="$l" F="$f" awk -F'|' '!($1 == ENVIRON["K"] || (ENVIRON["F"] ~ /_alt$/ && ENVIRON["L"] != "" && $2 == ENVIRON["L"]))' "$f" > "$f.tmp" && \
                chmod 600 "$f.tmp" && mv -f "$f.tmp" "$f"
        done
        echo "OK" ;;
    zhist)
        d=$(cur_net); k=${d%%"|"*}
        [ -n "$k" ] && [ -f "$ZHIST" ] && K="$k" awk -F'|' '$1 == ENVIRON["K"]' "$ZHIST"
        ;;
    zevents)
        n="${2:-30}"; case "$n" in ''|*[!0-9]*) n=30 ;; esac
        [ -f "$ZEVENTS" ] && tail -n "$n" "$ZEVENTS"
        ;;
    znet-del)
        [ -n "$2" ] || { echo "ERR ключ"; exit 1; }
        [ -f "$ZNETS" ] || { echo "OK"; exit 0; }
        K="$2" awk -F'|' '$1 != ENVIRON["K"]' "$ZNETS" > "$ZNETS.tmp" && chmod 600 "$ZNETS.tmp" && mv -f "$ZNETS.tmp" "$ZNETS"
        echo "OK"
        ;;

    # --- диагностика сети (идеи dpi-detector из ZDT-D) ----------------------
    # Всё мимо VPN, обхода и AdGuard (группа dnsproxy). Строки:
    #   R <id>|<ok|warn|bad|info>|<что>|<подробно>
    diag)
        wan=$(sed -n 's/^wan=//p' "$STATUS_FILE" 2>/dev/null)
        [ -n "$wan" ] || { echo "ERR не знаю интерфейс оператора — модуль ещё не видел сеть"; exit 1; }
        CA=/apex/com.android.conscrypt/cacerts
        [ -d "$CA" ] || CA=/system/etc/security/cacerts
        G=3999
        dcurl() { su 0 -g $G -c "curl -s --interface $wan --capath $CA $*" 2>/dev/null; }
        doh_a() { dcurl "-m 6 -H 'accept: application/dns-json' 'https://dns.google/resolve?name=$1&type=A'" | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1; }
        plain_a() { su 0 -g $G -c "$BB nslookup $1 $2" 2>/dev/null | awk '/^Name:/ {n = 1} n && /^Address/ {print $NF; exit}' | grep -E '^[0-9.]+$'; }

        # 1. DNS: обычный DNS к 8.8.8.8 (оператор может перехватывать :53).
        # Разные адреса ещё не подмена: CDN (Cloudflare и т.п.) раздаёт разные
        # узлы. Заглушка — частный/служебный адрес или один и тот же адрес у
        # разных заблокированных сайтов (21.10: rutracker 172.67.x против 104.21.x
        # — оба Cloudflare, ложная тревога).
        n=0; bog=""; seen=""; stub=""
        for h in rutracker.org x.com www.linkedin.com www.facebook.com; do
            p=$(plain_a "$h" 8.8.8.8)
            [ -n "$p" ] || continue
            n=$((n + 1))
            case "$p" in 10.*|127.*|0.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|169.254.*) bog="$bog $h:$p" ;; esac
            case " $seen " in *" $p "*) stub="$p" ;; esac
            seen="$seen $p"
        done
        if [ "$n" = 0 ]; then echo "R dns|info|Подмена DNS|не проверить: обычный DNS не ответил"
        elif [ -n "$bog" ]; then echo "R dns|warn|Подмена DNS|да: обычный DNS отдаёт служебные адреса ($bog) — без DoH заблокированные сайты не откроются"
        elif [ -n "$stub" ]; then echo "R dns|warn|Подмена DNS|да: разные заблокированные сайты получают один адрес $stub (заглушка) — без DoH они не откроются"
        else echo "R dns|ok|Подмена DNS|нет: обычный DNS отдаёт настоящие адреса ($n из $n)"; fi

        # 2. Обрыв на ~16 КБ: качаем 128 КБ с зарубежных хостингов
        cut=0; okn=0; det=""
        for t in "Cloudflare|https://speed.cloudflare.com/__down?bytes=131072" \
                 "Hetzner|https://fsn1-speed.hetzner.com/100MB.bin" \
                 "OVH|https://proof.ovh.net/files/1Mb.dat" \
                 "Linode|https://speedtest.frankfurt.linode.com/100MB-frankfurt.bin" \
                 "Vultr|https://fra-de-ping.vultr.com/vultr.com.100MB.bin"; do
            n="${t%%"|"*}"; u="${t#*"|"}"
            r=$(dcurl "-4 -o /dev/null -m 8 -r 0-131071 -w '%{http_code} %{size_download}' '$u'")
            set -- $r; sz="${2:-0}"
            if [ "$sz" -ge 120000 ] 2>/dev/null; then okn=$((okn + 1))
            elif [ "$sz" -ge 8000 ] 2>/dev/null && [ "$sz" -le 70000 ]; then cut=$((cut + 1)); det="$det $n:$((sz / 1024))КБ"
            else det="$det $n: нет соединения"; fi
        done
        if [ "$cut" -gt 0 ]; then echo "R tcp16|bad|Обрыв на 16–64 КБ|у зарубежных хостингов соединение глохнет после первых килобайт:$det — режут по объёму; поможет только VPN"
        elif [ "$okn" -gt 0 ]; then echo "R tcp16|ok|Обрыв на 16–64 КБ|нет: 128 КБ скачались ($okn из 5)${det:+;$det}"
        else echo "R tcp16|warn|Обрыв на 16–64 КБ|не проверить: хостинги не ответили$det"; fi

        # 3. Белые списки: открываются ли обычные зарубежные сайты и зависит ли
        # это от имени сервера (SNI) на одном и том же адресе
        fo=0; fn=0; ru=0
        for h in example.com en.wikipedia.org github.com www.cloudflare.com; do
            c=$(dcurl "-o /dev/null -m 6 -w '%{http_code}' https://$h/"); fn=$((fn + 1))
            [ -n "$c" ] && [ "$c" != 000 ] && fo=$((fo + 1))
        done
        for h in ya.ru vk.com; do
            c=$(dcurl "-o /dev/null -m 6 -w '%{http_code}' https://$h/"); [ -n "$c" ] && [ "$c" != 000 ] && ru=$((ru + 1))
        done
        ip=$(doh_a www.cloudflare.com)
        s_ru=""; s_xx=""
        if [ -n "$ip" ]; then
            s_ru=$(dcurl "-k -o /dev/null -m 6 --connect-to ya.ru:443:$ip:443 -w '%{time_appconnect}' https://ya.ru/")
            s_xx=$(dcurl "-k -o /dev/null -m 6 --connect-to example.org:443:$ip:443 -w '%{time_appconnect}' https://example.org/")
        fi
        tls_ok() { awk -v t="${1:-0}" 'BEGIN { exit !(t > 0) }'; }
        if [ "$ru" -gt 0 ] && [ "$fo" = 0 ]; then
            if tls_ok "$s_ru" && ! tls_ok "$s_xx"; then echo "R wl|bad|Белые списки|похоже, да: зарубежные сайты не открываются, а на тот же адрес с именем ya.ru рукопожатие проходит — пропускают по SNI"
            else echo "R wl|bad|Белые списки|похоже, да: открываются только российские сайты (зарубежных 0 из $fn)"; fi
        elif [ "$fo" -lt "$fn" ]; then echo "R wl|warn|Белые списки|нет, но открылись не все зарубежные сайты ($fo из $fn)"
        else echo "R wl|ok|Белые списки|нет: зарубежные сайты открываются ($fo из $fn)"; fi

        # 4. Telegram: серверы (по IP) и веб-версия
        tc=0
        for i in 149.154.175.50 149.154.167.51 149.154.175.100 149.154.167.91 91.108.56.130; do
            c=$(dcurl "-o /dev/null -m 4 -w '%{time_connect}' http://$i:443/")
            awk -v t="${c:-0}" 'BEGIN { exit !(t > 0) }' && tc=$((tc + 1))
        done
        w=$(dcurl "-o /dev/null -m 6 -w '%{http_code}' https://web.telegram.org/a/")
        if [ "$tc" = 0 ] && { [ -z "$w" ] || [ "$w" = 000 ]; }; then echo "R tg|bad|Telegram|закрыт по IP: серверы (0 из 5) и веб-версия недоступны — только через VPN"
        elif [ "$tc" -lt 5 ]; then echo "R tg|warn|Telegram|частично: серверов доступно $tc из 5, веб-версия: $([ -n "$w" ] && [ "$w" != 000 ] && echo открывается || echo нет)"
        else echo "R tg|ok|Telegram|серверы доступны (5 из 5)"; fi
        ;;

    # --- DNS Meta "как из Европы" --------------------------------------------
    metatest)
        # Как спрашивает dnsproxy для Meta: DNS_META_UPSTREAMS (Google) с ECS.
        # Через JSON API того же Google — тот же ответ, но без разбора DNS-пакетов.
        # Сравниваем с ответом без ECS (как для России).
        ecs=$(sh "$MODDIR/service.sh" --get DNS_META_ECS 2>/dev/null)
        [ -n "$ecs" ] || { echo "ERR нет DNS_META_ECS"; exit 1; }
        CA=/apex/com.android.conscrypt/cacerts
        [ -d "$CA" ] || CA=/system/etc/security/cacerts
        # мимо AdGuard: его прокси подменяет сертификаты (как в sitetest)
        iptables -w 2 -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
        trap 'iptables -w 2 -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null' EXIT
        trap 'exit 1' INT TERM HUP
        a1() {
            curl -s -m 6 --capath "$CA" "https://dns.google/resolve?name=$1&type=A$2" 2>/dev/null | \
                grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1
        }
        echo "ecs $ecs"
        for n in www.instagram.com scontent.cdninstagram.com www.facebook.com static.xx.fbcdn.net; do
            eu=$(a1 "$n" "&edns_client_subnet=$ecs/24")
            ru=$(a1 "$n" "")
            echo "host $n ${eu:--} ${ru:--}"
        done
        ;;

    *)
        echo "ERR команда"; exit 1 ;;
esac
