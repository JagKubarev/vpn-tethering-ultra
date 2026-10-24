# shellcheck shell=sh
# lib/opera.sh — Telegram через прокси Opera (OPERA_TG): opera-proxy и
# hev-socks5-tproxy, прозрачное перенаправление TCP к подсетям Telegram.
# Часть демона service.sh: подключается из него через ".", сам не запускается.
# Настройки (USER CONFIG) и общие переменные — в service.sh.

# ============================================================================
# YOTA и другие закрывают Telegram по IP — обход DPI тут не помогает. Пока
# VPN не поднят, TCP к подсетям Telegram (zapret/list-telegram-cidr.txt) с
# телефона и с раздачи (только режим «напрямую») уходит в бесплатный прокси
# Opera. Остальной трафик — как был.
#  - opera-proxy (root:OPERA_GID) регистрируется в API Opera через бесплатные
#    прокси из OPERA_API_LIST (из РФ API напрямую закрыт) и слушает SOCKS5 на
#    127.0.0.1:OPERA_PORT. Старт 7-8с, иногда до 2 мин — идёт в фоне.
#  - hev-socks5-tproxy принимает перехваченные соединения (127.0.0.1:
#    OPERA_TP_PORT) и отдаёт их в SOCKS5. Адрес назначения он берёт из самого
#    сокета (getsockname), SO_ORIGINAL_DST не умеет — поэтому TPROXY, а не
#    nat REDIRECT (после REDIRECT назначение = 127.0.0.1).
#  - mangle PREROUTING -> VPN_OPERA_IN: TCP с раздачи и вернувшиеся через lo
#    пакеты телефона -> VPN_OPERA_TP (подсети Telegram -> TPROXY).
#  - mangle OUTPUT -> VPN_OPERA_OUT: TCP приложений телефона к подсетям
#    Telegram получает бит OPERA_MARK; ip rule pref OPERA_PREF уводит его в
#    таблицу OPERA_TABLE (local default dev lo) — пакет возвращается через lo
#    в PREROUTING и попадает в TPROXY. Своя группа opera-proxy, nfqws,
#    dnsproxy и VPN-клиенты не помечаются.
#  - TPROXY без слушателя ДРОПАЕТ пакеты: умер hev или opera-proxy — правила
#    снимаются сразу (прямой таймаут лучше чёрной дыры), перезапуск с паузой.
#  - Только TCP: звонки (UDP) не пойдут. Только IPv4.
#  - VPN поднят — правила снимаются (Telegram и так через VPN), а процессы
#    остаются: повторная регистрация бывает долгой.
# ============================================================================
OPERA_PORT=18080            # SOCKS5 opera-proxy
OPERA_TP_PORT=18088         # hev-socks5-tproxy
OPERA_MARK=0x20000000       # бит метки (zapret — 0x40000000, YouTube — 0x10000000, scan.sh — 0x08000000)
OPERA_TABLE=3997
OPERA_PREF=2990             # раньше правил раздачи (3000) и всех правил netd
OPERA_CIDR_FILE="$ZAPRET_DIR/list-telegram-cidr.txt"
OPERA_LOG="/data/local/tmp/vpn_tether_opera.log"
OPERA_HEV_LOG="/data/local/tmp/vpn_tether_hev.log"
OPERA_HEV_CONF="/data/local/tmp/vpn_tether_hev.yml"
OPERA_CA="/data/local/tmp/vpn_tether_opera_ca.pem"
OPERA_API_CACHE="/data/adb/vpn_tether_opera_api"           # удачные прокси API, новые сверху (переживает перезагрузку)
OPERA_API_FILE="/data/local/tmp/vpn_tether_opera_api.txt"  # -api-proxy-file: кэш + запасной список
OPERA_API_SPARE="/data/local/tmp/vpn_tether_opera_spare.txt"
# Запасной список: строки "ip:port" (SOCKS5). opera-proxy такие строки считает
# HTTP-прокси, поэтому качаем сами и дописываем socks5://
OPERA_API_SPARE_URL="https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"
CHAIN_OPERA_IN="VPN_OPERA_IN"     # mangle PREROUTING
CHAIN_OPERA_OUT="VPN_OPERA_OUT"   # mangle OUTPUT
CHAIN_OPERA_TP="VPN_OPERA_TP"     # подсети Telegram -> TPROXY
OPERA_STATE="off"       # off | starting | on | fail
OPERA_ENDPOINT=""       # сервер Opera, выбранный opera-proxy
OPERA_ERR=""            # почему fail (для WebUI)
OPERA_SCOPE=""          # для кого стоят правила: "" | phone | "phone tether"
OPERA_RULES_SIG=""      # что стоит: "телефон|интерфейсы|исключения", "" = правил нет
OPERA_EXCL=""           # uid VPN-клиентов (как у zapret)
OPERA_RETRY=0           # пропустить N итераций до повтора
OPERA_FAILS=0           # неудачных стартов подряд
OPERA_START_TS=0
OPERA_TICK=0
OPERA_SU_G=""           # "" = не проверяли, 1 = su -g работает, 0 = нет
OPERA_CA_INFO=""
OPERA_NOSUPPORT=0       # 1 = ядро без TPROXY/бинарей нет — не пытаться до перечитывания настроек
OPERA_WAN=""            # WAN, на котором последний раз проверяли сервер Opera
OPERA_PROBE_DC="149.154.167.51:443"   # DC2 Telegram: проверка «через Opera доходит»

opera_cidrs() {
    sed 's/#.*//' "$OPERA_CIDR_FILE" 2>/dev/null | tr -d ' \t\r' | \
        grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$'
}

# PID-ы процессов, чей argv[0] начинается с $1, а в аргументах есть $2
# (обёртки su/sh не в счёт: у них argv[0] — su/sh)
_opera_pids() {
    local f
    for f in $(grep -l "$1" /proc/[0-9]*/cmdline 2>/dev/null); do
        case "$(tr '\0' ' ' 2>/dev/null < "$f")" in
            "$1"*"$2"*) f="${f#/proc/}"; echo "${f%/cmdline}" ;;
        esac
    done
}
opera_proxy_pids() { _opera_pids "$MODULE_DIR/bin/opera-proxy" "-bind-address 127.0.0.1:$OPERA_PORT "; }
opera_hev_pids()   { _opera_pids "$MODULE_DIR/bin/hev-socks5-tproxy" "$OPERA_HEV_CONF"; }
# hev слушает AF_INET6-сокетом: в ss он «[::ffff:127.0.0.1]:порт»
_opera_listening() { ss -ltn 2>/dev/null | grep -qE "(127\.0\.0\.1|\[::ffff:127\.0\.0\.1\]):$1[[:space:]]"; }

_opera_kill() {
    local p
    for p in "$@"; do kill "$p" 2>/dev/null; done
    [ -n "$*" ] || return 0
    sleep 0.3
    for p in "$@"; do kill -9 "$p" 2>/dev/null; done
}

# Go на Android не видит системные сертификаты: собираем PEM сами.
# Пользовательские (cacerts-added) — в DER, переводим в PEM: без них не
# работает у тех, у кого HTTPS-фильтр AdGuard («AdGuard Personal CA»).
opera_ca_build() {
    local d f n=0 u=0 b64=""
    command -v base64 >/dev/null 2>&1 && b64="base64"
    [ -z "$b64" ] && [ -n "$BUSYBOX" ] && b64="$BUSYBOX base64"
    : > "$OPERA_CA.tmp" 2>/dev/null || return 1
    for d in /apex/com.android.conscrypt/cacerts /system/etc/security/cacerts; do
        for f in "$d"/*.0; do
            [ -f "$f" ] || continue
            sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$f" >> "$OPERA_CA.tmp" && n=$((n + 1))
        done
        [ "$n" -gt 0 ] && break
    done
    for f in /data/misc/user/0/cacerts-added/*; do
        [ -f "$f" ] || continue
        if grep -q 'BEGIN CERTIFICATE' "$f" 2>/dev/null; then
            sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$f" >> "$OPERA_CA.tmp"
        elif [ -n "$b64" ]; then
            { echo "-----BEGIN CERTIFICATE-----"; $b64 < "$f"; echo "-----END CERTIFICATE-----"; } >> "$OPERA_CA.tmp"
        else
            continue
        fi
        u=$((u + 1))
    done
    mv -f "$OPERA_CA.tmp" "$OPERA_CA"
    OPERA_CA_INFO="$n системных, $u пользовательских"
    [ "$n" -gt 0 ]
}

# Исключение opera-proxy из перехвата AdGuard (как у dnsproxy): RETURN по
# группе в начале nat OUTPUT. Не строго первым: первое место держит
# dnsproxy_exempt, а AdGuard свой переход вставляет в позицию 1.
opera_exempt() {
    [ "$OPERA_SU_G" = "1" ] || return 0
    local want="-A OUTPUT -m owner --gid-owner $OPERA_GID -j RETURN"
    $iptables -t nat -S OUTPUT 2>/dev/null | sed -n '2,3p' | grep -qxF -- "$want" && return 0
    opera_exempt_down
    $iptables -t nat -I OUTPUT 1 -m owner --gid-owner "$OPERA_GID" -j RETURN 2>/dev/null
}
opera_exempt_down() {
    local _n=0
    [ -n "$OPERA_GID" ] || return 0
    while [ $_n -lt 8 ] && $iptables -t nat -D OUTPUT -m owner --gid-owner "$OPERA_GID" -j RETURN 2>/dev/null; do _n=$((_n + 1)); done
}

# Список кандидатов для -api-proxy-file: удачные раньше + запасной список
opera_api_file() {
    : > "$OPERA_API_FILE"
    [ -s "$OPERA_API_CACHE" ] && grep '://' "$OPERA_API_CACHE" >> "$OPERA_API_FILE"
    [ -s "$OPERA_API_SPARE" ] && cat "$OPERA_API_SPARE" >> "$OPERA_API_FILE"
    [ -s "$OPERA_API_FILE" ]
}

# Запасной список — в фоне (curl до 30с не держит цикл); пригодится на следующей попытке
opera_spare_fetch() {
    command -v curl >/dev/null 2>&1 || return 0
    setsid sh -c 'curl -s -m 30 --capath /apex/com.android.conscrypt/cacerts -o "$1.dl" "$2" || curl -s -m 30 -o "$1.dl" "$2"
        grep -E "^[0-9.]+:[0-9]+\$" "$1.dl" | head -n 3000 | sed "s#^#socks5://#" > "$1.new" && [ -s "$1.new" ] && mv -f "$1.new" "$1"
        rm -f "$1.dl" "$1.new"' opera "$OPERA_API_SPARE" "$OPERA_API_SPARE_URL" </dev/null >/dev/null 2>&1 &
}

opera_start() {
    local args via="" cand
    _opera_kill $(opera_proxy_pids)
    if [ -z "$OPERA_SU_G" ]; then
        OPERA_SU_G=0
        [ "$DNSPROXY_SU_G" != "0" ] && [ -n "$OPERA_GID" ] && su -g "$OPERA_GID" -c true >/dev/null 2>&1 && OPERA_SU_G=1
        [ "$OPERA_SU_G" = "1" ] || log "WARNING: opera: su -g не работает — opera-proxy без своей группы (исключение из перенаправления — по uid 0, nfqws и AdGuard его не пропустят)"
    fi
    # регистрация в API — уже мимо AdGuard
    opera_exempt
    opera_ca_build || log "WARNING: opera: системные сертификаты не найдены — opera-proxy может не проверить TLS"
    # -server-selection first: «fastest» меряет скачивание с ajax.googleapis.com
    # через каждый сервер, а Google через Opera с YOTA почти не качается —
    # opera-proxy молча завершался через ~17с (24.10, 4 из 4 запусков)
    args="-bind-address 127.0.0.1:$OPERA_PORT -socks-mode -country $OPERA_COUNTRY -server-selection first -verbosity 20 -cafile $OPERA_CA"
    args="$args -bootstrap-dns https://dns.comss.one/dns-query,https://dns.adguard-dns.com/dns-query,tls://9.9.9.9:853,https://1.1.1.3/dns-query"
    # Чётная попытка — список по ссылке (не скачался — файл); нечётная (после
    # сбоя) — только файл: удачные раньше + запасной список.
    if [ -n "$OPERA_API_LIST" ] && [ $((OPERA_FAILS % 2)) -eq 0 ]; then
        args="$args -api-proxy-list-url '$OPERA_API_LIST'"
        via="список по ссылке"
        opera_api_file && { args="$args -api-proxy-file $OPERA_API_FILE"; via="$via, запасной — файл"; }
    elif opera_api_file; then
        args="$args -api-proxy-file $OPERA_API_FILE"
        via="файл ($(wc -l < "$OPERA_API_FILE" | tr -d ' ') прокси)"
    elif [ -n "$OPERA_API_LIST" ]; then
        args="$args -api-proxy-list-url '$OPERA_API_LIST'"
        via="список по ссылке"
    else
        via="без прокси (API напрямую)"
    fi
    # последний удачный кандидат — первым
    cand=$(head -n 1 "$OPERA_API_CACHE" 2>/dev/null | grep -E "^[a-z0-9]+://[^' ]+$")
    [ -n "$cand" ] && [ "$via" != "без прокси (API напрямую)" ] && { args="$args -api-proxy '$cand'"; via="$via, первым — $cand"; }
    : > "$OPERA_LOG"
    # setsid: с nohup opera-proxy умирал вместе с сессией
    if [ "$OPERA_SU_G" = "1" ]; then
        setsid su -g "$OPERA_GID" -c "exec $OPERA_BIN $args" </dev/null >> "$OPERA_LOG" 2>&1 &
    else
        eval "setsid \"\$OPERA_BIN\" $args" </dev/null >> "$OPERA_LOG" 2>&1 &
    fi
    OPERA_START_TS=$(date +%s)
    OPERA_STATE="starting"
    OPERA_ENDPOINT=""
    OPERA_ERR=""
    log "opera: запускаю opera-proxy (регион $OPERA_COUNTRY, gid $([ "$OPERA_SU_G" = 1 ] && echo "$OPERA_GID" || echo 0), прокси API: $via; CA: $OPERA_CA_INFO)"
    phone_status_refresh
}

# opera-proxy слушает — запомнить удачный прокси API и сервер
opera_started() {
    local c ep secs
    secs=$(( $(date +%s) - OPERA_START_TS ))
    c=$(sed -n 's/.*Using API proxy candidate: \([^ ]*\).*/\1/p' "$OPERA_LOG" 2>/dev/null | tail -n 1)
    if [ -n "$c" ]; then
        { echo "$c"; grep -vxF -- "$c" "$OPERA_API_CACHE" 2>/dev/null; } | head -n 20 > "$OPERA_API_CACHE.tmp" && \
            mv -f "$OPERA_API_CACHE.tmp" "$OPERA_API_CACHE"
        chmod 600 "$OPERA_API_CACHE" 2>/dev/null
    fi
    ep=$(sed -n 's/.*Selected endpoint address: \([^ ]*\).*/\1/p; s/.*Endpoint override: \([^ ]*\).*/\1/p' "$OPERA_LOG" 2>/dev/null | tail -n 1)
    OPERA_ENDPOINT="$ep"
    OPERA_WAN="$LAST_WAN_IFACE"
    OPERA_FAILS=0
    log "opera: opera-proxy готов за ${secs}с (pid $(opera_proxy_pids | head -n 1), сервер ${ep:-?}${c:+, прокси API $c})"
}

opera_hev_start() {
    local i
    _opera_kill $(opera_hev_pids)
    cat > "$OPERA_HEV_CONF" <<EOF
main:
  workers: 1
socks5:
  port: $OPERA_PORT
  address: 127.0.0.1
  udp: 'tcp'
tcp:
  port: $OPERA_TP_PORT
  address: 127.0.0.1
misc:
  log-file: $OPERA_HEV_LOG
  log-level: warn
  limit-nofile: 8192
EOF
    : > "$OPERA_HEV_LOG"
    # журнал hev пишет сам (log-file); сюда — только ошибки до чтения конфига
    setsid "$OPERA_HEV_BIN" "$OPERA_HEV_CONF" </dev/null >/dev/null 2>> "$OPERA_HEV_LOG" &
    i=0
    while [ $i -lt 10 ]; do
        sleep 0.2
        [ -n "$(opera_hev_pids)" ] && _opera_listening "$OPERA_TP_PORT" && return 0
        i=$((i + 1))
    done
    return 1
}

opera_rules_off() {
    local _n
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null; do _n=$((_n + 1)); done
    $iptables -t mangle -F "$CHAIN_OPERA_IN" 2>/dev/null;  $iptables -t mangle -X "$CHAIN_OPERA_IN" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_OUT" 2>/dev/null; $iptables -t mangle -X "$CHAIN_OPERA_OUT" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_TP" 2>/dev/null;  $iptables -t mangle -X "$CHAIN_OPERA_TP" 2>/dev/null
    _n=0; while [ $_n -lt 8 ] && $ip rule del fwmark "$OPERA_MARK/$OPERA_MARK" lookup "$OPERA_TABLE" pref "$OPERA_PREF" 2>/dev/null; do _n=$((_n + 1)); done
    $ip route flush table "$OPERA_TABLE" 2>/dev/null
    OPERA_RULES_SIG=""
    OPERA_SCOPE=""
}

# opera_rules_on <1|0 — телефон> [интерфейсы раздачи...]
opera_rules_on() {
    local phone="$1" c u i cidrs; shift
    cidrs=$(opera_cidrs)
    [ -n "$cidrs" ] || { OPERA_ERR="пустой список подсетей Telegram"; return 1; }
    $iptables -t mangle -N "$CHAIN_OPERA_TP" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_TP" 2>/dev/null
    for c in $cidrs; do
        $iptables -t mangle -A "$CHAIN_OPERA_TP" -p tcp -d "$c" -j TPROXY \
            --on-ip 127.0.0.1 --on-port "$OPERA_TP_PORT" --tproxy-mark "$OPERA_MARK/$OPERA_MARK" 2>/dev/null || {
            OPERA_ERR="ядро без TPROXY (iptables -j TPROXY не встаёт)"; return 2; }
    done
    $iptables -t mangle -N "$CHAIN_OPERA_IN" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_IN" 2>/dev/null
    [ "$phone" = "1" ] && \
        $iptables -t mangle -A "$CHAIN_OPERA_IN" -i lo -p tcp -m mark --mark "$OPERA_MARK/$OPERA_MARK" -j "$CHAIN_OPERA_TP" 2>/dev/null
    for i in "$@"; do
        $iptables -t mangle -A "$CHAIN_OPERA_IN" -i "$i" -p tcp -j "$CHAIN_OPERA_TP" 2>/dev/null
    done
    # В конец: TPROXY завершает обход таблицы, системные цепочки — раньше
    $iptables -t mangle -C PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null || \
        $iptables -t mangle -A PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null

    if [ "$phone" = "1" ]; then
        $iptables -t mangle -N "$CHAIN_OPERA_OUT" 2>/dev/null
        $iptables -t mangle -F "$CHAIN_OPERA_OUT" 2>/dev/null
        $iptables -t mangle -A "$CHAIN_OPERA_OUT" -o lo -j RETURN 2>/dev/null
        # сам opera-proxy — мимо (иначе петля), nfqws и dnsproxy (и проверки WebUI от его группы) — тоже
        for u in $OPERA_GID $ZAPRET_GID $DNSPROXY_GID; do
            $iptables -t mangle -A "$CHAIN_OPERA_OUT" -m owner --gid-owner "$u" -j RETURN 2>/dev/null
        done
        [ "$OPERA_SU_G" = "1" ] || \
            $iptables -t mangle -A "$CHAIN_OPERA_OUT" -m owner --uid-owner 0 -j RETURN 2>/dev/null
        for u in $OPERA_EXCL; do
            $iptables -t mangle -A "$CHAIN_OPERA_OUT" -m owner --uid-owner "$u" -j RETURN 2>/dev/null
        done
        for c in $cidrs; do
            $iptables -t mangle -A "$CHAIN_OPERA_OUT" -p tcp -d "$c" -j MARK --set-xmark "$OPERA_MARK/$OPERA_MARK" 2>/dev/null
        done
        $iptables -t mangle -C OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null || \
            $iptables -t mangle -A OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null
    else
        while $iptables -t mangle -D OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null; do :; done
        $iptables -t mangle -F "$CHAIN_OPERA_OUT" 2>/dev/null; $iptables -t mangle -X "$CHAIN_OPERA_OUT" 2>/dev/null
    fi

    # помеченное — доставить локально (в TPROXY)
    $ip route replace local 0.0.0.0/0 dev lo table "$OPERA_TABLE" 2>/dev/null || {
        OPERA_ERR="не встал маршрут local в таблицу $OPERA_TABLE"; return 1; }
    $ip rule show 2>/dev/null | grep -q "^$OPERA_PREF:.*lookup $OPERA_TABLE" || \
        $ip rule add fwmark "$OPERA_MARK/$OPERA_MARK" lookup "$OPERA_TABLE" pref "$OPERA_PREF" 2>/dev/null || {
        OPERA_ERR="не встало ip rule fwmark"; return 1; }
    OPERA_SCOPE=$( { [ "$phone" = 1 ] && echo phone; [ -n "$*" ] && echo tether; } | tr '\n' ' ')
    OPERA_SCOPE="${OPERA_SCOPE% }"
    return 0
}

# хуки и ip rule на месте? (netd перетряхивает цепочки)
opera_rules_ok() {
    $iptables -t mangle -C PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null || return 1
    case "$OPERA_SCOPE" in phone*) $iptables -t mangle -C OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null || return 1 ;; esac
    $ip rule show 2>/dev/null | grep -q "^$OPERA_PREF:.*lookup $OPERA_TABLE" || return 1
    $ip route show table "$OPERA_TABLE" 2>/dev/null | grep -q . || return 1
}

# Сервер Opera доходит? Запрос к DC Telegram через SOCKS opera-proxy (curl от
# группы opera — мимо перенаправления и nfqws). 24.10: на Wi-Fi Dom.ru часть
# серверов 77.111.x не отвечала, а opera-proxy жил — Telegram висел.
opera_probe() {
    local code
    command -v curl >/dev/null 2>&1 || return 0
    if [ "$OPERA_SU_G" = "1" ]; then
        code=$(su -g "$OPERA_GID" -c "curl -s -o /dev/null -m 6 --socks5 127.0.0.1:$OPERA_PORT -w '%{http_code}' http://$OPERA_PROBE_DC/" 2>/dev/null)
    else
        code=$(curl -s -o /dev/null -m 6 --socks5 "127.0.0.1:$OPERA_PORT" -w '%{http_code}' "http://$OPERA_PROBE_DC/" 2>/dev/null)
    fi
    [ -n "$code" ] && [ "$code" != "000" ]
}

opera_fail() {   # причина [fast — сервер не отвечает: сразу другой]
    local p
    opera_rules_off
    _opera_kill $(opera_hev_pids)
    _opera_kill $(opera_proxy_pids)
    OPERA_FAILS=$((OPERA_FAILS + 1))
    case "$OPERA_FAILS" in 1) p=30 ;; 2) p=60 ;; *) p=150 ;; esac   # итераций по ~2с
    [ "$2" = "fast" ] && p=2
    OPERA_RETRY=$p
    OPERA_STATE="fail"
    OPERA_ERR="$1"
    OPERA_ENDPOINT=""
    log "WARNING: opera: $1 — Telegram напрямую, повтор через $([ "$p" -lt 30 ] && echo "~$((p * 2))с" || echo "~$((p * 2 / 60)) мин")"
    # после сбоя пригодится запасной список (не скачан или старше суток)
    if [ ! -s "$OPERA_API_SPARE" ] || [ -n "$(find "$OPERA_API_SPARE" -mmin +1440 2>/dev/null)" ]; then
        opera_spare_fetch
    fi
    phone_status_refresh
}

opera_down() {   # [quiet]
    opera_rules_off
    _opera_kill $(opera_hev_pids)
    _opera_kill $(opera_proxy_pids)
    opera_exempt_down
    [ "$OPERA_STATE" != "off" ] && [ "$1" != "quiet" ] && log "opera: выключен"
    OPERA_STATE="off"
    OPERA_ENDPOINT=""
    OPERA_ERR=""
    OPERA_RETRY=0
    OPERA_FAILS=0
    phone_status_refresh
}

# журнал opera-proxy — не больше ~256 КБ (дописывается через >>, обрезка на ходу)
opera_log_trim() {
    local f s
    for f in "$OPERA_LOG" "$OPERA_HEV_LOG"; do
        s=$(wc -c < "$f" 2>/dev/null) || continue
        [ "${s:-0}" -gt 262144 ] || continue
        tail -n 1000 "$f" > "$f.tmp" && cat "$f.tmp" > "$f"
        rm -f "$f.tmp"
    done
}

# Каждая итерация цикла (после phone_dns_reconcile: он считает PHONE_VPN_STABLE)
opera_reconcile() {
    local want=0 ifaces="" sig rc
    if [ "$OPERA_TG" != "1" ]; then
        [ "$OPERA_STATE" != "off" ] && opera_down
        return 0
    fi
    [ "$OPERA_NOSUPPORT" = "1" ] && return 0
    if [ -z "$OPERA_BIN" ] || [ -z "$OPERA_HEV_BIN" ]; then
        OPERA_NOSUPPORT=1
        OPERA_STATE="fail"
        OPERA_ERR="нет bin/opera-proxy или bin/hev-socks5-tproxy для $(uname -m)"
        log "WARNING: opera: $OPERA_ERR"
        phone_status_refresh
        return 0
    fi
    # VPN не поднят (phone_dns_reconcile: подтверждено и в последнем замере):
    # появление VPN снимает перенаправление сразу, без второго замера
    [ "$PHONE_VPN_STABLE" = "0" ] && [ "$PHONE_VPN_SEEN" = "0" ] && want=1

    case "$OPERA_STATE" in
        off|fail)
            [ "$want" = "1" ] && [ -n "$LAST_WAN_IFACE" ] || return 0
            if [ "$OPERA_RETRY" -gt 0 ]; then OPERA_RETRY=$((OPERA_RETRY - 1)); return 0; fi
            opera_start
            return 0 ;;
        starting)
            if [ -z "$(opera_proxy_pids)" ]; then
                opera_fail "opera-proxy не запустился: $(grep -iE 'critical|error' "$OPERA_LOG" 2>/dev/null | tail -n 1 | cut -c1-160)"
                return 0
            fi
            if ! _opera_listening "$OPERA_PORT"; then
                [ $(( $(date +%s) - OPERA_START_TS )) -ge 180 ] && opera_fail "opera-proxy не зарегистрировался в Opera за 3 мин"
                return 0
            fi
            opera_started
            if ! opera_hev_start; then
                opera_fail "hev-socks5-tproxy не запустился: $(tail -n 2 "$OPERA_HEV_LOG" 2>/dev/null | tr '\n' ' ' | cut -c1-160)"
                return 0
            fi
            OPERA_STATE="on"
            OPERA_TICK=15
            phone_status_refresh ;;
        on)
            if [ -z "$(opera_proxy_pids)" ]; then
                opera_fail "opera-proxy завершился"
                return 0
            fi
            if [ -z "$(opera_hev_pids)" ]; then
                opera_rules_off
                log "WARNING: opera: hev-socks5-tproxy умер, перезапускаю"
                opera_hev_start || { opera_fail "hev-socks5-tproxy не перезапустился"; return 0; }
            fi ;;
    esac

    OPERA_TICK=$((OPERA_TICK + 1))
    # сменилась сеть — сервер Opera мог стать недоступен: проверить сразу
    [ "$OPERA_STATE" = "on" ] && [ "$LAST_WAN_IFACE" != "$OPERA_WAN" ] && OPERA_TICK=15
    if [ "$OPERA_TICK" -ge 15 ]; then   # ~30с: дорогое (stat пакетов, iptables -C)
        OPERA_TICK=0
        if [ "$OPERA_STATE" = "on" ] && [ "$want" = "1" ]; then
            OPERA_WAN="$LAST_WAN_IFACE"
            # две неудачи подряд — перезапуск: opera-proxy возьмёт другой сервер
            if ! opera_probe && ! opera_probe; then
                opera_fail "сервер Opera ${OPERA_ENDPOINT:-?} не отвечает${OPERA_WAN:+ (сеть $OPERA_WAN)}" fast
                return 0
            fi
        fi
        OPERA_EXCL=$(zapret_vpn_uids)
        opera_exempt
        opera_log_trim
        [ -n "$OPERA_RULES_SIG" ] && ! opera_rules_ok && {
            log "WATCHDOG: opera: правила пропали, ставлю заново"; OPERA_RULES_SIG=""; }
    fi

    if [ "$want" = "0" ]; then
        if [ -n "$OPERA_RULES_SIG" ]; then
            opera_rules_off
            log "opera: VPN поднят — Telegram через VPN, перенаправление снято"
            phone_status_refresh
        fi
        return 0
    fi
    # раздача — только в режиме «напрямую»: в blocked и VPN её трогать нельзя
    [ "$VPN_TETHER_MODE" = "off" ] && ifaces="$LAST_TETHER_IFACES"
    sig="1|$ifaces|$OPERA_EXCL"
    [ "$sig" = "$OPERA_RULES_SIG" ] && return 0
    opera_rules_on 1 $ifaces; rc=$?
    if [ "$rc" = 0 ]; then
        OPERA_RULES_SIG="$sig"
        log "opera: Telegram через Opera (${OPERA_ENDPOINT:-?}): телефон$([ -n "$ifaces" ] && echo " + раздача [$ifaces]")${OPERA_EXCL:+; мимо VPN-клиенты: $OPERA_EXCL}"
        phone_status_refresh
        return 0
    fi
    opera_rules_off
    if [ "$rc" = 2 ]; then
        # ядро без TPROXY: повторять бессмысленно, процессы не держим
        _opera_kill $(opera_hev_pids)
        _opera_kill $(opera_proxy_pids)
        OPERA_NOSUPPORT=1
        OPERA_STATE="fail"
        log "WARNING: opera: $OPERA_ERR — функция недоступна на этом ядре"
        phone_status_refresh
    else
        opera_fail "${OPERA_ERR:-правила не встали}"
    fi
}
