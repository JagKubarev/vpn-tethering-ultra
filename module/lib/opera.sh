# shellcheck shell=sh
# lib/opera.sh — запасной выход через прокси Opera для сайтов из OPERA_DOMAINS.
# Часть демона service.sh: подключается из него через ".", сам не запускается.
#
# Опыт 3.13–3.15.1 (Opera убирали в 3.16) и замеры 05.11:
#  - Discover с российского адреса отдаёт закрытые 77.111.247.19 и 244.47, и
#    opera-proxy завершается. Через прокси для API — другие, живые адреса.
#    Бесплатный прокси нужен только для регистрации, трафик идёт прямо в Opera.
#  - Сервер выбирает сам opera-proxy (fastest по http://www.example.com/):
#    своего пула и замеров больше нет. С тестом по умолчанию (Google) он
#    завершался на YOTA.
#  - Только список доменов, адреса общих CDN — мимо: в 3.15 через общие адреса
#    Cloudflare в Opera уехали чужие сервисы (API Claude). «!домен» — и через
#    CDN (4pda.to на Cloudflare): чужие сайты на этом адресе пойдут туда же,
#    TPROXY видит только адрес. По умолчанию такого нет.
#  - hev-socks5-tproxy берёт адрес назначения из сокета, поэтому TPROXY, а не
#    REDIRECT. TPROXY без слушателя дропает пакеты: умер процесс — правила
#    снимаются сразу.
#  - Только TCP и IPv4. VPN поднят — правила снимаются, процессы остаются.
OPERA_PORT=18080            # SOCKS5 opera-proxy
OPERA_TP_PORT=18088         # hev-socks5-tproxy
OPERA_MARK=0x04000000       # zapret 0x40000000, WARP 0x20000000, YouTube 0x10000000, scan.sh 0x08000000
OPERA_TABLE=3997
OPERA_PREF=2990             # раньше правил раздачи (3000) и всех правил netd
OPERA_LOG="/data/local/tmp/vpn_tether_op.log"
OPERA_HEV_LOG="/data/local/tmp/vpn_tether_ophev.log"
OPERA_HEV_CONF="/data/local/tmp/vpn_tether_ophev.yml"
OPERA_CA="/data/local/tmp/vpn_tether_op_ca.pem"
OPERA_API_FILE="/data/adb/vpn_tether_op_api.txt"   # удачные прокси API: запасной список, если ссылка не скачалась
OPERA_API_URL="https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt"
OPERA_DQ_DIR="/data/adb/vpn_tether_op_dq"
CHAIN_OPERA_IN="VPN_OPERA_IN"     # mangle PREROUTING
CHAIN_OPERA_OUT="VPN_OPERA_OUT"   # mangle OUTPUT
CHAIN_OPERA_TP="VPN_OPERA_TP"     # адреса сайтов -> TPROXY
OPERA_DOM_SECS=600
OPERA_STATE="off"       # off | starting | on | fail
OPERA_ENDPOINT=""       # сервер Opera, выбранный opera-proxy
OPERA_ERR=""            # почему fail
OPERA_RULES_SIG=""      # что стоит: интерфейсы|исключения|адреса, "" = правил нет
OPERA_RETRY=0           # пропустить N итераций до повтора
OPERA_FAILS=0           # неудачных стартов подряд
OPERA_BAD=0             # неудачных проверок подряд
OPERA_START_TS=0
OPERA_TICK=0
OPERA_SU_G=""           # "" = не проверяли, 1 = su -g работает, 0 = нет
OPERA_NOSUPPORT=0       # 1 = ядро без TPROXY или нет бинарей: не пытаться до перечитывания
OPERA_WAN=""
OPERA_DOM_TS=0
OPERA_DOM_IPS=""
OPERA_DOM_LAST=""
OPERA_DOM_FLAST=""
OPERA_DOM_SKIP=0

_opera_pids() {
    local f
    [ -n "$1" ] || return 0     # нет бинаря под эту архитектуру: пустой шаблон совпал бы со всеми
    for f in $(grep -l "$1" /proc/[0-9]*/cmdline 2>/dev/null); do
        case "$(tr '\0' ' ' 2>/dev/null < "$f")" in
            "$1"*"$2"*) f="${f#/proc/}"; echo "${f%/cmdline}" ;;
        esac
    done
}
opera_proxy_pids() { _opera_pids "$OPERA_BIN" "-bind-address 127.0.0.1:$OPERA_PORT "; }
opera_hev_pids()   { _opera_pids "$OPERA_HEV_BIN" "$OPERA_HEV_CONF"; }
# без ss: на Android 8 его нет. hev слушает AF_INET6-сокетом
_opera_listening() {
    grep -qE "^ *[0-9]+: [0-9A-F]+:$(printf '%04X' "$1") [0-9A-F]+:0000 0A " /proc/net/tcp /proc/net/tcp6 2>/dev/null
}
_opera_kill() {
    local p
    for p in "$@"; do kill "$p" 2>/dev/null; done
    [ -n "$*" ] || return 0
    sleep 0.3
    for p in "$@"; do kill -9 "$p" 2>/dev/null; done
}

# Go на Android не видит системные сертификаты: собираем PEM сами
opera_ca_build() {
    local d f n=0
    : > "$OPERA_CA.tmp" 2>/dev/null || return 1
    for d in /apex/com.android.conscrypt/cacerts /system/etc/security/cacerts; do
        for f in "$d"/*.0; do
            [ -f "$f" ] || continue
            sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$f" >> "$OPERA_CA.tmp" && n=$((n + 1))
        done
        [ "$n" -gt 0 ] && break
    done
    mv -f "$OPERA_CA.tmp" "$OPERA_CA"
    [ "$n" -gt 0 ]
}

# Мимо перехвата AdGuard, как у dnsproxy
opera_exempt() {
    [ "$OPERA_SU_G" = "1" ] || return 0
    $iptables -t nat -C OUTPUT -m owner --gid-owner "$OPERA_GID" -j RETURN 2>/dev/null || \
        $iptables -t nat -I OUTPUT 1 -m owner --gid-owner "$OPERA_GID" -j RETURN 2>/dev/null
}
opera_exempt_down() {
    local _n=0
    while [ $_n -lt 8 ] && $iptables -t nat -D OUTPUT -m owner --gid-owner "$OPERA_GID" -j RETURN 2>/dev/null; do _n=$((_n + 1)); done
}

opera_start() {
    local args
    _opera_kill $(opera_proxy_pids)
    if [ -z "$OPERA_SU_G" ]; then
        OPERA_SU_G=0
        su -g "$OPERA_GID" -c true >/dev/null 2>&1 && OPERA_SU_G=1
    fi
    opera_exempt
    opera_ca_build || log "WARNING: opera: системные сертификаты не найдены"
    args="-bind-address 127.0.0.1:$OPERA_PORT -socks-mode -country EU -verbosity 20 -cafile $OPERA_CA"
    args="$args -server-selection fastest -server-selection-timeout 1s -server-selection-test-url http://www.example.com/"
    args="$args -api-address api2.sec-tunnel.com -api-proxy-parallel 24 -api-proxy-list-url $OPERA_API_URL"
    [ -s "$OPERA_API_FILE" ] && args="$args -api-proxy-file $OPERA_API_FILE"
    : > "$OPERA_LOG"
    # setsid: с nohup opera-proxy умирал вместе с сессией
    if [ "$OPERA_SU_G" = "1" ]; then
        setsid su -g "$OPERA_GID" -c "exec $OPERA_BIN $args" </dev/null >> "$OPERA_LOG" 2>&1 &
    else
        setsid $OPERA_BIN $args </dev/null >> "$OPERA_LOG" 2>&1 &
    fi
    OPERA_START_TS=$(date +%s)
    OPERA_STATE="starting"
    OPERA_ENDPOINT=""
    OPERA_ERR=""
    log "opera: запускаю opera-proxy"
    phone_status_refresh
}

# Готов: запомнить удачный прокси API и сервер
opera_started() {
    local c
    c=$(sed -n 's/.*Using API proxy candidate: \([^ ]*\).*/\1/p' "$OPERA_LOG" 2>/dev/null | tail -n 1)
    if [ -n "$c" ]; then
        { echo "$c"; grep -vxF -- "$c" "$OPERA_API_FILE" 2>/dev/null; } | head -n 20 > "$OPERA_API_FILE.tmp" && \
            mv -f "$OPERA_API_FILE.tmp" "$OPERA_API_FILE"
        chmod 600 "$OPERA_API_FILE" 2>/dev/null
    fi
    OPERA_ENDPOINT=$(sed -n 's/.*Selected endpoint address: \([^ ]*\).*/\1/p' "$OPERA_LOG" 2>/dev/null | tail -n 1)
    OPERA_WAN="$LAST_WAN_IFACE"
    OPERA_FAILS=0; OPERA_BAD=0
    log "opera: готов за $(( $(date +%s) - OPERA_START_TS )) с (сервер ${OPERA_ENDPOINT:-?}${c:+, API через $c})"
}

opera_hev_start() {
    local i=0
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
    setsid "$OPERA_HEV_BIN" "$OPERA_HEV_CONF" </dev/null >/dev/null 2>> "$OPERA_HEV_LOG" &
    while [ $i -lt 10 ]; do
        sleep 0.2
        [ -n "$(opera_hev_pids)" ] && _opera_listening "$OPERA_TP_PORT" && return 0
        i=$((i + 1))
    done
    return 1
}

# Адреса OPERA_DOMAINS без общих CDN -> OPERA_DOM_IPS (вместе с прошлым набором:
# ответы DNS скачут, открытое соединение не должно терять маршрут)
opera_domains_refresh() {
    local d f ips forced out k=0 pids="" p
    OPERA_DOM_TS=$(date +%s)
    mkdir -p "$OPERA_DQ_DIR" 2>/dev/null; chmod 700 "$OPERA_DQ_DIR" 2>/dev/null
    rm -f "$OPERA_DQ_DIR"/.dq* "$OPERA_DQ_DIR"/.fq*
    for d in $OPERA_DOMAINS; do
        case "$d" in '!'*) f=.fq; d="${d#?}" ;; *) f=.dq ;; esac
        warp_dq "$d" > "$OPERA_DQ_DIR/$f$k" 2>/dev/null & pids="$pids $!"; k=$((k + 1))
    done
    # wait — по своим pid и до конца: USR1 прерывает wait (см. warp_domains_refresh)
    for p in $pids; do while kill -0 "$p" 2>/dev/null; do wait "$p" 2>/dev/null; done; done
    ips=$(cat "$OPERA_DQ_DIR"/.dq* 2>/dev/null | tr '\n' ' ')
    forced=$(cat "$OPERA_DQ_DIR"/.fq* 2>/dev/null | tr '\n' ' ')
    rm -f "$OPERA_DQ_DIR"/.dq* "$OPERA_DQ_DIR"/.fq*
    out=$(echo $ips $OPERA_DOM_LAST | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u | \
        awk 'function n(s,  a) { split(s, a, "."); return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }
             FNR == NR { if ($1 ~ /^[0-9]/) { split($1, c, "/"); lo[k] = n(c[1]); sz[k] = 2 ^ (32 - c[2]); k++ } next }
             { v = n($1); for (j = 0; j < k; j++) if (v >= lo[j] && v < lo[j] + sz[j]) { skip++; next }; print }
             END { print "skip " skip + 0 }' k=0 "$MODULE_DIR/warp/cdn-ipv4.txt" -)
    OPERA_DOM_LAST="$ips"
    out="$out
$(echo $forced $OPERA_DOM_FLAST | tr ' ' '\n')"
    OPERA_DOM_FLAST="$forced"
    OPERA_DOM_SKIP=$(echo "$out" | sed -n 's/^skip //p')
    OPERA_DOM_IPS=$(echo "$out" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u | tr '\n' ' ')
    OPERA_DOM_IPS=${OPERA_DOM_IPS% }
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
}

# opera_rules_on <исключённые uid> [интерфейсы раздачи...]
opera_rules_on() {
    local excl="$1" a u i; shift
    $iptables -t mangle -N "$CHAIN_OPERA_TP" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_TP" 2>/dev/null
    for a in $OPERA_DOM_IPS; do
        $iptables -t mangle -A "$CHAIN_OPERA_TP" -p tcp -d "$a" -j TPROXY \
            --on-ip 127.0.0.1 --on-port "$OPERA_TP_PORT" --tproxy-mark "$OPERA_MARK/$OPERA_MARK" 2>/dev/null || return 2
    done
    $iptables -t mangle -N "$CHAIN_OPERA_IN" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_IN" 2>/dev/null
    $iptables -t mangle -A "$CHAIN_OPERA_IN" -i lo -p tcp -m mark --mark "$OPERA_MARK/$OPERA_MARK" -j "$CHAIN_OPERA_TP" 2>/dev/null
    for i in "$@"; do
        $iptables -t mangle -A "$CHAIN_OPERA_IN" -i "$i" -p tcp -j "$CHAIN_OPERA_TP" 2>/dev/null
    done
    # в конец: TPROXY завершает обход таблицы, системные цепочки — раньше
    $iptables -t mangle -C PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null || \
        $iptables -t mangle -A PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null

    $iptables -t mangle -N "$CHAIN_OPERA_OUT" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_OUT" 2>/dev/null
    $iptables -t mangle -A "$CHAIN_OPERA_OUT" -o lo -j RETURN 2>/dev/null
    # сам opera-proxy, nfqws и dnsproxy — мимо, иначе петля
    for u in $OPERA_GID $ZAPRET_GID $DNSPROXY_GID; do
        $iptables -t mangle -A "$CHAIN_OPERA_OUT" -m owner --gid-owner "$u" -j RETURN 2>/dev/null
    done
    # root — мимо: проверка сайтов и подбор идут от root и не должны «открывать»
    # адреса через Opera, иначе врут
    $iptables -t mangle -A "$CHAIN_OPERA_OUT" -m owner --uid-owner 0 -j RETURN 2>/dev/null
    for u in $excl; do
        $iptables -t mangle -A "$CHAIN_OPERA_OUT" -m owner --uid-owner "$u" -j RETURN 2>/dev/null
    done
    for a in $OPERA_DOM_IPS; do
        $iptables -t mangle -A "$CHAIN_OPERA_OUT" -p tcp -d "$a" -j MARK --set-xmark "$OPERA_MARK/$OPERA_MARK" 2>/dev/null
    done
    $iptables -t mangle -C OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null || \
        $iptables -t mangle -A OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null

    # помеченное — доставить локально (в TPROXY)
    $ip route replace local 0.0.0.0/0 dev lo table "$OPERA_TABLE" 2>/dev/null || return 1
    $ip rule show 2>/dev/null | grep -q "^$OPERA_PREF:.*lookup $OPERA_TABLE" || \
        $ip rule add fwmark "$OPERA_MARK/$OPERA_MARK" lookup "$OPERA_TABLE" pref "$OPERA_PREF" 2>/dev/null || return 1
    return 0
}

# хуки и ip rule на месте? (netd перетряхивает цепочки)
opera_rules_ok() {
    $iptables -t mangle -C PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null || return 1
    $iptables -t mangle -C OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null || return 1
    $ip rule show 2>/dev/null | grep -q "^$OPERA_PREF:.*lookup $OPERA_TABLE" || return 1
    $ip route show table "$OPERA_TABLE" 2>/dev/null | grep -q . || return 1
}

# Прокси пропускает? Через SOCKS opera-proxy, от его группы: мимо перенаправления
opera_probe() {
    local code g="sh -c"
    [ "$OPERA_SU_G" = "1" ] && g="su -g $OPERA_GID -c"
    code=$($g "$CURL_BIN -s -o /dev/null -m 6 --socks5-hostname 127.0.0.1:$OPERA_PORT -w %{http_code} http://www.example.com/" 2>/dev/null)
    [ -n "$code" ] && [ "$code" != "000" ]
}

opera_fail() {   # причина
    local p
    opera_rules_off
    _opera_kill $(opera_hev_pids)
    _opera_kill $(opera_proxy_pids)
    OPERA_FAILS=$((OPERA_FAILS + 1))
    # первые повторы быстрые: discover отдаёт случайный набор, и бывает, что все
    # его адреса закрыты (код 12, 05.11: 4 старта из 8) — другой старт даёт другой
    case "$OPERA_FAILS" in 1|2|3) p=3 ;; 4) p=15 ;; 5) p=60 ;; *) p=150 ;; esac   # итераций по ~2с
    OPERA_RETRY=$p
    OPERA_STATE="fail"
    OPERA_ERR="$1"
    OPERA_ENDPOINT=""
    log "WARNING: opera: $1 — сайты напрямую, повтор через ~$((p * 2)) с"
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
    OPERA_BAD=0
    OPERA_DOM_TS=0
    OPERA_DOM_IPS=""
    OPERA_DOM_LAST=""
    OPERA_DOM_FLAST=""
    phone_status_refresh
}

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
    local want=0 sig rc excl now
    if [ "$OPERA_ENABLE" != "1" ] || [ -z "$OPERA_DOMAINS" ]; then
        [ "$OPERA_STATE" != "off" ] && opera_down
        return 0
    fi
    [ "$OPERA_NOSUPPORT" = "1" ] && return 0
    if [ -z "$OPERA_BIN" ] || [ -z "$OPERA_HEV_BIN" ]; then
        OPERA_NOSUPPORT=1; OPERA_STATE="fail"; OPERA_ERR="нет bin/opera-proxy или bin/hev-socks5-tproxy"
        log "WARNING: opera: $OPERA_ERR"; phone_status_refresh
        return 0
    fi
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
                # упал молча — значит, ни один адрес из discover не ответил
                opera_fail "opera-proxy не запустился: $(grep -E 'CRITICAL|ERROR|Discovered endpoints' "$OPERA_LOG" 2>/dev/null | tail -n 1 | sed 's/.*Discovered endpoints: //; s/\. Starting.*//' | cut -c1-120)"
                return 0
            fi
            if ! _opera_listening "$OPERA_PORT"; then
                [ $(( $(date +%s) - OPERA_START_TS )) -ge 120 ] && opera_fail "opera-proxy не зарегистрировался за 2 мин"
                return 0
            fi
            opera_started
            opera_hev_start || { opera_fail "hev-socks5-tproxy не запустился: $(tail -n 1 "$OPERA_HEV_LOG" 2>/dev/null | cut -c1-120)"; return 0; }
            OPERA_STATE="on"
            OPERA_TICK=0
            phone_status_refresh ;;
        on)
            [ -n "$(opera_proxy_pids)" ] || { opera_fail "opera-proxy завершился"; return 0; }
            if [ -z "$(opera_hev_pids)" ]; then
                opera_rules_off
                log "WARNING: opera: hev-socks5-tproxy умер, перезапускаю"
                opera_hev_start || { opera_fail "hev-socks5-tproxy не перезапустился"; return 0; }
            fi ;;
    esac

    OPERA_TICK=$((OPERA_TICK + 1))
    # сменилась сеть — сервер мог стать недоступен: проверить сразу
    [ "$LAST_WAN_IFACE" != "$OPERA_WAN" ] && { OPERA_WAN="$LAST_WAN_IFACE"; OPERA_TICK=15; }
    if [ "$OPERA_TICK" -ge 15 ]; then   # ~30 с
        OPERA_TICK=0
        opera_log_trim
        if [ "$want" = "1" ]; then
            if opera_probe; then
                OPERA_BAD=0
            else
                OPERA_BAD=$((OPERA_BAD + 1))
                [ "$OPERA_BAD" -ge 3 ] && { opera_fail "прокси не отвечает"; return 0; }
            fi
        fi
    fi

    if [ "$want" != "1" ]; then
        [ -n "$OPERA_RULES_SIG" ] && { opera_rules_off; log "opera: правила сняты (VPN поднят)"; }
        return 0
    fi
    now=$(date +%s)
    [ $((now - OPERA_DOM_TS)) -ge $OPERA_DOM_SECS ] && opera_domains_refresh
    [ -n "$OPERA_DOM_IPS" ] || { [ -n "$OPERA_RULES_SIG" ] && opera_rules_off; return 0; }
    excl=$(zapret_vpn_uids)
    sig="$LAST_TETHER_IFACES|$excl|$OPERA_DOM_IPS"
    [ "$sig" = "$OPERA_RULES_SIG" ] && { [ "$OPERA_TICK" != 0 ] || opera_rules_ok; } && return 0
    opera_rules_off
    opera_rules_on "$excl" $LAST_TETHER_IFACES; rc=$?
    if [ "$rc" = 0 ]; then
        OPERA_RULES_SIG="$sig"
        log "opera: через Opera ${OPERA_ENDPOINT:-?}: адресов $(echo $OPERA_DOM_IPS | wc -w | tr -d ' '), общих CDN мимо: ${OPERA_DOM_SKIP:-0}, раздача: ${LAST_TETHER_IFACES:-нет}"
    elif [ "$rc" = 2 ]; then
        opera_rules_off
        OPERA_NOSUPPORT=1; OPERA_STATE="fail"; OPERA_ERR="ядро без TPROXY"
        log "WARNING: opera: $OPERA_ERR"; phone_status_refresh
    else
        opera_rules_off
        opera_fail "правила не встали"
    fi
}
