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
#  - Группы, приложения, телефон и раздача — как у WARP (OPERA_TELEGRAM,
#    OPERA_GOOGLE, OPERA_APPS, OPERA_PHONE, OPERA_TETHER): кому WARP работает хуже,
#    выключает группу там и включает здесь. Звонков (UDP) через Opera нет.
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
CHAIN_OPERA_QO="VPN_OPERA_QO"     # filter OUTPUT: QUIC к этим адресам — отказ, браузер уйдёт на TCP
CHAIN_OPERA_QF="VPN_OPERA_QF"     # filter FORWARD: то же для раздачи
CHAIN_OPERA_V6="VPN_OPERA_V6"     # ip6 OUTPUT: отбить, уйдёт на v4
CHAIN_OPERA_V6F="VPN_OPERA_V6F"   # ip6 FORWARD: то же для раздачи
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
OPERA_NETS=0            # сколько сетей и приложений в правилах (для WebUI)
OPERA_V6_SIG=""         # что стоит в IPv6: сотни вызовов ip6tables — только при смене
OPERA_RULE_ERR=""       # почему не встали правила
OPERA_APP_TS=0
OPERA_APP_UIDS=""
OPERA_EXCL=""

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

# Мимо перехвата AdGuard, как у dnsproxy. Важно место, а не наличие: AdGuard
# ставит свой переход выше, и opera-proxy видит сертификат AdGuard — x509, 500 на
# всё, код 12 (05.11 после перезагрузки). Не строго первым: первое место у dnsproxy_exempt
opera_exempt() {
    [ "$OPERA_SU_G" = "1" ] || return 0
    local want="-A OUTPUT -m owner --gid-owner $OPERA_GID -j RETURN"
    $iptables -t nat -S OUTPUT 2>/dev/null | sed -n '2,3p' | grep -qxF -- "$want" && return 0
    opera_exempt_down
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
    # DNS ещё не поднялся (после загрузки) — не ждать 10 минут
    [ -n "$OPERA_DOM_IPS" ] || [ "${OPERA_DOM_SKIP:-0}" -gt 0 ] || OPERA_DOM_TS=$((OPERA_DOM_TS - OPERA_DOM_SECS + 30))
}

# Что идёт через Opera — как у WARP: группы, сайты, приложения. Если то же самое
# включено и в WARP, побеждает WARP (его ip rule раньше), поэтому выбор — выключить там
opera_wanted() {
    [ "$OPERA_ENABLE" = "1" ] || return 1
    [ -n "$OPERA_DOMAINS$OPERA_APPS" ] || [ "$OPERA_TELEGRAM" = "1" ] || [ "$OPERA_GOOGLE" = "1" ]
}
opera_dst4() {
    local a
    [ "$OPERA_GOOGLE" = "1" ] && tr -d '\r' < "$MODULE_DIR/warp/google-ipv4.txt" 2>/dev/null | grep -E '^[0-9]+\.'
    [ "$OPERA_TELEGRAM" = "1" ] && tr -d '\r' < "$MODULE_DIR/warp/telegram.txt" 2>/dev/null | grep -E '^[0-9]+\.'
    for a in $OPERA_DOM_IPS; do echo "$a/32"; done
}
opera_dst6() {
    [ "$OPERA_GOOGLE" = "1" ] && tr -d '\r' < "$MODULE_DIR/warp/google-ipv6.txt" 2>/dev/null | grep -E '^[0-9a-f]+:'
    [ "$OPERA_TELEGRAM" = "1" ] && tr -d '\r' < "$MODULE_DIR/warp/telegram.txt" 2>/dev/null | grep -E '^[0-9a-f]+:'
}
# приложения целиком; клиенты Telegram — как у WARP: их запасные узлы вне сетей Telegram
opera_app_uids() {
    local p u out="" tg=""
    [ "$OPERA_TELEGRAM" = "1" ] && [ "$OPERA_PHONE" = "1" ] && tg="$WARP_TG_PKGS"
    for p in $OPERA_APPS $tg; do
        u=$(stat -c %u "/data/data/$p" 2>/dev/null)
        case "$u" in ''|*[!0-9]*) continue ;; esac
        [ "$u" -ge 10000 ] || continue
        case " $out " in *" $u "*) ;; *) out="$out $u" ;; esac
    done
    echo "${out# }"
}

opera_rules_off() {
    local _n
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null; do _n=$((_n + 1)); done
    $iptables -t mangle -F "$CHAIN_OPERA_IN" 2>/dev/null;  $iptables -t mangle -X "$CHAIN_OPERA_IN" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_OUT" 2>/dev/null; $iptables -t mangle -X "$CHAIN_OPERA_OUT" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_TP" 2>/dev/null;  $iptables -t mangle -X "$CHAIN_OPERA_TP" 2>/dev/null
    _n=0; while [ $_n -lt 8 ] && $iptables -D OUTPUT -j "$CHAIN_OPERA_QO" 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -D FORWARD -j "$CHAIN_OPERA_QF" 2>/dev/null; do _n=$((_n + 1)); done
    $iptables -F "$CHAIN_OPERA_QO" 2>/dev/null; $iptables -X "$CHAIN_OPERA_QO" 2>/dev/null
    $iptables -F "$CHAIN_OPERA_QF" 2>/dev/null; $iptables -X "$CHAIN_OPERA_QF" 2>/dev/null
    OPERA_V6_SIG=""
    $ip6tables -D OUTPUT -j "$CHAIN_OPERA_V6" 2>/dev/null
    $ip6tables -D FORWARD -j "$CHAIN_OPERA_V6F" 2>/dev/null
    $ip6tables -F "$CHAIN_OPERA_V6" 2>/dev/null;  $ip6tables -X "$CHAIN_OPERA_V6" 2>/dev/null
    $ip6tables -F "$CHAIN_OPERA_V6F" 2>/dev/null; $ip6tables -X "$CHAIN_OPERA_V6F" 2>/dev/null
    _n=0; while [ $_n -lt 8 ] && $ip rule del fwmark "$OPERA_MARK/$OPERA_MARK" lookup "$OPERA_TABLE" pref "$OPERA_PREF" 2>/dev/null; do _n=$((_n + 1)); done
    $ip route flush table "$OPERA_TABLE" 2>/dev/null
    OPERA_RULES_SIG=""
    OPERA_NETS=0
}

# есть ли TPROXY в ядре: иначе iptables-restore падает, а повторять незачем
opera_tproxy_ok() {
    local c=VPN_OPERA_CHK rc
    $iptables -t mangle -N "$c" 2>/dev/null
    $iptables -t mangle -A "$c" -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port "$OPERA_TP_PORT" --tproxy-mark "$OPERA_MARK/$OPERA_MARK" 2>/dev/null; rc=$?
    $iptables -t mangle -F "$c" 2>/dev/null; $iptables -t mangle -X "$c" 2>/dev/null
    return $rc
}

# opera_rules_on <исключённые uid> <uid приложений> [интерфейсы раздачи...]
# Сети групп — сотни правил: одним iptables-restore, как у WARP. Цепочки
# перезаполняются на месте, ip rule и таблица стоят
opera_rules_on() {
    local excl="$1" uids="$2" f="$OPERA_DQ_DIR/.rules" tp m u i s6; shift 2
    tp="-j TPROXY --on-ip 127.0.0.1 --on-port $OPERA_TP_PORT --tproxy-mark $OPERA_MARK/$OPERA_MARK"
    mkdir -p "$OPERA_DQ_DIR" 2>/dev/null
    {
        echo "*mangle"
        for m in "$CHAIN_OPERA_IN" "$CHAIN_OPERA_OUT" "$CHAIN_OPERA_TP"; do echo ":$m - [0:0]"; done
        # уже в WARP: TPROXY привязал бы к пакету сокет, а маршрут выбрал бы warp0 —
        # такой пакет ядро не форвардит, и клиент раздачи остался бы без связи
        echo "-A $CHAIN_OPERA_IN -m mark --mark $WARP_MARK/$WARP_MARK -j RETURN"
        # телефон: метка уже выбрала, что идёт в Opera. 127.0.0.0/8 — мимо: AdGuard
        # перенаправляет приложения на свой порт, метка остаётся, и hev получил бы
        # «127.0.0.1:33611» как адрес сайта (502 на всё, приложение молчит)
        echo "-A $CHAIN_OPERA_IN -i lo ! -d 127.0.0.0/8 -p tcp -m mark --mark $OPERA_MARK/$OPERA_MARK $tp"
        for i in "$@"; do echo "-A $CHAIN_OPERA_IN -i $i -p tcp -j $CHAIN_OPERA_TP"; done
        [ -n "$*" ] && opera_dst4 | while read -r m; do echo "-A $CHAIN_OPERA_TP -p tcp -d $m $tp"; done
        # ответы hev телефону: сокет наследует метку TPROXY, и SYN-ACK снова попал бы
        # в правило -i lo выше — приложение висит в SYN-SENT (05.11). addrtype в ядре нет
        echo "-A $CHAIN_OPERA_OUT -o lo -j MARK --set-xmark 0x0/$OPERA_MARK"
        echo "-A $CHAIN_OPERA_OUT -o lo -j RETURN"
        echo "-A $CHAIN_OPERA_OUT -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10 -j RETURN"
        # сам opera-proxy, nfqws и dnsproxy — мимо, иначе петля
        for u in $OPERA_GID $ZAPRET_GID $DNSPROXY_GID; do echo "-A $CHAIN_OPERA_OUT -m owner --gid-owner $u -j RETURN"; done
        # root и системные — мимо: проверка сайтов и подбор идут от root и не
        # должны «открывать» адреса через Opera, иначе врут
        echo "-A $CHAIN_OPERA_OUT -m owner --uid-owner 0-9999 -j RETURN"
        for u in $excl; do echo "-A $CHAIN_OPERA_OUT -m owner --uid-owner $u -j RETURN"; done
        for u in $uids; do echo "-A $CHAIN_OPERA_OUT -p tcp -m owner --uid-owner $u -j MARK --set-xmark $OPERA_MARK/$OPERA_MARK"; done
        [ "$OPERA_PHONE" = "1" ] && opera_dst4 | while read -r m; do
            echo "-A $CHAIN_OPERA_OUT -p tcp -d $m -j MARK --set-xmark $OPERA_MARK/$OPERA_MARK"
        done
        echo "COMMIT"
        # QUIC в TPROXY не попадёт, а сайт увидел бы адрес оператора: отказ,
        # браузер сразу перейдёт на TCP
        echo "*filter"
        for m in "$CHAIN_OPERA_QO" "$CHAIN_OPERA_QF"; do echo ":$m - [0:0]"; done
        echo "-A $CHAIN_OPERA_QO -m owner --uid-owner 0-9999 -j RETURN"
        for u in $excl; do echo "-A $CHAIN_OPERA_QO -m owner --uid-owner $u -j RETURN"; done
        for u in $uids; do echo "-A $CHAIN_OPERA_QO -p udp --dport 443 -m owner --uid-owner $u -j REJECT"; done
        [ "$OPERA_PHONE" = "1" ] && opera_dst4 | while read -r m; do echo "-A $CHAIN_OPERA_QO -p udp --dport 443 -d $m -j REJECT"; done
        [ -n "$*" ] && opera_dst4 | while read -r m; do echo "-A $CHAIN_OPERA_QF -p udp --dport 443 -d $m -j REJECT"; done
        echo "COMMIT"
    } > "$f"
    if ! ${iptables%% *}-restore -w 2 --noflush < "$f" 2>"$f.err" && \
       ! ${iptables%% *}-restore --noflush < "$f" 2>"$f.err"; then
        OPERA_RULE_ERR=$(tail -n 1 "$f.err" 2>/dev/null | cut -c1-120)
        rm -f "$f" "$f.err"
        opera_tproxy_ok || return 2
        return 1
    fi
    rm -f "$f" "$f.err"
    # в конец: TPROXY завершает обход таблицы, системные цепочки — раньше
    $iptables -t mangle -C PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null || $iptables -t mangle -A PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null
    $iptables -t mangle -C OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null || $iptables -t mangle -A OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null
    # FORWARD — вторым: первым должен стоять kill-switch
    $iptables -C OUTPUT -j "$CHAIN_OPERA_QO" 2>/dev/null || $iptables -I OUTPUT 1 -j "$CHAIN_OPERA_QO" 2>/dev/null
    $iptables -C FORWARD -j "$CHAIN_OPERA_QF" 2>/dev/null || $iptables -I FORWARD 2 -j "$CHAIN_OPERA_QF" 2>/dev/null

    # IPv6 групп и приложений — отбить, уйдёт на v4 (сайты из списка по IPv6 не
    # отбиваются). От адресов сайтов не зависит: их смена сюда не доходит
    s6="$OPERA_TELEGRAM$OPERA_GOOGLE$OPERA_PHONE|$excl|$uids|$*"
    [ "$s6" = "$OPERA_V6_SIG" ] && $ip6tables -C OUTPUT -j "$CHAIN_OPERA_V6" 2>/dev/null && \
        $ip6tables -C FORWARD -j "$CHAIN_OPERA_V6F" 2>/dev/null && s6=""
    if [ -n "$s6" ]; then
    $ip6tables -N "$CHAIN_OPERA_V6" 2>/dev/null; $ip6tables -F "$CHAIN_OPERA_V6" 2>/dev/null
    $ip6tables -A "$CHAIN_OPERA_V6" -m owner --uid-owner 0-9999 -j RETURN 2>/dev/null
    for u in $excl; do $ip6tables -A "$CHAIN_OPERA_V6" -m owner --uid-owner "$u" -j RETURN 2>/dev/null; done
    {
        for u in $uids; do echo "-m owner --uid-owner $u"; done
        [ "$OPERA_PHONE" = "1" ] && opera_dst6 | while read -r m; do echo "-d $m"; done
    } | while read -r m; do
        $ip6tables -A "$CHAIN_OPERA_V6" $m -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null
        $ip6tables -A "$CHAIN_OPERA_V6" $m -j REJECT --reject-with icmp6-adm-prohibited 2>/dev/null
    done
    $ip6tables -C OUTPUT -j "$CHAIN_OPERA_V6" 2>/dev/null || $ip6tables -I OUTPUT 1 -j "$CHAIN_OPERA_V6" 2>/dev/null
    $ip6tables -N "$CHAIN_OPERA_V6F" 2>/dev/null; $ip6tables -F "$CHAIN_OPERA_V6F" 2>/dev/null
    for i in "$@"; do
        opera_dst6 | while read -r m; do
            $ip6tables -A "$CHAIN_OPERA_V6F" -i "$i" -d "$m" -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null
            $ip6tables -A "$CHAIN_OPERA_V6F" -i "$i" -d "$m" -j REJECT --reject-with icmp6-adm-prohibited 2>/dev/null
        done
    done
    $ip6tables -C FORWARD -j "$CHAIN_OPERA_V6F" 2>/dev/null || $ip6tables -I FORWARD 1 -j "$CHAIN_OPERA_V6F" 2>/dev/null
    OPERA_V6_SIG="$s6"
    fi

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
    $iptables -C OUTPUT -j "$CHAIN_OPERA_QO" 2>/dev/null || return 1
    $iptables -C FORWARD -j "$CHAIN_OPERA_QF" 2>/dev/null || return 1
    $ip6tables -C OUTPUT -j "$CHAIN_OPERA_V6" 2>/dev/null || return 1
    $ip6tables -C FORWARD -j "$CHAIN_OPERA_V6F" 2>/dev/null || return 1
    $ip rule show 2>/dev/null | grep -q "^$OPERA_PREF:.*lookup $OPERA_TABLE" || return 1
    $ip route show table "$OPERA_TABLE" 2>/dev/null | grep -q . || return 1
}

# Прокси пропускает? Через SOCKS opera-proxy, от его группы: мимо перенаправления
opera_probe() {
    local code g="sh -c"
    [ -n "$CURL_BIN" ] || return 0      # нечем проверить — не перезапускать рабочий прокси
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
    case "$OPERA_FAILS" in 1|2|3) p=3 ;; 4) p=15 ;; *) p=60 ;; esac   # итераций по ~2с
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
    local want=0 sig rc now ifaces="" n
    if ! opera_wanted; then
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
            # другая сеть — прошлые неудачи не в счёт
            [ "$LAST_WAN_IFACE" != "$OPERA_WAN" ] && { OPERA_WAN="$LAST_WAN_IFACE"; OPERA_RETRY=0; OPERA_FAILS=0; }
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
        opera_exempt
        opera_log_trim
        if [ "$want" = "1" ]; then
            if opera_probe; then
                OPERA_BAD=0
            else
                OPERA_BAD=$((OPERA_BAD + 1))
                [ "$OPERA_BAD" -ge 3 ] && { opera_fail "прокси не отвечает"; return 0; }
                # через Opera могут идти целые группы: следующая проверка — через ~6 с
                OPERA_TICK=12
            fi
        fi
    fi

    if [ "$want" != "1" ]; then
        [ -n "$OPERA_RULES_SIG" ] && { opera_rules_off; log "opera: правила сняты (VPN поднят)"; }
        return 0
    fi
    now=$(date +%s)
    [ $((now - OPERA_DOM_TS)) -ge $OPERA_DOM_SECS ] && opera_domains_refresh
    if [ $((now - OPERA_APP_TS)) -ge 30 ]; then
        OPERA_APP_UIDS=$(opera_app_uids); OPERA_EXCL=$(zapret_vpn_uids); OPERA_APP_TS=$now
    fi
    if [ -z "$OPERA_DOM_IPS$OPERA_APP_UIDS" ] && [ "$OPERA_TELEGRAM$OPERA_GOOGLE" = "00" ]; then
        [ -n "$OPERA_RULES_SIG" ] && opera_rules_off
        return 0
    fi
    # раздача — только в режиме «напрямую»: TPROXY забирает пакет до FORWARD, и
    # в blocked клиенты вышли бы мимо kill-switch
    [ "$VPN_TETHER_MODE" = "off" ] && [ "$OPERA_TETHER" = "1" ] && ifaces="$LAST_TETHER_IFACES"
    sig="$OPERA_TELEGRAM$OPERA_GOOGLE$OPERA_PHONE|$ifaces|$OPERA_EXCL|$OPERA_APP_UIDS|$OPERA_DOM_IPS"
    [ "$sig" = "$OPERA_RULES_SIG" ] && { [ "$OPERA_TICK" != 0 ] || opera_rules_ok; } && return 0
    # без opera_rules_off: цепочки перезаполняются на месте, ip rule и таблица стоят —
    # новый адрес одного сайта не рвёт соединения других
    opera_rules_on "$OPERA_EXCL" "$OPERA_APP_UIDS" $ifaces; rc=$?
    if [ "$rc" = 0 ]; then
        OPERA_RULES_SIG="$sig"
        n=$(opera_dst4 | grep -c .)
        OPERA_NETS=$(echo $OPERA_APP_UIDS | wc -w)
        { [ "$OPERA_PHONE" = "1" ] || [ -n "$ifaces" ]; } && OPERA_NETS=$((OPERA_NETS + n))
        log "opera: через Opera ${OPERA_ENDPOINT:-?}: сетей $n, приложений $(echo $OPERA_APP_UIDS | wc -w | tr -d ' '), общих CDN мимо: ${OPERA_DOM_SKIP:-0}, телефон: $OPERA_PHONE, раздача: ${ifaces:-нет}"
        phone_status_refresh
    elif [ "$rc" = 2 ]; then
        opera_rules_off
        OPERA_NOSUPPORT=1; OPERA_STATE="fail"; OPERA_ERR="ядро без TPROXY"
        log "WARNING: opera: $OPERA_ERR"; phone_status_refresh
    else
        opera_rules_off
        opera_fail "правила не встали: $OPERA_RULE_ERR"
    fi
}
