# shellcheck shell=sh
# lib/warp.sh — WARP-туннель (AmneziaWG: userspace amneziawg-go + awg) в
# режиме «напрямую»: запуск, проверка трафиком, сторож, переход на другой
# конфиг, первые конфиги при первом запуске. Хранилище, импорт и генерация
# конфигов — warp/warp.sh. Что именно пускать в туннель — отдельно.
# Часть демона service.sh: подключается из него через ".", сам не запускается.
#
# Туннель — только когда VPN на телефоне не поднят: иначе UDP до Cloudflare
# от root уходит в tun (проверено 26.10), и WARP шёл бы внутри VPN.
# Интерфейс warp0 нарочно не tun*/wg*: модуль считает такие VPN-ом.

WARP_IF=warp0
WARP_TABLE=3996          # своя таблица: default dev warp0
WARP_PREF=2980           # «oif warp0 -> WARP_TABLE», раньше правил раздачи (3000) и netd
WARP_DIR=/data/adb/vpn_tether_warp
WARP_SOCK_DIR=/data/local/tmp/amneziawg   # вшит в amneziawg-go и awg при сборке
WARP_RUN=/data/local/tmp/vpn_tether_warp  # .wg (на миг, с ключом), .log, .ensure
WARP_CHECK_SECS=60       # проверка трафиком, пока всё хорошо
WARP_BAD_SECS=600        # конфиг, на котором не поднялось, — не брать 10 мин
WARP_RETRY_SECS=300      # все конфиги не поднялись / их нет — повтор через 5 мин
WARP_STATE=off           # off | starting | up | fail
WARP_CUR=""              # конфиг в работе
WARP_PID=""
WARP_TS=0                # когда запущен / поднялся
WARP_CHECK_TS=0          # последняя проверка трафиком (0 — проверить сейчас)
WARP_FAILS=0             # проверок подряд без ответа
WARP_CRASH=""            # конфиг, упавший сразу после подъёма (второй раз — в «плохие»)
WARP_BAD=""              # «имя:epoch …»
WARP_RETRY_TS=0
WARP_NOTE=""             # почему fail — для лога и WebUI
WARP_ENSURE_PID=""
WARP_ENSURE_DONE=0
WARP_SU_G=""             # su -g работает (проверка — мимо прокси AdGuard)
WARP_CA=/apex/com.android.conscrypt/cacerts
[ -d "$WARP_CA" ] || WARP_CA=/system/etc/security/cacerts

# Остатки от убитого демона: интерфейс, правило, процесс, сокет
warp_kill_strays() {
    local p
    for p in $(pidof amneziawg-go-arm64 amneziawg-go-arm 2>/dev/null); do kill "$p" 2>/dev/null; done
}

warp_down() {   # [причина] — пусто: молча
    $ip rule del oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    $ip -6 rule del oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    $ip route flush table $WARP_TABLE 2>/dev/null
    $ip -6 route flush table $WARP_TABLE 2>/dev/null
    $ip link del $WARP_IF 2>/dev/null
    [ -n "$WARP_PID" ] && kill "$WARP_PID" 2>/dev/null
    warp_kill_strays
    rm -f "$WARP_SOCK_DIR/$WARP_IF.sock" "$WARP_RUN.wg"
    [ -n "$1" ] && [ "$WARP_STATE" != off ] && log "WARP: туннель снят ($1)"
    WARP_PID=""; WARP_CUR=""; WARP_STATE=off; WARP_FAILS=0
}

# Конфиги по порядку: выбранный в WARP_CONF первым, дальше по имени
warp_conf_names() {
    local f n
    [ -n "$WARP_CONF" ] && [ -f "$WARP_DIR/$WARP_CONF.conf" ] && echo "$WARP_CONF"
    for f in "$WARP_DIR"/*.conf; do
        [ -f "$f" ] || continue
        n=${f##*/}; n=${n%.conf}
        [ "$n" = "$WARP_CONF" ] || echo "$n"
    done
}

warp_is_bad() {
    local e now=$(date +%s)
    for e in $WARP_BAD; do
        [ "${e%:*}" = "$1" ] && [ $((now - ${e##*:})) -lt $WARP_BAD_SECS ] && return 0
    done
    return 1
}

warp_mark_bad() {
    local e keep=""
    for e in $WARP_BAD; do [ "${e%:*}" = "$1" ] || keep="$keep $e"; done
    WARP_BAD="${keep# } $1:$(date +%s)"
}

warp_pick() {   # первый конфиг не из «плохих»; нет — код 1
    local n
    for n in $(warp_conf_names); do
        warp_is_bad "$n" || { echo "$n"; return 0; }
    done
    return 1
}

warp_start() {   # имя конфига
    local n="$1" f="$WARP_DIR/$1.conf" a mtu i=0 rc
    warp_down
    # старые прошивки (8.1): /dev/tun вместо /dev/net/tun
    [ -e /dev/net/tun ] || { mkdir -p /dev/net && ln -s /dev/tun /dev/net/tun; } 2>/dev/null
    mkdir -p "$WARP_SOCK_DIR"
    WG_PROCESS_FOREGROUND=1 "$AWG_GO_BIN" "$WARP_IF" > "$WARP_RUN.log" 2>&1 < /dev/null &
    WARP_PID=$!
    while [ $i -lt 30 ] && [ ! -S "$WARP_SOCK_DIR/$WARP_IF.sock" ]; do sleep 0.1; i=$((i + 1)); done
    # awg не знает Address/DNS/MTU (это wg-quick) — без них; файл с ключом — на миг
    (umask 077; grep -vE '^[[:space:]]*(#|(Address|DNS|MTU)[[:space:]]*=)' "$f" > "$WARP_RUN.wg")
    "$AWG_BIN" setconf "$WARP_IF" "$WARP_RUN.wg" >> "$WARP_RUN.log" 2>&1; rc=$?
    rm -f "$WARP_RUN.wg"
    if [ $rc != 0 ]; then
        log "WARP: $n — не запустился (amneziawg-go/awg setconf: $(tail -1 "$WARP_RUN.log" 2>/dev/null | cut -c1-120))"
        warp_down; warp_mark_bad "$n"; return 1
    fi
    for a in $(sed -n 's/^[[:space:]]*Address[[:space:]]*=//p' "$f" | tr ',' ' '); do
        case "$a" in
            *:*) $ip -6 addr add "$a" dev $WARP_IF 2>/dev/null ;;
            *.*) $ip addr add "$a" dev $WARP_IF 2>/dev/null ;;
        esac
    done
    mtu=$(sed -n 's/^[[:space:]]*MTU[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$f" | head -1)
    $ip link set $WARP_IF mtu "${mtu:-1280}" up 2>/dev/null
    $ip route replace default dev $WARP_IF table $WARP_TABLE 2>/dev/null
    $ip -6 route replace default dev $WARP_IF table $WARP_TABLE 2>/dev/null
    $ip rule add oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    $ip -6 rule add oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    WARP_CUR="$n"; WARP_STATE=starting; WARP_TS=$(date +%s); WARP_CHECK_TS=0; WARP_FAILS=0
    log "WARP: запускаю $n ($(sed -n 's/^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*//p' "$f" | head -1))"
    return 0
}

# Трафик через туннель есть: Cloudflare отвечает «warp=on». От группы
# dnsproxy — мимо прокси AdGuard (с --interface он даёт тайм-аут).
warp_probe() {
    local cmd="curl -s -m 5 --interface $WARP_IF --capath $WARP_CA https://www.cloudflare.com/cdn-cgi/trace" out
    if [ -z "$WARP_SU_G" ]; then
        WARP_SU_G=0
        su -g "$DNSPROXY_GID" -c true >/dev/null 2>&1 && WARP_SU_G=1
    fi
    if [ "$WARP_SU_G" = "1" ]; then out=$(su -g "$DNSPROXY_GID" -c "$cmd" 2>/dev/null); else out=$(eval "$cmd" 2>/dev/null); fi
    case "$out" in *warp=on*|*warp=plus*) return 0 ;; esac
    return 1
}

# Первый запуск: конфигов нет — создать 3 (в фоне: регистрация до ~15 с)
warp_ensure() {
    local r
    if [ -n "$WARP_ENSURE_PID" ]; then
        kill -0 "$WARP_ENSURE_PID" 2>/dev/null && return 0
        WARP_ENSURE_PID=""
        r=$(head -1 "$WARP_RUN.ensure" 2>/dev/null); rm -f "$WARP_RUN.ensure"
        case "$r" in
            OK*) log "WARP: созданы конфиги:${r#OK}"; WARP_RETRY_TS=0 ;;
            '') ;;
            *) log "WARP: не удалось создать конфиги — $r" ;;
        esac
        return 0
    fi
    [ "$WARP_ENSURE_DONE" = 1 ] && return 0
    WARP_ENSURE_DONE=1
    [ -f "$WARP_DIR/.init" ] && return 0
    ls "$WARP_DIR"/*.conf >/dev/null 2>&1 && return 0
    log "WARP: конфигов нет — создаю 3 (первый запуск)"
    sh "$MODULE_DIR/warp/warp.sh" ensure 3 > "$WARP_RUN.ensure" 2>/dev/null < /dev/null &
    WARP_ENSURE_PID=$!
}

warp_set_state() {   # состояние [заметка] — со статусом для WebUI
    [ "$WARP_STATE|$WARP_NOTE" = "$1|$2" ] && return 0
    WARP_STATE="$1"; WARP_NOTE="$2"
    phone_status_refresh
}

# Сторож: каждый проход цикла; дорогое (curl) — редко
warp_reconcile() {
    local now n why=""
    if [ "$WARP_ENABLE" != "1" ]; then why="выключен"
    elif [ -z "$AWG_BIN" ] || [ -z "$AWG_GO_BIN" ]; then why="нет бинарей"
    elif vpn_up_now; then why="поднят VPN"
    elif [ "$WAN_DOWN_LOGGED" = "1" ] || [ -z "$LAST_WAN_IFACE" ]; then why="нет сети"
    fi
    [ "$WARP_ENABLE" = "1" ] && [ -n "$AWG_BIN" ] && warp_ensure
    if [ -n "$why" ]; then
        if [ "$WARP_STATE" != off ]; then warp_down "$why"; WARP_BAD=""; WARP_RETRY_TS=0; warp_set_state off; fi
        return 0
    fi
    now=$(date +%s)
    case "$WARP_STATE" in
        off|fail)
            [ "$WARP_STATE" = fail ] && [ "$now" -lt "$WARP_RETRY_TS" ] && return 0
            [ -n "$WARP_ENSURE_PID" ] && return 0   # конфиги ещё создаются
            if ! n=$(warp_pick); then
                if [ -z "$(warp_conf_names)" ]; then
                    [ "$WARP_NOTE" = "нет конфигов" ] || log "WARP: нет конфигов — создайте или импортируйте в WebUI"
                    warp_set_state fail "нет конфигов"
                else
                    log "WARP: ни один конфиг не поднялся — повтор через $((WARP_RETRY_SECS / 60)) мин"
                    warp_set_state fail "не поднялся"
                fi
                WARP_BAD=""; WARP_RETRY_TS=$((now + WARP_RETRY_SECS))
                return 0
            fi
            warp_start "$n" && phone_status_refresh ;;
        starting)
            if warp_probe; then
                log "WARP: $WARP_CUR поднят за $(( $(date +%s) - WARP_TS )) с"
                WARP_TS=$(date +%s); WARP_CHECK_TS=$WARP_TS; WARP_FAILS=0
                warp_set_state up ""
            else
                WARP_FAILS=$((WARP_FAILS + 1))
                # 3 проверки по 5 с + такты цикла ≈ 20 с (свежий поднимается за ~0,7 с)
                if [ $WARP_FAILS -ge 3 ]; then
                    log "WARP: $WARP_CUR — нет трафика через туннель, беру следующий"
                    warp_mark_bad "$WARP_CUR"; warp_down; warp_set_state off ""
                fi
            fi ;;
        up)
            # процесс умер (или интерфейс снесли) — сразу на перезапуск, без проверок
            if { [ -n "$WARP_PID" ] && ! kill -0 "$WARP_PID" 2>/dev/null; } || [ ! -d /sys/class/net/$WARP_IF ]; then
                n=$(tail -1 "$WARP_RUN.log" 2>/dev/null | cut -c1-120)
                log "WARP: туннель пропал${n:+ ($n)}, перезапуск"
                # второй раз подряд падает сразу после подъёма — не крутить
                # его по кругу каждые 2 с (одно падение — просто перезапуск)
                if [ $((now - WARP_TS)) -lt 60 ]; then
                    [ "$WARP_CRASH" = "$WARP_CUR" ] && warp_mark_bad "$WARP_CUR"
                    WARP_CRASH="$WARP_CUR"
                else
                    WARP_CRASH=""
                fi
                warp_down; warp_set_state off ""; return 0
            fi
            [ $((now - WARP_CHECK_TS)) -lt $WARP_CHECK_SECS ] && return 0
            WARP_CHECK_TS=$now
            if warp_probe; then
                [ $WARP_FAILS -gt 0 ] && log "WARP: $WARP_CUR снова отвечает"
                WARP_FAILS=0
            else
                WARP_FAILS=$((WARP_FAILS + 1))
                # после сбоя — проверять чаще: 3 подряд ≈ полминуты
                WARP_CHECK_TS=$((now - WARP_CHECK_SECS + 10))
                log "WARP: $WARP_CUR не отвечает ($WARP_FAILS/3)"
                if [ $WARP_FAILS -ge 3 ]; then
                    warp_mark_bad "$WARP_CUR"; warp_down "не отвечает"; warp_set_state off ""
                fi
            fi ;;
    esac
}
