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
WARP_RUN=/data/local/tmp/vpn_tether_warp  # .log, .ensure (файл с ключом — $WARP_DIR/.run.wg, на миг)
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
WARP_CF=0                # Endpoint — сервер Cloudflare: проверка требует warp=on
WARP_EP0=""              # адрес из конфига (engage… — числом)
WARP_EP_FILE=$WARP_DIR/.endpoints   # «сеть|адрес» — рабочий адрес Cloudflare для сети
WARP_EP_FULL=0           # конфигов за круг, не давших хендшейк ни на одном адресе пула
WARP_EP_TRIED=""         # адреса, уже испробованные этим конфигом
WARP_EP_Q=""             # ещё не испробованные
WARP_EP_CUR=""           # пробуем сейчас
WARP_EP_T0=0             # когда подан (мс от загрузки)
WARP_HS=0                # хендшейк на WARP_EP_CUR был
WARP_NETCHG=0            # сменилась сеть (loop.sh), туннель на ней ещё не проверен
WARP_ENSURE_WAIT=300     # пауза перед повтором создания конфигов: удваивается, до часа
WARP_BAD=""              # «имя:epoch …»
WARP_RETRY_TS=0
WARP_NOTE=""             # почему fail — для лога и WebUI
WARP_PUB=""              # «состояние|заметка», уже записанные в status
WARP_ENSURE_PID=""
WARP_ENSURE_DONE=0
WARP_ENSURE_AT=0         # не вышло (нет сети при загрузке) — повтор после этого времени
WARP_SU_G=""             # su -g работает (проверка — мимо прокси AdGuard)
WARP_CA=/apex/com.android.conscrypt/cacerts
[ -d "$WARP_CA" ] || WARP_CA=/system/etc/security/cacerts

# Остатки от убитого демона: интерфейс, правило, процесс, сокет
warp_kill_strays() {
    local p
    for p in $(pidof amneziawg-go-arm64 amneziawg-go-arm 2>/dev/null); do kill "$p" 2>/dev/null; done
}

warp_down() {   # [причина] — пусто: молча
    warp_routes_off
    $ip rule del oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    $ip -6 rule del oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    $ip route flush table $WARP_TABLE 2>/dev/null
    $ip -6 route flush table $WARP_TABLE 2>/dev/null
    $ip link del $WARP_IF 2>/dev/null
    [ -n "$WARP_PID" ] && kill "$WARP_PID" 2>/dev/null
    warp_kill_strays
    rm -f "$WARP_SOCK_DIR/$WARP_IF.sock" "$WARP_DIR/.run.wg"
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

# .run.wg для awg (с ключом — на миг). awg не знает Address/DNS/MTU (это
# wg-quick) — без них. AllowedIPs — весь трафик: что пускать в туннель, решают
# наши правила, а «сплит» из генератора молча отбросил бы Telegram/Google.
# $2 — адрес вместо Endpoint конфига (пусто — как в конфиге)
warp_wg_file() {   # конфиг [адрес]
    (umask 077; awk -v ep="$2" '/^[ \t]*(#|(Address|DNS|MTU|AllowedIPs|J[1-3]|Itime)[ \t]*=)/ { next }
        ep != "" && /^[ \t]*Endpoint[ \t]*=/ { print "Endpoint = " ep; next }
        { print }
        /^[ \t]*\[Peer\]/ { print "AllowedIPs = 0.0.0.0/0, ::/0" }' "$1" > "$WARP_DIR/.run.wg")
}

# Адреса Cloudflare по порядку: рабочий для этой сети, из конфига, пул
# (warp/endpoints.txt). После двух конфигов без хендшейка за круг — без пула:
# на сети, где WARP закрыт целиком, не гонять весь пул по каждому конфигу.
warp_ep_list() {
    { [ -f "$WARP_EP_FILE" ] && awk -F'|' -v k="${NET_KEY:--}" '$1 == k { print $2 }' "$WARP_EP_FILE"
      echo "$WARP_EP0"
      [ "$WARP_EP_FULL" -lt 2 ] && grep -E '^[0-9.]+:[0-9]+$' "$MODULE_DIR/warp/endpoints.txt" 2>/dev/null
    } | awk 'NF && !s[$0]++'
}

warp_ep_save() {   # адрес — рабочий для текущей сети
    local k="${NET_KEY:--}"
    { awk -F'|' -v k="$k" '$1 != k' "$WARP_EP_FILE" 2>/dev/null | tail -n 49; echo "$k|$1"; } > "$WARP_EP_FILE.tmp" &&
        mv -f "$WARP_EP_FILE.tmp" "$WARP_EP_FILE"
}

# Сети режут WARP по-разному (замер 28.10, 9 сетей): одни — подсети
# 188.114.96/97, другие — всё, кроме них, роутер МТС — порты 500/4500. Адрес
# из конфига молчит — следующий; признак — хендшейк за 4 с (замер: 0,1–0,9 с),
# а не проверка трафиком (~25 с на попытку). 28.10 на роутере МТС 14 конфигов
# подряд ушли в «плохие» за 7,5 мин — все на одном 162.159.192.1:4500.
# По шагу на проход цикла (~2 с): ждать 10 адресов подряд — 40 с без сторожа.
warp_ep_kick() {   # адрес — пробуем его с этого момента
    WARP_EP_CUR="$1"; WARP_EP_TRIED="$WARP_EP_TRIED $1"; WARP_EP_T0=$(uptime_ms)
    # пакет в туннель — повод для хендшейка (и PersistentKeepalive)
    ping -c 1 -W 1 -I $WARP_IF 1.1.1.1 >/dev/null 2>&1 &
}

warp_ep_step() {   # 0 — ждём или дождались (WARP_HS=1), 1 — адреса кончились
    local hs e was
    hs=$("$AWG_BIN" show $WARP_IF latest-handshakes 2>/dev/null | awk '{print $2; exit}')
    if [ "${hs:-0}" -gt 0 ]; then
        # запомнить для сети — после warp=on (warp_reconcile): хендшейк без
        # трафика не повод ставить адрес первым для всех конфигов
        WARP_HS=1; WARP_EP_FULL=0
        was="${WARP_EP_TRIED% $WARP_EP_CUR}"; was="${was# }"
        [ "$WARP_EP_CUR" = "$WARP_EP0" ] || log "WARP: $WARP_CUR — через $WARP_EP_CUR${was:+ (молчали: $was)}"
        return 0
    fi
    [ $(( $(uptime_ms) - WARP_EP_T0 )) -lt 4000 ] && return 0
    set -- $WARP_EP_Q
    [ $# -gt 0 ] || return 1
    e="$1"; shift; WARP_EP_Q="$*"
    warp_wg_file "$WARP_DIR/$WARP_CUR.conf" "$e"
    "$AWG_BIN" setconf "$WARP_IF" "$WARP_DIR/.run.wg" >> "$WARP_RUN.log" 2>&1
    rm -f "$WARP_DIR/.run.wg"
    warp_ep_kick "$e"
    return 0
}

warp_start() {   # имя конфига
    local n="$1" f="$WARP_DIR/$1.conf" a mtu i=0 rc ep1=""
    warp_down
    # старые прошивки (8.1): /dev/tun вместо /dev/net/tun
    [ -e /dev/net/tun ] || { mkdir -p /dev/net && ln -s /dev/tun /dev/net/tun; } 2>/dev/null
    # каталог сокета — в /data/local/tmp (вшит при сборке), там пишет и shell:
    # пересоздаём своим (root, 700), чтобы awg не отдал ключ чужому сокету
    rm -rf "$WARP_SOCK_DIR"
    if ! mkdir -m 700 "$WARP_SOCK_DIR" 2>/dev/null; then
        # кто-то успел создать его между rm и mkdir — ключ туда не отдаём
        log "WARNING: WARP: каталог сокета $WARP_SOCK_DIR занят чужим — не запускаю"
        warp_down; WARP_RETRY_TS=$(( $(date +%s) + 60 )); warp_set_state fail "amneziawg-go не запустился"
        return 1
    fi
    WG_PROCESS_FOREGROUND=1 "$AWG_GO_BIN" "$WARP_IF" > "$WARP_RUN.log" 2>&1 < /dev/null &
    WARP_PID=$!
    # холодный старт на слабом телефоне (MT6580) — до нескольких секунд
    while [ $i -lt 100 ] && [ ! -S "$WARP_SOCK_DIR/$WARP_IF.sock" ]; do sleep 0.1; i=$((i + 1)); done
    if [ ! -S "$WARP_SOCK_DIR/$WARP_IF.sock" ]; then
        # не вина конфига — в «плохие» не ставим, повтор через минуту
        log "WARP: amneziawg-go не запустился за 10 с ($(tail -1 "$WARP_RUN.log" 2>/dev/null | cut -c1-120))"
        warp_down; WARP_RETRY_TS=$(( $(date +%s) + 60 )); warp_set_state fail "amneziawg-go не запустился"
        return 1
    fi
    # сервер Cloudflare — проверка строже: trace должен сказать warp=on (не
    # «ответил кто-то по дороге»); свой сервер так не скажет — ему любой ответ.
    # Cloudflare — и подбор адреса (warp_ep_step); свой сервер не трогаем.
    WARP_CF=0; WARP_EP0=""
    grep -qE '^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*(engage\.cloudflareclient\.com|162\.159\.|188\.114\.)' "$f" && WARP_CF=1
    if [ "$WARP_CF" = 1 ]; then
        # Endpoint WARP — адресом: awg резолвит имя сам, и без DNS «Configuration
        # parsing error» записывал исправный конфиг в «плохие» (27.10 09:52)
        WARP_EP0=$(sed -n 's/^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*//p' "$f" | head -1 | tr -d ' \r')
        case "$WARP_EP0" in engage.cloudflareclient.com:*) WARP_EP0="162.159.192.1:${WARP_EP0##*:}" ;; esac
        ep1=$(warp_ep_list | head -1)
    fi
    warp_wg_file "$f" "$ep1"
    "$AWG_BIN" setconf "$WARP_IF" "$WARP_DIR/.run.wg" >> "$WARP_RUN.log" 2>&1; rc=$?
    rm -f "$WARP_DIR/.run.wg"
    if [ $rc != 0 ]; then
        log "WARP: $n — не запустился (awg setconf: $(tail -2 "$WARP_RUN.log" 2>/dev/null | tr '\n' ' ' | cut -c1-160))"
        # Имя Endpoint не находится (bionic: «No address associated with
        # hostname»). У WARP имя подставлено адресом выше, так что это свой
        # сервер или шаблон (server.example.com из zip AmneziaVPN, 27.10):
        # пропускаем на WARP_BAD_SECS, как плохой, и сразу берём следующий —
        # ждать минуту на одном и том же значило бы не дойти до рабочих
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
    # обратный маршрут ответов идёт не через warp0: при строгом rp_filter прошивки они бы отбрасывались
    echo 2 > /proc/sys/net/ipv4/conf/$WARP_IF/rp_filter 2>/dev/null
    $ip route replace default dev $WARP_IF table $WARP_TABLE 2>/dev/null
    $ip -6 route replace default dev $WARP_IF table $WARP_TABLE 2>/dev/null
    $ip rule add oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    $ip -6 rule add oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    WARP_CUR="$n"; WARP_STATE=starting; WARP_TS=$(date +%s); WARP_CHECK_TS=0; WARP_FAILS=0; WARP_NETCHG=0
    log "WARP: запускаю $n ($(sed -n 's/^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*//p' "$f" | head -1))"
    WARP_HS=0; WARP_EP_TRIED=""; WARP_EP_Q=""
    if [ "$WARP_CF" = 1 ]; then
        WARP_EP_Q=$(warp_ep_list | awk 'NR > 1' | tr '\n' ' ')
        warp_ep_kick "$ep1"
    fi
    return 0
}

# Трафик через туннель есть: trace Cloudflare ответил через warp0. Сервер
# Cloudflare — нужен «warp=on» (WARP_CF); свой AmneziaWG/WireGuard честно
# отвечает «warp=off» и отбраковывался (лог 4PDA 26.10) — ему любой ответ. От группы dnsproxy — мимо
# прокси AdGuard (с --interface он даёт тайм-аут).
warp_probe() {
    # по IP: при отказе DNS (DoH не отвечает) проверка по имени валилась и
    # живой туннель считался мёртвым (27.10 09:52)
    local cmd="curl -s -m 5 --interface $WARP_IF --capath $WARP_CA https://1.1.1.1/cdn-cgi/trace" out
    if [ -z "$WARP_SU_G" ]; then
        WARP_SU_G=0
        su -g "$DNSPROXY_GID" -c true >/dev/null 2>&1 && WARP_SU_G=1
    fi
    if [ "$WARP_SU_G" = "1" ]; then out=$(su -g "$DNSPROXY_GID" -c "$cmd" 2>/dev/null); else out=$(eval "$cmd" 2>/dev/null); fi
    if [ "$WARP_CF" = 1 ]; then
        case "$out" in *warp=on*|*warp=plus*) return 0 ;; esac
    else
        case "$out" in *ip=*) return 0 ;; esac
    fi
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
            *) log "WARP: не удалось создать конфиги — $r (повтор через $((WARP_ENSURE_WAIT / 60)) мин)"
               # Cloudflare стабильно не отвечает — не дёргать nfqws и правила
               # каждые 5 минут: пауза растёт вдвое, до часа
               WARP_ENSURE_DONE=0; WARP_ENSURE_AT=$(( $(date +%s) + WARP_ENSURE_WAIT ))
               WARP_ENSURE_WAIT=$((WARP_ENSURE_WAIT * 2)); [ "$WARP_ENSURE_WAIT" -gt 3600 ] && WARP_ENSURE_WAIT=3600 ;;
        esac
        return 0
    fi
    [ "$WARP_ENSURE_DONE" = 1 ] && return 0
    [ "$(date +%s)" -lt "$WARP_ENSURE_AT" ] && return 0
    WARP_ENSURE_DONE=1
    [ -f "$WARP_DIR/.init" ] && return 0
    ls "$WARP_DIR"/*.conf >/dev/null 2>&1 && return 0
    log "WARP: конфигов нет — создаю 3 (первый запуск)"
    sh "$MODULE_DIR/warp/warp.sh" ensure 3 > "$WARP_RUN.ensure" 2>/dev/null < /dev/null &
    WARP_ENSURE_PID=$!
}

warp_set_state() {   # состояние [заметка] — со статусом для WebUI
    WARP_STATE="$1"; WARP_NOTE="$2"
    # сверяем с тем, что уже в status: warp_down сам ставит off, и сравнение
    # с WARP_STATE оставляло в status «up» после снятия туннеля
    [ "$WARP_PUB" = "$1|$2" ] && return 0
    WARP_PUB="$1|$2"
    phone_status_refresh
}

# Сторож: каждый проход цикла; дорогое (curl) — редко
warp_reconcile() {
    local now n why=""
    if [ "$WARP_ENABLE" != "1" ]; then why="выключен"
    elif [ -z "$AWG_BIN" ] || [ -z "$AWG_GO_BIN" ]; then why="нет бинарей"
    elif vpn_up_now; then why="поднят VPN"
    # раздача на паузе (kill-switch) или VPN переподключается (гистерезис держит «on»):
    # WARP впереди guard открыл бы клиентам Telegram/Google — «VPN или ничего»
    elif [ "$VPN_TETHER_MODE" = "blocked" ]; then why="пауза kill-switch"
    elif [ "$VPN_TETHER_MODE" != "off" ]; then why="поднят VPN"
    elif [ "$WAN_DOWN_LOGGED" = "1" ] || [ -z "$LAST_WAN_IFACE" ]; then why="нет сети"
    fi
    # первые конфиги — только при сети (иначе регистрация падает до перезагрузки)
    [ -z "$why" ] && warp_ensure
    if [ -n "$why" ]; then
        if [ "$WARP_STATE" != off ]; then warp_down "$why"; WARP_BAD=""; WARP_EP_FULL=0; WARP_RETRY_TS=0; fi
        warp_set_state off "$why"   # повторы отсекает WARP_PUB
        return 0
    fi
    now=$(date +%s)
    case "$WARP_STATE" in
        off|fail)
            if [ "$WARP_STATE" = fail ] && [ "$now" -lt "$WARP_RETRY_TS" ]; then
                # конфиги создали/импортировали в WebUI — сразу, не через 5 мин
                [ "$WARP_NOTE" = "нет конфигов" ] && [ -n "$(warp_conf_names)" ] || return 0
            fi
            [ -n "$WARP_ENSURE_PID" ] && return 0   # конфиги ещё создаются
            if ! n=$(warp_pick); then
                if [ -z "$(warp_conf_names)" ]; then
                    [ "$WARP_NOTE" = "нет конфигов" ] || log "WARP: нет конфигов — создайте или импортируйте в WebUI"
                    warp_set_state fail "нет конфигов"
                else
                    log "WARP: ни один конфиг не поднялся — повтор через $((WARP_RETRY_SECS / 60)) мин"
                    warp_set_state fail "не поднялся"
                fi
                WARP_BAD=""; WARP_EP_FULL=0; WARP_RETRY_TS=$((now + WARP_RETRY_SECS))
                return 0
            fi
            # NET_KEY (адрес для сети) считает zapret_reconcile — при выключенном
            # zapret он не обновляется, и адрес новой сети лёг бы под ключ старой
            net_identity_reconcile
            warp_start "$n" && warp_set_state starting "" ;;
        starting)
            if [ "$WARP_NETCHG" = 1 ]; then
                # сеть сменилась посреди подъёма (warp_start флаг сбросил):
                # очередь адресов и промахи — от прошлой сети, конфиг не виноват
                WARP_NETCHG=0
                warp_down "сменилась сеть"; warp_set_state off ""
            elif [ "$WARP_CF" = 1 ] && [ "$WARP_HS" = 0 ]; then
                # адрес Cloudflare: сначала хендшейк, молчит — следующий адрес
                if [ -n "$WARP_PID" ] && ! kill -0 "$WARP_PID" 2>/dev/null; then
                    # процесс умер — перебор адресов бессмыслен (и это не «закрыт пул»)
                    log "WARP: $WARP_CUR — amneziawg-go завершился при запуске ($(tail -1 "$WARP_RUN.log" 2>/dev/null | cut -c1-120))"
                    warp_mark_bad "$WARP_CUR"; warp_down; warp_set_state off ""
                elif ! warp_ep_step; then
                    log "WARP: $WARP_CUR — нет хендшейка ни на одном адресе (${WARP_EP_TRIED# }), беру следующий"
                    WARP_EP_FULL=$((WARP_EP_FULL + 1))
                    warp_mark_bad "$WARP_CUR"; warp_down; warp_set_state off ""
                fi
            elif warp_probe; then
                log "WARP: $WARP_CUR поднят за $(( $(date +%s) - WARP_TS )) с"
                [ "$WARP_CF" = 1 ] && warp_ep_save "$WARP_EP_CUR"
                WARP_TS=$(date +%s); WARP_CHECK_TS=$WARP_TS; WARP_FAILS=0
                warp_set_state up ""
                warp_routes_reconcile
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
            warp_routes_reconcile
            [ $((now - WARP_CHECK_TS)) -lt $WARP_CHECK_SECS ] && return 0
            WARP_CHECK_TS=$now
            if warp_probe; then
                [ $WARP_FAILS -gt 0 ] && log "WARP: $WARP_CUR снова отвечает"
                WARP_FAILS=0; WARP_NETCHG=0
            elif [ "$WARP_NETCHG" = 1 ]; then
                # сменилась сеть, а туннель молчит — сразу заново (хендшейк и
                # адрес для этой сети), не ждать 3 промаха (~30 с, лог 28.10:
                # Wi-Fi -> Wi-Fi без пропадания WAN). Конфиг не виноват
                WARP_NETCHG=0
                warp_down "сменилась сеть"; warp_set_state off ""
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

# ============================================================================
# Что идёт в WARP. Новые соединения к адресам групп (Google, Telegram, домены
# из WARP_DOMAINS не на общих CDN) — от раздачи и (WARP_PHONE=1) от
# приложений телефона, плюс всё от приложений WARP_APPS:
#  - mangle OUTPUT/PREROUTING: NEW к адресу группы -> connmark WARP_MARK,
#    пакеты соединения с ним -> fwmark; ip rule «fwmark -> WARP_TABLE»;
#    уже открытые соединения не переезжают (иначе рвались бы посреди);
#  - nat MASQUERADE на warp0, FORWARD раздача <-> warp0 (до tetherctrl с его
#    DROP), MSS 1240 (MTU 1280; фиксированный, не clamp-to-pmtu — уроки);
#  - IPv6: NAT для v6 в ядре нет — v6 к адресам групп и v6 приложений
#    WARP_APPS телефону отбиваем, приложение уходит на v4 и в туннель.
# Только по адресам, которые принадлежат самим сервисам (урок 3.15).
# Root (uid 0: dnsproxy, сам amneziawg-go, проверки) — никогда.
# ============================================================================
WARP_MARK=0x20000000             # 0x08000000 — connmark сканера (zapret/scan.sh SCMARK)
WARP_MARK_PREF=2979
WARP_MSS=1240
CHAIN_WARP_OUT="VPN_WARP_OUT"     # mangle OUTPUT
CHAIN_WARP_PRE="VPN_WARP_PRE"     # mangle PREROUTING
CHAIN_WARP_DST="VPN_WARP_DST"     # адреса групп -> VPN_WARP_SET
CHAIN_WARP_SET="VPN_WARP_SET"     # connmark + fwmark
CHAIN_WARP_NAT="VPN_WARP_NAT"     # nat POSTROUTING
CHAIN_WARP_FWD="VPN_WARP_FWD"     # filter FORWARD
CHAIN_WARP_V6="VPN_WARP_V6"       # filter OUTPUT (v6): отбить
CHAIN_WARP_V6F="VPN_WARP_V6F"     # filter FORWARD (v6 раздачи): отбить
WARP_DOM_SECS=600                 # домены перерезолвить раз в 10 мин
WARP_RT_ON=0
WARP_RT_SIG=""                    # что стоит: группы|раздача|uid|адреса доменов
WARP_RT_GRP=""                    # группы из настроек при последней сборке
WARP_RT_DST=""                    # сети v4 при последней сборке (что закрыть при смене групп)
WARP_DOM_TS=0
WARP_DOM_IPS=""
WARP_DOM_LAST=""                  # адреса прошлого обновления (без накопления)
WARP_DOM_SKIP=0
WARP_APP_UIDS=""
WARP_APP_TS=0

# Домен -> IPv4 через наш dnsproxy (те же ответы, что у клиентов); его нет —
# через 1.1.1.1. Свой разбор ответа: у busybox nslookup нет -port, dig нет.
warp_dq() {
    local d="${1%.}" q="" l srv=127.0.0.1 port="$DNSPROXY_PORT"
    [ -n "$DNSPROXY_BIN" ] && [ -n "$port" ] || { srv=1.1.1.1; port=53; }
    for l in $(echo "$d" | tr '.' ' '); do q="$q$(printf '\\%03o' ${#l})$l"; done
    # shellcheck disable=SC2059
    printf "\\022\\064\\001\\000\\000\\001\\000\\000\\000\\000\\000\\000$q\\000\\000\\001\\000\\001" | \
        timeout 3 toybox nc -u -q 1 "$srv" "$port" 2>/dev/null | od -An -tu1 -v | \
        awk -v skip=$((12 + ${#d} + 2 + 4)) '{ for (i = 1; i <= NF; i++) b[n++] = $i }
            END { if (n < 12 || b[3] % 16 != 0) exit
                  # только секция ответов (ANCOUNT): A из Additional — не наши
                  an = b[6] * 256 + b[7]; i = skip
                  while (an-- > 0 && i + 10 < n) {
                      # имя: метки, затем ноль или ссылка (в т.ч. «метка + ссылка»)
                      while (i < n && b[i] != 0 && b[i] < 192) i += b[i] + 1
                      if (b[i] >= 192) i += 2; else i++
                      t = b[i] * 256 + b[i+1]; len = b[i+8] * 256 + b[i+9]; i += 10
                      if (t == 1 && len == 4) print b[i] "." b[i+1] "." b[i+2] "." b[i+3]
                      i += len
                  } }'
}

# Адреса WARP_DOMAINS без общих CDN -> WARP_DOM_IPS (вместе с прошлым набором:
# ответы DNS скачут, открытое соединение не должно терять маршрут)
warp_domains_refresh() {
    local d ips="" out k=0 pids="" p
    WARP_DOM_TS=$(date +%s)
    [ -n "$WARP_DOMAINS" ] || { WARP_DOM_IPS=""; WARP_DOM_LAST=""; WARP_DOM_SKIP=0; return 0; }
    # параллельно: по ~1 с на запрос, 50 доменов подряд держали бы цикл минуту.
    # wait — по своим pid: у оболочки демона в фоне ещё amneziawg-go
    # ответы — в свой каталог (root, 700): в /data/local/tmp пишет и shell,
    # подложенный .dq99 увёл бы чужие адреса в WARP
    rm -f "$WARP_DIR"/.dq*
    for d in $WARP_DOMAINS; do warp_dq "$d" > "$WARP_DIR/.dq$k" 2>/dev/null & pids="$pids $!"; k=$((k + 1)); done
    for p in $pids; do wait "$p" 2>/dev/null; done
    ips=$(cat "$WARP_DIR"/.dq* 2>/dev/null | tr '\n' ' '); rm -f "$WARP_DIR"/.dq*
    # с прошлым обновлением (ответы DNS скачут — открытое соединение не теряет
    # маршрут), но не со всеми прошлыми: адрес, ушедший другому, не копится
    out=$(echo $ips $WARP_DOM_LAST | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u | \
        awk 'function n(s,  a) { split(s, a, "."); return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }
             FNR == NR { if ($1 ~ /^[0-9]/) { split($1, c, "/"); lo[k] = n(c[1]); sz[k] = 2 ^ (32 - c[2]); k++ } next }
             { v = n($1); for (j = 0; j < k; j++) if (v >= lo[j] && v < lo[j] + sz[j]) { skip++; next }; print }
             END { print "skip " skip + 0 }' k=0 "$MODULE_DIR/warp/cdn-ipv4.txt" -)
    WARP_DOM_LAST="$ips"
    WARP_DOM_SKIP=$(echo "$out" | sed -n 's/^skip //p')
    WARP_DOM_IPS=$(echo "$out" | grep -v '^skip ' | tr '\n' ' ')
    WARP_DOM_IPS=${WARP_DOM_IPS% }
}

# Клиенты Telegram. При WARP_TELEGRAM (и WARP_PHONE) — в WARP целиком, как
# WARP_APPS: когда основные серверы отвечают плохо, Telegram берёт конфиг
# через DoH (dns.google, Cloudflare) и уходит на запасные узлы на чужих
# хостингах (iNet, Vodafone; порты 443/5448/7909/9941) — их нет в сетях
# Telegram, а напрямую их режет ТСПУ (27.10: TCP не устанавливается, через
# WARP — 80–110 мс). По сетям в WARP шли только основные, и Telegram висел на
# «Соединение…»; целиком — без отвалов. Сети Telegram остаются для раздачи и
# для клиентов, которых фильтрует AdGuard (его соединения — от его uid).
WARP_TG_PKGS="org.telegram.messenger org.telegram.messenger.web org.telegram.messenger.beta org.thunderdog.challegram org.telegram.plus tw.nekomimi.nekogram xyz.nextalone.nagram com.exteragram.messenger uz.unnarsx.cherrygram org.forkgram.messenger it.octogram.android"
warp_tg_pkgs() {   # установленные клиенты Telegram, если они идут в WARP целиком
    local p
    [ "$WARP_TELEGRAM" = "1" ] && [ "$WARP_PHONE" = "1" ] || return 0
    for p in $WARP_TG_PKGS; do [ -d "/data/data/$p" ] && echo "$p"; done
}

warp_app_uids() {
    local p u out=""
    for p in $WARP_APPS $(warp_tg_pkgs); do
        u=$(stat -c %u "/data/data/$p" 2>/dev/null)
        case "$u" in ''|*[!0-9]*) continue ;; esac
        [ "$u" -ge 10000 ] || continue
        case " $out " in *" $u "*) ;; *) out="$out $u" ;; esac
    done
    echo "${out# }"
}

# Адреса групп по строке: google/telegram из файлов, домены
warp_dst4() {   # \r — на случай списка, сохранённого в Windows (iptables-restore его не примет)
    local a
    # сервисы Google без Google Cloud (goog.json минус cloud.json): на GCP — чужие сайты
    [ "$WARP_GOOGLE" = "1" ] && tr -d '\r' < "$MODULE_DIR/warp/google-ipv4.txt" 2>/dev/null | grep -E '^[0-9]+\.'
    [ "$WARP_TELEGRAM" = "1" ] && tr -d '\r' < "$MODULE_DIR/warp/telegram.txt" 2>/dev/null | grep -E '^[0-9]+\.'
    for a in $WARP_DOM_IPS; do echo "$a/32"; done
}
warp_dst6() {
    [ "$WARP_GOOGLE" = "1" ] && tr -d '\r' < "$MODULE_DIR/warp/google-ipv6.txt" 2>/dev/null | grep -E '^[0-9a-f]+:'
    [ "$WARP_TELEGRAM" = "1" ] && tr -d '\r' < "$MODULE_DIR/warp/telegram.txt" 2>/dev/null | grep -E '^[0-9a-f]+:'
}

# Путь к адресам групп сменился (маршруты WARP встали или сняты) — старые
# соединения телефона к ним мертвы: через Cloudflare началась новая сессия
# или источник стал другим. Telegram замечал это только по своему таймауту и
# минутами висел на «Соединение…» (27.10; так же в AmneziaWG и WG Tunnel).
# Закрываем их сокеты (ss -K, как отбой мёртвых серверов YouTube) —
# приложения переподключаются сразу и уже новым путём. Сокеты самого телефона
# (соединения раздачи живут на клиенте), и только при WARP_PHONE=1: иначе путь
# у телефона не менялся, а рвать ему Google (FCM, поиск) — урок 25.10. По uid
# ss не фильтрует: закроются и сокеты root/системы к этим адресам — они просто
# переподключатся. Установленные и висящие на SYN (блок по IP: SYN глушится,
# а NAT у соединения уже назначен мимо туннеля). Один ss на все сети.
warp_kill_sockets() {   # причина [сети — по умолчанию все сети групп]
    local f="" m n nets="${2-$(warp_dst4)}"
    [ "$WARP_PHONE" = "1" ] || return 0
    command -v ss >/dev/null 2>&1 || return 0
    for m in $nets; do f="$f${f:+ or }dst $m"; done
    [ -n "$f" ] || return 0
    # shellcheck disable=SC2086
    n=$(ss -K -tn state established state syn-sent "( $f )" 2>/dev/null | awk 'NR > 1' | grep -c .)
    [ "${n:-0}" -gt 0 ] && log "WARP: закрыто соединений телефона к адресам из WARP: $n ($1) — приложения переподключатся сразу"
    return 0
}

warp_routes_off() {   # [force] — снять, даже если по флагу не стоят
    local t c _n
    [ "$WARP_RT_ON" = "1" ] || [ "$1" = "force" ] || return 0
    $ip rule del fwmark $WARP_MARK/$WARP_MARK lookup $WARP_TABLE pref $WARP_MARK_PREF 2>/dev/null
    for t in "$iptables" "$ip6tables"; do
        _n=0; while [ $_n -lt 8 ] && $t -t mangle -D OUTPUT -j "$CHAIN_WARP_OUT" 2>/dev/null; do _n=$((_n + 1)); done
        _n=0; while [ $_n -lt 8 ] && $t -t mangle -D PREROUTING -j "$CHAIN_WARP_PRE" 2>/dev/null; do _n=$((_n + 1)); done
        for c in "$CHAIN_WARP_OUT" "$CHAIN_WARP_PRE" "$CHAIN_WARP_DST" "$CHAIN_WARP_SET"; do
            $t -t mangle -F "$c" 2>/dev/null; $t -t mangle -X "$c" 2>/dev/null
        done
        $t -t mangle -D POSTROUTING -o $WARP_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $WARP_MSS 2>/dev/null
        $t -t mangle -D PREROUTING -i $WARP_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $WARP_MSS 2>/dev/null
    done
    _n=0; while [ $_n -lt 8 ] && $iptables -t nat -D POSTROUTING -j "$CHAIN_WARP_NAT" 2>/dev/null; do _n=$((_n + 1)); done
    $iptables -t nat -F "$CHAIN_WARP_NAT" 2>/dev/null; $iptables -t nat -X "$CHAIN_WARP_NAT" 2>/dev/null
    _n=0; while [ $_n -lt 8 ] && $iptables -D FORWARD -j "$CHAIN_WARP_FWD" 2>/dev/null; do _n=$((_n + 1)); done
    $iptables -F "$CHAIN_WARP_FWD" 2>/dev/null; $iptables -X "$CHAIN_WARP_FWD" 2>/dev/null
    _n=0; while [ $_n -lt 8 ] && $ip6tables -D OUTPUT -j "$CHAIN_WARP_V6" 2>/dev/null; do _n=$((_n + 1)); done
    $ip6tables -F "$CHAIN_WARP_V6" 2>/dev/null; $ip6tables -X "$CHAIN_WARP_V6" 2>/dev/null
    _n=0; while [ $_n -lt 8 ] && $ip6tables -D FORWARD -j "$CHAIN_WARP_V6F" 2>/dev/null; do _n=$((_n + 1)); done
    $ip6tables -F "$CHAIN_WARP_V6F" 2>/dev/null; $ip6tables -X "$CHAIN_WARP_V6F" 2>/dev/null
    if [ "$WARP_RT_ON" = "1" ]; then
        log "WARP: маршруты в туннель сняты"
        warp_kill_sockets "туннель снят"
    fi
    WARP_RT_ON=0; WARP_RT_SIG=""
}

warp_routes_apply() {   # ифейсы раздачи
    local tif="$1" uids="$WARP_APP_UIDS" f="$WARP_DIR/.rules" c i u m n4 n6 what=""
    # mangle v4: адреса групп одним iptables-restore (~150 правил за раз)
    {
        echo "*mangle"
        for c in "$CHAIN_WARP_OUT" "$CHAIN_WARP_PRE" "$CHAIN_WARP_DST" "$CHAIN_WARP_SET"; do echo ":$c - [0:0]"; done
        echo "-A $CHAIN_WARP_SET -j CONNMARK --set-xmark $WARP_MARK/$WARP_MARK"
        echo "-A $CHAIN_WARP_SET -j MARK --set-xmark $WARP_MARK/$WARP_MARK"
        warp_dst4 | while read -r m; do echo "-A $CHAIN_WARP_DST -d $m -j $CHAIN_WARP_SET"; done
        # соединение уже в WARP -> метка каждому пакету; новое -> по адресу.
        # В PREROUTING — только со стороны раздачи: ответы из warp0 с той же
        # connmark иначе получили бы метку и ушли обратно в туннель
        # к локальным сетям (раздача: ICMP «frag needed» клиенту по его соединению с connmark) — не в туннель
        echo "-A $CHAIN_WARP_OUT -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10 -j RETURN"
        echo "-A $CHAIN_WARP_OUT -m connmark --mark $WARP_MARK/$WARP_MARK -j MARK --set-xmark $WARP_MARK/$WARP_MARK"
        echo "-A $CHAIN_WARP_OUT -m connmark --mark $WARP_MARK/$WARP_MARK -j RETURN"
        echo "-A $CHAIN_WARP_OUT -o lo -j RETURN"
        # root и системные uid (проверки связи NetworkMonitor, DoT netd) — мимо:
        # сбой WARP не должен выглядеть для Android как «сеть без интернета»
        echo "-A $CHAIN_WARP_OUT -m owner --uid-owner 0-9999 -j RETURN"
        echo "-A $CHAIN_WARP_OUT -m conntrack ! --ctstate NEW -j RETURN"
        for u in $uids; do echo "-A $CHAIN_WARP_OUT -m owner --uid-owner $u -j $CHAIN_WARP_SET"; done
        [ "$WARP_PHONE" = "1" ] && echo "-A $CHAIN_WARP_OUT -j $CHAIN_WARP_DST"
        for i in $tif; do
            echo "-A $CHAIN_WARP_PRE -i $i -m connmark --mark $WARP_MARK/$WARP_MARK -j MARK --set-xmark $WARP_MARK/$WARP_MARK"
            echo "-A $CHAIN_WARP_PRE -i $i -m conntrack --ctstate NEW -j $CHAIN_WARP_DST"
        done
        echo "COMMIT"
    } > "$f"
    if ! ${iptables%% *}-restore -w 2 --noflush < "$f" 2>>"$WARP_RUN.log" && \
       ! ${iptables%% *}-restore --noflush < "$f" 2>>"$WARP_RUN.log"; then
        log "WARNING: WARP: правила маршрутов не встали ($(tail -1 "$WARP_RUN.log" | cut -c1-120))"
        rm -f "$f"; warp_routes_off force; return 1
    fi
    rm -f "$f"
    $iptables -t mangle -C OUTPUT -j "$CHAIN_WARP_OUT" 2>/dev/null || $iptables -t mangle -A OUTPUT -j "$CHAIN_WARP_OUT"
    $iptables -t mangle -C PREROUTING -j "$CHAIN_WARP_PRE" 2>/dev/null || $iptables -t mangle -A PREROUTING -j "$CHAIN_WARP_PRE"
    $ip rule del fwmark $WARP_MARK/$WARP_MARK lookup $WARP_TABLE pref $WARP_MARK_PREF 2>/dev/null
    $ip rule add fwmark $WARP_MARK/$WARP_MARK lookup $WARP_TABLE pref $WARP_MARK_PREF
    # NAT и FORWARD
    $iptables -t nat -N "$CHAIN_WARP_NAT" 2>/dev/null; $iptables -t nat -F "$CHAIN_WARP_NAT"
    $iptables -t nat -A "$CHAIN_WARP_NAT" -o $WARP_IF -j MASQUERADE
    $iptables -t nat -C POSTROUTING -j "$CHAIN_WARP_NAT" 2>/dev/null || $iptables -t nat -I POSTROUTING 1 -j "$CHAIN_WARP_NAT"
    $iptables -N "$CHAIN_WARP_FWD" 2>/dev/null; $iptables -F "$CHAIN_WARP_FWD"
    for i in $tif; do
        $iptables -A "$CHAIN_WARP_FWD" -i "$i" -o $WARP_IF -j ACCEPT
        $iptables -A "$CHAIN_WARP_FWD" -i $WARP_IF -o "$i" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    done
    $iptables -C FORWARD -j "$CHAIN_WARP_FWD" 2>/dev/null || $iptables -I FORWARD 1 -j "$CHAIN_WARP_FWD"
    # MSS: туда и обратно (SYN-ACK к телефону и клиентам)
    $iptables -t mangle -C POSTROUTING -o $WARP_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $WARP_MSS 2>/dev/null || \
        $iptables -t mangle -I POSTROUTING 1 -o $WARP_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $WARP_MSS
    $iptables -t mangle -C PREROUTING -i $WARP_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $WARP_MSS 2>/dev/null || \
        $iptables -t mangle -I PREROUTING 1 -i $WARP_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $WARP_MSS
    # IPv6 телефона: отбить (tcp — RST, остальное — недоступен), уйдёт на v4
    $ip6tables -N "$CHAIN_WARP_V6" 2>/dev/null; $ip6tables -F "$CHAIN_WARP_V6"
    $ip6tables -A "$CHAIN_WARP_V6" -m owner --uid-owner 0-9999 -j RETURN
    {
        for u in $uids; do echo "-m owner --uid-owner $u"; done
        [ "$WARP_PHONE" = "1" ] && warp_dst6 | while read -r m; do echo "-d $m"; done
    } | while read -r m; do
        $ip6tables -A "$CHAIN_WARP_V6" $m -p tcp -j REJECT --reject-with tcp-reset
        $ip6tables -A "$CHAIN_WARP_V6" $m -j REJECT --reject-with icmp6-adm-prohibited
    done
    $ip6tables -C OUTPUT -j "$CHAIN_WARP_V6" 2>/dev/null || $ip6tables -I OUTPUT 1 -j "$CHAIN_WARP_V6"
    # v6 клиентов раздачи к адресам групп — тоже отбить (Windows идёт на v6 первым)
    $ip6tables -N "$CHAIN_WARP_V6F" 2>/dev/null; $ip6tables -F "$CHAIN_WARP_V6F"
    for i in $tif; do
        warp_dst6 | while read -r m; do
            $ip6tables -A "$CHAIN_WARP_V6F" -i "$i" -d "$m" -p tcp -j REJECT --reject-with tcp-reset
            $ip6tables -A "$CHAIN_WARP_V6F" -i "$i" -d "$m" -j REJECT --reject-with icmp6-adm-prohibited
        done
    done
    $ip6tables -C FORWARD -j "$CHAIN_WARP_V6F" 2>/dev/null || $ip6tables -I FORWARD 1 -j "$CHAIN_WARP_V6F"
    n4=$(warp_dst4 | grep -c .); n6=$(warp_dst6 | grep -c .)
    [ "$WARP_GOOGLE" = 1 ] && what="$what Google,"
    [ "$WARP_TELEGRAM" = 1 ] && what="$what Telegram,"
    [ -n "$WARP_DOMAINS" ] && what="$what домены ($(echo $WARP_DOM_IPS | wc -w) адр.$([ "${WARP_DOM_SKIP:-0}" -gt 0 ] && echo ", общий CDN мимо: $WARP_DOM_SKIP")),"
    m=$(warp_tg_pkgs | tr '\n' ' '); m=${m% }
    [ -n "$m" ] && what="$what клиенты Telegram целиком ($m),"
    [ -n "$WARP_APPS" ] && what="$what приложения $WARP_APPS,"
    [ -n "$m$WARP_APPS" ] && what="$what uid ${uids:-не установлены},"
    WARP_RT_ON=1
    log "WARP: в туннель —${what:- ничего,} $n4 сетей v4, v6 отбито: $n6; для:$([ "$WARP_PHONE" = 1 ] && echo ' телефона')${tif:+ раздачи [$tif]}"
}

# Из цикла, пока туннель поднят: пересобрать, если что-то поменялось
warp_routes_reconcile() {
    local now sig tif
    now=$(date +%s)
    [ $((now - WARP_DOM_TS)) -ge $WARP_DOM_SECS ] && warp_domains_refresh
    if [ $((now - WARP_APP_TS)) -ge 30 ]; then WARP_APP_UIDS=$(warp_app_uids); WARP_APP_TS=$now; fi
    tif="$LAST_TETHER_IFACES"
    sig="$WARP_GOOGLE$WARP_TELEGRAM$WARP_PHONE|$tif|$WARP_APP_UIDS|$WARP_DOM_IPS"
    # netd мог перетряхнуть цепочки — проверяем, что хук на месте
    [ "$WARP_RT_ON" = "1" ] && [ "$sig" = "$WARP_RT_SIG" ] && \
        $iptables -t mangle -C OUTPUT -j "$CHAIN_WARP_OUT" 2>/dev/null && \
        $iptables -C FORWARD -j "$CHAIN_WARP_FWD" 2>/dev/null && return 0
    local was="$WARP_RT_ON" grp="$WARP_GOOGLE$WARP_TELEGRAM$WARP_PHONE|$WARP_DOMAINS" old new
    old="$WARP_RT_DST"
    warp_routes_apply "$tif" && WARP_RT_SIG="$sig"
    [ "$WARP_RT_ON" = "1" ] || return 0
    new=$(warp_dst4); WARP_RT_DST="$new"
    # маршруты встали впервые — старые соединения шли мимо. Сменились группы
    # при поднятом туннеле (Telegram/Google/домены в настройках; не адреса
    # доменов — те обновляются раз в 10 мин, и не раздача/uid) — путь сменился
    # только у сетей, что добавились или ушли: их и закрываем
    if [ "$was" != "1" ]; then warp_kill_sockets "туннель поднят"
    elif [ -n "$WARP_RT_GRP" ] && [ "$grp" != "$WARP_RT_GRP" ]; then
        warp_kill_sockets "сменились группы" "$(printf '%s\n%s\n' "$old" "$new" | grep . | sort | uniq -u)"
    fi
    WARP_RT_GRP="$grp"
    return 0
}
