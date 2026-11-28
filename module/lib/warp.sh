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
WARP_NONET_RETRY=30      # не поднялся, и напрямую сети нет — тот же конфиг через 30 с
WARP_WL_RETRY=300        # то же при белом списке оператора: он на часы, а перебор адресов ~50 с
WARP_STATE=off           # off | starting | up | fail
WARP_CUR=""              # конфиг в работе
WARP_PID=""
WARP_CH_ADDR=""          # адрес warp1 (своего сервера после WARP) — для запрета «адрес туннеля мимо туннеля»
CHAIN_WARP_SRC=VPN_WARP_SRC
WARP_TS=0                # когда запущен / поднялся
WARP_CHECK_TS=0          # последняя проверка трафиком (0 — проверить сейчас)
WARP_FAILS=0             # проверок подряд без ответа
WARP_NONET=0             # туннель молчит, и напрямую сети нет (warp_uplink) — конфиг держим
WARP_CRASH=""            # конфиг, упавший сразу после подъёма (второй раз — в «плохие»)
WARP_CF=0                # Endpoint — сервер Cloudflare: проверка требует warp=on
WARP_EP0=""              # адрес из конфига (engage… — числом)
WARP_EP_FILE=$WARP_DIR/.endpoints   # «сеть|адрес» — рабочий адрес Cloudflare для сети
WARP_EP_FULL=0           # конфигов за круг, не давших хендшейк ни на одном адресе пула
WARP_EP_TRIED=""         # адреса, уже испробованные этим конфигом
WARP_EP_SILENT=""        # из них не давшие хендшейк (для лога «молчали»)
WARP_EP_Q=""             # ещё не испробованные
WARP_EP_CUR=""           # пробуем сейчас
WARP_EP_T0=0             # когда подан (мс от загрузки)
WARP_HS=0                # хендшейк на WARP_EP_CUR был
WARP_NETCHG=0            # сменилась сеть (loop.sh), туннель на ней ещё не проверен
WARP_COLO=""             # площадка Cloudflare из последней проверки (colo= в trace)
WARP_COLO_UP=""          # площадка работающего туннеля — в status (warp_colo)
# Российские площадки Cloudflare: с российского адреса там режут часть
# адресов — Telegram по IPv4 и др. (форум Cloudflare, 02 и 04.2026: DME, KJA,
# LED; с европейских HEL/ARN/FRA работает). WARP через них — только если
# другой площадки ни на одном адресе нет. По списку Cloudflare в России — DME и LED
WARP_RU_COLOS=" DME LED KJA "
WARP_RU_EP=""            # адрес, выводивший на российскую площадку, — запасной
WARP_RU_TRY=0            # к запасному российскому уже вернулись (его молчание — не «пул закрыт»)
WARP_ENSURE_WAIT=300     # пауза перед повтором создания конфигов: удваивается, до часа
WARP_BAD=""              # «имя:epoch …»
WARP_RETRY_TS=0
WARP_NOTE=""             # почему fail — для лога и WebUI
WARP_PUB=""              # «состояние|заметка», уже записанные в status
WARP_ENSURE_PID=""
WARP_ENSURE_DONE=0
WARP_ENSURE_AT=0         # не вышло (нет сети при загрузке) — повтор после этого времени
WARP_ENSURE_BUSY=0       # 1 = ждём конца подбора: повторы каждые 30 с в журнал не пишем
WARP_TG_SECS=300         # Telegram DC2/DC4 через туннель — проверка раз в 5 мин (warp_tg_dead)
WARP_TG_TS=0             # последняя такая проверка (0 — на первой проверке сессии)
WARP_TG_TRIES=0          # переподключений подряд из-за DC2/DC4
WARP_TG_YTW=0            # откладываний подряд из-за видео YouTube в туннеле (не больше 2 = 10 мин)
WARP_TG_MAX=5
WARP_TG_PAUSE=1800       # не помогли WARP_TG_MAX подряд — 30 мин не переподключать
WARP_TG_HOLD=0           # до этого времени (epoch) не переподключать
WARP_SU_G=""             # su -g работает (проверка — мимо прокси AdGuard)
# MASQUE (WARP_ENGINE=masque, 28.11): usque вместо amneziawg-go, интерфейс тот же warp0 — маршруты, группы, свой сервер
# после WARP и проверки — как у AmneziaWG. usque — от uid 1000 (system): от root, даже с группой 3999, AdGuard с
# root-прокси отбивает UDP 443 («sendmsg: operation not permitted», 13T), uid 1000 пропускает; группа 3999 — мимо его
# перехвата TCP (HTTP/2). tun создаёт root и отдаёт uid 1000 (ip tuntap … user), usque его только открывает (-I: адреса
# и маршруты — наши). В /data/adb uid 1000 не войти — бинарь и копия аккаунта в WARP_MQ_DIR (uid 1000, 700).
# 28.11 ночью на YOTA: 37–44 Мбит/с против 20–29 у AmneziaWG, пинг под нагрузкой 145–180 мс против 250–320
WARP_MQ_NAME=masque                  # «конфиг» в WARP_CUR и статусе
WARP_MQ_CONF=$WARP_DIR/masque.json   # аккаунт (usque register): ключ — только root
WARP_MQ_DIR=/data/local/tmp/vpn_tether_mq
WARP_MQ_UID=1000
WARP_MQ_SU=""                        # как запускать от uid 1000 (warp_mq_su)
WARP_MQ_REG_TS=0                     # когда начата регистрация (0 — не идёт)
WARP_MQ_WARN=""                      # «MASQUE только arm64» — в журнал один раз

# Адрес туннеля — только через туннель: на пакеты уже закрытых сокетов (после ss -K, смены пути) ядро отвечает
# RST без метки и привязки, и main уводил их оператору с адресом warp0/warp1 (26.11 на 13T: 15 RST к Telegram
# за минуту — данных нет, но ТСПУ видит). filter OUTPUT, в начале; снимается вместе с туннелем
warp_src_guard() {   # add|del адрес (IPv4, можно с /маской)
    local a="${2%%/*}"
    case "$a" in *.*.*.*) ;; *) return 0 ;; esac
    if [ "$1" = add ]; then
        $iptables -N "$CHAIN_WARP_SRC" 2>/dev/null
        $iptables -C "$CHAIN_WARP_SRC" -s "$a" ! -o warp+ -j DROP 2>/dev/null || $iptables -A "$CHAIN_WARP_SRC" -s "$a" ! -o warp+ -j DROP
        $iptables -C OUTPUT -j "$CHAIN_WARP_SRC" 2>/dev/null || $iptables -I OUTPUT 1 -j "$CHAIN_WARP_SRC"
    else
        $iptables -D "$CHAIN_WARP_SRC" -s "$a" ! -o warp+ -j DROP 2>/dev/null
    fi
    return 0
}

# Остатки от убитого демона: интерфейс, правило, процесс, сокет
warp_kill_strays() {
    local p
    for p in $(pidof amneziawg-go-arm64 amneziawg-go-arm 2>/dev/null); do kill "$p" 2>/dev/null; done
    # usque — только наш (из WARP_MQ_DIR): свой usque юзера (стенд, набор для проверки) не трогаем
    for p in $(pidof usque 2>/dev/null); do
        case "$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)" in "$WARP_MQ_DIR/usque "*) kill "$p" 2>/dev/null ;; esac
    done
}

warp_down() {   # [причина] — пусто: молча
    # свой сервер после WARP — первым: без warp0 его правила к серверу ведут в никуда (prohibit)
    warp_chain_down "${1:+WARP снят}"
    # выход демона — блок снять (warp_reconcile при VPN и т.п. снимает его сам, до warp_down); кроме перезапуска
    # (webctl restart, флаг моложе минуты): новый демон ставит его через ~2 с, а без него эти секунды то, что
    # идёт в WARP, уходило оператору (26.11 на 13T ~30 пакетов к Telegram за перезапуск)
    if [ "$1" = "выход" ] && ! restart_flag_fresh; then warp_block_set 0; fi
    if [ "$WARP_BLK_LVL" -ge 1 ] 2>/dev/null; then
        # «Если выход не работает» — не напрямую: разметку держим, то, что идёт в WARP, упрётся в запрет
        # (таблица WARP пустая); открытые соединения закрыть — приложения сразу увидят «нет сети»
        [ "$WARP_RT_ON" = 1 ] && warp_kill_sockets "туннель снят, блок"
    else
        warp_routes_off
    fi
    $ip rule del oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    $ip -6 rule del oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    $ip route flush table $WARP_TABLE 2>/dev/null
    $ip -6 route flush table $WARP_TABLE 2>/dev/null
    $ip link del $WARP_IF 2>/dev/null
    # запрет «адрес туннеля мимо туннеля» — целиком (и от убитого демона): туннелей больше нет
    $iptables -F "$CHAIN_WARP_SRC" 2>/dev/null
    [ -n "$WARP_PID" ] && kill "$WARP_PID" 2>/dev/null
    warp_kill_strays
    rm -f "$WARP_SOCK_DIR/$WARP_IF.sock" "$WARP_DIR/.run.wg"
    [ -n "$1" ] && [ "$WARP_STATE" != off ] && log "WARP: туннель снят ($1)"
    WARP_PID=""; WARP_CUR=""; WARP_STATE=off; WARP_FAILS=0; WARP_NONET=0; WARP_COLO_UP=""
}

# Конфиги по порядку: выбранный в WARP_CONF первым, дальше по имени. Свой сервер после WARP (WARP_CHAIN) — не WARP:
# поднятый вместо Cloudflare, он шёл бы к серверу напрямую — ради чего цепочка и нужна
# «Не менять сервер» (WARP_STICK): за какой держаться — основной (WARP_CONF), не выбран — тот, что поднимался последним
# (ревью 25.11: без основного выключатель молча не действовал); пусто — пока ни один не поднимался, по порядку
warp_mq_on() { [ "$WARP_ENGINE" = masque ] && [ -n "$USQUE_BIN" ]; }

warp_stick_name() {
    local n
    [ "$WARP_STICK" = 1 ] || return 1
    for n in "$WARP_CONF" "$WARP_LAST_UP"; do
        [ -n "$n" ] && [ "$n" != "$WARP_CHAIN" ] && [ -f "$WARP_DIR/$n.conf" ] && { echo "$n"; return 0; }
    done
    return 1
}

warp_conf_names() {
    local f n
    # MASQUE — один «конфиг», аккаунт создаётся при запуске (warp_mq_start); конфиги AmneziaWG не берём
    if warp_mq_on; then echo "$WARP_MQ_NAME"; return 0; fi
    if n=$(warp_stick_name); then echo "$n"; return 0; fi
    [ -n "$WARP_CONF" ] && [ "$WARP_CONF" != "$WARP_CHAIN" ] && [ -f "$WARP_DIR/$WARP_CONF.conf" ] && echo "$WARP_CONF"
    for f in "$WARP_DIR"/*.conf; do
        [ -f "$f" ] || continue
        n=${f##*/}; n=${n%.conf}
        [ "$n" = "$WARP_CONF" ] || [ "$n" = "$WARP_CHAIN" ] || echo "$n"
    done
}

warp_is_bad() {
    local e now=$(date +%s)
    # «Не менять сервер»: «плохой» не на 10 мин, а на 30 с — замолчал, его же заново; без паузы конфиг, что падает
    # сразу (имя сервера не резолвится), перезапускался бы каждый проход цикла (ревью 25.11)
    if [ "$1" = "$(warp_stick_name)" ]; then
        for e in $WARP_BAD; do [ "${e%:*}" = "$1" ] && [ $((now - ${e##*:})) -lt 30 ] && return 0; done
        return 1
    fi
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
# $2 — адрес вместо Endpoint конфига (пусто — как в конфиге), $3 — I1 вместо конфига (warp_i1); с ним
# I2–I5 конфига (AmneziaWG 1.5 шлёт их следом, у импортированных — со своими именами) — не шлём: иначе
# имя, по которому режут, уходило бы и после смены. У созданных модулем их нет, рукопожатию не нужны
warp_wg_file() {   # конфиг [адрес] [I1]
    (umask 077; awk -v ep="$2" -v i1="$3" '/^[ \t]*(#|(Address|DNS|MTU|AllowedIPs|J[1-3]|Itime)[ \t]*=)/ { next }
        ep != "" && /^[ \t]*Endpoint[ \t]*=/ { print "Endpoint = " ep; next }
        i1 != "" && /^[ \t]*I1[ \t]*=/ { print "I1 = " i1; next }
        i1 != "" && /^[ \t]*I[2-5][ \t]*=/ { next }
        { print }
        /^[ \t]*\[Peer\]/ { print "AllowedIPs = 0.0.0.0/0, ::/0" }' "$1" > "$WARP_DIR/.run.wg")
}

# WARP_I1: I1 конфигов Cloudflare — поддельный QUIC Initial (или DNS-запрос, «dns_имя»: имени сайта для
# классификации в нём нет вовсе — идея ZapretKVN v0.6.56, 26.11 рукопожатие и скорость как у QUIC), по имени
# в QUIC оператор опознаёт весь
# поток туннеля (08.11: bag.itunes.apple.com днём 2,5 Мбит/с, apteka.ru 20–30). Готовые — warp/i1/<имя>.txt
# (tools/i1gen.py), собранные на телефоне (warp.sh i1gen, свои DCID и ключи) — $WARP_DIR/i1, они раньше.
# Только вместо I1 конфига, свой не добавляем; свои серверы (не Cloudflare) — как в конфиге
# I1 — только из тегов AmneziaWG: <b 0x…> байты, <r N> случайные (ID DNS-запроса), <c> счётчик, <t> время
i1_valid() {   # I1 — только из тегов AmneziaWG
    case "$1" in "<"*">") ;; *) return 1 ;; esac
    [ -z "$(printf '%s' "$1" | sed -e 's/<b 0x[0-9a-fA-F][0-9a-fA-F]*>//g' -e 's/<r [0-9][0-9]*>//g' -e 's/<[ct]>//g')" ]
}
WARP_I1_RUN=""           # свежий I1 этого подъёма туннеля (warp_i1_fresh); пусто — из файла
warp_i1() {
    local v f
    [ "$WARP_CF" = 1 ] && [ -n "$WARP_I1" ] || return 0
    [ -n "$WARP_I1_RUN" ] && { echo "$WARP_I1_RUN"; return 0; }
    for f in "$WARP_DIR/i1/$WARP_I1.txt" "$MODULE_DIR/warp/i1/$WARP_I1.txt"; do   # свой испорчен — готовый
        v=$(head -1 "$f" 2>/dev/null | tr -d '\r')
        i1_valid "$v" && { echo "$v"; return 0; }
    done
}
# Свежий I1 на каждый подъём туннеля: новые DCID, SCID, random и ключи — как у браузера на каждое соединение.
# Из файла неделями уходил бы один и тот же пакет, а по совпадению байтов его легко запомнить. Образец —
# выбранный I1 (имя и раскладка те же), nfqws2 + warp/i1gen.lua: ~16 мс на 13T, ~85 мс на MT6580 (26.11).
# DNS-вариант не трогаем: ID у него AmneziaWG и так меняет на каждой отправке (<r 2>). Не вышло — I1 из файла,
# с причиной в журнале (иначе I1 тихо стал бы статичным навсегда). Частые повторы подъёма (нет сети — раз в
# 30 с, перебор конфигов) — прошлый I1 в пределах минуты: nfqws2 зря не гоняем (~0,5 с на MT6580).
# Ограничение: в пределах сеанса AmneziaWG шлёт этот I1 на каждом новом рукопожатии (~раз в 2 мин) — внутрь
# зашифрованного QUIC случайное тегом <r> не вставить; свежий — только с новым подъёмом туннеля
WARP_I1_RUN_NAME=""; WARP_I1_RUN_TS=0; WARP_I1_ERR=""
warp_i1_fresh() {
    local src o r e now
    now=$(date +%s)
    [ "$WARP_CF" = 1 ] && [ -n "$WARP_I1" ] && [ -n "$NFQWS2_BIN" ] && [ -f "$MODULE_DIR/warp/i1gen.lua" ] || { WARP_I1_RUN=""; return 0; }
    case "$WARP_I1" in dns_*) WARP_I1_RUN=""; return 0 ;; esac
    [ -n "$WARP_I1_RUN" ] && [ "$WARP_I1_RUN_NAME" = "$WARP_I1" ] && [ $((now - WARP_I1_RUN_TS)) -lt 60 ] && return 0
    WARP_I1_RUN=""
    src=$(warp_i1)
    case "$src" in "<b 0x"*">") ;; *) return 0 ;; esac
    # shellcheck disable=SC2086
    o=$($TIMEOUT_CMD "$NFQWS2_BIN" --intercept=0 --uid=0:3998 --lua-init="I1_NAME='$WARP_I1' I1_SRC='$src'" \
        --lua-init=@"$MODULE_DIR/warp/i1gen.lua" 2>&1)
    r=$(printf '%s\n' "$o" | grep '^<b 0x' | head -1)
    if i1_valid "$r"; then
        WARP_I1_RUN="$r"; WARP_I1_RUN_NAME="$WARP_I1"; WARP_I1_RUN_TS=$now; WARP_I1_ERR=""
        return 0
    fi
    e=$(printf '%s\n' "$o" | grep '^ERR ' | head -1)
    [ -n "$e" ] || e=$(printf '%s\n' "$o" | grep . | tail -1 | cut -c1-120)
    [ -n "$e" ] || e="nfqws2 не ответил"
    # одна и та же причина — один раз, не на каждый подъём
    [ "$e" != "$WARP_I1_ERR" ] && log "WARNING: WARP: свежий I1 не собрался ($e) — шлю I1 из файла"
    WARP_I1_ERR="$e"
    return 0
}
# Для журнала и WebUI: «dns_ya.ru» — DNS-запрос, иначе имя в поддельном QUIC
warp_i1_label() { case "$1" in dns_*) echo "DNS-запрос ${1#dns_}" ;; *) echo "с именем $1" ;; esac; }

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

# для журнала: сервер молчит или отвечает, но трафик не идёт (свой сервер так
# не проверяется при подъёме — без этого «нет трафика» значило и то, и другое)
warp_hs_note() {
    local hs tr n="рукопожатия нет"
    if [ "$WARP_CUR" = "$WARP_MQ_NAME" ]; then
        # у usque своего «show» нет — последняя строка его журнала
        hs=$(grep -v 'Hop Limit' "$WARP_MQ_DIR/usque.log" 2>/dev/null | tail -1 | cut -c 25-140)
        echo "usque: ${hs:-журнал пуст}${WARP_PROBE_NOTE:+; $WARP_PROBE_NOTE}"
        return 0
    fi
    hs=$("$AWG_BIN" show $WARP_IF latest-handshakes 2>/dev/null | awk '{print $2; exit}')
    [ "${hs:-0}" -gt 0 ] && n="рукопожатие есть"
    # принято больше рукопожатия — сервер отвечает; rc — как упала проверка:
    # 28 — тайм-аут, 7 и 35 — сброс, 45 — интерфейс без адреса (лог 04.11: отказ за 8 с)
    tr=$("$AWG_BIN" show $WARP_IF transfer 2>/dev/null | awk '{print "принято " $2 " Б, отправлено " $3 " Б"; exit}')
    echo "$n${WARP_PROBE_NOTE:+; $WARP_PROBE_NOTE}${tr:+; $tr}"
}

warp_ep_step() {   # 0 — ждём или дождались (WARP_HS=1), 1 — адреса кончились
    local hs e was
    hs=$("$AWG_BIN" show $WARP_IF latest-handshakes 2>/dev/null | awk '{print $2; exit}')
    if [ "${hs:-0}" -gt 0 ]; then
        # запомнить для сети — после warp=on (warp_reconcile): хендшейк без
        # трафика не повод ставить адрес первым для всех конфигов
        WARP_HS=1; WARP_EP_FULL=0
        was="${WARP_EP_SILENT# }"
        [ "$WARP_EP_CUR" = "$WARP_EP0" ] || log "WARP: $WARP_CUR — через $WARP_EP_CUR${was:+ (молчали: $was)}"
        return 0
    fi
    [ $(( $(uptime_ms) - WARP_EP_T0 )) -lt 4000 ] && return 0
    WARP_EP_SILENT="$WARP_EP_SILENT $WARP_EP_CUR"
    warp_ep_next
}

warp_ep_next() {   # следующий адрес из очереди в туннель; 1 — очередь пуста
    local e
    set -- $WARP_EP_Q
    [ $# -gt 0 ] || return 1
    e="$1"; shift; WARP_EP_Q="$*"
    warp_wg_file "$WARP_DIR/$WARP_CUR.conf" "$e" "$(warp_i1)"
    "$AWG_BIN" setconf "$WARP_IF" "$WARP_DIR/.run.wg" >> "$WARP_RUN.log" 2>&1
    rm -f "$WARP_DIR/.run.wg"
    WARP_HS=0
    warp_ep_kick "$e"
    return 0
}

warp_colo_ru() { case "$WARP_RU_COLOS" in *" $WARP_COLO "*) return 0 ;; esac; return 1; }

warp_start() {   # имя конфига
    local n="$1" f="$WARP_DIR/$1.conf" a mtu i=0 rc ep1=""
    if [ "$n" = "$WARP_MQ_NAME" ] && warp_mq_on; then warp_mq_start; return $?; fi
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
    warp_i1_fresh
    warp_wg_file "$f" "$ep1" "$(warp_i1)"
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
            *.*) $ip addr add "$a" dev $WARP_IF 2>/dev/null; warp_src_guard add "$a" ;;
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
    WARP_CUR="$n"; WARP_STATE=starting; WARP_TS=$(date +%s); WARP_CHECK_TS=0; WARP_FAILS=0; WARP_NETCHG=0; WARP_TG_TS=0
    log "WARP: запускаю $n ($(sed -n 's/^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*//p' "$f" | head -1))$(
        if [ -n "$(warp_i1)" ]; then echo ", I1 $(warp_i1_label "$WARP_I1")${WARP_I1_RUN:+ (свежий)}"
        elif [ "$WARP_CF" = 1 ] && [ -n "$WARP_I1" ]; then echo ", I1 как в конфиге: нет годного I1 «$WARP_I1» (ни своего, ни готового)"; fi)"
    WARP_HS=0; WARP_EP_TRIED=""; WARP_EP_SILENT=""; WARP_EP_Q=""; WARP_RU_EP=""; WARP_RU_TRY=0
    if [ "$WARP_CF" = 1 ]; then
        WARP_EP_Q=$(warp_ep_list | awk 'NR > 1' | tr '\n' ' ')
        warp_ep_kick "$ep1"
    fi
    return 0
}

# ---- MASQUE (usque) ----
warp_mq_su() {   # WARP_MQ_SU — запуск от uid 1000 (с группой 3999, если su умеет); 1 — никак
    [ -n "$WARP_MQ_SU" ] && return 0
    if su $WARP_MQ_UID -g "$DNSPROXY_GID" -c true >/dev/null 2>&1; then WARP_MQ_SU="su $WARP_MQ_UID -g $DNSPROXY_GID"
    elif su $WARP_MQ_UID -c true >/dev/null 2>&1; then WARP_MQ_SU="su $WARP_MQ_UID"
    else return 1; fi
}

warp_mq_pid() {   # pid нашего usque
    local p
    for p in $(pidof usque 2>/dev/null); do
        case "$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)" in "$WARP_MQ_DIR/usque nativetun "*) echo "$p"; return 0 ;; esac
    done
    return 1
}

# Каталог uid 1000: бинарь (копия, если другой) и копия аккаунта. В /data/local/tmp пишет и shell — чужой или
# не каталог (ссылка) пересоздаём своим
warp_mq_prep() {
    if [ -L "$WARP_MQ_DIR" ] || [ ! -d "$WARP_MQ_DIR" ] || [ "$(stat -c %u "$WARP_MQ_DIR" 2>/dev/null)" != "$WARP_MQ_UID" ]; then
        rm -rf "$WARP_MQ_DIR"
        mkdir -m 700 "$WARP_MQ_DIR" 2>/dev/null || return 1
        chown $WARP_MQ_UID:$WARP_MQ_UID "$WARP_MQ_DIR" || return 1
    fi
    chmod 700 "$WARP_MQ_DIR"
    if ! cmp -s "$USQUE_BIN" "$WARP_MQ_DIR/usque"; then
        cp -f "$USQUE_BIN" "$WARP_MQ_DIR/usque.new" && chmod 755 "$WARP_MQ_DIR/usque.new" &&
            mv -f "$WARP_MQ_DIR/usque.new" "$WARP_MQ_DIR/usque" || return 1
    fi
    return 0
}

# Аккаунт Cloudflare для MASQUE: нет — usque register в фоне (до ~15 с), от uid 1000, мимо AdGuard.
# 0 — есть, 1 — создаётся, 2 — не создался (журнал — здесь)
warp_mq_register() {
    local now e
    [ -s "$WARP_MQ_CONF" ] && return 0
    now=$(date +%s)
    if grep -q '"private_key"' "$WARP_MQ_DIR/new.json" 2>/dev/null; then
        mkdir -p "$WARP_DIR"
        (umask 077; cp -f "$WARP_MQ_DIR/new.json" "$WARP_MQ_CONF.tmp") && mv -f "$WARP_MQ_CONF.tmp" "$WARP_MQ_CONF" || return 2
        rm -f "$WARP_MQ_DIR/new.json"; WARP_MQ_REG_TS=0
        log "WARP: MASQUE — аккаунт Cloudflare создан"
        return 0
    fi
    if [ "$WARP_MQ_REG_TS" -gt 0 ]; then
        [ $((now - WARP_MQ_REG_TS)) -lt 60 ] && return 1
        e=$(grep -v '^[[:space:]]*$' "$WARP_MQ_DIR/reg.log" 2>/dev/null | tail -1 | cut -c1-160)
        log "WARP: MASQUE — аккаунт не создался (${e:-нет ответа за минуту})"
        WARP_MQ_REG_TS=0
        return 2
    fi
    warp_mq_prep || return 2
    rm -f "$WARP_MQ_DIR/new.json" "$WARP_MQ_DIR/reg.log"
    log "WARP: MASQUE — аккаунта нет, создаю (usque register)"
    $WARP_MQ_SU -c "cd $WARP_MQ_DIR && exec ./usque register -a -n vpn-tether -c $WARP_MQ_DIR/new.json > $WARP_MQ_DIR/reg.log 2>&1" \
        < /dev/null > /dev/null 2>&1 &
    WARP_MQ_REG_TS=$now
    return 1
}

warp_mq_fail() {   # заметка пауза_с [строка журнала]
    [ -n "$3" ] && log "WARP: MASQUE — $3"
    warp_down; WARP_RETRY_TS=$(( $(date +%s) + $2 )); warp_set_state fail "$1"
    return 1
}

warp_mq_start() {
    local a4 a6 sni="$WARP_MASQUE_SNI" i=0 h2="" how="HTTP/3 по UDP 443"
    warp_down
    [ -e /dev/net/tun ] || { mkdir -p /dev/net && ln -s /dev/tun /dev/net/tun; } 2>/dev/null
    warp_mq_su || { warp_mq_fail "MASQUE: нет su $WARP_MQ_UID" $WARP_RETRY_SECS "не запустить от uid $WARP_MQ_UID (su $WARP_MQ_UID не работает)"; return 1; }
    warp_mq_register
    case $? in
        0) ;;
        1) warp_mq_fail "создаю аккаунт MASQUE" 10; return 1 ;;
        *) warp_mq_fail "аккаунт MASQUE не создался" $WARP_RETRY_SECS; return 1 ;;
    esac
    warp_mq_prep || { warp_mq_fail "MASQUE: нет каталога" 60 "не подготовить $WARP_MQ_DIR"; return 1; }
    (umask 077; cp -f "$WARP_MQ_CONF" "$WARP_MQ_DIR/config.json") && chown $WARP_MQ_UID:$WARP_MQ_UID "$WARP_MQ_DIR/config.json"
    a4=$(sed -n 's/.*"ipv4"[[:space:]]*:[[:space:]]*"\([0-9.]*\)".*/\1/p' "$WARP_MQ_CONF" | head -1)
    a6=$(sed -n 's/.*"ipv6"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F:]*\)".*/\1/p' "$WARP_MQ_CONF" | head -1)
    [ -n "$a4" ] || { warp_mq_fail "MASQUE: в аккаунте нет адреса" $WARP_RETRY_SECS "в $WARP_MQ_CONF нет адреса ipv4"; return 1; }
    $ip tuntap add dev $WARP_IF mode tun user $WARP_MQ_UID 2>/dev/null || {
        warp_mq_fail "MASQUE: нет tun" 60 "не создать $WARP_IF (ip tuntap)"; return 1; }
    [ "$WARP_MASQUE_H2" = 1 ] && { h2=" --http2"; how="HTTP/2 по TCP 443"; }
    : > "$WARP_MQ_DIR/usque.log"; chown $WARP_MQ_UID:$WARP_MQ_UID "$WARP_MQ_DIR/usque.log"
    $WARP_MQ_SU -c "exec $WARP_MQ_DIR/usque nativetun -c $WARP_MQ_DIR/config.json -n $WARP_IF -I --always-reconnect -m 1280${sni:+ -s $sni}$h2 >> $WARP_MQ_DIR/usque.log 2>&1" \
        < /dev/null > /dev/null 2>&1 &
    WARP_PID=""
    while [ $i -lt 50 ] && [ -z "$WARP_PID" ]; do sleep 0.1; i=$((i + 1)); WARP_PID=$(warp_mq_pid); done
    [ -n "$WARP_PID" ] || { warp_mq_fail "MASQUE: usque не запустился" 60 \
        "usque не запустился за 5 с ($(tail -1 "$WARP_MQ_DIR/usque.log" 2>/dev/null | cut -c1-120))"; return 1; }
    $ip addr add "$a4/32" dev $WARP_IF 2>/dev/null; warp_src_guard add "$a4"
    [ -n "$a6" ] && $ip -6 addr add "$a6/128" dev $WARP_IF 2>/dev/null
    $ip link set $WARP_IF mtu 1280 up 2>/dev/null
    echo 2 > /proc/sys/net/ipv4/conf/$WARP_IF/rp_filter 2>/dev/null
    $ip route replace default dev $WARP_IF table $WARP_TABLE 2>/dev/null
    $ip -6 route replace default dev $WARP_IF table $WARP_TABLE 2>/dev/null
    $ip rule add oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    $ip -6 rule add oif $WARP_IF lookup $WARP_TABLE pref $WARP_PREF 2>/dev/null
    # Cloudflare — проверка строгая (warp=on); хендшейка awg нет — сразу к проверке трафиком, адреса не перебираем
    WARP_CUR="$WARP_MQ_NAME"; WARP_STATE=starting; WARP_TS=$(date +%s); WARP_CHECK_TS=0; WARP_FAILS=0; WARP_NETCHG=0; WARP_TG_TS=0
    WARP_CF=1; WARP_EP0=""; WARP_HS=1; WARP_EP_TRIED=""; WARP_EP_SILENT=""; WARP_EP_Q=""; WARP_EP_CUR=""; WARP_RU_EP=""; WARP_RU_TRY=0
    log "WARP: запускаю MASQUE (usque, $how, имя ${sni:-как у Cloudflare})"
    return 0
}

# Трафик через туннель есть: trace Cloudflare ответил через warp0. Сервер
# Cloudflare — нужен «warp=on» (WARP_CF); свой AmneziaWG/WireGuard честно
# отвечает «warp=off» и отбраковывался (лог 4PDA 26.10) — ему любой ответ. От группы dnsproxy — мимо
# прокси AdGuard (с --interface он даёт тайм-аут).
warp_probe() {
    # по IP: при отказе DNS (DoH не отвечает) проверка по имени валилась и
    # живой туннель считался мёртвым (27.10 09:52)
    # -k: в Android 8 нет корня сертификата 1.1.1.1, а запрос и так идёт в туннель
    local cmd="$CURL_BIN -s -k -m 5 --interface $WARP_IF https://1.1.1.1/cdn-cgi/trace" out rc a
    if [ -z "$WARP_SU_G" ]; then
        WARP_SU_G=0
        [ -n "$SUG_CMD" ] && $SUG_CMD "$DNSPROXY_GID" -c true >/dev/null 2>&1 && WARP_SU_G=1
    fi
    if [ "$WARP_SU_G" = "1" ]; then out=$($SUG_CMD "$DNSPROXY_GID" -c "$cmd" 2>/dev/null); else out=$(eval "$cmd" 2>/dev/null); fi
    rc=$?
    WARP_PROBE_NOTE="1.1.1.1 rc=$rc, ответ ${#out} Б"
    WARP_COLO=$(echo "$out" | sed -n 's/^colo=\([A-Z]*\).*/\1/p' | head -1)
    if [ "$WARP_CF" = 1 ]; then
        case "$out" in *warp=on*|*warp=plus*) return 0 ;; esac
    else
        case "$out" in *ip=*) return 0 ;; esac
        # свой сервер: публичные DNS за ним бывают закрыты (конфиги юзера 05.11: шлюз
        # отвечает Port Unreachable на 1.1.1.1 и 8.8.8.8, ya.ru и GitHub открыты), а
        # туннель жив — любой ответ по этим адресам тоже трафик. Cloudflare — строго
        for a in 8.8.8.8 77.88.55.242 140.82.121.3; do
            cmd="$CURL_BIN -s -k -m 3 -o /dev/null -w %{http_code} --interface $WARP_IF https://$a/"
            if [ "$WARP_SU_G" = "1" ]; then out=$($SUG_CMD "$DNSPROXY_GID" -c "$cmd" 2>/dev/null); else out=$(eval "$cmd" 2>/dev/null); fi
            rc=$?
            WARP_PROBE_NOTE="$WARP_PROBE_NOTE, $a rc=$rc, код ${out:-нет}"
            case "$out" in ''|000) ;; *) return 0 ;; esac
        done
    fi
    return 1
}

# Telegram DC2/DC4 (Амстердам, 149.154.166–167.x) через туннель. 30.10: в части
# сессий WARP (выход один — 104.28.244.74, FRA) TCP до них есть, а ответа нет;
# DC1/3/5 и IPv6 тех же ДЦ живы. Аккаунты из России — в DC2/DC4: фото шли через
# запасные узлы Telegram (142.252.58.x) по 30 КБ, веб — висел. Новая сессия —
# лотерея (живы были 2 из 7). 0 — мертвы при живом DC1, 1 — живы или не понять
warp_tg_dead() {
    local a c
    for a in 149.154.167.51 149.154.167.91 149.154.175.50; do
        if [ "$WARP_SU_G" = "1" ]; then
            c=$($SUG_CMD "$DNSPROXY_GID" -c "$CURL_BIN -s -o /dev/null -m 3 --interface $WARP_IF -w %{http_code} http://$a/api" 2>/dev/null)
        else
            c=$(curl -s -o /dev/null -m 3 --interface $WARP_IF -w %{http_code} "http://$a/api" 2>/dev/null)
        fi
        # DC2 или DC4 ответил — живы; дошли до DC1 — значит, оба молчали
        [ "$a" = 149.154.175.50 ] && { [ "${c:-000}" != 000 ]; return $?; }
        [ "${c:-000}" != 000 ] && return 1
    done
    return 1
}

# пауза до повтора и заметка в статус, когда туннель молчит, а дело не в конфиге
warp_nonet_wait() { if [ "$ZAPRET_WL" = "1" ]; then echo "$WARP_WL_RETRY"; else echo "$WARP_NONET_RETRY"; fi; }
warp_nonet_note() { if [ "$ZAPRET_WL" = "1" ]; then echo "белые списки"; else echo "нет сети"; fi; }

# Сеть вообще есть? Туннель молчит — проверка мимо него (Cloudflare, Google по IP).
# Метро 29.10 11:15–11:22: связь пропадала каждые ~2 мин, и WARP браковал
# конфиг за конфигом (4 штуки), хотя молчало всё — DoH, YouTube. Белые списки
# оператора — тоже «сети нет»: перебор конфигов там не поможет
# (только «дошёл ли ответ» — -k, сертификат не важен)
warp_uplink() {
    local u
    # Белый список (zapret_whitelist_check): 1.1.1.1 и 8.8.8.8 на части адресов оператора
    # в нём открыты, а адреса WARP закрыты — «сеть есть», и конфиги шли в брак один за
    # другим (11.11 18:44–18:46: три конфига за две минуты, потом по кругу раз в 5 мин)
    [ "$ZAPRET_WL" = "1" ] && return 1
    # при подъёме без хендшейка warp_probe ещё не звали — флаг пуст, и curl
    # шёл бы от root через прокси AdGuard
    if [ -z "$WARP_SU_G" ]; then
        WARP_SU_G=0
        [ -n "$SUG_CMD" ] && $SUG_CMD "$DNSPROXY_GID" -c true >/dev/null 2>&1 && WARP_SU_G=1
    fi
    for u in https://1.1.1.1/cdn-cgi/trace https://8.8.8.8/; do
        if [ "$WARP_SU_G" = "1" ]; then
            $SUG_CMD "$DNSPROXY_GID" -c "$CURL_BIN -s -k -m 3 -o /dev/null $u" >/dev/null 2>&1 && return 0
        else
            curl -s -k -m 3 -o /dev/null "$u" >/dev/null 2>&1 && return 0
        fi
    done
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
            OK*) log "WARP: созданы конфиги:${r#OK}"; WARP_RETRY_TS=0; WARP_ENSURE_BUSY=0 ;;
            '') ;;
            # занято (сторож проверяет обход — после включения WARP почти всегда, 09.11 на MT6580 и
            # NX1) — не сбой Cloudflare: через 30 с, без удвоения паузы
            # (тексты — из warp/warp.sh gen)
            *"идёт подбор"*|*"уже идёт"*)
               [ "$WARP_ENSURE_BUSY" = 1 ] || log "WARP: конфиги создам позже — ${r#ERR } (повтор каждые 30 с)"
               WARP_ENSURE_BUSY=1; WARP_ENSURE_DONE=0; WARP_ENSURE_AT=$(( $(date +%s) + 30 )) ;;
            *) WARP_ENSURE_BUSY=0
               log "WARP: не удалось создать конфиги — $r (повтор через $((WARP_ENSURE_WAIT / 60)) мин)"
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
    # свой сервер после WARP (WARP_CHAIN) — не WARP: только он в хранилище — конфигов Cloudflare всё равно нет
    [ -n "$(warp_conf_names)" ] && return 0
    [ "$WARP_ENSURE_BUSY" = 1 ] || log "WARP: конфигов нет — создаю 3 (первый запуск)"
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

# WebUI «Переподключить»: тот же конфиг заново — новая сессия Cloudflare. 30.10:
# от сессии зависят DC2/DC4 Telegram и скорость (2,5 Мбит/с против 21,8 напрямую);
# вручную в WG Tunnel помогало переподключить тот же конфиг
warp_reconnect() {
    local n="$WARP_CUR"
    case "$WARP_STATE" in up|starting) ;; *) return 0 ;; esac
    [ -n "$n" ] || return 0
    log "WARP: $n — переподключаю (кнопка в WebUI)"
    warp_down "переподключение"
    warp_set_state off ""
    net_identity_reconcile
    warp_start "$n" && warp_set_state starting ""
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
    elif wan_gone; then why="нет сети"
    fi
    if [ "$WARP_ENGINE" = masque ] && [ -z "$USQUE_BIN" ] && [ -z "$WARP_MQ_WARN" ]; then
        WARP_MQ_WARN=1; log "WARNING: WARP: MASQUE (usque) только на arm64 — беру AmneziaWG"
    fi
    # первые конфиги — только при сети (иначе регистрация падает до перезагрузки)
    [ -z "$why" ] && warp_ensure
    # «Если выход не работает» (WARP_STRICT): блок держим, пока WARP включён и нужен — и без сети, и в паузе kill-switch
    # (VPN выбран, но не поднят: иначе Telegram телефона шёл бы через оператора — ревью 25.11; раздачу держит guard).
    # Выключен, поднят VPN — блок и разметку снять (через VPN всё и так идёт в туннель)
    case "$why" in
        ''|"нет сети"|"пауза kill-switch") warp_block_set "$WARP_STRICT" ;;
        *) warp_block_set 0; warp_routes_off ;;
    esac
    # блок, а WARP ещё/уже не поднят: разметка всё равно стоит — иначе то, что идёт в WARP, ушло бы напрямую
    # (после загрузки до первого подъёма, при переподключении, без конфигов)
    [ "$WARP_BLK_LVL" -ge 1 ] 2>/dev/null && [ "$WARP_STATE" != up ] && warp_routes_reconcile
    if [ -n "$why" ]; then
        if [ "$WARP_STATE" != off ]; then warp_down "$why"; WARP_BAD=""; WARP_EP_FULL=0; WARP_RETRY_TS=0; fi
        warp_set_state off "$why"   # повторы отсекает WARP_PUB
        return 0
    fi
    now=$(date +%s)
    case "$WARP_STATE" in
        off|fail)
            if [ "$WARP_STATE" = fail ] && [ "$now" -lt "$WARP_RETRY_TS" ]; then
                if [ "$WARP_NOTE" = "белые списки" ] && [ "$ZAPRET_WL" != "1" ]; then
                    :   # список снят — сразу, не ждать остаток WARP_WL_RETRY
                else
                    # конфиги создали/импортировали в WebUI — сразу, не через 5 мин
                    [ "$WARP_NOTE" = "нет конфигов" ] && [ -n "$(warp_conf_names)" ] || return 0
                fi
            fi
            [ -n "$WARP_ENSURE_PID" ] && return 0   # конфиги ещё создаются
            if ! n=$(warp_pick); then
                if [ -z "$(warp_conf_names)" ]; then
                    [ "$WARP_NOTE" = "нет конфигов" ] || log "WARP: нет конфигов — создайте или импортируйте в WebUI"
                    warp_set_state fail "нет конфигов"
                elif n=$(warp_stick_name); then
                    # «Не менять сервер»: тот же через 30 с, не через 5 мин; в журнал — один раз
                    [ "$WARP_NOTE" = "не поднялся" ] || log "WARP: $n не поднялся — «Не менять сервер»: пробую его же каждые 30 с"
                    warp_set_state fail "не поднялся"
                    WARP_BAD=""; WARP_EP_FULL=0; WARP_RETRY_TS=$((now + 30))
                    return 0
                elif warp_mq_on; then
                    # MASQUE — один: не ждать 5 мин, как после круга конфигов; в журнал — один раз
                    [ "$WARP_NOTE" = "не поднялся" ] || log "WARP: MASQUE не поднялся — повтор каждую минуту"
                    warp_set_state fail "не поднялся"
                    WARP_BAD=""; WARP_RETRY_TS=$((now + 60))
                    return 0
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
                    if [ -n "$WARP_RU_EP" ]; then
                        # иначе — только российская площадка: лучше она, чем без WARP
                        WARP_EP_Q="$WARP_RU_EP"; WARP_RU_EP=""; WARP_RU_TRY=1
                        log "WARP: $WARP_CUR — другой площадки нет, беру $WARP_EP_Q (российская)"
                        warp_ep_next
                        return 0
                    fi
                    if ! warp_uplink; then
                        # и напрямую сети нет (метро) — конфиг не виноват: тот же заново
                        # пауза: из off тот же конфиг поднимался бы сразу, и без сети
                        # (белые списки — часами) перебор адресов и перезапуски шли по кругу
                        log "WARP: $WARP_CUR — нет хендшейка, но напрямую тоже — $(warp_nonet_note) — конфиг не бракую, повтор через $(warp_nonet_wait) с"
                        warp_down; WARP_RETRY_TS=$((now + $(warp_nonet_wait))); warp_set_state fail "$(warp_nonet_note)"
                        return 0
                    fi
                    if [ "$WARP_RU_TRY" = 1 ]; then
                        # хендшейк другие адреса давали — не «пул закрыт» (WARP_EP_FULL)
                        log "WARP: $WARP_CUR — и запасной российский $WARP_EP_CUR не ответил, беру следующий"
                    else
                        log "WARP: $WARP_CUR — нет хендшейка ни на одном адресе (${WARP_EP_TRIED# }), беру следующий"
                        WARP_EP_FULL=$((WARP_EP_FULL + 1))
                    fi
                    warp_mark_bad "$WARP_CUR"; warp_down; warp_set_state off ""
                fi
            elif warp_probe; then
                if [ "$WARP_CF" = 1 ] && warp_colo_ru && [ -n "$WARP_EP_Q" ]; then
                    # российская площадка — сначала остальные адреса; эта — запасная
                    log "WARP: $WARP_CUR — $WARP_EP_CUR выводит на российскую площадку $WARP_COLO (там режут Telegram и др.), пробую следующий адрес"
                    [ -n "$WARP_RU_EP" ] || WARP_RU_EP="$WARP_EP_CUR"
                    WARP_FAILS=0
                    warp_ep_next
                    return 0
                fi
                WARP_LAST_UP="$WARP_CUR"   # за него держится «Не менять сервер», если основной не выбран
                log "WARP: $WARP_CUR поднят за $(( $(date +%s) - WARP_TS )) с${WARP_COLO:+ (площадка $WARP_COLO)}"
                if [ "$WARP_CF" = 1 ] && warp_colo_ru; then
                    log "WARNING: WARP: только российская площадка Cloudflare ($WARP_COLO) — Telegram и часть сайтов через WARP могут не открываться"
                elif [ "$WARP_CF" = 1 ] && [ -n "$WARP_EP_CUR" ]; then
                    warp_ep_save "$WARP_EP_CUR"
                fi
                WARP_COLO_UP="$WARP_COLO"
                WARP_TS=$(date +%s); WARP_CHECK_TS=$WARP_TS; WARP_FAILS=0
                # переподняли из-за Telegram — проверить новую сессию через ~10 с, не через минуту
                [ "$WARP_TG_TRIES" -gt 0 ] && WARP_CHECK_TS=$((WARP_TS - WARP_CHECK_SECS + 10))
                warp_set_state up ""
                warp_routes_reconcile
            else
                WARP_FAILS=$((WARP_FAILS + 1))
                # 3 проверки по 5 с + такты цикла ≈ 20 с (свежий поднимается за ~0,7 с)
                if [ $WARP_FAILS -ge 3 ] && [ -n "$WARP_RU_EP" ]; then
                    # адрес после российского: хендшейк есть, трафика нет — конфиг
                    # не виноват, российский с трафиком уже был: к нему
                    WARP_EP_Q="$WARP_RU_EP"; WARP_RU_EP=""; WARP_RU_TRY=1; WARP_FAILS=0
                    log "WARP: $WARP_CUR — через $WARP_EP_CUR нет трафика, беру $WARP_EP_Q (российская)"
                    warp_ep_next
                elif [ $WARP_FAILS -ge 3 ] && ! warp_uplink; then
                    log "WARP: $WARP_CUR — нет трафика ($(warp_hs_note)), но напрямую тоже — $(warp_nonet_note) — конфиг не бракую, повтор через $(warp_nonet_wait) с"
                    warp_down; WARP_RETRY_TS=$((now + $(warp_nonet_wait))); warp_set_state fail "$(warp_nonet_note)"
                elif [ $WARP_FAILS -ge 3 ]; then
                    log "WARP: $WARP_CUR — нет трафика через туннель ($(warp_hs_note)), беру следующий"
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
            warp_chain_reconcile
            [ $((now - WARP_CHECK_TS)) -lt $WARP_CHECK_SECS ] && return 0
            WARP_CHECK_TS=$now
            if warp_probe; then
                { [ $WARP_FAILS -gt 0 ] || [ "$WARP_NONET" = 1 ]; } && log "WARP: $WARP_CUR снова отвечает"
                WARP_FAILS=0; WARP_NETCHG=0; WARP_NONET=0
                # Cloudflare перевёл на другую площадку (роуминг, маршруты) — в лог
                # и в статус; на российскую посреди работы — только предупредить
                if [ -n "$WARP_COLO" ] && [ "$WARP_COLO" != "$WARP_COLO_UP" ]; then
                    log "WARP: площадка сменилась: ${WARP_COLO_UP:-?} -> $WARP_COLO"
                    [ "$WARP_CF" = 1 ] && warp_colo_ru && \
                        log "WARNING: WARP: российская площадка Cloudflare ($WARP_COLO) — Telegram и часть сайтов через WARP могут не открываться"
                    WARP_COLO_UP="$WARP_COLO"; phone_status_refresh
                fi
                # Telegram DC2/DC4 через эту сессию — раз в WARP_TG_SECS; мертвы при
                # живом DC1 — переподнять (новая сессия), не больше WARP_TG_MAX подряд
                # со своим сервером после WARP Telegram идёт через него — сессия Cloudflare ни при чём; при «только свой
                # сервер» (блок 2) через WARP он не идёт и когда цепочка не поднята — переподключать WARP незачем
                if [ "$WARP_TELEGRAM" = 1 ] && [ "$WARP_CF" = 1 ] && [ "$WARP_CH_STATE" != up ] && [ "$WARP_BLK_LVL" != 2 ] && \
                   [ "$now" -ge "$WARP_TG_HOLD" ] && \
                   [ $((now - WARP_TG_TS)) -ge $WARP_TG_SECS ]; then
                    WARP_TG_TS=$now
                    if warp_tg_dead; then
                        WARP_TG_TRIES=$((WARP_TG_TRIES + 1))
                        # через туннель сейчас идёт видео (отбой YouTube вёл туда адреса) —
                        # снос оборвал бы его: 08.11 ролик висел 11 с. Попытка не в счёт.
                        # Не больше 2 раз подряд: warp_yt_busy видит и простаивающие
                        # соединения (conntrack держит ESTABLISHED до 2 ч) — без предела
                        # Telegram через WARP мог не ожить вовсе (облачное ревью 08.11)
                        if [ "$WARP_TG_YTW" -lt 2 ] && warp_yt_busy; then
                            WARP_TG_YTW=$((WARP_TG_YTW + 1))
                            WARP_TG_TRIES=$((WARP_TG_TRIES - 1))
                            log "WARP: Telegram DC2/DC4 через туннель молчат, но через него идёт видео YouTube — переподключу на следующей проверке"
                            return 0
                        fi
                        WARP_TG_YTW=0
                        if [ $WARP_TG_TRIES -gt $WARP_TG_MAX ]; then
                            log "WARP: Telegram DC2/DC4 через туннель молчат — $WARP_TG_MAX переподключений подряд не помогли, жду $((WARP_TG_PAUSE / 60)) мин"
                            WARP_TG_TRIES=0; WARP_TG_HOLD=$((now + WARP_TG_PAUSE))
                        else
                            log "WARP: $WARP_CUR — Telegram DC2/DC4 (Амстердам) через туннель молчат, DC1 отвечает — переподключаю ($WARP_TG_TRIES/$WARP_TG_MAX)"
                            warp_down "Telegram DC2/DC4 недоступны"; warp_set_state off ""
                            return 0
                        fi
                    else
                        [ $WARP_TG_TRIES -gt 0 ] && log "WARP: Telegram DC2/DC4 через туннель отвечают (переподключений: $WARP_TG_TRIES)"
                        WARP_TG_TRIES=0; WARP_TG_YTW=0
                    fi
                fi
            elif [ "$WARP_NETCHG" = 1 ]; then
                # сменилась сеть, а туннель молчит — сразу заново (хендшейк и
                # адрес для этой сети), не ждать 3 промаха (~30 с, лог 28.10:
                # Wi-Fi -> Wi-Fi без пропадания WAN). Конфиг не виноват
                WARP_NETCHG=0
                warp_down "сменилась сеть"; warp_set_state off ""
            elif [ "$ZAPRET_WL" = "1" ]; then
                # белый список: туннель молчит часами, а проверка каждые 10 с — это до 11 с
                # curl на круг демона. После трёх промахов подряд (как без списка: весной
                # при списке WARP жил, один промах — не повод) снимаем и пробуем раз в
                # WARP_WL_RETRY. Конфиг не бракуем
                WARP_FAILS=$((WARP_FAILS + 1))
                WARP_CHECK_TS=$((now - WARP_CHECK_SECS + 10))
                if [ $WARP_FAILS -ge 3 ]; then
                    log "WARP: $WARP_CUR не отвечает, у оператора белые списки — снимаю, повтор через $WARP_WL_RETRY с"
                    warp_down; WARP_RETRY_TS=$(( $(date +%s) + WARP_WL_RETRY )); warp_set_state fail "белые списки"
                else
                    log "WARP: $WARP_CUR не отвечает ($WARP_FAILS/3)"
                fi
            elif ! warp_uplink; then
                # мимо туннеля тоже тишина — конфиг не виноват: держим его,
                # проверяем чаще; оживёт сеть — «снова отвечает». Промахи — с нуля:
                # туннелю после возврата сети нужен новый хендшейк (тест: 1 промах).
                # 10 с — от конца проверок: они сами до 11 с (5 + 2×3), от now
                # следующая шла бы сразу, и цикл демона почти не выходил из curl
                WARP_CHECK_TS=$(( $(date +%s) - WARP_CHECK_SECS + 10 ))
                [ "$WARP_NONET" = 1 ] || log "WARP: $WARP_CUR не отвечает, но и напрямую сети нет — конфиг не меняю"
                WARP_NONET=1; WARP_FAILS=0
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
    local d="${1%.}" q="" l srv=127.0.0.1 port="$DNSPROXY_PORT" r
    # жив, а не «бинарь есть»: остановленный (DNS_PHONE=0 без раздачи, не
    # поднялся) давал пустой ответ на все WARP_DOMAINS на 10 мин (ревью PR #19)
    [ -n "$port" ] && dnsproxy_alive || { srv=1.1.1.1; port=53; }
    for l in $(echo "$d" | tr '.' ' '); do q="$q$(printf '\\%03o' ${#l})$l"; done
    # shellcheck disable=SC2059
    r=$(printf "\\022\\064\\001\\000\\000\\001\\000\\000\\000\\000\\000\\000$q\\000\\000\\001\\000\\001" | \
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
                  } }')
    [ -n "$r" ] && { echo "$r"; return 0; }
    # Android 8 (нет /apex): toybox nc не принимает эти ключи, у busybox nc нет UDP.
    # На новых пустой ответ — сбой DNS: обычный DNS мимо dnsproxy дал бы чужие адреса
    [ -d /apex ] && return 0
    # busybox nslookup умеет «сервер:порт» — тот же dnsproxy, что у приложений. 09.11 на MT6580
    # через 8.8.8.8 провайдер отдал 4pda.to 8.6.112.0/8.47.69.0, Chrome по DoH — 104.20.39.144:
    # правила Opera стояли не на тех адресах, 4pda шёл напрямую (451). Адреса — после «Name:»,
    # строки выше — сам сервер
    [ -n "$BUSYBOX" ] && timeout 4 "$BUSYBOX" nslookup "$d" "$srv:$port" 2>/dev/null | \
        sed -n '/^Name/,$ s/^Address[ 0-9]*: *\([0-9.]*\).*/\1/p' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
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
    # до конца, а не до сигнала: USR1 прерывает wait — недочитанные ответы (ревью PR #19)
    for p in $pids; do while kill -0 "$p" 2>/dev/null; do wait "$p" 2>/dev/null; done; done
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
    pkg_with_clones $WARP_TG_PKGS
}

warp_app_uids() {
    local p u out=""
    for p in $WARP_APPS $(warp_tg_pkgs); do
        u=$(pkg_uid "$p")
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
# Приложения целиком (WARP_APPS, клиенты Telegram) ходят и мимо сетей групп (у Telegram — запасные узлы):
# их сокеты — по uid, при любой смене пути, кроме смены групп ($3 = «-»). 26.11 на 13T: соединения Telegram,
# открытые через голый WARP, так и шли через него после подъёма своего сервера (~80 пакетов за минуту)
warp_kill_sockets() {   # причина [сети — по умолчанию все сети групп] [- — без приложений]
    local f="" m n=0 k=0 nets="${2-$(warp_dst4)}"
    command -v ss >/dev/null 2>&1 || return 0
    if [ "$WARP_PHONE" = "1" ]; then
        for m in $nets; do f="$f${f:+ or }dst $m"; done
        # shellcheck disable=SC2086
        if [ -n "$f" ] && [ -n "$WARP_KILL_KEEP" ]; then
            # смена своего сервера: у приложений мимо него путь не менялся — по одному, кроме их uid
            n=$(warp_kill_each "( $f )" "" "$WARP_KILL_KEEP")
        elif [ -n "$f" ]; then
            n=$(ss -K -tn state established state syn-sent "( $f )" 2>/dev/null | awk 'NR > 1' | grep -c .)
        fi
    fi
    [ "$3" = "-" ] || k=$(warp_kill_app_sockets)
    [ "$((${n:-0} + ${k:-0}))" -gt 0 ] && log "WARP: закрыто соединений телефона к адресам из WARP: ${n:-0}$([ "${k:-0}" -gt 0 ] && echo ", приложений целиком: $k") ($1) — приложения переподключатся сразу"
    return 0
}

# Сокеты приложений целиком (uid из WARP_APP_UIDS, кроме WARP_KILL_KEEP — мимо своего сервера при его смене).
# Печатает, сколько закрыто
warp_kill_app_sockets() {
    local u="" k
    for k in $WARP_APP_UIDS; do case " $WARP_KILL_KEEP " in *" $k "*) ;; *) u="$u $k" ;; esac; done
    [ -n "$u" ] && command -v ss >/dev/null 2>&1 || { echo 0; return 0; }
    warp_kill_each "" "${u# }" ""
}

# Сокеты по одному: ss -K по uid не фильтрует, но показывает его (-e). Фильтр ss (пусто — все), только эти uid
# (пусто — любые), кроме этих uid. Печатает, сколько закрыто
warp_kill_each() {   # "фильтр" "только uid" "кроме uid"
    local l lp p a n=0
    command -v ss >/dev/null 2>&1 || { echo 0; return 0; }
    # два состояния — с колонкой State: $4 свой адрес, $5 чужой; фильтр — словами (ss их склеит)
    # shellcheck disable=SC2086
    for l in $(ss -tne state established state syn-sent $1 2>/dev/null | awk -v o=" $2 " -v x=" $3 " 'NR > 1 {
            u = "-"; for (i = 6; i <= NF; i++) if ($i ~ /^uid:/) { u = substr($i, 5); break }
            if ((o == "  " || index(o, " " u " ")) && !index(x, " " u " ")) print $4 "|" $5 }'); do
        lp=${l%%|*}; p=${l#*|}
        a=${p%:*}; a=${a#[}; a=${a%]}
        ss -K -tn state established state syn-sent dst "$a" dport = ":${p##*:}" sport = ":${lp##*:}" 2>/dev/null | \
            awk 'NR > 1' | grep -q . && n=$((n + 1))
    done
    echo $n
}

# Соединения, открытые до разметки WARP (старт демона): метка ставится только новым соединениям, и такие
# шли бы мимо WARP, пока не закроются. Раздача (WARP_TETHER=1) к сетям групп — записи conntrack без метки WARP
# с её подсетей (следующий пакет заведёт новую, уже с меткой: клиент переподключится через WARP или упрётся в
# блок); сокеты телефона — warp_kill_sockets (по WARP_PHONE, и приложений целиком). То, что идёт мимо WARP
# намеренно (раздача при WARP_TETHER=0, root и система), не трогаем. «ct» — только conntrack (второй вызов на
# старте: сокеты телефона к тому времени уже переподключились с меткой, рвать их снова незачем)
warp_drop_unmarked() {   # причина [ct] [ифейсы раздачи — по умолчанию LAST_TETHER_IFACES]
    local i s m c n=0 ifs="${3-$LAST_TETHER_IFACES}"
    if [ -n "$CONNTRACK_BIN" ] && [ "$WARP_TETHER" = 1 ]; then
        for i in $ifs; do
            s=$($ip -4 addr show dev "$i" 2>/dev/null | awk '/inet / { print $2; exit }')
            [ -n "$s" ] || continue
            for m in $(warp_dst4); do
                c=$($CONNTRACK_BIN -D -s "$s" -d "$m" --mark 0/$WARP_MARK 2>&1 | sed -n 's/.* \([0-9][0-9]*\) flow entries.*/\1/p')
                n=$((n + ${c:-0}))
            done
        done
    fi
    [ "$n" -gt 0 ] && log "WARP: сброшено соединений раздачи без разметки ($1): $n — переподключатся уже через WARP"
    [ "$2" = ct ] || warp_kill_sockets "$1"
    return 0
}

# Соединения раздачи к этим сетям — заново: путь сменился (свой сервер <-> WARP), а NAT старых записан на прежний
# туннель, и клиент висел бы до своего тайм-аута. Печатает, сколько сброшено
warp_drop_tether_ct() {   # сети
    local i s m c n=0
    if [ -n "$CONNTRACK_BIN" ]; then
        for i in $LAST_TETHER_IFACES; do
            s=$($ip -4 addr show dev "$i" 2>/dev/null | awk '/inet / { print $2; exit }')
            [ -n "$s" ] || continue
            for m in $1; do
                c=$($CONNTRACK_BIN -D -s "$s" -d "$m" 2>&1 | sed -n 's/.* \([0-9][0-9]*\) flow entries.*/\1/p')
                n=$((n + ${c:-0}))
            done
        done
    fi
    echo $n
}

# Старт демона (service.sh): блок и разметку WARP — сразу, а не в первом круге цикла (~15 с: сеть, DNS, обход).
# Иначе в это окно то, что идёт в WARP, уходило оператору напрямую, а открытые тогда соединения так и оставались
# без метки: 26.11 на 13T за перезапуск ~100 пакетов к сетям Telegram через оператора (телефон и раздача) и ещё
# ~50 после подъёма своего сервера. Только при «Если выход не работает» = блок (WARP_STRICT 1/2): при 0 без
# туннеля размеченное и так идёт напрямую. Вызов 1 — до настройки сети: телефон и раздача (её ифейсы — discovery:
# при перезапуске старая разметка снесена, и до вызова 2 клиенты шли бы мимо — 26.11 ~19 пакетов), без адресов
# доменов (DNS ещё нет); вызов 2 (аргумент 1) — после apply_state: домены и ифейсы, как их увидел apply_state
warp_start_block() {   # [1 — второй вызов]
    local tif
    [ "$WARP_ENABLE" = 1 ] && [ "$WARP_STRICT" -ge 1 ] 2>/dev/null || return 0
    [ -n "$AWG_BIN" ] && [ -n "$AWG_GO_BIN" ] || return 0
    vpn_up_now && return 0
    if [ "$1" = 1 ]; then
        [ "$WARP_RT_ON" = 1 ] || return 0
        warp_routes_reconcile
        warp_drop_unmarked "старт демона, раздача" ct
        return 0
    else
        WARP_APP_UIDS=$(warp_app_uids); WARP_APP_TS=$(date +%s)
        tif=""; [ "$WARP_TETHER" = 1 ] && tif=$(get_active_tether_ifaces)
        warp_block_set "$WARP_STRICT"
        warp_routes_apply "$tif" || return 0
        # подпись пустая — первый же reconcile пересоберёт с раздачей и доменами; группы — как сейчас
        WARP_RT_SIG=""; WARP_RT_DST=$(warp_dst4); WARP_RT_GRP="$WARP_GOOGLE$WARP_TELEGRAM$WARP_PHONE|$WARP_DOMAINS"
    fi
    warp_drop_unmarked "старт демона" "" "$tif"
}

# Через туннель идёт видео YouTube: в conntrack есть установленные соединения с обеими
# метками — видео (YT_CTMARK, googlevideo в ClientHello) и WARP: группа Google (WARP_GOOGLE),
# и телефон, и раздача
warp_yt_busy() {
    local m
    [ -n "$CONNTRACK_BIN" ] || return 1
    m=$(printf '0x%x' $((YT_CTMARK | WARP_MARK)))
    $CONNTRACK_BIN -L -p tcp --mark "$m/$m" 2>/dev/null | grep -q ' ESTABLISHED '
}

warp_routes_off() {   # [force] — снять, даже если по флагу не стоят
    local t c _n
    [ "$WARP_RT_ON" = "1" ] || [ "$1" = "force" ] || return 0
    $ip rule del fwmark $WARP_MARK/$WARP_MARK lookup $WARP_TABLE pref $WARP_MARK_PREF 2>/dev/null
    for t in "$iptables" "$ip6tables"; do
        _n=0; while [ $_n -lt 8 ] && $t -t mangle -D OUTPUT -j "$CHAIN_WARP_OUT" 2>/dev/null; do _n=$((_n + 1)); done
        _n=0; while [ $_n -lt 8 ] && $t -t mangle -D PREROUTING -j "$CHAIN_WARP_PRE" 2>/dev/null; do _n=$((_n + 1)); done
        # VPN_WARP_YT — видеосерверы в WARP до 15.11: после обновления без перезагрузки осталась бы сиротой
        for c in "$CHAIN_WARP_OUT" "$CHAIN_WARP_PRE" "$CHAIN_WARP_DST" "$CHAIN_WARP_SET" VPN_WARP_YT; do
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
        # соединения после сноса туннеля идут мимо со старым NAT и молча висят до
        # тайм-аута приложения. 08.11: переподключения из-за Telegram DC2/DC4 — 5 раз за 2 мин
        warp_kill_sockets "туннель снят" "$(warp_dst4)"
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
    # первой, как у Opera: чужая цепочка с NFQUEUE в конце таблицы не должна съедать метку WARP
    $iptables -t mangle -C OUTPUT -j "$CHAIN_WARP_OUT" 2>/dev/null || $iptables -t mangle -I OUTPUT 1 -j "$CHAIN_WARP_OUT"
    $iptables -t mangle -C PREROUTING -j "$CHAIN_WARP_PRE" 2>/dev/null || $iptables -t mangle -A PREROUTING -j "$CHAIN_WARP_PRE"
    $ip rule del fwmark $WARP_MARK/$WARP_MARK lookup $WARP_TABLE pref $WARP_MARK_PREF 2>/dev/null
    $ip rule add fwmark $WARP_MARK/$WARP_MARK lookup $WARP_TABLE pref $WARP_MARK_PREF
    # NAT и FORWARD
    $iptables -t nat -N "$CHAIN_WARP_NAT" 2>/dev/null; $iptables -t nat -F "$CHAIN_WARP_NAT"
    # warp+ — и warp0, и свой сервер после WARP (warp1, WARP_CHAIN)
    $iptables -t nat -A "$CHAIN_WARP_NAT" -o warp+ -j MASQUERADE
    $iptables -t nat -C POSTROUTING -j "$CHAIN_WARP_NAT" 2>/dev/null || $iptables -t nat -I POSTROUTING 1 -j "$CHAIN_WARP_NAT"
    $iptables -N "$CHAIN_WARP_FWD" 2>/dev/null; $iptables -F "$CHAIN_WARP_FWD"
    for i in $tif; do
        $iptables -A "$CHAIN_WARP_FWD" -i "$i" -o warp+ -j ACCEPT
        $iptables -A "$CHAIN_WARP_FWD" -i warp+ -o "$i" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
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
    # WARP_TETHER=0 — раздаче без WARP: нет ифейсов — нет правил клиентов
    # (PREROUTING, FORWARD, v6); телефон — по WARP_PHONE, как раньше
    [ "$WARP_TETHER" = "1" ] || tif=""
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
    if [ "$was" != "1" ]; then warp_kill_sockets "$([ "$WARP_STATE" = up ] && echo 'туннель поднят' || echo 'блок: разметка без туннеля')"
    elif [ -n "$WARP_RT_GRP" ] && [ "$grp" != "$WARP_RT_GRP" ]; then
        warp_kill_sockets "сменились группы" "$(printf '%s\n%s\n' "$old" "$new" | grep . | sort | uniq -u)" -
    fi
    WARP_RT_GRP="$grp"
    return 0
}

# ============================================================================
# Свой сервер после WARP (WARP_CHAIN, 25.11): AmneziaWG к своему серверу внутри туннеля Cloudflare. ТСПУ видит
# только WARP, свой сервер — подключения с адресов Cloudflare: бан адреса VPS «для России» (ноябрь 2026, статья
# zapret.moe: «через WARP работает») цепочку не задевает. Стенд 25.11 (13T, YOTA, Vultr SG): выход SG,
# 7–8 Мбит/с против 23 у одного WARP, RTT 333 против 121 мс, к серверу напрямую 0 пакетов.
#  - warp1: имя warp* — detect_tun_name не берёт его за VPN телефона, правила «-o warp+» те же, что у warp0;
#  - пакеты самого warp1 к серверу — правилом «to адрес -> WARP_TABLE», за ним «to адрес prohibit»: без warp0
#    (таблица пуста) напрямую не уходят. Правила ставятся до запуска — первый же пакет рукопожатия через WARP;
#  - что идёт в WARP (метка WARP_MARK) — при живой цепочке правилом выше WARP_MARK_PREF в свою таблицу;
#    цепочка не поднялась или замолчала — правило снимается, всё снова через WARP (повтор через 2 мин).
# Только поверх Cloudflare (WARP_CF=1) и только IPv4-адрес сервера. Конфиг цепочки WARP-ом не берётся (warp_conf_names).
# ============================================================================
WARP_CH_IF=warp1
WARP_CH_TABLE=3995
WARP_CH_EP_PREF=2970       # to сервер -> WARP_TABLE (default dev warp0)
WARP_CH_NO_PREF=2971       # to сервер -> prohibit: warp0 нет — не напрямую
WARP_CH_OIF_PREF=2976      # oif warp1 -> WARP_CH_TABLE (проверки, привязанные к warp1)
WARP_CH_MARK_PREF=2977     # метка WARP -> WARP_CH_TABLE, раньше WARP_MARK_PREF (2979)
WARP_CH_SKIP_PREF=2975     # uid из WARP_CHAIN_SKIP + метка WARP -> WARP_TABLE: мимо своего сервера, раньше 2977
WARP_CH_SKIP_ON=""         # «<список>|<сети Telegram 0/1>|<uid>» — для них стоят правила мимо своего сервера; пусто — не стоят
WARP_CH_SKIP_UIDS=""       # uid этих правил: их сокеты при смене своего сервера не трогаем (путь не менялся)
WARP_CH_SKIP_TS=0          # uid пересчитываем раз в 30 с: переустановка меняет uid (как WARP_APP_TS)
WARP_CH_SKIP_WARN=""       # отказ ip rule uidrange — в журнал один раз
WARP_KILL_KEEP=""          # warp_kill_sockets: uid, чьи сокеты не трогать (на время вызова)
WARP_CH_MTU=1200           # MTU warp0 1280 минус заголовки WireGuard (80)
WARP_CH_MSS=1160
WARP_CH_RETRY=120          # не поднялась / замолчала — повтор через 2 мин, дальше пауза растёт вдвое (до 30 мин):
WARP_CH_WAIT=120           # подъём синхронный, у мёртвого сервера ~10–15 с, и цикл демона их стоит (ревью 25.11)
WARP_CH_STATE=off          # off | up | fail
WARP_CH_PID=""
WARP_CH_NAME=""            # конфиг поднятой цепочки
WARP_CH_EP=""              # адрес сервера (IPv4), для которого стоят правила
WARP_CH_IP=""              # выход по trace
WARP_CH_LOC=""
WARP_CH_NOTE=""
WARP_CH_FAILS=0
WARP_CH_NONET=0            # не отвечал без связи (метро) — промахи не считали
WARP_CH_RETRY_TS=0
WARP_CH_CHECK_TS=0
# «Если выход не работает» (WARP_STRICT): запрет для метки WARP сразу за выходом, который защищаем. Выход жив —
# трафик уходит в него раньше (правило выше), упал — его таблица пуста или правило снято, и трафик упирается в
# запрет, а не идёт дальше: 2978 — за своим сервером (2977), до WARP (2979); 2981 — за WARP (2979/2980), до netd
WARP_BLK_PREF_CH=2978
WARP_BLK_PREF=2981
WARP_BLK_LVL=""            # стоит: 0 — нет, 1 — не напрямую, 2 — только свой сервер; пусто — ещё не выставляли:
                           # первый вызов снимает запреты, оставшиеся от убитого демона (ревью 25.11)
WARP_LAST_UP=""            # конфиг, что поднимался последним (warp_stick_name)

warp_block_set() {   # 0 | 1 | 2
    local l="${1:-0}"
    # без своего сервера после WARP «только свой» = «не напрямую»: основной WARP и есть свой (напрямую) или Cloudflare
    [ "$l" = 2 ] && [ -z "$WARP_CHAIN" ] && l=1
    [ "$l" = "$WARP_BLK_LVL" ] && return 0
    $ip rule del fwmark $WARP_MARK/$WARP_MARK prohibit pref $WARP_BLK_PREF_CH 2>/dev/null
    $ip rule del fwmark $WARP_MARK/$WARP_MARK prohibit pref $WARP_BLK_PREF 2>/dev/null
    [ "$l" -ge 1 ] && $ip rule add fwmark $WARP_MARK/$WARP_MARK prohibit pref $WARP_BLK_PREF 2>/dev/null
    [ "$l" = 2 ] && $ip rule add fwmark $WARP_MARK/$WARP_MARK prohibit pref $WARP_BLK_PREF_CH 2>/dev/null
    case "$l" in
        0) case "$WARP_BLK_LVL" in 1|2) log "WARP: блок снят — без выхода то, что идёт в WARP, идёт напрямую" ;; esac ;;
        1) log "WARP: блок — WARP не работает, и то, что идёт в WARP, не пускаю напрямую (WARP_STRICT=1)" ;;
        2) log "WARP: блок — только через свой сервер ($WARP_CHAIN): не отвечает он или WARP — не пускаю (WARP_STRICT=2)" ;;
    esac
    WARP_BLK_LVL=$l
    phone_status_refresh
}

# Мимо своего сервера (WARP_CHAIN_SKIP): у этих приложений телефона то, что идёт в WARP, идёт в голый WARP (выход
# Cloudflare, без крюка через сервер: 26.11 Telegram через Сингапур — ~600 мс, через WARP — ~230). Правило по uid
# раньше правила цепочки (2977) и её запрета (2978): держим, пока WARP поднят и свой сервер задан, — и когда он не
# отвечает: при WARP_STRICT=2 иначе и эти приложения упирались бы в запрет, хотя WARP жив. WARP упал — его таблица
# пуста, и дальше как у всех: при WARP_STRICT 1/2 — запрет (2978/2981). Только IPv4 — как и правило цепочки
# Сети Telegram мимо своего сервера (WARP_CHAIN_SKIP_TG): по адресу — и для раздачи, у которой нет uid. 26.11 вечером
# через свой сервер 0,2–7,5 Мбит/с и ~600 мс до Telegram, через WARP — 11–18 Мбит/с и ~230 мс
warp_chain_skip_tg() { [ "$WARP_CHAIN_SKIP_TG" = 1 ] && [ "$WARP_TELEGRAM" = 1 ] && echo 1 || echo 0; }
warp_tg4() { tr -d '\r' < "$MODULE_DIR/warp/telegram.txt" 2>/dev/null | grep -E '^[0-9]+\.'; }

warp_chain_skip_uids() {
    local p u out=""
    for p in $WARP_CHAIN_SKIP; do
        u=$(pkg_uid "$p")
        case "$u" in ''|*[!0-9]*) continue ;; esac
        [ "$u" -ge 10000 ] || continue
        case " $out " in *" $u "*) ;; *) out="$out $u" ;; esac
    done
    echo "${out# }"
}
warp_chain_skip_set() {   # [- — только снять | uid, уже посчитанные]
    local u uids _n=0
    local tg m
    while [ $_n -lt 128 ] && $ip rule del pref $WARP_CH_SKIP_PREF 2>/dev/null; do _n=$((_n + 1)); done
    WARP_CH_SKIP_ON=""; WARP_CH_SKIP_UIDS=""
    [ "$1" = - ] && return 0
    if [ $# -gt 0 ]; then uids=$1; else uids=$(warp_chain_skip_uids); fi
    tg=$(warp_chain_skip_tg)
    if [ "$tg" = 1 ]; then
        for m in $(warp_tg4); do
            $ip rule add to "$m" fwmark $WARP_MARK/$WARP_MARK lookup $WARP_TABLE pref $WARP_CH_SKIP_PREF 2>/dev/null
        done
    fi
    for u in $uids; do
        $ip rule add uidrange "$u-$u" fwmark $WARP_MARK/$WARP_MARK lookup $WARP_TABLE pref $WARP_CH_SKIP_PREF 2>/dev/null && continue
        # ядро или ip без uidrange — список молча не действовал бы
        [ -n "$WARP_CH_SKIP_WARN" ] || log "WARNING: WARP: правило по uid ($u) не встало — «мимо своего сервера» не работает (ip rule uidrange)"
        WARP_CH_SKIP_WARN=1
    done
    WARP_CH_SKIP_ON="$WARP_CHAIN_SKIP|$tg|$uids"; WARP_CH_SKIP_UIDS="$uids"; WARP_CH_SKIP_TS=$(date +%s)
}

warp_chain_down() {   # [причина] — пусто: молча
    local was="$WARP_CH_STATE" k _n keep="$WARP_CH_SKIP_UIDS"
    # сначала в WARP — то, что шло через цепочку; потом процесс; правила к серверу — последними
    $ip rule del fwmark $WARP_MARK/$WARP_MARK lookup $WARP_CH_TABLE pref $WARP_CH_MARK_PREF 2>/dev/null
    # мимо своего сервера: при сбое (молча — неудачный подъём, «туннель пропал», «не отвечает») правила держим — WARP
    # жив, и при WARP_STRICT=2 эти приложения иначе на время упирались бы в запрет (26.11: ~3 с на каждый сбой);
    # снимаем, когда свой сервер выключен, сменён или снят WARP. Пусто и правил не ставили — хвост убитого демона
    case "$1" in
        ''|"туннель пропал"|"не отвечает") [ -n "$WARP_CH_SKIP_ON" ] || warp_chain_skip_set - ;;
        *) warp_chain_skip_set - ;;
    esac
    [ -n "$WARP_CH_PID" ] && kill "$WARP_CH_PID" 2>/dev/null
    $ip link del $WARP_CH_IF 2>/dev/null
    [ -n "$WARP_CH_ADDR" ] && warp_src_guard del "$WARP_CH_ADDR"; WARP_CH_ADDR=""
    $ip rule del oif $WARP_CH_IF lookup $WARP_CH_TABLE pref $WARP_CH_OIF_PREF 2>/dev/null
    $ip route flush table $WARP_CH_TABLE 2>/dev/null
    # по pref, а не по адресу: после убитого демона адреса прошлого запуска не знаем
    for k in $WARP_CH_EP_PREF $WARP_CH_NO_PREF; do
        _n=0; while [ $_n -lt 8 ] && $ip rule del pref $k 2>/dev/null; do _n=$((_n + 1)); done
    done
    $iptables -t mangle -D POSTROUTING -o $WARP_CH_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $WARP_CH_MSS 2>/dev/null
    $iptables -t mangle -D PREROUTING -i $WARP_CH_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $WARP_CH_MSS 2>/dev/null
    rm -f "$WARP_SOCK_DIR/$WARP_CH_IF.sock"
    if [ "$was" = up ]; then
        # имя — поднятого: при выключении в настройках WARP_CHAIN уже пуст
        [ -n "$1" ] && log "WARP: свой сервер после WARP ($WARP_CH_NAME) снят ($1) — что шло через него, снова через WARP"
        # соединения через warp1 после снятия молча висели бы до тайм-аута приложения (как у warp_routes_off);
        # приложения мимо своего сервера шли и идут через WARP — их не трогаем
        WARP_KILL_KEEP="$keep"; warp_kill_sockets "свой сервер снят"; WARP_KILL_KEEP=""
    fi
    # «не поднялась» держим: иначе каждое переподключение WARP (warp_down) сбрасывало паузу, и мёртвый сервер
    # пробовался сразу после подъёма — 25.11 четыре попытки по 10 с за 2 мин (WARP переподнимался из-за Telegram)
    WARP_CH_PID=""; WARP_CH_EP=""; WARP_CH_FAILS=0; WARP_CH_NONET=0; WARP_CH_IP=""; WARP_CH_LOC=""
    [ "$WARP_CH_STATE" = fail ] || WARP_CH_STATE=off
}

warp_chain_fail() {   # заметка — в журнал один раз, пока она та же
    [ "$WARP_CH_NOTE" = "$1" ] || log "WARP: свой сервер после WARP ($WARP_CHAIN) — $1; что идёт в WARP, идёт через WARP, повтор через $((WARP_CH_WAIT / 60)) мин"
    WARP_CH_STATE=fail; WARP_CH_NOTE="$1"; WARP_CH_RETRY_TS=$(( $(date +%s) + WARP_CH_WAIT ))
    WARP_CH_WAIT=$((WARP_CH_WAIT * 2)); [ "$WARP_CH_WAIT" -gt 1800 ] && WARP_CH_WAIT=1800
    phone_status_refresh
}

# Живость: trace Cloudflare (ip= — адрес выхода), иначе любой ответ, как у своего сервера в warp_probe
warp_chain_probe() {
    local cmd="$CURL_BIN -s -k -m 6 --interface $WARP_CH_IF https://1.1.1.1/cdn-cgi/trace" out a
    if [ "$WARP_SU_G" = "1" ]; then out=$($SUG_CMD "$DNSPROXY_GID" -c "$cmd" 2>/dev/null); else out=$(eval "$cmd" 2>/dev/null); fi
    WARP_CH_IP=$(echo "$out" | sed -n 's/^ip=//p' | head -1); WARP_CH_LOC=$(echo "$out" | sed -n 's/^loc=//p' | head -1)
    [ -n "$WARP_CH_IP" ] && return 0
    for a in 8.8.8.8 140.82.121.3; do
        cmd="$CURL_BIN -s -k -m 4 -o /dev/null -w %{http_code} --interface $WARP_CH_IF https://$a/"
        if [ "$WARP_SU_G" = "1" ]; then out=$($SUG_CMD "$DNSPROXY_GID" -c "$cmd" 2>/dev/null); else out=$(eval "$cmd" 2>/dev/null); fi
        case "$out" in ''|000) ;; *) return 0 ;; esac
    done
    return 1
}

warp_chain_up() {
    local f="$WARP_DIR/$WARP_CHAIN.conf" ep host port a mtu i=0 rc hs=0 pk
    [ -f "$f" ] || { warp_chain_fail "нет конфига"; return 1; }
    ep=$(sed -n 's/^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*//p' "$f" | head -1 | tr -d ' \r')
    host=${ep%:*}; port=${ep##*:}
    # имя — в адрес заранее: правила ставятся на адрес, а awg резолвил бы сам (и мог получить другой)
    case "$host" in *[!0-9.]*) host=$(ping -c 1 -W 2 "$host" 2>/dev/null | sed -n '1s/^PING [^(]*(\([0-9.]*\)).*/\1/p') ;; esac
    case "$host" in [0-9]*.[0-9]*.[0-9]*.[0-9]*) ;; *) warp_chain_fail "адрес сервера не IPv4 ($ep)"; return 1 ;; esac
    case "$port" in ''|*[!0-9]*) warp_chain_fail "нет порта в Endpoint"; return 1 ;; esac
    WARP_CH_EP="$host"
    # без этих двух правил рукопожатие при упавшем WARP ушло бы к серверу напрямую — ради чего всё и делается:
    # не встали (ip без prohibit, занят pref) — не запускаем вовсе
    if ! $ip rule add to "$host" lookup $WARP_TABLE pref $WARP_CH_EP_PREF 2>/dev/null || \
       ! $ip rule add to "$host" prohibit pref $WARP_CH_NO_PREF 2>/dev/null; then
        warp_chain_down; warp_chain_fail "не встали правила «к серверу только через WARP» — не запускаю"; return 1
    fi
    WG_PROCESS_FOREGROUND=1 "$AWG_GO_BIN" "$WARP_CH_IF" > "$WARP_RUN.chain.log" 2>&1 < /dev/null &
    WARP_CH_PID=$!
    while [ $i -lt 50 ] && [ ! -S "$WARP_SOCK_DIR/$WARP_CH_IF.sock" ]; do sleep 0.1; i=$((i + 1)); done
    if [ ! -S "$WARP_SOCK_DIR/$WARP_CH_IF.sock" ]; then warp_chain_down; warp_chain_fail "amneziawg-go не запустился"; return 1; fi
    warp_wg_file "$f" "$host:$port"
    "$AWG_BIN" setconf "$WARP_CH_IF" "$WARP_DIR/.run.wg" >> "$WARP_RUN.chain.log" 2>&1; rc=$?
    rm -f "$WARP_DIR/.run.wg"
    if [ $rc != 0 ]; then warp_chain_down; warp_chain_fail "конфиг не принят (awg setconf)"; return 1; fi
    # keepalive: соединение через WARP к серверу держит NAT Cloudflare, без него после тишины рукопожатие заново
    for pk in $("$AWG_BIN" show "$WARP_CH_IF" peers 2>/dev/null); do "$AWG_BIN" set "$WARP_CH_IF" peer "$pk" persistent-keepalive 25 2>/dev/null; done
    for a in $(sed -n 's/^[[:space:]]*Address[[:space:]]*=//p' "$f" | tr ',' ' '); do
        case "$a" in *:*) $ip -6 addr add "$a" dev $WARP_CH_IF 2>/dev/null ;;
            *.*) $ip addr add "$a" dev $WARP_CH_IF 2>/dev/null; WARP_CH_ADDR="$a"; warp_src_guard add "$a" ;; esac
    done
    mtu=$(sed -n 's/^[[:space:]]*MTU[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$f" | head -1)
    [ -n "$mtu" ] && [ "$mtu" -lt "$WARP_CH_MTU" ] || mtu=$WARP_CH_MTU
    $ip link set $WARP_CH_IF mtu "$mtu" up 2>/dev/null
    echo 2 > /proc/sys/net/ipv4/conf/$WARP_CH_IF/rp_filter 2>/dev/null
    $ip route replace default dev $WARP_CH_IF table $WARP_CH_TABLE 2>/dev/null
    $ip rule add oif $WARP_CH_IF lookup $WARP_CH_TABLE pref $WARP_CH_OIF_PREF 2>/dev/null
    # рукопожатие — до ~10 с (стенд: сразу); пинг его будит
    i=0
    while [ $i -lt 10 ]; do
        hs=$("$AWG_BIN" show "$WARP_CH_IF" latest-handshakes 2>/dev/null | awk '{ print $2; exit }')
        [ "${hs:-0}" -gt 0 ] && break
        ping -c 1 -W 1 -I $WARP_CH_IF 1.1.1.1 >/dev/null 2>&1; i=$((i + 1))
    done
    if [ "${hs:-0}" -le 0 ]; then warp_chain_down; warp_chain_fail "нет рукопожатия с $host через WARP"; return 1; fi
    if ! warp_chain_probe; then warp_chain_down; warp_chain_fail "рукопожатие есть, трафика нет"; return 1; fi
    $iptables -t mangle -I POSTROUTING 1 -o $WARP_CH_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $WARP_CH_MSS 2>/dev/null
    $iptables -t mangle -I PREROUTING 1 -i $WARP_CH_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $WARP_CH_MSS 2>/dev/null
    warp_chain_skip_set
    $ip rule add fwmark $WARP_MARK/$WARP_MARK lookup $WARP_CH_TABLE pref $WARP_CH_MARK_PREF 2>/dev/null
    WARP_CH_STATE=up; WARP_CH_FAILS=0; WARP_CH_CHECK_TS=$(date +%s); WARP_CH_NOTE=""; WARP_CH_WAIT=$WARP_CH_RETRY; WARP_CH_NAME="$WARP_CHAIN"
    log "WARP: после WARP — свой сервер $WARP_CHAIN ($host): выход ${WARP_CH_IP:-?}${WARP_CH_LOC:+, $WARP_CH_LOC}; напрямую к серверу ничего не идёт${WARP_CHAIN_SKIP:+; мимо него — $WARP_CHAIN_SKIP}"
    # что уже шло через WARP — переподключится через цепочку (кроме приложений мимо неё)
    WARP_KILL_KEEP="$WARP_CH_SKIP_UIDS"; warp_kill_sockets "свой сервер поднят"; WARP_KILL_KEEP=""
    phone_status_refresh
}

# Из warp_reconcile, пока WARP поднят
warp_chain_reconcile() {
    local now n
    if [ -z "$WARP_CHAIN" ]; then
        [ "$WARP_CH_STATE" = off ] || warp_chain_down "выключено"
        # свой сервер выключили в настройках (reload уже снял цепочку и поставил off) — правила мимо него тоже
        [ -n "$WARP_CH_SKIP_ON" ] && warp_chain_skip_set -
        WARP_CH_NOTE=""; WARP_CH_STATE=off
        return 0
    fi
    # WARP поднят на своём сервере, а не на Cloudflare: цепочка «свой поверх своего» ничего не прячет —
    # не поднимаем, но говорим почему (иначе WebUI вечно «ждёт WARP», ревью 25.11)
    if [ "$WARP_CF" != 1 ]; then
        [ "$WARP_CH_STATE" = up ] && warp_chain_down "WARP не Cloudflare"
        n="только поверх WARP Cloudflare, а сейчас поднят $WARP_CUR"
        if [ "$WARP_CH_NOTE" != "$n" ]; then
            log "WARP: свой сервер после WARP ($WARP_CHAIN) — $n: не запускаю"
            WARP_CH_NOTE="$n"; WARP_CH_STATE=fail; WARP_CH_RETRY_TS=0
            phone_status_refresh
        fi
        return 0
    fi
    # мимо своего сервера — и пока он не поднят или не отвечает; по подписи (список и uid), чтобы не трогать правила
    # на каждом круге; uid — раз в 30 с: переустановленное или поставленное позже приложение получает новый
    now=$(date +%s)
    if [ -z "$WARP_CH_SKIP_ON" ] || [ "${WARP_CH_SKIP_ON%|*}" != "$WARP_CHAIN_SKIP|$(warp_chain_skip_tg)" ] || \
       [ $((now - WARP_CH_SKIP_TS)) -ge 30 ]; then
        n=$(warp_chain_skip_uids); WARP_CH_SKIP_TS=$now
        [ "$WARP_CH_SKIP_ON" = "$WARP_CHAIN_SKIP|$(warp_chain_skip_tg)|$n" ] || warp_chain_skip_set "$n"
    fi
    case "$WARP_CH_STATE" in
        off) warp_chain_up ;;
        fail) [ "$now" -ge "$WARP_CH_RETRY_TS" ] && warp_chain_up ;;
        up)
            if { [ -n "$WARP_CH_PID" ] && ! kill -0 "$WARP_CH_PID" 2>/dev/null; } || [ ! -d /sys/class/net/$WARP_CH_IF ]; then
                warp_chain_down "туннель пропал"   # следующий проход поднимет заново
                return 0
            fi
            [ $((now - WARP_CH_CHECK_TS)) -lt $WARP_CHECK_SECS ] && return 0
            WARP_CH_CHECK_TS=$now
            # netd мог перетряхнуть правила
            $ip rule show 2>/dev/null | grep -q "^$WARP_CH_MARK_PREF:" || \
                { warp_chain_skip_set; $ip rule add fwmark $WARP_MARK/$WARP_MARK lookup $WARP_CH_TABLE pref $WARP_CH_MARK_PREF 2>/dev/null; }
            # WARP сам не отвечает (нет сети, метро) — цепочке внутри него ответить нечем: проба ничего не скажет и стоила
            # бы до 14 с цикла демона; промах не считаем, следующая — через 10 с (ревью 25.11)
            if [ "$WARP_NONET" = 1 ] || [ "${WARP_FAILS:-0}" -gt 0 ]; then
                WARP_CH_CHECK_TS=$(( $(date +%s) - WARP_CHECK_SECS + 10 ))
                return 0
            fi
            # «через 10 с» — от конца проверок (как у WARP): проба без ответа сама ~14 с, и от now следующая шла бы сразу
            if warp_chain_probe; then
                [ $WARP_CH_FAILS -gt 0 ] || [ "$WARP_CH_NONET" = 1 ] && log "WARP: свой сервер после WARP ($WARP_CHAIN) снова отвечает"
                WARP_CH_FAILS=0; WARP_CH_NONET=0
            elif [ "$ZAPRET_WL" != 1 ] && ! warp_uplink; then
                # молчит и связь мимо туннеля (метро) — сервер не виноват: промах не считаем, проверяем чаще; как у WARP.
                # 25.11 в метро цепочка дошла до 2/3 только из-за обрывов, при длинном — ушла бы в паузу до 30 мин.
                # Белый список (ZAPRET_WL): warp_uplink всегда «нет», а WARP жив (проверка выше) — промах считаем,
                # иначе Telegram часами уходил бы в мёртвую цепочку вместо WARP
                WARP_CH_CHECK_TS=$(( $(date +%s) - WARP_CHECK_SECS + 10 ))
                [ "$WARP_CH_NONET" = 1 ] || log "WARP: свой сервер после WARP ($WARP_CHAIN) не отвечает, но и напрямую сети нет — не считаю"
                WARP_CH_NONET=1; WARP_CH_FAILS=0
            else
                WARP_CH_FAILS=$((WARP_CH_FAILS + 1))
                WARP_CH_CHECK_TS=$(( $(date +%s) - WARP_CHECK_SECS + 10 ))
                log "WARP: свой сервер после WARP ($WARP_CHAIN) не отвечает ($WARP_CH_FAILS/3)"
                if [ $WARP_CH_FAILS -ge 3 ]; then warp_chain_down "не отвечает"; warp_chain_fail "не отвечал 3 проверки подряд"; fi
            fi ;;
    esac
}
