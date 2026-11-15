# shellcheck shell=sh
# lib/youtube.sh — YouTube: мимо кэшей оператора (YT_GGC_BLOCK), повтор застрявших
# видеосоединений и разрыв запросов без ответа (YT_DEAD_FAILFAST).
# Часть демона service.sh: подключается из него через ".", сам не запускается.
# Настройки (USER CONFIG) и общие переменные — в service.sh.

# --- YT_GGC_BLOCK: googlevideo.com на адреса не из сетей Google -> RST ----
# filter, а не mangle: отказ до NFQUEUE, nfqws этот ClientHello не видит.
# OUTPUT — телефон (если zapret для телефона включён), FORWARD — раздача.
# tun+ — мимо: через VPN кэш оператора не попадается.
GGC_FAILS=0
zapret_ggc_hooks_off() {
    local t="$1" c _n
    for c in OUTPUT FORWARD; do
        _n=0; while [ $_n -lt 8 ] && $t -D "$c" $GGC_MATCH -j "$CHAIN_ZAPRET_GGC" 2>/dev/null; do _n=$((_n + 1)); done
    done
}

zapret_ggc_on() {
    local t f p n st=""
    # ядро без string — нечем узнать googlevideo.com (zapret_caps)
    zapret_cap str || { [ -n "$GGC_STATE" ] && zapret_ggc_off; GGC_STATE=""; return 0; }
    for t in "$iptables" "$ip6tables"; do
        zapret_ggc_hooks_off "$t"
        if [ "$t" = "$iptables" ]; then f="$ZAPRET_DIR/google-ipv4.txt"; else f="$ZAPRET_DIR/google-ipv6.txt"; fi
        if [ "$YT_GGC_BLOCK" != "1" ] || [ ! -s "$f" ]; then
            $t -F "$CHAIN_ZAPRET_GGC" 2>/dev/null; $t -X "$CHAIN_ZAPRET_GGC" 2>/dev/null
            continue
        fi
        $t -N "$CHAIN_ZAPRET_GGC" 2>/dev/null
        $t -F "$CHAIN_ZAPRET_GGC" 2>/dev/null
        $t -A "$CHAIN_ZAPRET_GGC" -o tun+ -j RETURN 2>/dev/null
        $t -A "$CHAIN_ZAPRET_GGC" -o lo -j RETURN 2>/dev/null
        n=0
        while read -r p; do
            case "$p" in ''|'#'*) continue ;; esac
            $t -A "$CHAIN_ZAPRET_GGC" -d "$p" -j RETURN 2>/dev/null && n=$((n + 1))
        done < "$f"
        # список не встал (битый файл) — лучше пропустить всё, чем отбить сервер Google
        if [ "$n" -lt 5 ]; then
            $t -F "$CHAIN_ZAPRET_GGC" 2>/dev/null; $t -X "$CHAIN_ZAPRET_GGC" 2>/dev/null
            continue
        fi
        $t -A "$CHAIN_ZAPRET_GGC" -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null
        $t -I FORWARD 1 $GGC_MATCH -j "$CHAIN_ZAPRET_GGC" 2>/dev/null
        [ "$ZAPRET_PHONE" = "1" ] && $t -I OUTPUT 1 $GGC_MATCH -j "$CHAIN_ZAPRET_GGC" 2>/dev/null
        # хук не встал — не считаем включённым и убираем начатое (цепочку с REJECT,
        # хук в OUTPUT); сторож попробует ещё пару раз (GGC_FAILS), потом сдаётся
        if ! $t -C FORWARD $GGC_MATCH -j "$CHAIN_ZAPRET_GGC" 2>/dev/null; then
            zapret_ggc_hooks_off "$t"; $t -F "$CHAIN_ZAPRET_GGC" 2>/dev/null; $t -X "$CHAIN_ZAPRET_GGC" 2>/dev/null
            [ "$t" = "$iptables" ] && GGC_FAILS=$((GGC_FAILS + 1))
            continue
        fi
        st="$st${st:++}$([ "$t" = "$iptables" ] && echo v4 || echo v6)"
    done
    case "$st" in v4*) GGC_FAILS=0 ;; esac
    [ "$GGC_FAILS" = 3 ] && log "WARNING: zapret: правила «YouTube мимо кэшей оператора» не встали 3 раза — выключено до смены сети"
    [ "$st" != "$GGC_STATE" ] && [ -n "$st" ] && log "zapret: YouTube мимо кэшей оператора включено ($st)"
    GGC_STATE="$st"
}

zapret_ggc_off() {
    local t
    for t in "$iptables" "$ip6tables"; do
        zapret_ggc_hooks_off "$t"
        $t -F "$CHAIN_ZAPRET_GGC" 2>/dev/null; $t -X "$CHAIN_ZAPRET_GGC" 2>/dev/null
    done
    GGC_STATE=""
}

# сколько соединений с кэшами оператора отбито (для status/WebUI)
zapret_ggc_hits() {
    [ -n "$GGC_STATE" ] || { echo 0; return; }
    $iptables -L "$CHAIN_ZAPRET_GGC" -v -x -n 2>/dev/null | awk '/REJECT/ {s += $1} END {print s + 0}'
}

# --- YT_DEAD_FAILFAST: повтор застрявших видеосоединений YouTube ---------------
# Пометка — mangle OUTPUT (телефон, кроме root: это проверки самого модуля) и FORWARD
# (раздача): там ClientHello ещё целый, nfqws его режет позже, в POSTROUTING. По метке
# yt_dead_scan находит видеосоединения в conntrack. Застрявшее рвём (у раздачи — RST на
# повтор клиента), приложение открывает новое: обход проходит не с каждой попытки.
# Отбой мёртвых серверов (RST адресу на 30 мин, перепроверка, проверка молчащих, QUIC, Play)
# убран 15.11: с повтором и разрывом запросов без ответа он только мешал — 12.11 шортсы без
# него стартовали чаще, а отбой в фоне оставлял плеер на закрытом сервере
yt_match_build() {   # zapret_caps зовёт снова, если ядро без connbytes
    YT_MARK_OUT="! -o tun+ -m owner ! --uid-owner 0 $GGC_MATCH -j CONNMARK --set-xmark $YT_CTMARK/$YT_CTMARK"
    YT_MARK_FWD="! -o tun+ $GGC_MATCH -j CONNMARK --set-xmark $YT_CTMARK/$YT_CTMARK"
}
yt_match_build

YT_DEAD_FAILS=0
yt_dead_hooks_off() {
    local c m _n
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D OUTPUT $YT_MARK_OUT 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D FORWARD $YT_MARK_FWD 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -D FORWARD -p tcp --dport 443 -j "$CHAIN_YT_RST" 2>/dev/null; do _n=$((_n + 1)); done
    # от прежних версий (отбой до 15.11): пометка Play и хуки цепочки VPN_YT_DEAD — иначе после
    # обновления без перезагрузки остались бы, и RST мёртвым адресам шёл бы дальше
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D OUTPUT ! -o tun+ -m owner ! --uid-owner 0 $GVT_MATCH -j CONNMARK --set-xmark 0x04000000/0x04000000 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D FORWARD ! -o tun+ $GVT_MATCH -j CONNMARK --set-xmark 0x04000000/0x04000000 2>/dev/null; do _n=$((_n + 1)); done
    for c in OUTPUT FORWARD; do
        for m in "$GGC_MATCH" "$GVT_MATCH" "-p udp --dport 443" "-p udp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 1:9"; do
            _n=0; while [ $_n -lt 8 ] && $iptables -D "$c" $m -j VPN_YT_DEAD 2>/dev/null; do _n=$((_n + 1)); done
        done
    done
    $iptables -F VPN_YT_DEAD 2>/dev/null; $iptables -X VPN_YT_DEAD 2>/dev/null
}

yt_dead_on() {
    yt_dead_hooks_off
    # без string (zapret_caps) видеосоединения не узнать — выключено
    if [ "$YT_DEAD_FAILFAST" != "1" ] || [ -z "$CONNTRACK_BIN" ] || ! zapret_cap str; then
        yt_dead_off
        return 0
    fi
    # оба движка (15.11: проба nfqws1 — те же механизмы, сравнивались стратегии)
    YT_DEAD_MODE=retry
    # сети Google числами — для соединений раздачи, где пометку стирает
    # tether_unblock (CONNMARK 0x40/0xffffffff на каждом пакете с TTL≠63)
    awk -F'[./]' '/^[0-9]/ && NF == 5 { s = (($1 * 256 + $2) * 256 + $3) * 256 + $4; printf "%.0f %.0f\n", s, s + 2 ^ (32 - $5) - 1 }' \
        "$ZAPRET_DIR/google-ipv4.txt" > "$YT_GRANGES" 2>/dev/null
    $iptables -t mangle -I FORWARD 1 $YT_MARK_FWD 2>/dev/null
    # раздача: её соединение ss не рвёт (транзит, сокета на телефоне нет) — RST клиенту на его
    # следующий повтор (yt_retry_hits, «запрос без ответа»). Цепочка пуста, пока ничего не застряло
    $iptables -N "$CHAIN_YT_RST" 2>/dev/null
    $iptables -I FORWARD 1 -p tcp --dport 443 -j "$CHAIN_YT_RST" 2>/dev/null
    [ "$ZAPRET_PHONE" = "1" ] && $iptables -t mangle -I OUTPUT 1 $YT_MARK_OUT 2>/dev/null
    # пометка не встала — не «on»: иначе сторож zapret ставил бы правила по кругу
    if ! $iptables -t mangle -C FORWARD $YT_MARK_FWD 2>/dev/null; then
        YT_DEAD_FAILS=$((YT_DEAD_FAILS + 1))
        [ "$YT_DEAD_FAILS" -ge 3 ] && [ "$YT_DEAD_STATE" != "fail" ] && \
            log "WARNING: zapret: правила повтора застрявших видеосоединений YouTube не встали 3 раза — выключено"
        yt_dead_hooks_off; YT_DEAD_STATE="fail"; return 0
    fi
    YT_DEAD_FAILS=0
    [ "$YT_DEAD_STATE" = "on" ] || \
        log "zapret: повтор застрявших видеосоединений YouTube включён (ClientHello без ответа ${YT_RETRY_AFTER}с — рву соединение, приложение откроет новое; запрос без ответа ${YT_REQ_AFTER}с — тоже)"
    YT_DEAD_STATE="on"
}

# Фоновая проверка ещё идёт: PID жив и это наш ребёнок. Закончившаяся
# проверка оставляет PID в переменной, а демон форкает десятки процессов в
# минуту — освободившийся PID быстро достаётся чужому процессу: kill -0 по
# нему «жив» навсегда (проверки больше не запускаются), kill -9 бьёт мимо
# (ревью 25.10). Родителя берём после «) » — имя процесса бывает с пробелами.
yt_bg_alive() {
    local st
    [ -n "$1" ] || return 1
    # "состояние родитель …"; Z — уже закончилась, ждёт, пока её подберут
    st=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f1,2)
    case "$st" in Z*|'') return 1 ;; esac
    [ "${st#* }" = "$$" ]
}

yt_dead_off() {
    yt_dead_hooks_off
    $iptables -F "$CHAIN_YT_RST" 2>/dev/null; $iptables -X "$CHAIN_YT_RST" 2>/dev/null
    # и файлы прежнего отбоя (до 15.11)
    rm -f "$YT_SEEN_FILE" "$YT_SEEN_FILE.new" "$YT_SEEN_FILE.req" "$YT_SEEN_FILE.req.new" "$YT_GRANGES" \
        /data/local/tmp/vpn_tether_ytdead /data/local/tmp/vpn_tether_ytdead.tmp "$YT_SEEN_FILE.udp" "$YT_SEEN_FILE.udp.new" \
        /data/local/tmp/vpn_tether_ytrecheck.* /data/local/tmp/vpn_tether_ytsprobe.*
    YT_DEAD_STATE=""; YT_STUCK=""
    YT_DEAD_MODE=""; YT_RETRY_CNT=""; YT_RETRY_KILLS=0; YT_RETRY_RJ=""; YT_RETRY_RSTS=0
}

# Застрявшее видеосоединение YouTube (см. YT_RETRY_MAX в service.sh) — рвём только его, приложение
# откроет новое. Раздача — транзитом, ss её сокет не видит: RST на повтор ClientHello клиента.
# YT_RETRY_MAX провалов адреса за YT_RETRY_WIN с, пока видео нигде не идёт, — сигнал сторожу: застряло
# всё подряд — это сломанная стратегия, а не сервер
#   yt_retry_hits ВЫВОД_AWK NOW АДРЕС_ТЕЛЕФОНА
yt_retry_hits() {
    local hit dip src sp c l kd
    # правила RST раздачи — на 20 с: клиент повторяет ClientHello через 1–4 с, дольше не нужно
    if [ -n "$YT_RETRY_RJ" ]; then
        for l in $(printf '%s\n' "$YT_RETRY_RJ" | awk -v now="$2" 'NF == 4 && $1 <= now { print $2 "_" $3 "_" $4 }'); do
            src=${l%%_*}; l=${l#*_}; sp=${l%%_*}; dip=${l#*_}
            $iptables -D "$CHAIN_YT_RST" -s "$src" -d "$dip" -p tcp --sport "$sp" --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null
        done
        YT_RETRY_RJ=$(printf '%s\n' "$YT_RETRY_RJ" | awk -v now="$2" 'NF == 4 && $1 > now')
    fi
    for hit in $(printf '%s\n' "$1" | awk '$1 == "HIT" { print $3 "_" $4 "_" $5 "_" $2 }'); do
        dip=${hit%%_*}; l=${hit#*_}; src=${l%%_*}; l=${l#*_}; sp=${l%%_*}; kd=${l#*_}
        case "$dip" in *[!0-9.]*|'') continue ;; esac
        case "$sp" in *[!0-9]*|'') continue ;; esac
        case "$src" in *[!0-9.]*|'') continue ;; esac
        if [ -n "$3" ] && [ "$src" = "$3" ]; then
            ss -K -tn dst "$dip" dport = :443 sport = :"$sp" >/dev/null 2>&1; YT_RETRY_KILLS=$((YT_RETRY_KILLS + 1))
        elif [ "$kd" = stuck ]; then
            # раздача, ClientHello не подтверждён: клиент сам его повторит — на повтор RST, и он
            # откроет новое соединение. «Принял и молчит» так не порвать: клиент ждёт и ничего не шлёт
            $iptables -I "$CHAIN_YT_RST" -s "$src" -d "$dip" -p tcp --sport "$sp" --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null && {
                YT_RETRY_RJ="$YT_RETRY_RJ
$(($2 + 20)) $src $sp $dip"
                YT_RETRY_RSTS=$((YT_RETRY_RSTS + 1))
            }
        fi
        c=$(printf '%s\n' "$YT_RETRY_CNT" | awk -v d="$dip" -v now="$2" -v w="$YT_RETRY_WIN" '$1 == d && now - $3 <= w { print $2 }')
        c=$(( ${c:-0} + 1 ))
        YT_RETRY_CNT=$(printf '%s\n' "$YT_RETRY_CNT" | awk -v d="$dip" -v now="$2" -v w="$YT_RETRY_WIN" 'NF == 3 && $1 != d && now - $3 <= w')
        if [ "$c" -lt "$YT_RETRY_MAX" ]; then
            YT_RETRY_CNT="$YT_RETRY_CNT
$dip $c $2"
            continue
        fi
        # видео нигде не идёт — похоже на сломанную стратегию, а не на сервер: сигнал сторожу.
        # Идёт — это закрытый сервер, плеер уйдёт с него сам; с сигналом на каждый такой адрес
        # сторож проверял стратегию каждые 3 мин (14.11)
        [ $(($2 - YT_DATA_TS)) -le 60 ] || YT_RETRY_ESC=$((YT_RETRY_ESC + 1))
    done
}

# Раз в ~1,3 с (дважды за круг демона): видеосоединения с googlevideo.com из conntrack
# (помечены; у раздачи пометку может стереть tether_unblock — тогда любые к сетям Google).
# ClientHello ушёл (>=600 байт), а от сервера ни байта данных:
#   1 пакет (только SYN-ACK) — ClientHello не подтверждён sa с (YT_RETRY_AFTER, 6×RTT);
#   больше — подтвердил, но молчит da с (YT_DEAD_AFTER, 12×RTT) -> yt_retry_hits.
# Запрос без ответа (YT_REQ_AFTER) — у любого видеосоединения, см. ниже
yt_dead_scan() {
    [ "$YT_DEAD_STATE" = "on" ] || return 0
    local now out k sa da ds rqh rqd rqa rqp rqb rqv rqw rqs rqc rqe n t keep=""
    # не ip: локальная ip затирала бы $ip (/system/bin/ip) — адрес WAN ниже не узнавался
    now=$(date +%s)
    # Пороги от RTT канала. 08.11, «медленный Wi-Fi» (netem: RTT ~380 мс, потери 4%): около половины
    # «мёртвых» были живыми — ответ не успевал за 2–3 с после одной потери. RTT — медиана активных
    # HTTPS-сокетов телефона (ss, раз в 30 с; данные за последние 30 с; меньше 5 мс — AdGuard)
    if [ $((now - YT_RTT_TS)) -ge 30 ]; then
        YT_RTT_TS=$now
        YT_RTT_MS=$(ss -tin state established '( dport = :443 )' 2>/dev/null | awk '
            { r = ""; l = 999999
              for (i = 1; i <= NF; i++) { if ($i ~ /^rtt:/) { split(substr($i, 5), a, "/"); r = a[1] } else if ($i ~ /^lastrcv:/) l = substr($i, 9) + 0 }
              if (r != "" && r + 0 >= 5 && l <= 30000) print int(r) }' | sort -n | awk '{ v[NR] = $1 } END { if (NR >= 3) print v[int((NR + 1) / 2)] }')
    fi
    # «не подтвердил» — 6×RTT, «принял и молчит» — 12×RTT, но не меньше заданного: ложный разрыв
    # стоит одного соединения
    k=0; [ -n "$YT_RTT_MS" ] && k=$(( (6 * YT_RTT_MS + 999) / 1000 ))
    sa=$YT_RETRY_AFTER; [ "$k" -gt "$sa" ] && sa=$k
    k=0; [ -n "$YT_RTT_MS" ] && k=$(( (12 * YT_RTT_MS + 999) / 1000 ))
    da=$YT_DEAD_AFTER; [ "$k" -gt "$da" ] && da=$k
    # в журнал — только смена «обычные / поднятые», и не чаще раза в 10 мин: RTT около
    # границы двигал порог каждые 30 с (под netem — 7 строк за 8 мин)
    if [ "$sa" -gt "$YT_RETRY_AFTER" ] || [ "$da" -gt "$YT_DEAD_AFTER" ]; then k=up; else k=base; fi
    if [ "$k" != "${YT_SA_LAST:-base}" ] && [ $((now - YT_RTT_LOG_TS)) -ge 600 ]; then
        if [ "$k" = up ]; then
            log "YouTube: RTT соединений ${YT_RTT_MS} мс — повтор ждёт ответа сервера ${sa} с (ClientHello) и ${da} с (данные), обычно ${YT_RETRY_AFTER} и ${YT_DEAD_AFTER}"
        else
            log "YouTube: RTT соединений ${YT_RTT_MS:-?} мс — пороги повтора обычные (${YT_RETRY_AFTER} и ${YT_DEAD_AFTER} с)"
        fi
        YT_SA_LAST=$k; YT_RTT_LOG_TS=$now
    fi
    # «запрос без ответа» (YT_REQ_AFTER): не меньше 8×RTT — при потере запроса клиент повторит его
    # через RTO, и живой сервер подтвердит позже; на медленном канале порог растёт сам
    rqe=$YT_REQ_AFTER
    if [ "$rqe" -gt 0 ] && [ -n "$YT_RTT_MS" ]; then
        k=$(( (8 * YT_RTT_MS + 999) / 1000 )); [ "$k" -gt "$rqe" ] && rqe=$k
    fi
    [ -f "$YT_SEEN_FILE" ] || : > "$YT_SEEN_FILE"
    [ -f "$YT_SEEN_FILE.req" ] || : > "$YT_SEEN_FILE.req"
    # адрес телефона в мобильной сети: его соединения помечены надёжно,
    # подстраховка "по сетям Google" — только для раздачи
    local wip="$LAST_WAN_IP"
    [ -n "$wip" ] || wip=$($ip -4 addr show "$LAST_WAN_IFACE" 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')
    # IPv6-only сеть с CLAT: IPv4 у v4-<WAN>, иначе запасной поиск выключен
    [ -n "$wip" ] || wip=$($ip -4 addr show "v4-$LAST_WAN_IFACE" 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')
    out=$($CONNTRACK_BIN -L -p tcp --dport 443 2>/dev/null | awk -v now="$now" -v after="$da" -v sa="$sa" -v hs="$YT_HS_MAX" -v sf="$YT_SEEN_FILE" -v rf="$YT_SEEN_FILE.req" -v rq="$rqe" -v gr="$YT_GRANGES" -v wip="$wip" '
        FILENAME == gr { gs[++ng] = $1; ge[ng] = $2; next }
        FILENAME == sf { seen[$1] = $2; rep[$1] = $4; next }
        FILENAME == rf { rbr[$1] = $2; rob0[$1] = $3; rop0[$1] = $4; rtq0[$1] = $5; rlg0[$1] = $6; next }
        / ESTABLISHED / {
            src = ""; dst = ""; rsrc = ""; rdst = ""; sp = ""; po = -1; bo = -1; pr = -1; br = -1; mk = 0
            for (i = 1; i <= NF; i++) {
                split($i, kv, "=")
                if (kv[1] == "src") { if (src == "") src = kv[2]; else if (rsrc == "") rsrc = kv[2] }
                else if (kv[1] == "dst") { if (dst == "") dst = kv[2]; else if (rdst == "") rdst = kv[2] }
                else if (kv[1] == "sport" && sp == "") sp = kv[2]
                else if (kv[1] == "packets") { if (po < 0) po = kv[2]; else if (pr < 0) pr = kv[2] }
                else if (kv[1] == "bytes") { if (bo < 0) bo = kv[2]; else if (br < 0) br = kv[2] }
                else if (kv[1] == "mark") mk = kv[2]
            }
            # приложение -> AdGuard (REDIRECT): отвечает сам AdGuard, о сервере это ничего не говорит
            if (rsrc != dst) next
            # googlevideo.com (метка); без метки — только если сервер в сетях Google
            yt = (int(mk / 268435456) % 2 == 1)
            if (!yt) {
                # без метки — только раздача, ушедшая наружу через WAN (ответ
                # идёт на адрес телефона). Через VPN метки нет никогда: и
                # раздача (ответ на адрес tun), и сам телефон (src — адрес
                # tun) попадали сюда — ss -K по общим адресам Google (ревью 25.10)
                if (wip == "" || rdst != wip || src == wip) next
                # без метки — только «застрял/молчит» — остальное не перебираем
                if (bo < 600 || pr < 1 || br > 80 * pr || pr > 32 || bo > 65536) next
                split(dst, o, "."); n = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]; g = 0
                for (j = 1; j <= ng; j++) if (n >= gs[j] && n <= ge[j]) { g = 1; break }
                if (!g) next
            }
            k = src ":" sp ">" dst
            t0 = (k in seen) ? seen[k] : now
            d = (k in rep) ? rep[k] : 0
            # Запрос ушёл, ответа нет (YT_REQ_AFTER; разрыв — ниже, в шелле). После последних данных
            # сервера клиент отправил больше 80 байт полезного (байты минус ~64 на пакет: его ACK
            # запросом не считаются) и rq с ни байта от сервера. Так висит шортс, который открывается,
            # если перелистнуть и вернуться (15.11): плеер бросает запрос и открывает новое соединение.
            # Простаивающее в пуле соединение (последним говорил сервер) сюда не попадает
            if (yt && rq > 0) {
                rnb = (k in rbr && rbr[k] == br)
                rob = rnb ? rob0[k] : bo; rop = rnb ? rop0[k] : po
                pay = (bo - rob) - 64 * (po - rop)
                rtq = (rnb && rtq0[k] > 0) ? rtq0[k] : ((pay > 80) ? now : 0)
                rlg = rnb ? rlg0[k] : 0
                # br > 100: от сервера были данные, не только SYN-ACK (тот случай — «застрял»)
                # раздаче на 1 с раньше: ей RST — только на повтор запроса, а повторы всё реже
                # (~0,4 / 1,2 / 2,8 / 6 / 12 с); с порогом 3 правило вставало после повтора на 2,8 с,
                # и RST доставался следующему — шортс на втором телефоне висел ~15 с (15.11)
                rql = (src == wip) ? rq : rq - 1; if (rql < 1) rql = 1
                if (!rlg && rtq > 0 && now - rtq >= rql && br > 100) {
                    print "REQ", dst, now - rtq, pay, br, (int(mk / 536870912) % 2 == 1) ? "warp" : "direct", (src == wip) ? "phone" : "tether", sp, src
                    rlg = 1
                }
                nr[k] = br " " rob " " rop " " rtq " " rlg
            }
            # видео идёт: сумма байт от видеосерверов (больше рукопожатия) — сигнал сторожу только
            # без живого видео; шелл сравнит с прошлым кругом: важен прирост, а не накопленное
            # за жизнь соединения (старое простаивающее держало бы «видео идёт» вечно)
            if (yt && br > hs && br > 80 * pr) dsum += br
            # от сервера — только пустые пакеты: ни одного байта данных. Пустой
            # пакет — до 80 байт (IP 20 + TCP до 60: метки времени, SACK; SACK
            # бывает из-за нарезки обходом). Порог по общему объёму (а не на пакет) путал
            # с мёртвыми простаивающие соединения с коротким ответом (возобновлённая TLS-сессия)
            # и не выгрузка: при ней сервер тоже шлёт одни ACK (Drive, Фото, загрузка
            # в YouTube — облачное ревью PR #22). У мёртвого — ClientHello с повторами
            # (до ~27 КБ) и пара десятков пакетов от сервера, у выгрузки за 3 с — больше
            if (bo < 600 || pr < 1 || br > 80 * pr || pr > 32 || bo > 65536) next
            kind = (pr <= 1) ? "stuck" : "dead"
            # застрявшие — только точно googlevideo.com
            if (kind == "stuck" && !yt) next
            # и не в WARP (connmark WARP_MARK 0x20000000): там застревает туннель, а не стойка
            if (kind == "stuck" && int(mk / 536870912) % 2 == 1) next
            # Раздача (src не телефон) — +2 с: Wi-Fi до клиента в RTT телефона (ss) не виден,
            # а отсчёт идёт от появления соединения, ClientHello клиента сам может опоздать
            lim = (kind == "stuck") ? sa : after
            if (src != wip) lim += 2
            if (now - t0 >= lim && d == 0) { print "HIT", kind, dst, src, sp; d = 1 }
            ns[k] = t0 " " kind " " d
        }
        END { for (k in ns) print k, ns[k] > (sf ".new"); for (k in nr) print k, nr[k] > (rf ".new"); printf "DATA %.0f\n", dsum }
    ' "$YT_GRANGES" "$YT_SEEN_FILE" "$YT_SEEN_FILE.req" - 2>/dev/null)
    if [ -f "$YT_SEEN_FILE.new" ]; then mv -f "$YT_SEEN_FILE.new" "$YT_SEEN_FILE"; else : > "$YT_SEEN_FILE"; fi
    if [ -f "$YT_SEEN_FILE.req.new" ]; then mv -f "$YT_SEEN_FILE.req.new" "$YT_SEEN_FILE.req"; else : > "$YT_SEEN_FILE.req"; fi
    # «запрос ушёл, ответа нет» (YT_REQ_AFTER): соединение телефона напрямую — рвём, плеер сразу
    # откроет новое (15.11: 16 таких за 7 мин, зависание шортса в 12:49:45 — запрос ~12 КБ к фронту
    # 173.194.165.4). Раздачу ss не порвёт — ей RST на повтор запроса; через WARP — только журнал
    for rqh in $(printf '%s\n' "$out" | awk '$1 == "REQ" { print $2 "_" $3 "_" $4 "_" $5 "_" $6 "_" $7 "_" $8 "_" $9 }'); do
        rqd=${rqh%%_*}; rqh=${rqh#*_}; rqa=${rqh%%_*}; rqh=${rqh#*_}; rqp=${rqh%%_*}; rqh=${rqh#*_}; rqb=${rqh%%_*}; rqh=${rqh#*_}
        rqv=${rqh%%_*}; rqh=${rqh#*_}; rqw=${rqh%%_*}; rqh=${rqh#*_}; rqs=${rqh%%_*}; rqc=${rqh#*_}
        case "$rqd$rqs$rqc" in *[!0-9.]*|'') continue ;; esac
        if [ "$rqv" = direct ] && [ "$rqw" = phone ] && [ -n "$rqs" ]; then
            ss -K -tn dst "$rqd" dport = :443 sport = :"$rqs" >/dev/null 2>&1
            YT_REQ_KILLS=$((YT_REQ_KILLS + 1))
            log "YouTube: $rqd — запрос без ответа ${rqa}с (~${rqp} Б после последних данных сервера, от сервера $rqb Б) — рву соединение"
        elif [ "$rqv" = direct ] && [ "$rqw" = tether ] && [ -n "$rqs" ]; then
            # раздача: от сервера ни байта, даже ACK — клиент повторит запрос и на повтор получит RST
            # (правило на одно соединение, 20 с, снимает yt_retry_hits — как у застрявших)
            $iptables -I "$CHAIN_YT_RST" -s "$rqc" -d "$rqd" -p tcp --sport "$rqs" --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null && {
                YT_RETRY_RJ="$YT_RETRY_RJ
$(($now + 20)) $rqc $rqs $rqd"
                YT_REQ_KILLS=$((YT_REQ_KILLS + 1))
                log "YouTube: $rqd — запрос клиента раздачи $rqc без ответа ${rqa}с (~${rqp} Б, от сервера $rqb Б) — RST на его повтор"
            }
        else
            log "YouTube: наблюдение: $rqd — запрос без ответа ${rqa}с (~${rqp} Б после последних данных сервера, от сервера $rqb Б, $rqv, $rqw)"
        fi
    done
    ds=$(printf '%s\n' "$out" | sed -n 's/^DATA //p')
    [ "${ds:-0}" -gt "$YT_DATA_SUM" ] && YT_DATA_TS=$now
    YT_DATA_SUM=${ds:-0}
    yt_retry_hits "$out" "$now" "$wip"
    # сигнал сторожу (держим последние 2 мин): только адреса, которым не помогли и YT_RETRY_MAX
    # повторов, пока видео нигде не идёт (yt_retry_hits) — застревает треть попыток (14.11 YOTA)
    keep=""
    for t in $YT_STUCK; do [ $((now - t)) -lt 120 ] && keep="$keep $t"; done
    n=$YT_RETRY_ESC; YT_RETRY_ESC=0
    while [ "$n" -gt 0 ]; do keep="$keep $now"; n=$((n - 1)); done
    YT_STUCK="$keep"
}
