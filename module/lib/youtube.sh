# shellcheck shell=sh
# lib/youtube.sh — YouTube: мимо кэшей оператора (YT_GGC_BLOCK), отбой мёртвых
# видеосерверов (YT_DEAD_FAILFAST), обрыв медленных (zapret/ytslow.sh).
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

# --- YT_DEAD_FAILFAST: мёртвые видеосерверы -> RST ---------------------------
# Пометка — mangle OUTPUT (телефон, кроме root: это проверки самого модуля) и
# FORWARD (раздача): там ClientHello ещё целый, nfqws его режет позже, в
# POSTROUTING. Отбой — filter, как у GGC: RST на ClientHello к подсети из
# списка. tun+ — мимо: через VPN сервер достижим.
yt_match_build() {   # zapret_caps зовёт снова, если ядро без connbytes
    YT_MARK_OUT="! -o tun+ -m owner ! --uid-owner 0 $GGC_MATCH -j CONNMARK --set-xmark $YT_CTMARK/$YT_CTMARK"
    YT_MARK_FWD="! -o tun+ $GGC_MATCH -j CONNMARK --set-xmark $YT_CTMARK/$YT_CTMARK"
    # Play Маркет (gvt1.com) — свой бит: обрыв медленных его не трогает
    YT_GMARK_OUT="! -o tun+ -m owner ! --uid-owner 0 $GVT_MATCH -j CONNMARK --set-xmark $YT_GCTMARK/$YT_GCTMARK"
    YT_GMARK_FWD="! -o tun+ $GVT_MATCH -j CONNMARK --set-xmark $YT_GCTMARK/$YT_GCTMARK"
}
yt_match_build

YT_DEAD_FAILS=0
yt_dead_hooks_off() {
    local c m _n
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D OUTPUT $YT_MARK_OUT 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D FORWARD $YT_MARK_FWD 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D OUTPUT $YT_GMARK_OUT 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D FORWARD $YT_GMARK_FWD 2>/dev/null; do _n=$((_n + 1)); done
    for c in OUTPUT FORWARD; do
        for m in "$GGC_MATCH" "$GVT_MATCH"; do
            _n=0; while [ $_n -lt 8 ] && $iptables -D "$c" $m -j "$CHAIN_YT_DEAD" 2>/dev/null; do _n=$((_n + 1)); done
        done
    done
}

yt_dead_on() {
    yt_dead_hooks_off
    # без string (zapret_caps) мёртвые серверы не узнать — выключено
    if [ "$YT_DEAD_FAILFAST" != "1" ] || [ -z "$CONNTRACK_BIN" ] || ! zapret_cap str; then
        yt_dead_off
        return 0
    fi
    $iptables -N "$CHAIN_YT_DEAD" 2>/dev/null
    # сети Google числами — для соединений раздачи, где пометку стирает
    # tether_unblock (CONNMARK 0x40/0xffffffff на каждом пакете с TTL≠63)
    awk -F'[./]' '/^[0-9]/ && NF == 5 { s = (($1 * 256 + $2) * 256 + $3) * 256 + $4; printf "%.0f %.0f\n", s, s + 2 ^ (32 - $5) - 1 }' \
        "$ZAPRET_DIR/google-ipv4.txt" > "$YT_GRANGES" 2>/dev/null
    YT_DEAD_SIG="-"
    yt_dead_apply
    $iptables -t mangle -I FORWARD 1 $YT_MARK_FWD 2>/dev/null
    $iptables -t mangle -I FORWARD 1 $YT_GMARK_FWD 2>/dev/null
    $iptables -I FORWARD 1 $GVT_MATCH -j "$CHAIN_YT_DEAD" 2>/dev/null
    $iptables -I FORWARD 1 $GGC_MATCH -j "$CHAIN_YT_DEAD" 2>/dev/null
    if [ "$ZAPRET_PHONE" = "1" ]; then
        $iptables -t mangle -I OUTPUT 1 $YT_MARK_OUT 2>/dev/null
        $iptables -t mangle -I OUTPUT 1 $YT_GMARK_OUT 2>/dev/null
        $iptables -I OUTPUT 1 $GVT_MATCH -j "$CHAIN_YT_DEAD" 2>/dev/null
        $iptables -I OUTPUT 1 $GGC_MATCH -j "$CHAIN_YT_DEAD" 2>/dev/null
    fi
    # хук не встал — не «on»: иначе сторож zapret ставил бы правила по кругу
    if ! $iptables -C FORWARD $GGC_MATCH -j "$CHAIN_YT_DEAD" 2>/dev/null; then
        YT_DEAD_FAILS=$((YT_DEAD_FAILS + 1))
        [ "$YT_DEAD_FAILS" -ge 3 ] && [ "$YT_DEAD_STATE" != "fail" ] && \
            log "WARNING: zapret: правила отбоя мёртвых серверов YouTube не встали 3 раза — отбой выключен"
        yt_dead_hooks_off; YT_DEAD_STATE="fail"; return 0
    fi
    YT_DEAD_FAILS=0
    [ "$YT_DEAD_STATE" = "on" ] || log "zapret: отбой мёртвых и молчащих серверов YouTube и Play включён (нет ответа ${YT_DEAD_AFTER}с, на запрос ${YT_SILENT_AFTER}с и проверка не прошла -> RST на $((YT_DEAD_TTL / 60)) мин)"
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
    $iptables -F "$CHAIN_YT_DEAD" 2>/dev/null; $iptables -X "$CHAIN_YT_DEAD" 2>/dev/null
    # -9: TERM подоболочке «( … ) &» в mksh доходит до trap демона ->
    # cleanup_on_exit и выход (25.10, воспроизведено на телефоне); curl
    # внутри сам закончится за <=3с
    yt_bg_alive "$YT_RECHECK_PID" && kill -9 "$YT_RECHECK_PID" 2>/dev/null; YT_RECHECK_PID=""
    yt_bg_alive "$YT_SPROBE_PID" && kill -9 "$YT_SPROBE_PID" 2>/dev/null; YT_SPROBE_PID=""
    yt_slow_stop
    rm -f "$YT_DEAD_FILE" "$YT_SEEN_FILE" "$YT_SEEN_FILE.new" "$YT_GRANGES" "$YT_RECHECK_FILE".* "$YT_SPROBE_FILE".*
    YT_DEAD_STATE=""; YT_DEAD_SIG=""; YT_STUCK=""
}

# цепочка отбоя = содержимое YT_DEAD_FILE (пересобираем только при изменении)
yt_dead_apply() {
    local sig="" net
    for net in $(awk '{print $1}' "$YT_DEAD_FILE" 2>/dev/null | sort -u); do
        case "$net" in *[!0-9./]*|'') continue ;; esac
        sig="$sig $net"
    done
    [ "$sig" = "$YT_DEAD_SIG" ] && return 0
    $iptables -F "$CHAIN_YT_DEAD" 2>/dev/null
    $iptables -A "$CHAIN_YT_DEAD" -o tun+ -j RETURN 2>/dev/null
    # -p tcp обязателен: без него REJECT --reject-with tcp-reset не встаёт
    # (3.0: правило молча не добавлялось, мёртвые сети не отбивались)
    for net in $sig; do
        $iptables -A "$CHAIN_YT_DEAD" -p tcp -d "$net" -j REJECT --reject-with tcp-reset 2>/dev/null || \
            log "WARNING: YouTube: не удалось поставить отбой для $net"
    done
    YT_DEAD_SIG="$sig"
}

# --- YT_SLOW_RETRY: фоновый zapret/ytslow.sh, пока работает отбой мёртвых
# (он помечает видеосоединения). Сам выходит, когда демона нет.
yt_slow_reconcile() {
    local p
    if [ "$YT_SLOW_RETRY" = "1" ] && [ "$YT_DEAD_STATE" = "on" ]; then
        # свой ребёнок: PID умершего ytslow мог достаться чужому процессу
        yt_bg_alive "$YT_SLOW_PID" && return 0
        # чужой/оставшийся экземпляр (демон перезапускали) — убрать
        for p in $(pgrep -f "zapret/ytslow.sh" 2>/dev/null); do kill "$p" 2>/dev/null; done
        [ -n "$YT_SLOW_PID" ] || log "YouTube: обрыв медленных видеосоединений включён — плеер переподключится и иногда попадёт на быстрое"
        setsid sh "$ZAPRET_DIR/ytslow.sh" "$$" "$CONNTRACK_BIN" </dev/null >/dev/null 2>&1 &
        YT_SLOW_PID=$!
    else
        [ -n "$YT_SLOW_PID" ] && log "YouTube: обрыв медленных видеосоединений выключен"
        yt_slow_stop
    fi
}
yt_slow_stop() {
    yt_bg_alive "$YT_SLOW_PID" && kill "$YT_SLOW_PID" 2>/dev/null
    YT_SLOW_PID=""
    rm -f "$YT_SLOW_STAT"
}

yt_dead_hits() {
    [ "$YT_DEAD_STATE" = "on" ] || { echo 0; return; }
    $iptables -L "$CHAIN_YT_DEAD" -v -x -n 2>/dev/null | awk '/REJECT/ {s += $1} END {print s + 0}'
}

# Проверка адреса сервера: TLS-рукопожатие с нейтральным именем
# (www.google.com) и ответ 204 мимо обхода и AdGuard (группа dnsproxy).
# Печатает ok/dead. Зовётся только в фоне — до 3 с на адрес.
yt_probe_ip() {
    local cmd c
    cmd="curl -s -k -o /dev/null -m 3 --interface $LAST_WAN_IFACE --connect-to www.google.com:443:$1:443 -w '%{http_code}' https://www.google.com/generate_204"
    if [ "$DNSPROXY_SU_G" = "1" ]; then c=$(su -g "$DNSPROXY_GID" -c "$cmd" 2>/dev/null); else c=$(eval "$cmd" 2>/dev/null); fi
    if [ "$c" = 204 ]; then echo ok; else echo dead; fi
}

# Отбить адрес мёртвого/молчащего сервера: /32, второй в той же /24 — вся /24.
#   yt_dead_add АДРЕС КТО ЧТО_С_НИМ NOW   (КТО и ЧТО — для журнала)
# 0 — добавлен (цепочку отбоя надо пересобрать), 1 — нет.
yt_dead_add() {
    local dip="$1" who="$2" why="$3" now="$4" kill="${5:-1}" net n24 sib keep t nlist
    case "$dip" in *[!0-9.]*|'') return 1 ;; esac
    net="$dip/32"; n24="${dip%.*}.0/24"
    # уже открытые соединения телефона к нему — закрыть сразу: AdGuard и
    # приложение переподключатся (с раздачи соединение доживёт до таймаута).
    # Не для «молчит после запроса» ($5=0): так выглядит и простаивающее
    # соединение с общим фронтендом Google — ss -K рвал поиск и YouTube
    # (25.10 23:00, 173.194.165.4 / 173.194.190.72)
    [ "$kill" = 1 ] && ss -K -tn dst "$dip" dport = :443 >/dev/null 2>&1
    grep -q -e "^$net " -e "^$n24 " "$YT_DEAD_FILE" 2>/dev/null && return 1
    [ "$now" -lt "$YT_DEAD_PAUSE" ] && return 1
    # лавина (>=6 подсетей за минуту) — не мёртвые серверы, а сломанный
    # обход или связь: отбив всё подряд, оставим плеер без серверов
    keep=""
    for t in $YT_DEAD_ADDS; do [ $((now - t)) -lt 60 ] && keep="$keep $t"; done
    YT_DEAD_ADDS="$keep"
    if [ "$(echo $YT_DEAD_ADDS | wc -w)" -ge 6 ]; then
        YT_DEAD_PAUSE=$((now + 300))
        log "WARNING: YouTube: слишком много «мёртвых» видеосерверов подряд — похоже, сломан обход или связь; 5 мин новые не отбиваю"
        return 1
    fi
    nlist=$(awk 'END {print NR}' "$YT_DEAD_FILE" 2>/dev/null)
    [ "${nlist:-0}" -ge "$YT_DEAD_MAX" ] && return 1
    # второй мёртвый в той же /24 — отбиваем подсеть целиком (в записи —
    # все замеченные адреса: по ним перепроверка поймёт, ожила ли она)
    sib=$(awk -v p="${dip%.*}." 'index($1, p) == 1 && $1 ~ /\/32$/ { sub(/\/32$/, "", $1); printf "%s,", $1 }' "$YT_DEAD_FILE" 2>/dev/null)
    if [ -n "$sib" ]; then
        awk -v p="${dip%.*}." '!(index($1, p) == 1 && $1 ~ /\/32$/)' "$YT_DEAD_FILE" > "$YT_DEAD_FILE.tmp" && mv -f "$YT_DEAD_FILE.tmp" "$YT_DEAD_FILE"
        echo "$n24 $((now + YT_DEAD_TTL)) $sib$dip" >> "$YT_DEAD_FILE"
        log "$who $dip $why — в $n24 это уже второй (${sib%,}), отбиваю подсеть на $((YT_DEAD_TTL / 60)) мин"
    else
        echo "$net $((now + YT_DEAD_TTL)) $dip" >> "$YT_DEAD_FILE"
        log "$who $dip $why — отбиваю его на $((YT_DEAD_TTL / 60)) мин"
    fi
    YT_DEAD_ADDS="$YT_DEAD_ADDS $now"
    return 0
}

yt_dead_who() {
    case "$1" in play) echo "Play Маркет: сервер загрузок" ;; *) echo "YouTube: видеосервер" ;; esac
}

# Раз в ~4с: соединения с googlevideo.com и gvt1.com (помечены; у раздачи
# пометку может стереть tether_unblock — тогда любые к сетям Google) из
# conntrack. ClientHello ушёл (>=600 байт), а от сервера дольше
# YT_DEAD_AFTER — ни байта данных:
#   пакетов от сервера >=2 — ClientHello он подтвердил, но молчит -> мёртв;
#   1 (только SYN-ACK) — ClientHello не дошёл: это DPI, а не сервер -> сторожу.
# Молчит после запроса (только помеченные): от сервера было рукопожатие,
# но не больше YT_SILENT_MAX, и YT_SILENT_AFTER — ни байта нового. Так же
# выглядит и живое соединение без запроса (заготовка, короткий ответ), поэтому
# такой адрес сначала проверяется в фоне (yt_probe_ip), отбой — только если
# проверка не прошла; прошедшие 5 мин не проверяем снова.
yt_dead_scan() {
    [ "$YT_DEAD_STATE" = "on" ] || return 0
    local now out dip hit n t keep="" changed=0 sil res tag cnt
    # не ip: локальная ip затирала бы $ip (/system/bin/ip) — адрес WAN ниже не узнавался
    now=$(date +%s)
    if [ -s "$YT_DEAD_FILE" ]; then
        n=$(awk 'END {print NR}' "$YT_DEAD_FILE")
        awk -v now="$now" '$2 > now' "$YT_DEAD_FILE" > "$YT_DEAD_FILE.tmp" 2>/dev/null && mv -f "$YT_DEAD_FILE.tmp" "$YT_DEAD_FILE"
        [ "$(awk 'END {print NR}' "$YT_DEAD_FILE")" != "$n" ] && changed=1
    fi
    [ -f "$YT_SEEN_FILE" ] || : > "$YT_SEEN_FILE"
    # адрес телефона в мобильной сети: его соединения помечены надёжно,
    # подстраховка "по сетям Google" — только для раздачи
    local wip="$LAST_WAN_IP"
    [ -n "$wip" ] || wip=$($ip -4 addr show "$LAST_WAN_IFACE" 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')
    # IPv6-only сеть с CLAT: IPv4 у v4-<WAN>, иначе запасной поиск выключен
    [ -n "$wip" ] || wip=$($ip -4 addr show "v4-$LAST_WAN_IFACE" 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')
    out=$($CONNTRACK_BIN -L -p tcp --dport 443 2>/dev/null | awk -v now="$now" -v after="$YT_DEAD_AFTER" -v safter="$YT_SILENT_AFTER" -v smax="$YT_SILENT_MAX" -v sf="$YT_SEEN_FILE" -v gr="$YT_GRANGES" -v wip="$wip" '
        FILENAME == gr { gs[++ng] = $1; ge[ng] = $2; next }
        FILENAME == sf { seen[$1] = $2; rep[$1] = $4; sbr[$1] = $5; stb[$1] = $6; next }
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
            # yt — googlevideo.com, gv — gvt1.com (Play); не помечено — тогда
            # только если сервер в сетях Google
            yt = (int(mk / 268435456) % 2 == 1)
            gv = (int(mk / 67108864) % 2 == 1)
            if (!yt && !gv) {
                # без метки — только раздача, ушедшая наружу через WAN (ответ
                # идёт на адрес телефона). Через VPN метки нет никогда: и
                # раздача (ответ на адрес tun), и сам телефон (src — адрес
                # tun) попадали сюда — ss -K по общим адресам Google и
                # перепроверка мимо VPN (ревью 25.10)
                if (wip == "" || rdst != wip || src == wip) next
                # без метки бывает только «мёртв» — остальное не перебираем
                if (bo < 600 || pr < 1 || br > 60 * pr) next
                split(dst, o, "."); n = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]; g = 0
                for (j = 1; j <= ng; j++) if (n >= gs[j] && n <= ge[j]) { g = 1; break }
                if (!g) next
            }
            tag = (gv && !yt) ? "play" : "yt"
            k = src ":" sp ">" dst
            t0 = (k in seen) ? seen[k] : now
            d = (k in rep) ? rep[k] : 0
            # молчит после запроса: данные от сервера были (рукопожатие), но
            # мало, и safter ни байта нового -> кандидат на проверку (каждый
            # раз: повторы отсекают отбой и «живой» на 5 мин у демона)
            # *.4 — фронтенды www.youtube/youtubei (их не трогает и ytslow)
            if ((yt || gv) && bo >= 600 && br > 60 * pr && br <= smax) {
                if (dst ~ /\.4$/) next
                tb = (k in sbr && sbr[k] == br) ? stb[k] : now
                if (now - tb >= safter) print "SIL", dst, tag
                ns[k] = t0 " silent " d " " br " " tb
                next
            }
            # от сервера — только пустые пакеты (SYN-ACK 60 + ACK 52 байта): ни
            # одного байта данных. Порог по объёму путал с мёртвыми простаивающие
            # соединения с коротким ответом (возобновлённая TLS-сессия)
            if (bo < 600 || pr < 1 || br > 60 * pr) next
            kind = (pr <= 1) ? "stuck" : "dead"
            # Play (gvt1.com): имя YOTA не режет (замер 25.10), так что ClientHello
            # без подтверждения — мёртвый сервер/адрес, а не DPI. 26.10 Play висел
            # на 172.217.133.234 / 173.194.188.42 (TLS нет и с www.google.com):
            # от сервера 1 пакет, ClientHello переотправлен 14 раз
            if (kind == "stuck" && gv && !yt) kind = "dead"
            # застрявшие (сигнал сторожу) — только точно googlevideo.com
            if (kind == "stuck" && !yt) next
            if (now - t0 >= after && d == 0) { print "HIT", kind, dst, tag; d = 1 }
            ns[k] = t0 " " kind " " d " " br " " now
        }
        END { for (k in ns) print k, ns[k] > (sf ".new") }
    ' "$YT_GRANGES" "$YT_SEEN_FILE" - 2>/dev/null)
    if [ -f "$YT_SEEN_FILE.new" ]; then mv -f "$YT_SEEN_FILE.new" "$YT_SEEN_FILE"; else : > "$YT_SEEN_FILE"; fi

    # адрес_кто (не через "while read" из трубы: тот идёт в подоболочке)
    for hit in $(printf '%s\n' "$out" | awk '$1 == "HIT" && $2 == "dead" && !s[$3]++ {print $3 "_" $4}'); do
        dip="${hit%_*}"; tag="${hit#*_}"
        yt_dead_add "$dip" "$(yt_dead_who "$tag")" "принял ClientHello и молчит ${YT_DEAD_AFTER}с" "$now" && changed=1
    done

    # молчащие: итог фоновой проверки с прошлых вызовов -> отбой или
    # «живой» на 5 мин; новые кандидаты -> в проверку (по 4 за раз)
    if [ -f "$YT_SPROBE_FILE.done" ]; then
        while read -r dip tag res; do
            case "$dip" in *[!0-9.]*|'') continue ;; esac
            if [ "$res" = ok ]; then
                echo "$dip $((now + 300))" >> "$YT_SPROBE_FILE.ok"
            else
                yt_dead_add "$dip" "$(yt_dead_who "$tag")" "ответил на рукопожатие, а на запрос молчит ${YT_SILENT_AFTER}с, проверка не прошла" "$now" 0 && changed=1
            fi
        done < "$YT_SPROBE_FILE.done"
        rm -f "$YT_SPROBE_FILE.done"
    fi
    if [ -s "$YT_SPROBE_FILE.ok" ]; then
        awk -v now="$now" '$2 > now' "$YT_SPROBE_FILE.ok" > "$YT_SPROBE_FILE.ok.tmp" 2>/dev/null && mv -f "$YT_SPROBE_FILE.ok.tmp" "$YT_SPROBE_FILE.ok"
    fi
    sil=$(printf '%s\n' "$out" | awk '$1 == "SIL" && !s[$2]++ {print $2, $3}')
    if [ -n "$sil" ] && [ -n "$LAST_WAN_IFACE" ] && ! yt_bg_alive "$YT_SPROBE_PID"; then
        : > "$YT_SPROBE_FILE.in"
        cnt=0
        for hit in $(printf '%s\n' "$sil" | tr ' ' '_'); do
            dip="${hit%_*}"
            case "$dip" in *[!0-9.]*|'') continue ;; esac
            # уже в отбое или недавно прошёл проверку — не трогаем
            grep -q -e "^$dip/32 " -e "^${dip%.*}.0/24 " "$YT_DEAD_FILE" 2>/dev/null && continue
            grep -q "^$dip " "$YT_SPROBE_FILE.ok" 2>/dev/null && continue
            echo "$hit" | tr '_' ' ' >> "$YT_SPROBE_FILE.in"
            cnt=$((cnt + 1)); [ "$cnt" -ge 4 ] && break
        done
        if [ -s "$YT_SPROBE_FILE.in" ]; then
            (
                while read -r dip tag; do
                    echo "$dip $tag $(yt_probe_ip "$dip")"
                done < "$YT_SPROBE_FILE.in" > "$YT_SPROBE_FILE.tmp"
                mv -f "$YT_SPROBE_FILE.tmp" "$YT_SPROBE_FILE.done"
            ) </dev/null >/dev/null 2>&1 &
            YT_SPROBE_PID=$!
        fi
    fi

    # застрявшие на ClientHello — сигнал сторожу (держим последние 2 мин)
    keep=""
    for t in $YT_STUCK; do [ $((now - t)) -lt 120 ] && keep="$keep $t"; done
    n=$(printf '%s\n' "$out" | awk '$1 == "HIT" && $2 == "stuck"' | awk 'END {print NR}')
    while [ "$n" -gt 0 ]; do keep="$keep $now"; n=$((n - 1)); done
    YT_STUCK="$keep"

    if [ "$changed" = 1 ]; then
        yt_dead_apply
        phone_status_refresh
    fi
}

# Раз в ~минуту: отбитые (старше минуты) перепроверяются в фоне — TLS-рукопожатие
# с нейтральным именем (www.google.com) мимо обхода и AdGuard (группа dnsproxy):
# жив ли сам адрес. Ожил (у подсети — хоть один из её адресов) — отбой снимаем,
# не дожидаясь срока. Результат забираем на следующем вызове: цикл не ждёт curl.
yt_dead_recheck() {
    [ "$YT_DEAD_STATE" = "on" ] || return 0
    local net res now changed=0
    if [ -f "$YT_RECHECK_FILE.done" ]; then
        while read -r net res; do
            [ "$res" = ok ] || continue
            case "$net" in *[!0-9./]*|'') continue ;; esac
            grep -q "^$net " "$YT_DEAD_FILE" 2>/dev/null || continue
            N="$net" awk '$1 != ENVIRON["N"]' "$YT_DEAD_FILE" > "$YT_DEAD_FILE.tmp" && mv -f "$YT_DEAD_FILE.tmp" "$YT_DEAD_FILE"
            changed=1
            log "YouTube: ${net%/32} снова отвечает — снимаю отбой"
        done < "$YT_RECHECK_FILE.done"
        rm -f "$YT_RECHECK_FILE.done"
        if [ "$changed" = 1 ]; then yt_dead_apply; phone_status_refresh; fi
    fi
    [ -s "$YT_DEAD_FILE" ] && [ -n "$LAST_WAN_IFACE" ] || return 0
    yt_bg_alive "$YT_RECHECK_PID" && return 0
    now=$(date +%s)
    # только добавленные больше минуты назад (свежие проверять рано)
    awk -v now="$now" -v ttl="$YT_DEAD_TTL" '$2 - ttl + 60 <= now' "$YT_DEAD_FILE" > "$YT_RECHECK_FILE.in" 2>/dev/null
    [ -s "$YT_RECHECK_FILE.in" ] || return 0
    (
        while read -r net _ ips; do
            res=dead
            for ip in $(echo "$ips" | tr ',' ' '); do
                case "$ip" in *[!0-9.]*|'') continue ;; esac
                [ "$(yt_probe_ip "$ip")" = ok ] && { res=ok; break; }
            done
            echo "$net $res"
        done < "$YT_RECHECK_FILE.in" > "$YT_RECHECK_FILE.tmp"
        mv -f "$YT_RECHECK_FILE.tmp" "$YT_RECHECK_FILE.done"
    ) </dev/null >/dev/null 2>&1 &
    YT_RECHECK_PID=$!
}

