# shellcheck shell=sh
# lib/youtube.sh — YouTube: мимо кэшей оператора (YT_GGC_BLOCK), отбой мёртвых
# видеосерверов (YT_DEAD_FAILFAST), обрыв медленных (zapret/ytslow.sh).
# Часть демона service.sh: подключается из него через ".", сам не запускается.
# Настройки (USER CONFIG) и общие переменные — в service.sh.

# --- YT_GGC_BLOCK: googlevideo.com на адреса не из сетей Google -> RST ----
# filter, а не mangle: отказ до NFQUEUE, nfqws этот ClientHello не видит.
# OUTPUT — телефон (если zapret для телефона включён), FORWARD — раздача.
# tun+ — мимо: через VPN кэш оператора не попадается.
zapret_ggc_hooks_off() {
    local t="$1" c _n
    for c in OUTPUT FORWARD; do
        _n=0; while [ $_n -lt 8 ] && $t -D "$c" $GGC_MATCH -j "$CHAIN_ZAPRET_GGC" 2>/dev/null; do _n=$((_n + 1)); done
    done
}

zapret_ggc_on() {
    local t f p n st=""
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
        st="$st${st:++}$([ "$t" = "$iptables" ] && echo v4 || echo v6)"
    done
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
YT_MARK_OUT="! -o tun+ -m owner ! --uid-owner 0 $GGC_MATCH -j CONNMARK --set-xmark $YT_CTMARK/$YT_CTMARK"
YT_MARK_FWD="! -o tun+ $GGC_MATCH -j CONNMARK --set-xmark $YT_CTMARK/$YT_CTMARK"

yt_dead_hooks_off() {
    local c _n
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D OUTPUT $YT_MARK_OUT 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D FORWARD $YT_MARK_FWD 2>/dev/null; do _n=$((_n + 1)); done
    for c in OUTPUT FORWARD; do
        _n=0; while [ $_n -lt 8 ] && $iptables -D "$c" $GGC_MATCH -j "$CHAIN_YT_DEAD" 2>/dev/null; do _n=$((_n + 1)); done
    done
}

yt_dead_on() {
    yt_dead_hooks_off
    if [ "$YT_DEAD_FAILFAST" != "1" ] || [ -z "$CONNTRACK_BIN" ]; then
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
    $iptables -I FORWARD 1 $GGC_MATCH -j "$CHAIN_YT_DEAD" 2>/dev/null
    if [ "$ZAPRET_PHONE" = "1" ]; then
        $iptables -t mangle -I OUTPUT 1 $YT_MARK_OUT 2>/dev/null
        $iptables -I OUTPUT 1 $GGC_MATCH -j "$CHAIN_YT_DEAD" 2>/dev/null
    fi
    [ "$YT_DEAD_STATE" = "on" ] || log "zapret: отбой мёртвых видеосерверов YouTube включён (нет ответа ${YT_DEAD_AFTER}с -> /24 на $((YT_DEAD_TTL / 60)) мин)"
    YT_DEAD_STATE="on"
}

yt_dead_off() {
    yt_dead_hooks_off
    $iptables -F "$CHAIN_YT_DEAD" 2>/dev/null; $iptables -X "$CHAIN_YT_DEAD" 2>/dev/null
    [ -n "$YT_RECHECK_PID" ] && kill "$YT_RECHECK_PID" 2>/dev/null; YT_RECHECK_PID=""
    yt_slow_stop
    rm -f "$YT_DEAD_FILE" "$YT_SEEN_FILE" "$YT_SEEN_FILE.new" "$YT_GRANGES" "$YT_RECHECK_FILE".*
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
        [ -n "$YT_SLOW_PID" ] && kill -0 "$YT_SLOW_PID" 2>/dev/null && return 0
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
    [ -n "$YT_SLOW_PID" ] && kill "$YT_SLOW_PID" 2>/dev/null
    YT_SLOW_PID=""
    rm -f "$YT_SLOW_STAT"
}

yt_dead_hits() {
    [ "$YT_DEAD_STATE" = "on" ] || { echo 0; return; }
    $iptables -L "$CHAIN_YT_DEAD" -v -x -n 2>/dev/null | awk '/REJECT/ {s += $1} END {print s + 0}'
}

# Раз в ~4с: соединения с googlevideo.com (помечены; у раздачи пометку
# может стереть tether_unblock — тогда любые к сетям Google) из conntrack. ClientHello ушёл
# (>=600 байт), а от сервера дольше YT_DEAD_AFTER — ни байта данных:
#   пакетов от сервера >=2 — ClientHello он подтвердил, но молчит -> мёртв;
#   1 (только SYN-ACK) — ClientHello не дошёл: это DPI, а не сервер -> сторожу.
yt_dead_scan() {
    [ "$YT_DEAD_STATE" = "on" ] || return 0
    local now out dip net n t keep="" changed=0 nlist
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
    out=$($CONNTRACK_BIN -L -p tcp --dport 443 2>/dev/null | awk -v now="$now" -v after="$YT_DEAD_AFTER" -v sf="$YT_SEEN_FILE" -v gr="$YT_GRANGES" -v wip="$wip" '
        FILENAME == gr { gs[++ng] = $1; ge[ng] = $2; next }
        FILENAME == sf { seen[$1] = $2; rep[$1] = $4; next }
        / ESTABLISHED / {
            src = ""; dst = ""; rsrc = ""; sp = ""; po = -1; bo = -1; pr = -1; br = -1; mk = 0
            for (i = 1; i <= NF; i++) {
                split($i, kv, "=")
                if (kv[1] == "src") { if (src == "") src = kv[2]; else if (rsrc == "") rsrc = kv[2] }
                else if (kv[1] == "dst" && dst == "") dst = kv[2]
                else if (kv[1] == "sport" && sp == "") sp = kv[2]
                else if (kv[1] == "packets") { if (po < 0) po = kv[2]; else if (pr < 0) pr = kv[2] }
                else if (kv[1] == "bytes") { if (bo < 0) bo = kv[2]; else if (br < 0) br = kv[2] }
                else if (kv[1] == "mark") mk = kv[2]
            }
            # приложение -> AdGuard (REDIRECT): отвечает сам AdGuard, о сервере это ничего не говорит
            if (rsrc != dst) next
            # не помечено как googlevideo — тогда только если сервер в сетях Google
            marked = (int(mk / 268435456) % 2 == 1)
            if (!marked) {
                if (src == wip) next
                split(dst, o, "."); n = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]; g = 0
                for (j = 1; j <= ng; j++) if (n >= gs[j] && n <= ge[j]) { g = 1; break }
                if (!g) next
            }
            # от сервера — только пустые пакеты (SYN-ACK 60 + ACK 52 байта): ни
            # одного байта данных. Порог по объёму путал с мёртвыми простаивающие
            # соединения с коротким ответом (возобновлённая TLS-сессия)
            if (bo < 600 || pr < 1 || br > 60 * pr) next
            k = src ":" sp ">" dst
            kind = (pr <= 1) ? "stuck" : "dead"
            # застрявшие (сигнал сторожу) — только точно googlevideo.com
            if (kind == "stuck" && !marked) next
            t0 = (k in seen) ? seen[k] : now
            d = (k in rep) ? rep[k] : 0
            if (now - t0 >= after && d == 0) { print "HIT", kind, dst; d = 1 }
            ns[k] = t0 " " kind " " d
        }
        END { for (k in ns) print k, ns[k] > (sf ".new") }
    ' "$YT_GRANGES" "$YT_SEEN_FILE" - 2>/dev/null)
    if [ -f "$YT_SEEN_FILE.new" ]; then mv -f "$YT_SEEN_FILE.new" "$YT_SEEN_FILE"; else : > "$YT_SEEN_FILE"; fi

    for dip in $(printf '%s\n' "$out" | awk '$1 == "HIT" && $2 == "dead" {print $3}' | sort -u); do
        case "$dip" in *[!0-9.]*|'') continue ;; esac
        net="$dip/32"; n24="${dip%.*}.0/24"
        # уже открытые соединения телефона к нему — закрыть сразу: AdGuard и
        # приложение переподключатся (с раздачи соединение доживёт до таймаута)
        ss -K -tn dst "$dip" dport = :443 >/dev/null 2>&1
        grep -q -e "^$net " -e "^$n24 " "$YT_DEAD_FILE" 2>/dev/null && continue
        [ "$now" -lt "$YT_DEAD_PAUSE" ] && continue
        # лавина (>=6 подсетей за минуту) — не мёртвые серверы, а сломанный
        # обход или связь: отбив всё подряд, оставим плеер без серверов
        keep=""
        for t in $YT_DEAD_ADDS; do [ $((now - t)) -lt 60 ] && keep="$keep $t"; done
        YT_DEAD_ADDS="$keep"
        if [ "$(echo $YT_DEAD_ADDS | wc -w)" -ge 6 ]; then
            YT_DEAD_PAUSE=$((now + 300))
            log "WARNING: YouTube: слишком много «мёртвых» видеосерверов подряд — похоже, сломан обход или связь; 5 мин новые не отбиваю"
            continue
        fi
        nlist=$(awk 'END {print NR}' "$YT_DEAD_FILE" 2>/dev/null)
        [ "${nlist:-0}" -ge "$YT_DEAD_MAX" ] && continue
        # второй мёртвый в той же /24 — отбиваем подсеть целиком (в записи —
        # все замеченные адреса: по ним перепроверка поймёт, ожила ли она)
        sib=$(awk -v p="${dip%.*}." 'index($1, p) == 1 && $1 ~ /\/32$/ { sub(/\/32$/, "", $1); printf "%s,", $1 }' "$YT_DEAD_FILE" 2>/dev/null)
        if [ -n "$sib" ]; then
            awk -v p="${dip%.*}." '!(index($1, p) == 1 && $1 ~ /\/32$/)' "$YT_DEAD_FILE" > "$YT_DEAD_FILE.tmp" && mv -f "$YT_DEAD_FILE.tmp" "$YT_DEAD_FILE"
            echo "$n24 $((now + YT_DEAD_TTL)) $sib$dip" >> "$YT_DEAD_FILE"
            log "YouTube: видеосервер $dip молчит после ClientHello — в $n24 это уже второй (${sib%,}), отбиваю подсеть на $((YT_DEAD_TTL / 60)) мин"
        else
            echo "$net $((now + YT_DEAD_TTL)) $dip" >> "$YT_DEAD_FILE"
            log "YouTube: видеосервер $dip принял ClientHello и молчит ${YT_DEAD_AFTER}с — отбиваю его на $((YT_DEAD_TTL / 60)) мин"
        fi
        YT_DEAD_ADDS="$YT_DEAD_ADDS $now"
        changed=1
    done

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
    [ -n "$YT_RECHECK_PID" ] && kill -0 "$YT_RECHECK_PID" 2>/dev/null && return 0
    now=$(date +%s)
    # только добавленные больше минуты назад (свежие проверять рано)
    awk -v now="$now" -v ttl="$YT_DEAD_TTL" '$2 - ttl + 60 <= now' "$YT_DEAD_FILE" > "$YT_RECHECK_FILE.in" 2>/dev/null
    [ -s "$YT_RECHECK_FILE.in" ] || return 0
    (
        while read -r net _ ips; do
            res=dead
            for ip in $(echo "$ips" | tr ',' ' '); do
                case "$ip" in *[!0-9.]*|'') continue ;; esac
                cmd="curl -s -k -o /dev/null -m 3 --interface $LAST_WAN_IFACE --connect-to www.google.com:443:$ip:443 -w '%{http_code}' https://www.google.com/generate_204"
                if [ "$DNSPROXY_SU_G" = "1" ]; then c=$(su -g "$DNSPROXY_GID" -c "$cmd" 2>/dev/null); else c=$(eval "$cmd" 2>/dev/null); fi
                [ "$c" = 204 ] && { res=ok; break; }
            done
            echo "$net $res"
        done < "$YT_RECHECK_FILE.in" > "$YT_RECHECK_FILE.tmp"
        mv -f "$YT_RECHECK_FILE.tmp" "$YT_RECHECK_FILE.done"
    ) </dev/null >/dev/null 2>&1 &
    YT_RECHECK_PID=$!
}

