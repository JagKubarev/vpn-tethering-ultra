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
    # Загрузки Play (gvt1.com) — та же пометка: это те же видеостойки (rr…---sn-….gvt1.com). Без неё соединение с
    # gvt1 было «Google не видео», молчащая стойка уходила в мёртвые фронты — 15 мин RST на SYN вместо малого окна
    # (18.11 ночью: 74.125.11.35, стойка загрузки из redirector.gvt1.com), и Play на ней висел
    # Только стойки (имя rr…---sn-…): фронт redirector.gvt1.com — обычный фронт Google, молчит — ему отказ фронта, а
    # не малое окно на 2 суток всей его /28 (там и другие сервисы Google). И свой бит YT_PLAY_CTMARK — загрузки Play не
    # зовут сторожа «сломалась стратегия» (yt_retry_hits): молчащая стойка Play — не признак (ревью 18.11)
    YT_MARK_OUT_G="! -o tun+ -m owner ! --uid-owner 0 $GVT_MATCH -m string --string ---sn- --algo bm -j CONNMARK --set-xmark $YT_PLAY_XMARK"
    YT_MARK_FWD_G="! -o tun+ $GVT_MATCH -m string --string ---sn- --algo bm -j CONNMARK --set-xmark $YT_PLAY_XMARK"
}
yt_match_build

YT_DEAD_FAILS=0
yt_dead_hooks_off() {
    local c m _n
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D OUTPUT $YT_MARK_OUT 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D FORWARD $YT_MARK_FWD 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D OUTPUT $YT_MARK_OUT_G 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D FORWARD $YT_MARK_FWD_G 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -D FORWARD -p tcp --dport 443 -j "$CHAIN_YT_RST" 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -D OUTPUT -p tcp --dport 443 --syn -j "$CHAIN_YT_FRONT" 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -D FORWARD -p tcp --dport 443 --syn -j "$CHAIN_YT_FRONT" 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t raw -D OUTPUT $YT_POKE_NT_M -j CT --notrack 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t raw -D OUTPUT $YT_POKE_NT_M -j NOTRACK 2>/dev/null; do _n=$((_n + 1)); done
    YT_POKE_NT=0
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
# Переход в RST раздаче — снова первым в FORWARD. setup_direct_rules при каждой пересборке (WebUI, смена
# состояния) ставит первым «ESTABLISHED,RELATED → ACCEPT», а хуки yt_dead_on ставятся только при включении
# zapret: пакеты установленных соединений клиента принимались раньше, и RST («запрос без ответа», повтор
# ClientHello) не доходил, хотя в журнале был (17.11: работало 13:48–14:31 и 15:20–15:34, остальное время — нет)
yt_rst_hook_top() {
    local _n=0
    [ "$YT_DEAD_STATE" = on ] || return 0
    $iptables -L "$CHAIN_YT_RST" -n >/dev/null 2>&1 || return 0
    while [ $_n -lt 8 ] && $iptables -D FORWARD -p tcp --dport 443 -j "$CHAIN_YT_RST" 2>/dev/null; do _n=$((_n + 1)); done
    $iptables -I FORWARD 1 -p tcp --dport 443 -j "$CHAIN_YT_RST" 2>/dev/null
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
    $iptables -t mangle -I FORWARD 1 $YT_MARK_FWD_G 2>/dev/null
    # раздача: её соединение ss не рвёт (транзит, сокета на телефоне нет) — RST клиенту на его
    # следующий повтор (yt_retry_hits, «запрос без ответа»). Цепочка пуста, пока ничего не застряло
    $iptables -N "$CHAIN_YT_RST" 2>/dev/null
    $iptables -I FORWARD 1 -p tcp --dport 443 -j "$CHAIN_YT_RST" 2>/dev/null
    # мёртвые фронты (yt_front_hit): RST на SYN — и телефону, и раздаче; цепочку заполнит yt_front_sync
    $iptables -N "$CHAIN_YT_FRONT" 2>/dev/null
    $iptables -I OUTPUT 1 -p tcp --dport 443 --syn -j "$CHAIN_YT_FRONT" 2>/dev/null
    $iptables -I FORWARD 1 -p tcp --dport 443 --syn -j "$CHAIN_YT_FRONT" 2>/dev/null
    # пустой ACK раздаче (YT_POKE): пакет идёт с адресом WAN и портом после NAT — conntrack телефона своего
    # соединения в нём не узнаёт, заводит новое, и NAT меняет порт: пакет уходит мимо. Мимо conntrack — только
    # 40-байтный голый ACK с меткой модуля (так шлёт лишь vtpoke). Стенд 17.11 (t41): ответ сервера проходит
    # обратный NAT до клиента. Старые ядра без CT — NOTRACK; не встало ни одно — раздаче без пакета
    if [ -n "$VTPOKE_BIN" ] && [ "${YT_POKE:-0}" -gt 0 ]; then
        if $iptables -t raw -I OUTPUT 1 $YT_POKE_NT_M -j CT --notrack 2>/dev/null || \
           $iptables -t raw -I OUTPUT 1 $YT_POKE_NT_M -j NOTRACK 2>/dev/null; then
            YT_POKE_NT=1
        fi
    fi
    YT_DEAD_ON_TS=$(date +%s); YT_FRONT_KEY=""
    # простой соединения = таймаут ESTABLISHED минус остаток (таймер сбрасывает каждый пакет); нет файла — без обрыва
    YT_CT_EST=$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established 2>/dev/null)
    case "$YT_CT_EST" in ''|*[!0-9]*) YT_CT_EST=0 ;; esac
    [ "$ZAPRET_PHONE" = "1" ] && $iptables -t mangle -I OUTPUT 1 $YT_MARK_OUT 2>/dev/null && \
        $iptables -t mangle -I OUTPUT 1 $YT_MARK_OUT_G 2>/dev/null
    # пометка не встала — не «on»: иначе сторож zapret ставил бы правила по кругу
    if ! $iptables -t mangle -C FORWARD $YT_MARK_FWD 2>/dev/null; then
        YT_DEAD_FAILS=$((YT_DEAD_FAILS + 1))
        [ "$YT_DEAD_FAILS" -ge 3 ] && [ "$YT_DEAD_STATE" != "fail" ] && \
            log "WARNING: zapret: правила повтора застрявших видеосоединений YouTube не встали 3 раза — выключено"
        yt_dead_hooks_off; YT_DEAD_STATE="fail"; return 0
    fi
    YT_DEAD_FAILS=0
    [ "$YT_DEAD_STATE" = "on" ] || \
        log "zapret: повтор застрявших видеосоединений YouTube включён (ClientHello без ответа ${YT_RETRY_AFTER}с — рву соединение, приложение откроет новое; запрос без ответа ${YT_REQ_AFTER}с — тоже$([ "$YT_CT_EST" -gt 300 ] && { [ -n "$VTPOKE_BIN" ] && [ "${YT_POKE:-0}" -gt 0 ] && printf '%s' "; простой телефона$([ "$YT_POKE_NT" = 1 ] && echo ' и раздачи') ${YT_POKE}с — пустой ACK (до ${YT_POKE_MAX}с без данных)$([ "$YT_POKE_NT" = 1 ] || echo ', раздаче — нет: ядро не дало пустить пакет мимо conntrack')"; [ "$YT_IDLE_KILL" -gt 0 ] && { [ -z "$VTPOKE_BIN" ] || [ "${YT_POKE:-0}" -le 0 ]; } && printf '%s' "; простой телефона ${YT_IDLE_KILL}с — рву заранее"; }))"
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
    $iptables -F "$CHAIN_YT_FRONT" 2>/dev/null; $iptables -X "$CHAIN_YT_FRONT" 2>/dev/null
    YT_FRONT_LIST=""; YT_FRONT_DEAD=""; YT_FRONT_N=0; YT_FRONT_KEY=""; YT_FRONT_HOLD=0; YT_FRONT_HOLD_KEY=""; YT_GDATA_SUM=""
    # и файлы прежнего отбоя (до 15.11)
    rm -f "$YT_SEEN_FILE" "$YT_SEEN_FILE.new" "$YT_SEEN_FILE.req" "$YT_SEEN_FILE.req.new" "$YT_GRANGES" \
        /data/local/tmp/vpn_tether_ytdead /data/local/tmp/vpn_tether_ytdead.tmp "$YT_SEEN_FILE.udp" "$YT_SEEN_FILE.udp.new" \
        /data/local/tmp/vpn_tether_ytrecheck.* /data/local/tmp/vpn_tether_ytsprobe.*
    YT_DEAD_STATE=""; YT_STUCK=""; YT_IDLE_LIST=""
    YT_DEAD_MODE=""; YT_RETRY_CNT=""; YT_RETRY_KILLS=0; YT_RETRY_RJ=""; YT_RETRY_RSTS=0; YT_RAMP_DEAD=""; YT_RAMP_BAD=""
}

# --- Мёртвые фронты (YT_DEAD_FAILFAST): быстрый отказ, по сети, на YT_FRONT_TTL ------------------
# Адрес Google (не видео), где у телефона дважды за YT_RETRY_WIN сервер после рукопожатия не прислал ни байта
# данных (ClientHello не подтверждён или подтверждён и тишина, 1 с или 6×RTT; и закрывающиеся), — новым
# соединениям к нему RST на SYN (CHAIN_YT_FRONT: OUTPUT и FORWARD), висящие — ss -K: приложение сразу берёт
# другой адрес из ответа DNS. 15.11 YOTA: у youtubei.googleapis.com 8 адресов, мёртв 172.217.114.4 (через
# WARP жив — блок по адресу на пути, малое окно не лечит); с отказом за 9 мин шортсов одна попытка к нему и
# 0 зависаний API против 4 соединений, висевших до 8 мин. Свой список у каждой сети и короткий срок: ТСПУ
# разные, адрес, мёртвый здесь, в другой сети или через час может быть жив. Не больше 16 на сеть; первые
# 30 с после включения — мимо (прежний отброс ловил там живые адреса)
yt_front_hit() {   # адрес now
    local p k="${NET_KEY:--}"
    case "$1" in *[!0-9.]*|'') return 0 ;; esac
    [ $(($2 - YT_DEAD_ON_TS)) -ge 30 ] || return 0
    # пауза после волны — только в сети, где была волна (отказы тоже по сетям)
    [ "$k" != "$YT_FRONT_HOLD_KEY" ] || [ "$2" -ge "$YT_FRONT_HOLD" ] || return 0
    printf '%s\n' "$YT_FRONT_LIST" | awk -v k="$k" -v d="$1" '$1 == k && $2 == d { f = 1 } END { exit !f }' && return 0
    p=$(printf '%s\n' "$YT_FRONT_DEAD" | awk -v d="$1" -v now="$2" -v w="$YT_RETRY_WIN" '$1 == d && now - $2 <= w { print $2; exit }')
    YT_FRONT_DEAD=$(printf '%s\n' "$YT_FRONT_DEAD" | awk -v d="$1" -v now="$2" -v w="$YT_RETRY_WIN" 'NF == 2 && $1 != d && now - $2 <= w')
    if [ -z "$p" ]; then
        YT_FRONT_DEAD="$YT_FRONT_DEAD
$1 $2"
        return 0
    fi
    # Волна: молчит не адрес, а весь Google (16.11 YOTA, 09:00 и 13:40 — за 5 мин в отказ ушли все 8 адресов API
    # и фронты youtube.com; автопроверка потом видела «HTTPS молчит, HTTP отвечает» — это и наш RST). Отказ
    # тогда только мешает: после волны приложение ещё до 15 мин не пускали бы к ожившим адресам. Третий адрес
    # сети за 2 мин — снимаем её отказы и 10 мин новых не ставим
    p=$(printf '%s\n' "$YT_FRONT_LIST" | awk -v k="$k" -v t="$YT_FRONT_TTL" -v now="$2" '$1 == k && $3 - t > now - 120' | wc -l)
    if [ "$p" -ge 2 ]; then
        YT_FRONT_HOLD=$(($2 + 600)); YT_FRONT_HOLD_KEY="$k"; YT_FRONT_DEAD=""
        YT_FRONT_LIST=$(printf '%s\n' "$YT_FRONT_LIST" | awk -v k="$k" 'NF == 3 && $1 != k')
        log "YouTube: молчат сразу несколько адресов Google ($((p + 1)) за 2 мин, последний $1) — похоже на волну ТСПУ, а не на мёртвый адрес: отказы сети сняты, 10 мин новых не ставлю"
        YT_FRONT_KEY=""; yt_front_sync "$2"
        return 0
    fi
    [ "$(printf '%s\n' "$YT_FRONT_LIST" | awk -v k="$k" '$1 == k' | wc -l)" -lt 16 ] || return 0
    YT_FRONT_LIST="$YT_FRONT_LIST
$k $1 $(($2 + YT_FRONT_TTL))"
    ss -K -tn dst "$1" dport = :443 >/dev/null 2>&1
    log "YouTube: $1 — сервер Google дважды молчит после рукопожатия — отказ новым соединениям к нему на $((YT_FRONT_TTL / 60)) мин (приложение возьмёт другой адрес)"
    YT_FRONT_KEY=""   # собрать цепочку заново
    yt_front_sync "$2"
}
# цепочка CHAIN_YT_FRONT — по списку текущей сети без истёкших; другая сеть — её адреса. Не ip: local
# в этих шеллах видна и в вызываемых функциях — update_status (phone_status_refresh) взял бы $ip за /system/bin/ip.
# REJECT tcp-reset — только с -p tcp, иначе «Invalid argument» (и 2>/dev/null его прятал)
yt_front_sync() {   # now
    local k="${NET_KEY:--}" fa
    YT_FRONT_TS=$1
    # та же сеть и ничего не истекло — цепочка уже верна
    [ "$k" = "$YT_FRONT_KEY" ] && ! printf '%s\n' "$YT_FRONT_LIST" | awk -v now="$1" 'NF == 3 && $3 <= now { f = 1 } END { exit !f }' && return 0
    printf '%s\n' "$YT_FRONT_LIST" | awk -v now="$1" -v k="$k" 'NF == 3 && $3 <= now && $1 == k { print $2 }' | \
        while read -r fa; do log "YouTube: $fa — срок отказа истёк, снова пускаю (если по-прежнему молчит — вернётся)"; done
    YT_FRONT_LIST=$(printf '%s\n' "$YT_FRONT_LIST" | awk -v now="$1" 'NF == 3 && $3 > now')
    YT_FRONT_KEY="$k"
    $iptables -F "$CHAIN_YT_FRONT" 2>/dev/null
    # мёртв он на прямом пути (замер — по соединениям через WAN): через VPN и WARP — не трогаем
    $iptables -A "$CHAIN_YT_FRONT" -o tun+ -j RETURN 2>/dev/null
    $iptables -A "$CHAIN_YT_FRONT" -o warp+ -j RETURN 2>/dev/null
    # проверки модуля (connmark 0x08000000 ставится в mangle OUTPUT — до этой цепочки) видят сеть как есть, без нашего RST
    $iptables -A "$CHAIN_YT_FRONT" -m connmark --mark 0x08000000/0x08000000 -j RETURN 2>/dev/null
    YT_FRONT_N=0
    for fa in $(printf '%s\n' "$YT_FRONT_LIST" | awk -v k="$k" '$1 == k { print $2 }'); do
        $iptables -A "$CHAIN_YT_FRONT" -d "$fa" -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null && YT_FRONT_N=$((YT_FRONT_N + 1))
    done
    phone_status_refresh
}

# --- YT_WSSIZE_RAMP: малое окно для молчащих стоек (см. service.sh) -------------------
yt_ramp_on() { [ "$YT_WSSIZE_RAMP" = 1 ] && [ "$YT_DEAD_FAILFAST" = 1 ] && [ "$ZAPRET_ENGINE_RUN" = nfqws2 ]; }
# цепочка CHAIN_YT_RAMP по списку текущей сети: все исходящие пакеты к стойкам — в nfqws2 (без
# connbytes: vt_wssize_ramp правит окно в каждом пакете соединения); 0.0.0.0/32 — заглушка файла
yt_ramp_chain() {
    local n
    $iptables -t mangle -N "$CHAIN_YT_RAMP" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_YT_RAMP" 2>/dev/null
    yt_ramp_on || return 0
    for n in $(grep -v '^0\.0\.0\.0/32$' "$YT_RAMP_RUN" 2>/dev/null); do
        case "$n" in *[!0-9./]*|'') continue ;; esac
        $iptables -t mangle -A "$CHAIN_YT_RAMP" -d "$n" -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null
    done
}
# список текущей сети (YT_RAMP_RUN) из YT_RAMP_FILE — записи моложе YT_RAMP_HOURS; из файла удаляю старше
# недели (или срока, если он длиннее): укоротили срок на пробу и вернули — стойки не узнавать заново; поменялся — цепочка
# заново, а файл nfqws2 перечитывает сам
yt_ramp_sync() {   # now
    local k="${NET_KEY:--}"
    YT_RAMP_KEY="$k"; YT_RAMP_TS=$1
    local ttl=$((${YT_RAMP_HOURS:-48} * 3600)) keep=604800
    [ "$ttl" -gt "$keep" ] && keep=$ttl
    if [ -f "$YT_RAMP_FILE" ]; then
        awk -F'|' -v now="$1" -v ttl="$keep" 'NF == 3 && now - $3 < ttl' "$YT_RAMP_FILE" > "$YT_RAMP_FILE.new" 2>/dev/null
        if cmp -s "$YT_RAMP_FILE.new" "$YT_RAMP_FILE"; then rm -f "$YT_RAMP_FILE.new"; else chmod 600 "$YT_RAMP_FILE.new"; mv -f "$YT_RAMP_FILE.new" "$YT_RAMP_FILE"; fi
    fi
    { echo 0.0.0.0/32; K="$k" awk -F'|' -v now="$1" -v ttl="$ttl" '$1 == ENVIRON["K"] && now - $3 < ttl { print $2 }' "$YT_RAMP_FILE" 2>/dev/null | sort -u; } > "$YT_RAMP_RUN.new"
    YT_RAMP_N=$(( $(wc -l < "$YT_RAMP_RUN.new") - 1 ))
    if cmp -s "$YT_RAMP_RUN.new" "$YT_RAMP_RUN"; then rm -f "$YT_RAMP_RUN.new"; return 0; fi
    mv -f "$YT_RAMP_RUN.new" "$YT_RAMP_RUN"
    yt_ramp_chain
    # «не помогает» (yt_ramp_hit) — только для стоек, что ещё в списке
    local n b=""
    for n in $YT_RAMP_BAD; do grep -qx "$n" "$YT_RAMP_RUN" && b="$b $n"; done
    YT_RAMP_BAD="$b"
    # число стоек в статусе (WebUI): сам он пишется только по событиям
    phone_status_refresh
}
# nfqws2 запущен заново: настоящий масштаб окна каждого соединения к стойкам (vt_wssize_ramp) остался в
# прежнем — без него сервер видит окно в ~128 раз меньше, и видео ползёт. Соединения телефона рвём (ss -K),
# раздаче — RST на следующий пакет клиента; приложение откроет новые
yt_ramp_kill() {
    local n c=0 t=0 l src sp dip now wip="$LAST_WAN_IP"
    # список стоек — текущей сети: при смене сети nfqws2 перезапускается раньше, чем yt_dead_scan его обновит,
    # и рвались бы соединения к стойкам прежней сети (ревью 15.11)
    [ "$YT_RAMP_KEY" = "${NET_KEY:--}" ] || yt_ramp_sync "$(date +%s)"
    for n in $(grep -v '^0\.0\.0\.0/32$' "$YT_RAMP_RUN" 2>/dev/null); do
        case "$n" in *[!0-9./]*|'') continue ;; esac
        c=$((c + $(ss -K -tn state established dst "$n" dport = :443 2>/dev/null | awk 'NR > 1' | wc -l)))
    done
    # Раздача: её соединения ss не видит (транзит) — из conntrack (клиент раздачи наружу через WAN: ответ идёт
    # на адрес телефона) к стойкам списка; каждому — RST на следующий пакет клиента (CHAIN_YT_RST, 5 мин,
    # снимает yt_retry_hits — как у застрявших). Клиент сразу откроет новое, и его SYN пройдёт малое окно.
    # Цепочку создаём здесь же: при запуске демона nfqws2 стартует раньше yt_dead_on, а соединения в
    # conntrack — от прежнего
    # адрес WAN — как в yt_dead_scan: при запуске демона LAST_WAN_IP бывает ещё пуст, а в сети с CLAT IPv4 у v4-<WAN>
    [ -n "$wip" ] || wip=$($ip -4 addr show "$LAST_WAN_IFACE" 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')
    [ -n "$wip" ] || wip=$($ip -4 addr show "v4-$LAST_WAN_IFACE" 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')
    if [ -n "$wip" ] && [ -n "$CONNTRACK_BIN" ]; then
        now=$(date +%s)
        $iptables -N "$CHAIN_YT_RST" 2>/dev/null
        for l in $($CONNTRACK_BIN -L -p tcp --dport 443 2>/dev/null | awk -v wip="$wip" -v rf="$YT_RAMP_RUN" '
            FILENAME == rf {
                if ($1 ~ /^[0-9.]+\/[0-9]+$/ && $1 != "0.0.0.0/32") {
                    split($1, a, "/"); split(a[1], o, "."); b = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]
                    nb[++nn] = b; ne[nn] = b + 2 ^ (32 - a[2]) - 1
                }
                next
            }
            / ESTABLISHED / {
                src = ""; dst = ""; rdst = ""; sp = ""
                for (i = 1; i <= NF; i++) {
                    split($i, kv, "=")
                    if (kv[1] == "src" && src == "") src = kv[2]
                    else if (kv[1] == "dst") { if (dst == "") dst = kv[2]; else if (rdst == "") rdst = kv[2] }
                    else if (kv[1] == "sport" && sp == "") sp = kv[2]
                }
                if (src == wip || rdst != wip) next
                split(dst, o, "."); x = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]
                for (j = 1; j <= nn; j++) if (x >= nb[j] && x <= ne[j]) { print src "_" sp "_" dst; break }
            }' "$YT_RAMP_RUN" -); do
            src=${l%%_*}; l=${l#*_}; sp=${l%%_*}; dip=${l#*_}
            case "$src" in *[!0-9.]*|'') continue ;; esac
            case "$sp" in *[!0-9]*|'') continue ;; esac
            case "$dip" in *[!0-9.]*|'') continue ;; esac
            # 5 мин, а не 20 с, как у застрявших: соединение в пуле простаивает минутами, и без пакета клиента
            # правило снялось бы, не сработав (порт клиента в правиле — чужое не заденет)
            $iptables -I "$CHAIN_YT_RST" -s "$src" -d "$dip" -p tcp --sport "$sp" --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null && {
                YT_RETRY_RJ="$YT_RETRY_RJ
$((now + 300)) $src $sp $dip"
                t=$((t + 1))
            }
        done
    fi
    [ $((c + t)) -gt 0 ] && log "YouTube: nfqws2 перезапущен — порвано соединений к стойкам малого окна: телефона $c, раздачи $t (RST на следующий пакет клиента; их окно он больше не пересчитывает)"
    return 0
}
# Сервер напрямую принял ClientHello и молчит («dead», yt_retry_hits; только соединения с пометкой
# googlevideo.com — без неё у раздачи в счёт шли бы любые сети Google, вплоть до DoH 8.8.8.8). Второй раз
# за YT_RETRY_WIN у того же адреса — его стойку (/28: YOTA режет стойками, 29–30.10) в список сети на YT_RAMP_HOURS (2 суток),
# не больше 128 на сеть (32 на YOTA набиралось за час — вытеснялись ещё закрытые). Стойка уже в списке
# (дольше YT_RETRY_WIN) и снова дважды молчит — малое окно ей не помогает: запись не продлеваем, в журнал
yt_ramp_hit() {   # адрес now
    local p net e k="${NET_KEY:--}"
    yt_ramp_on || return 0
    # Только сети Google. Кэш оператора (YOTA 188.170.166.x, Дом.ру 80.64.175.x) на возобновлённой TLS-сессии
    # отвечает ~400 Б — для «запроса без ответа» это «ни байта данных», и он попадал сюда. Стенд 17.11 (кэш YOTA,
    # 4 адреса): без малого окна первый запрос за 0,12–0,15 с (16 из 16), с ним 0,38–0,48 с, а после простоя
    # умирало больше (15 с: 5 из 24 запросов против 0, 60 с: 6 против 3)
    awk -v ip="$1" 'BEGIN { split(ip, o, "."); x = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4] }
        x >= $1 && x <= $2 { f = 1; exit } END { exit !f }' "$YT_GRANGES" 2>/dev/null || return 0
    p=$(printf '%s\n' "$YT_RAMP_DEAD" | awk -v d="$1" -v now="$2" -v w="$YT_RETRY_WIN" '$1 == d && now - $2 <= w { print $2; exit }')
    YT_RAMP_DEAD=$(printf '%s\n' "$YT_RAMP_DEAD" | awk -v d="$1" -v now="$2" -v w="$YT_RETRY_WIN" 'NF == 2 && $1 != d && now - $2 <= w')
    if [ -z "$p" ]; then
        YT_RAMP_DEAD="$YT_RAMP_DEAD
$1 $2"
        return 0
    fi
    net=$(echo "$1" | awk -F. '{ printf "%d.%d.%d.%d/28", $1, $2, $3, $4 - $4 % 16 }')
    if grep -qx "$net" "$YT_RAMP_RUN" 2>/dev/null; then
        e=$(K="$k" N="$net" awk -F'|' '$1 == ENVIRON["K"] && $2 == ENVIRON["N"] { print $3 }' "$YT_RAMP_FILE" 2>/dev/null)
        # только что в списке: молчали соединения, открытые до него
        [ $(($2 - ${e:-0})) -le "$YT_RETRY_WIN" ] && return 0
        case " $YT_RAMP_BAD " in *" $net "*) ;; *)
            YT_RAMP_BAD="$YT_RAMP_BAD $net"
            log "YouTube: $1 — стойка $net молчит и с малым окном — запись не продлеваю (снимется через ${YT_RAMP_HOURS:-48} ч после добавления)" ;;
        esac
        return 0
    fi
    { K="$k" N="$net" awk -F'|' '!($1 == ENVIRON["K"] && $2 == ENVIRON["N"])' "$YT_RAMP_FILE" 2>/dev/null; echo "$k|$net|$2"; } | \
        K="$k" awk -F'|' '$1 != ENVIRON["K"] { print; next } { l[++n] = $0 } END { for (i = (n > 128 ? n - 127 : 1); i <= n; i++) print l[i] }' > "$YT_RAMP_FILE.new" && \
        chmod 600 "$YT_RAMP_FILE.new" && mv -f "$YT_RAMP_FILE.new" "$YT_RAMP_FILE"
    log "YouTube: $1 — сервер дважды принял ClientHello и молчит: стойке $net малое окно на ${YT_RAMP_HOURS:-48} ч (wssize_ramp)"
    yt_ramp_sync "$2"
}

# Застрявшее видеосоединение YouTube (см. YT_RETRY_MAX в service.sh) — рвём только его, приложение
# откроет новое. Раздача — транзитом, ss её сокет не видит: RST на повтор ClientHello клиента.
# YT_RETRY_MAX провалов адреса за YT_RETRY_WIN с, пока видео нигде не идёт, — сигнал сторожу: застряло
# всё подряд — это сломанная стратегия, а не сервер
#   yt_retry_hits ВЫВОД_AWK NOW АДРЕС_ТЕЛЕФОНА
yt_retry_hits() {
    local hit dip src sp c l kd via gv
    # правила RST раздачи — на 20 с: клиент повторяет ClientHello через 1–4 с, дольше не нужно
    if [ -n "$YT_RETRY_RJ" ]; then
        for l in $(printf '%s\n' "$YT_RETRY_RJ" | awk -v now="$2" 'NF == 4 && $1 <= now { print $2 "_" $3 "_" $4 }'); do
            src=${l%%_*}; l=${l#*_}; sp=${l%%_*}; dip=${l#*_}
            $iptables -D "$CHAIN_YT_RST" -s "$src" -d "$dip" -p tcp --sport "$sp" --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null
        done
        YT_RETRY_RJ=$(printf '%s\n' "$YT_RETRY_RJ" | awk -v now="$2" 'NF == 4 && $1 > now')
    fi
    for hit in $(printf '%s\n' "$1" | awk '$1 == "HIT" { print $3 "_" $4 "_" $5 "_" $2 "_" $6 "_" $7 }'); do
        dip=${hit%%_*}; l=${hit#*_}; src=${l%%_*}; l=${l#*_}; sp=${l%%_*}; l=${l#*_}; kd=${l%%_*}; l=${l#*_}; via=${l%%_*}; gv=${l#*_}
        case "$dip" in *[!0-9.]*|'') continue ;; esac
        case "$sp" in *[!0-9]*|'') continue ;; esac
        case "$src" in *[!0-9.]*|'') continue ;; esac
        # принял и молчит напрямую, видеосервер (пометка) — кандидат в малое окно (YT_WSSIZE_RAMP)
        [ "$kd" = dead ] && [ "$via" = direct ] && { [ "$gv" = gv ] || [ "$gv" = gp ]; } && yt_ramp_hit "$dip" "$2"
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
        # загрузки Play (gp) — не в счёт: молчащая стойка Play при неидущем YouTube о стратегии не говорит
        [ "$gv" = gp ] || [ $(($2 - YT_DATA_TS)) -le 60 ] || YT_RETRY_ESC=$((YT_RETRY_ESC + 1))
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
    local now out k sa da ds rqh rqd rqa rqp rqb rqv rqw rqs rqc rqe rqn rqk rqt n t keep=""
    # не ip: локальная ip затирала бы $ip (/system/bin/ip) — адрес WAN ниже не узнавался
    now=$(date +%s)
    # малое окно: другая сеть — её список стоек; раз в 5 мин — старые записи вон
    if [ "$YT_RAMP_KEY" != "${NET_KEY:--}" ] || [ $((now - YT_RAMP_TS)) -ge 300 ]; then
        yt_ramp_on && yt_ramp_sync "$now"
    fi
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
    # стойки малого окна текущей сети (для «запроса без ответа» без данных); нет — пустой файл
    local rrf=/dev/null pk=0
    yt_ramp_on && [ -f "$YT_RAMP_RUN" ] && rrf="$YT_RAMP_RUN"
    # пустой ACK телефону — только если есть vtpoke и он не отказал (иначе обрыв простоя, как раньше)
    # (после сбоя — снова в другой сети или через 5 мин: при смене сети интерфейс бывает на миг не тот)
    [ -n "$VTPOKE_BIN" ] && { [ "${YT_POKE_FAIL:-0}" -eq 0 ] || [ "${NET_KEY:--}" != "$YT_POKE_FAIL_NET" ] || [ $((now - YT_POKE_FAIL)) -ge 300 ]; } && pk="${YT_POKE:-0}"
    out=$($CONNTRACK_BIN -L -p tcp --dport 443 2>/dev/null | awk -v now="$now" -v after="$da" -v sa="$sa" -v hs="$YT_HS_MAX" -v sf="$YT_SEEN_FILE" -v rf="$YT_SEEN_FILE.req" -v rq="$rqe" -v gr="$YT_GRANGES" -v wip="$wip" -v zp="$ZAPRET_PHONE" -v ik="$YT_IDLE_KILL" -v cte="$YT_CT_EST" -v rr="$rrf" -v pk="$pk" -v pm="$YT_POKE_MAX" -v pt="$YT_POKE_NT" -v ps="${YT_PLAY_STALL:-0}" '
        FILENAME == gr { gs[++ng] = $1; ge[ng] = $2; next }
        FILENAME == sf { seen[$1] = $2; rep[$1] = $4; next }
        FILENAME == rf { rbr[$1] = $2; rob0[$1] = $3; rop0[$1] = $4; rtq0[$1] = $5; rlg0[$1] = $6; ldt0[$1] = $7; lpr0[$1] = $8; lpk0[$1] = $9; next }
        FILENAME == rr { if (split($1, a, "[./]") == 5) { s = ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4]; rps[++nrp] = s; rpe[nrp] = s + 2 ^ (32 - a[5]) - 1 }; next }
        / (ESTABLISHED|FIN_WAIT|CLOSE_WAIT|LAST_ACK|TIME_WAIT|CLOSE) / {
            est = ($0 ~ / ESTABLISHED /)
            src = ""; dst = ""; rsrc = ""; rdst = ""; sp = ""; nd0 = 0; rdp = ""; po = -1; bo = -1; pr = -1; br = -1; mk = 0
            for (i = 1; i <= NF; i++) {
                split($i, kv, "=")
                if (kv[1] == "src") { if (src == "") src = kv[2]; else if (rsrc == "") rsrc = kv[2] }
                else if (kv[1] == "dst") { if (dst == "") dst = kv[2]; else if (rdst == "") rdst = kv[2] }
                else if (kv[1] == "sport" && sp == "") sp = kv[2]
                # второй dport — порт ответа, то есть порт после NAT (раздача): для пустого ACK
                else if (kv[1] == "dport") { if (nd0++ == 1) rdp = kv[2] }
                else if (kv[1] == "packets") { if (po < 0) po = kv[2]; else if (pr < 0) pr = kv[2] }
                else if (kv[1] == "bytes") { if (bo < 0) bo = kv[2]; else if (br < 0) br = kv[2] }
                else if (kv[1] == "mark") mk = kv[2]
            }
            # приложение -> AdGuard (REDIRECT): отвечает сам AdGuard, о сервере это ничего не говорит
            if (rsrc != dst) next
            # googlevideo.com (метка); без метки — только если сервер в сетях Google
            yt = (int(mk / 268435456) % 2 == 1)
            # закрывающиеся — только в мёртвые фронты (ниже): приложение (AdGuard) бросало попытки к мёртвому
            # фронту через ~4 с, и второе зависание до счёта не доживало (стенд 15.11, 22:01)
            if (!est && (yt || src != wip)) next
            if (!yt) {
                # без метки — только наружу через WAN (ответ идёт на адрес телефона). Через VPN метки
                # нет никогда: и раздача (ответ на адрес tun), и сам телефон (src — адрес tun) попадали
                # сюда — ss -K по общим адресам Google (ревью 25.10). Телефон без метки — не видео
                # (фронты, API; у YouTube через AdGuard это соединения AdGuard) — только в мёртвые фронты
                if (wip == "" || rdst != wip) next
                # DoH Google (dnsproxy) — не фронт: у него свои запасные серверы
                if (dst ~ /^8\.8\.[48]\./) next
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
            # Простаивающее в пуле соединение (последним говорил сервер) сюда не попадает. Состояние (.req) —
            # у всех видеосоединений: по нему и пустой ACK (YT_POKE), даже если «запрос без ответа» выключен (rq 0)
            if (yt) {
                rnb = (k in rbr && rbr[k] == br)
                rob = rnb ? rob0[k] : bo; rop = rnb ? rop0[k] : po
                pay = (bo - rob) - 64 * (po - rop)
                rtq = (rnb && rtq0[k] > 0) ? rtq0[k] : ((pay > 80) ? now : 0)
                # Загрузка Play (gp): кусок запрашивается сразу за рукопожатием, и первый проход видит соединение уже
                # с запросом — он уходит в «базу», и отсчёт не начинался. 19.11 YOTA: из 4–5 параллельных кусков один
                # (рукопожатие 4,5 КБ, запрос ~930 Б) молчал 18–35 с, Play висел на 98–99% до «Отмены». От сервера
                # только рукопожатие (меньше 8 КБ; удачные мелкие куски — 9–12 КБ) — отсчёт с первого появления
                if (rtq == 0 && est && int(mk / 33554432) % 2 == 1 && br < 8192) rtq = now
                rlg = rnb ? rlg0[k] : 0
                # br > 100: от сервера были данные, не только SYN-ACK (тот случай — «застрял»)
                # раздаче на 1 с раньше: ей RST — только на повтор запроса, а повторы всё реже
                # (~0,4 / 1,2 / 2,8 / 6 / 12 с); с порогом 3 правило вставало после повтора на 2,8 с,
                # и RST доставался следующему — шортс на втором телефоне висел ~15 с (15.11)
                rql = (src == wip) ? rq : rq - 1; if (rql < 1) rql = 1
                # От сервера ни байта данных — только SYN-ACK и пустые подтверждения (16.11: «от сервера 112–228 Б»
                # у 7 из 25): ClientHello принят, ответа нет — стойку режут по адресу, живой сервер отвечает за RTT.
                # На 1 с раньше — кроме стоек малого окна: там ответ приходит каплями по 1–2 байта (~0,9 с,
                # persist-таймер сервера) и в conntrack выглядит так же
                nd = (br <= 60 * pr)
                if (nd && rql > 1) {
                    split(dst, o, "."); n = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]; inr = 0
                    for (j = 1; j <= nrp; j++) if (n >= rps[j] && n <= rpe[j]) { inr = 1; break }
                    if (!inr) rql--
                }
                if (rq > 0 && !rlg && rtq > 0 && now - rtq >= rql && br > 100) {
                    print "REQ", dst, now - rtq, pay, br, (int(mk / 536870912) % 2 == 1) ? "warp" : "direct", (src == wip) ? "phone" : "tether", sp, src, nd, (int(mk / 33554432) % 2 == 1) ? "play" : "yt"
                    rlg = 1
                }
                # когда от сервера в последний раз пришли данные (не только пустые пакеты — их шлёт и он в ответ
                # на наш пустой ACK, YT_POKE): для простоя «без данных» ниже
                ldt = (k in ldt0 && ldt0[k] > 0) ? ldt0[k] : now
                if ((k in rbr) && br - rbr[k] > 60 * (pr - lpr0[k])) ldt = now
                lpk = (k in lpk0) ? lpk0[k] + 0 : 0
                # Загрузка Play (gp) замолчала посреди куска (YT_PLAY_STALL): от сервера больше 8 КБ, потом ps с ни байта
                # данных. Только телефону напрямую (ss -K): раздаче RST нужен повтор клиента, а тот молча ждёт
                if (ps > 0 && est && !rlg && int(mk / 33554432) % 2 == 1 && br >= 8192 && src == wip && int(mk / 536870912) % 2 == 0 && now - ldt >= ps) {
                    print "PSTALL", dst, now - ldt, br, sp
                    rlg = 1
                }
                nr[k] = br " " rob " " rop " " rtq " " rlg " " ldt " " pr " " lpk
            }
            # видео идёт: сумма байт от видеосерверов (больше рукопожатия) — сигнал сторожу только
            # без живого видео; шелл сравнит с прошлым кругом: важен прирост, а не накопленное
            # за жизнь соединения (старое простаивающее держало бы «видео идёт» вечно)
            if (yt && br > hs && br > 80 * pr) {
                dsum += br
                # и отдельно — с серверов Google напрямую (не кэш оператора 188.170.x: он в волну играет
                # сам; не через WARP или VPN: волна — на прямом пути, а через туннель видео идёт и в неё)
                if (wip != "" && rdst == wip && int(mk / 536870912) % 2 == 0) {
                    split(dst, o, "."); n = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]
                    for (j = 1; j <= ng; j++) if (n >= gs[j] && n <= ge[j]) { gsum += br; break }
                }
            }
            # Простаивает (YT_IDLE_KILL): прямое (ответ на адрес WAN, не WARP) к серверу Google, сервер уже слал
            # данные, ik с ни пакета. $3 — остаток таймера conntrack; у соединения с неподтверждёнными данными
            # таймер 300 с (это «запрос без ответа» выше) — такие мимо
            # Телефону вместо обрыва — пустой ACK (YT_POKE, pk с тишины; pm — сколько держать без данных от сервера).
            # Не чаще раза в pk с на соединение: если сервер не ответил, таймер conntrack не сброшен, и без этого пакет
            # уходил бы на каждом проходе (~1,3 с). Не только сетям Google — и кэшу оператора (метка googlevideo.com):
            # 17.11 на кэше YOTA после 60 с простоя без пакета умерло 3 запроса из 24, с пакетом (15 с) — 0
            # Раздаче (pt — правило notrack стоит) — тот же пакет с адресом WAN и портом после NAT (rdp): стенд 17.11
            # (t41, клиент в netns за NAT): после 15 с простоя умерло 0 из 36 против 15 из 36, после 60 с — 0 против 20
            if (yt && est && pk > 0 && (src == wip || (pt == 1 && rdp ~ /^[0-9]+$/)) && cte > 300 && $3 > 300 && cte - $3 >= pk && br > 80 * pr && wip != "" && rdst == wip && int(mk / 536870912) % 2 == 0 && (k in nr) && now - ldt < pm && now - lpk >= pk) {
                print "POKE", dst, (src == wip) ? sp : rdp, wip
                nr[k] = br " " rob " " rop " " rtq " " rlg " " ldt " " pr " " now
            }
            # Только сетям Google, не кэшу оператора (в отличие от пустого ACK — тот ничего не рвёт): кэш YOTA 15 с
            # простоя переживает (стенд 17.11: 0 из 24 умерло). И только телефону, когда vtpoke не отправляет (pk 0):
            # раздаче с 17.11 не рвём — смерть потока после простоя видели только на YOTA, а в других сетях это
            # просто лишние разрывы; с 15:34 17.11 RST раздаче не доходили вовсе (yt_rst_hook_top), и видео шло хорошо
            if (yt && est && ik > 0 && src == wip && pk == 0 && cte > 300 && $3 > 300 && cte - $3 >= ik && br > 80 * pr && wip != "" && rdst == wip && int(mk / 536870912) % 2 == 0) {
                split(dst, o, "."); n = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]
                for (j = 1; j <= ng; j++) if (n >= gs[j] && n <= ge[j]) { print "IDLE", dst, cte - $3, sp, src; break }
            }
            # от сервера — только пустые пакеты: ни одного байта данных. Пустой
            # пакет — до 80 байт (IP 20 + TCP до 60: метки времени, SACK; SACK
            # бывает из-за нарезки обходом). Порог по общему объёму (а не на пакет) путал
            # с мёртвыми простаивающие соединения с коротким ответом (возобновлённая TLS-сессия)
            # и не выгрузка: при ней сервер тоже шлёт одни ACK (Drive, Фото, загрузка
            # в YouTube — облачное ревью PR #22). У мёртвого — ClientHello с повторами
            # (до ~27 КБ) и пара десятков пакетов от сервера, у выгрузки за 3 с — больше
            if (bo < 600 || pr < 1 || br > 80 * pr || pr > 32 || bo > 65536) next
            kind = (pr <= 1) ? "stuck" : "dead"
            # Телефон, без метки: ClientHello к сети Google ушёл, а от сервера после рукопожатия ни байта
            # (застрял — sa, принял и молчит — after) — кандидат в мёртвые фронты (yt_front_hit). 15.11:
            # фронт API 172.217.114.4 так держал соединения AdGuard до 8 мин, а 7 соседних адресов из
            # ответа DNS были живы
            if (!yt && src == wip) {
                # пометку видео телефону ставит правило только при ZAPRET_PHONE=1 — иначе «без пометки» и видео
                if (zp != "1" || int(mk / 536870912) % 2 == 1) next
                # проверки самого модуля (бит 0x08000000: подбор, «Проверить сайт», замер YouTube, регистрация WARP)
                # нарочно пробуют и неработающие приёмы — их молчание не признак. 20.11 подбор из 70 стратегий
                # отправил так в отказ 3 фронта youtube.com/i.ytimg.com, и дальше все стратегии упирались в наш RST
                if (int(mk / 134217728) % 2 == 1) next
                # от сервера ни байта данных: не больше 4 пакетов, все пустые (ответ на SYN, подтверждения;
                # у пустого до 60 байт). У выгрузки, долгого запроса, возобновлённой сессии сервер успел
                # прислать хоть что-то (ServerHello) — их не берём (ревью 15.11: бэкап Фото на слабой сети
                # иначе мог попасть под отказ). При таком признаке живой фронт отвечает за RTT — порог sa
                if (pr > 4 || br > 60 * pr) next
                if (now - t0 >= sa && d == 0) { print "FRONT", dst, sp; d = 1 }
                ns[k] = t0 " " kind " " d
                next
            }
            # застрявшие — только точно googlevideo.com
            if (kind == "stuck" && !yt) next
            # и не в WARP (connmark WARP_MARK 0x20000000): там застревает туннель, а не стойка
            if (kind == "stuck" && int(mk / 536870912) % 2 == 1) next
            # Раздача (src не телефон) — +2 с: Wi-Fi до клиента в RTT телефона (ss) не виден,
            # а отсчёт идёт от появления соединения, ClientHello клиента сам может опоздать
            lim = (kind == "stuck") ? sa : after
            if (src != wip) lim += 2
            # gp — загрузка Play (gvt1, бит YT_PLAY_CTMARK 0x02000000): малое окно — как видео, сигнала сторожу — нет
            if (now - t0 >= lim && d == 0) { print "HIT", kind, dst, src, sp, (int(mk / 536870912) % 2 == 1) ? "warp" : "direct", yt ? ((int(mk / 33554432) % 2 == 1) ? "gp" : "gv") : "net"; d = 1 }
            ns[k] = t0 " " kind " " d
        }
        END { for (k in ns) print k, ns[k] > (sf ".new"); for (k in nr) print k, nr[k] > (rf ".new"); printf "DATA %.0f\n", dsum; printf "GDATA %.0f\n", gsum }
    ' "$YT_GRANGES" "$YT_SEEN_FILE" "$YT_SEEN_FILE.req" "$rrf" - 2>/dev/null)
    if [ -f "$YT_SEEN_FILE.new" ]; then mv -f "$YT_SEEN_FILE.new" "$YT_SEEN_FILE"; else : > "$YT_SEEN_FILE"; fi
    if [ -f "$YT_SEEN_FILE.req.new" ]; then mv -f "$YT_SEEN_FILE.req.new" "$YT_SEEN_FILE.req"; else : > "$YT_SEEN_FILE.req"; fi
    # Связь молчит целиком (метро, слабый сигнал или Wi-Fi): «запрос без ответа», «ClientHello без ответа», простой и
    # мёртвые фронты тогда говорят о канале, а не о сервере. Рвать всё подряд хуже — 17.11 в метро плеер терял все
    # соединения разом и следующее видео не играл, — а стойки и фронты зря попадали бы в списки. Один пинг на проход
    # и только если есть что рвать: 77.88.8.8 (DNS Яндекса — открыт и при белом списке оператора), до 1 с.
    # Нет ответа — пропускаем: связь вернётся, соединения оживут или зависнут снова и будут порваны тогда.
    # И только если за проход на интерфейс почти ничего не пришло (меньше 2 КБ): в сети, где ICMP закрыт (бывает
    # в офисном и гостевом Wi-Fi), пинг не проходит никогда — без этого зависания там не рвались бы вовсе
    rqa=$(cat "/sys/class/net/$LAST_WAN_IFACE/statistics/rx_bytes" 2>/dev/null); rqa=${rqa:-0}
    rqp=$((rqa - ${YT_WAN_RX:-0})); YT_WAN_RX=$rqa
    if [ "$rqp" -lt 2048 ] && printf '%s\n' "$out" | grep -q -e '^REQ ' -e '^HIT ' -e '^FRONT ' -e '^IDLE ' -e '^PSTALL ' && command -v ping >/dev/null 2>&1; then
        rqh="$LAST_WAN_IFACE"
        $ip -4 addr show "$rqh" 2>/dev/null | grep -q "inet $wip/" || rqh="v4-$LAST_WAN_IFACE"
        if $TIMEOUT_CMD ping -c 1 -W 1 -I "$rqh" 77.88.8.8 >/dev/null 2>&1; then
            [ "$YT_LINK_DEAD" = 1 ] && log "YouTube: связь снова отвечает — зависшие соединения снова рву"
            YT_LINK_DEAD=0
        else
            [ "$YT_LINK_DEAD" = 1 ] || log "YouTube: связь молчит целиком (нет ответа и от 77.88.8.8 через $rqh) — зависшие соединения не рву, жду"
            YT_LINK_DEAD=1
            # пометку «уже обработано» (rlg в .req, d в seen) awk уже записал — снимаем у отложенных, иначе соединение,
            # что так и висит после возврата связи, не порвалось бы никогда (ревью 17.11)
            rqk=$(printf '%s\n' "$out" | awk -v w="$wip" '$1 == "REQ" { printf " %s:%s>%s", $9, $8, $2 }
                $1 == "HIT" { printf " %s:%s>%s", $4, $5, $3 } $1 == "FRONT" { printf " %s:%s>%s", w, $3, $2 }
                $1 == "PSTALL" { printf " %s:%s>%s", w, $5, $2 }')
            if [ -n "$rqk" ]; then
                awk -v ks="$rqk " 'index(ks, " " $1 " ") { $4 = 0 } { print }' "$YT_SEEN_FILE" > "$YT_SEEN_FILE.new" 2>/dev/null && mv -f "$YT_SEEN_FILE.new" "$YT_SEEN_FILE"
                awk -v ks="$rqk " 'index(ks, " " $1 " ") { $6 = 0 } { print }' "$YT_SEEN_FILE.req" > "$YT_SEEN_FILE.req.new" 2>/dev/null && mv -f "$YT_SEEN_FILE.req.new" "$YT_SEEN_FILE.req"
            fi
            out=$(printf '%s\n' "$out" | grep -v -e '^REQ ' -e '^HIT ' -e '^FRONT ' -e '^IDLE ' -e '^PSTALL ')
        fi
    fi
    # трафик идёт (больше 2 КБ за проход) — связь жива, даже если пинг до этого не проходил
    [ "$rqp" -ge 2048 ] && [ "$YT_LINK_DEAD" = 1 ] && { log "YouTube: связь снова отвечает — зависшие соединения снова рву"; YT_LINK_DEAD=0; }
    # «запрос ушёл, ответа нет» (YT_REQ_AFTER): соединение телефона напрямую — рвём, плеер сразу
    # откроет новое (15.11: 16 таких за 7 мин, зависание шортса в 12:49:45 — запрос ~12 КБ к фронту
    # 173.194.165.4). Раздачу ss не порвёт — ей RST на повтор запроса; через WARP — только журнал
    for rqh in $(printf '%s\n' "$out" | awk '$1 == "REQ" { print $2 "_" $3 "_" $4 "_" $5 "_" $6 "_" $7 "_" $8 "_" $9 "_" $10 "_" $11 }'); do
        rqd=${rqh%%_*}; rqh=${rqh#*_}; rqa=${rqh%%_*}; rqh=${rqh#*_}; rqp=${rqh%%_*}; rqh=${rqh#*_}; rqb=${rqh%%_*}; rqh=${rqh#*_}
        rqv=${rqh%%_*}; rqh=${rqh#*_}; rqw=${rqh%%_*}; rqh=${rqh#*_}; rqs=${rqh%%_*}; rqh=${rqh#*_}; rqc=${rqh%%_*}; rqh=${rqh#*_}; rqn=${rqh%%_*}
        # в журнал — «Play:» у загрузок Play (метка gvt1), иначе «YouTube:»
        rqt="YouTube"; [ "${rqh#*_}" = play ] && rqt="Play"
        case "$rqd$rqs$rqc" in *[!0-9.]*|'') continue ;; esac
        # от сервера ни байта данных — это «принял ClientHello и молчит»: и в малое окно (yt_ramp_hit, два раза за
        # YT_RETRY_WIN — стойке). Иначе такие соединения рвались здесь за 2 с, а «принял и молчит» (HIT, 3 с), который
        # заносит стойку, до них не доходил (16.11: 3 из 7 таких стоек не попали в список)
        [ "$rqn" = 1 ] && [ "$rqv" = direct ] && yt_ramp_hit "$rqd" "$now"
        if [ "$rqv" = direct ] && [ "$rqw" = phone ] && [ -n "$rqs" ]; then
            ss -K -tn dst "$rqd" dport = :443 sport = :"$rqs" >/dev/null 2>&1
            YT_REQ_KILLS=$((YT_REQ_KILLS + 1))
            # Play: запрос сразу за рукопожатием (отсчёт с появления соединения) — «~0 Б после данных» читалось бы как «запроса не было»
            if [ "$rqt" = Play ] && [ "${rqp#-}" -le 80 ] 2>/dev/null; then
                log "Play: $rqd — запрос сразу за рукопожатием без ответа ${rqa}с (от сервера $rqb Б) — рву соединение"
            else
                log "$rqt: $rqd — запрос без ответа ${rqa}с (~${rqp} Б после последних данных сервера, от сервера $rqb Б) — рву соединение"
            fi
        elif [ "$rqv" = direct ] && [ "$rqw" = tether ] && [ -n "$rqs" ]; then
            # раздача: от сервера ни байта, даже ACK — клиент повторит запрос и на повтор получит RST
            # (правило на одно соединение, 20 с, снимает yt_retry_hits — как у застрявших)
            $iptables -I "$CHAIN_YT_RST" -s "$rqc" -d "$rqd" -p tcp --sport "$rqs" --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null && {
                YT_RETRY_RJ="$YT_RETRY_RJ
$(($now + 20)) $rqc $rqs $rqd"
                YT_REQ_KILLS=$((YT_REQ_KILLS + 1))
                log "$rqt: $rqd — запрос клиента раздачи $rqc без ответа ${rqa}с (~${rqp} Б, от сервера $rqb Б) — RST на его повтор"
            }
        else
            log "$rqt: наблюдение: $rqd — запрос без ответа ${rqa}с (~${rqp} Б после последних данных сервера, от сервера $rqb Б, $rqv, $rqw)"
        fi
    done
    # загрузка Play замолчала посреди куска (PSTALL, YT_PLAY_STALL): рвём — Play откроет новое и докачает с того же места
    for rqh in $(printf '%s\n' "$out" | awk '$1 == "PSTALL" { print $2 "_" $3 "_" $4 "_" $5 }'); do
        rqd=${rqh%%_*}; rqh=${rqh#*_}; rqa=${rqh%%_*}; rqh=${rqh#*_}; rqb=${rqh%%_*}; rqs=${rqh#*_}
        case "$rqd$rqa$rqb$rqs" in *[!0-9.]*|'') continue ;; esac
        ss -K -tn dst "$rqd" dport = :443 sport = :"$rqs" >/dev/null 2>&1
        YT_REQ_KILLS=$((YT_REQ_KILLS + 1))
        log "Play: $rqd — кусок замолчал на середине (${rqa} с без данных, скачано $((rqb / 1024)) КБ) — рву, Play докачает"
    done
    # простаивающие видеосоединения телефона (YT_POKE): по пустому ACK в каждое — одним вызовом vtpoke. Интерфейс —
    # тот, где адрес WAN (в сети с CLAT IPv4 у v4-<WAN>)
    k=$(printf '%s\n' "$out" | awk '$1 == "POKE" && $2 ~ /^[0-9.]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9.]+$/ { printf " %s %s %s 443", $4, $3, $2; n++ } END { if (n) print "" }')
    if [ -n "$k" ]; then
        rqh="$LAST_WAN_IFACE"
        $ip -4 addr show "$rqh" 2>/dev/null | grep -q "inet $wip/" || rqh="v4-$LAST_WAN_IFACE"
        # shellcheck disable=SC2086
        "$VTPOKE_BIN" "$rqh" $k >/dev/null 2>&1
        rqa=$?
        if [ "$rqa" -ge 126 ]; then
            # не открылся сырой сокет или интерфейс (255), не запустился (126/127) — 5 мин или до другой сети
            # обрыв простоя, как без vtpoke; в журнал — только первый сбой подряд
            [ "${YT_POKE_FAIL:-0}" -eq 0 ] && log "WARNING: YouTube: vtpoke не отправляет (код $rqa, интерфейс $rqh) — простаивающие видеосоединения пока рву, как раньше; попробую снова через 5 мин или в другой сети"
            YT_POKE_FAIL=$now; YT_POKE_FAIL_NET="${NET_KEY:--}"
        else
            [ "${YT_POKE_FAIL:-0}" -ne 0 ] && log "YouTube: vtpoke снова отправляет — простаивающие видеосоединения телефона держу пустым ACK"
            YT_POKE_FAIL=0
            YT_POKES=$((YT_POKES + $(echo $k | wc -w) / 4 - rqa))
        fi
    fi
    # простаивающие видеосоединения телефона (YT_IDLE_KILL — только когда vtpoke не отправляет): ss -K. Раздаче с
    # 17.11 не рвём (её держит пустой ACK). Порванные помним, пока запись conntrack висит — без повторов в журнале
    if [ -n "$YT_IDLE_LIST" ]; then
        k=$(printf '%s\n' "$out" | awk '$1 == "IDLE" { printf " %s:%s>%s", $5, $4, $2 }')
        YT_IDLE_LIST=$(printf '%s\n' "$YT_IDLE_LIST" | awk -v ks="$k " 'NF == 2 && index(ks, " " $1 " ")')
    fi
    for rqh in $(printf '%s\n' "$out" | awk '$1 == "IDLE" { print $2 "_" $3 "_" $4 "_" $5 }'); do
        rqd=${rqh%%_*}; rqh=${rqh#*_}; rqa=${rqh%%_*}; rqh=${rqh#*_}; rqs=${rqh%%_*}; rqc=${rqh#*_}
        case "$rqd$rqa$rqs$rqc" in *[!0-9.]*|'') continue ;; esac
        # ключ — с начала строки списка (иначе 2.18.x:порт нашёлся бы внутри 172.18.x:порт)
        case "
$YT_IDLE_LIST" in *"
$rqc:$rqs>$rqd "*) continue ;; esac
        [ "$rqc" = "$wip" ] || continue
        ss -K -tn dst "$rqd" dport = :443 sport = :"$rqs" >/dev/null 2>&1
        log "YouTube: $rqd — видеосоединение простаивало ${rqa}с — рву заранее"
        YT_IDLE_KILLS=$((YT_IDLE_KILLS + 1))
        YT_IDLE_LIST="$YT_IDLE_LIST
$rqc:$rqs>$rqd $now"
    done
    # мёртвые фронты: кандидаты из conntrack, истёкшие и другая сеть — раз в 30 с
    for rqh in $(printf '%s\n' "$out" | awk '$1 == "FRONT" { print $2 }'); do yt_front_hit "$rqh" "$now"; done
    { [ -n "$YT_FRONT_LIST" ] && [ $((now - YT_FRONT_TS)) -ge 30 ]; } || [ "${NET_KEY:--}" != "$YT_FRONT_KEY" ] && yt_front_sync "$now"
    ds=$(printf '%s\n' "$out" | sed -n 's/^DATA //p')
    [ "${ds:-0}" -gt "$YT_DATA_SUM" ] && YT_DATA_TS=$now
    YT_DATA_SUM=${ds:-0}
    # Волна прошла: метка сторожа (scan.sh, .wave) держит «Волну» в WebUI 30 мин и паузу проверок 15 мин, хотя
    # Google часто оживает раньше (16.11: волна в 13:40, в 14:05 видео шло, а WebUI показывал волну). Снимаем,
    # как только с серверов Google снова пошло видео (прирост от 256 КБ за круг) — не раньше минуты после метки
    ds=$(printf '%s\n' "$out" | sed -n 's/^GDATA //p')
    # (на первом проходе после запуска прошлой суммы нет — всё скачанное раньше выглядело бы приростом)
    if [ -n "$YT_GDATA_SUM" ] && [ $(( ${ds:-0} - YT_GDATA_SUM )) -ge 262144 ] && [ -f "${ZSCAN_PID_FILE%.pid}.wave" ]; then
        k=$(stat -c %Y "${ZSCAN_PID_FILE%.pid}.wave" 2>/dev/null)
        [ -n "$k" ] && [ $((now - k)) -ge 60 ] && rm -f "${ZSCAN_PID_FILE%.pid}.wave" && \
            log "YouTube: видео с серверов Google снова идёт — волна прошла, метку снимаю"
    fi
    YT_GDATA_SUM=${ds:-0}
    yt_retry_hits "$out" "$now" "$wip"
    # сигнал сторожу (держим последние 2 мин): только адреса, которым не помогли и YT_RETRY_MAX
    # повторов, пока видео нигде не идёт (yt_retry_hits) — застревает треть попыток (14.11 YOTA)
    keep=""
    for t in $YT_STUCK; do [ $((now - t)) -lt 120 ] && keep="$keep $t"; done
    n=$YT_RETRY_ESC; YT_RETRY_ESC=0
    while [ "$n" -gt 0 ]; do keep="$keep $now"; n=$((n - 1)); done
    YT_STUCK="$keep"
}
