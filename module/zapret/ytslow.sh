#!/system/bin/sh
# ============================================================================
# Обрыв медленных видеосоединений YouTube (YT_SLOW_RETRY, 2.26).
#
# 22.10, YOTA: ТСПУ режет ~85-90% соединений с серверами Google до ~1 Мбит/с
# (по адресам, имя сайта не важно), остальные идут 20-60 Мбит/с и такими
# остаются. Видно это уже по первым секундам. Медленное молодое видео-
# соединение рвём — плеер переподключается и с шансом ~1/10 попадает на
# быстрое, а дальше качает по нему же.
#
# Запускает демон (service.sh) вместе с отбоем мёртвых серверов: видео-
# соединения он помечает битом connmark 0x10000000. Раз в секунду:
#   - история байт ответа каждого помеченного соединения (conntrack);
#   - медленно = 3 шага подряд есть прирост, но за 3 с 40 КБ..1.2 МБ
#     (0.1-3 Мбит/с) — идёт качка, и она медленная (простаивающий плеер не
#     трогаем: у него прироста нет);
#   - рвём только молодые (до 15 с) и не адреса на .4 — это www.youtube.com /
#     API YouTube, а не видеосерверы (22.10 обрыв такого = ролик висел 1.5 мин);
#   - когда-то было быстро (> 1 МБ за секунду) — не трогаем, пока ТСПУ его не
#     «догонит»: 5 с подряд непрерывно качает медленнее ~2 Мбит/с (у плеера,
#     который просто отдыхает, прироста нет вовсе) — тогда рвём, в журнал.
# Телефон (сокет на самом телефоне, в т.ч. AdGuard) — ss -K; раздача —
# REJECT tcp-reset на 15 с для этого соединения.
# Предохранитель: за 10 мин >= 30 обрывов и ни одного быстрого — режут всё
# подряд, обрывы только мешают: пауза 10 мин.
#
#   ytslow.sh PID_ДЕМОНА [CONNTRACK]
# ============================================================================
DPID="$1"
MODDIR="${0%/*}/.."
[ -f "$MODDIR/service.sh" ] || MODDIR=/data/adb/modules/vpn-to-hotspot-usb
case "$(uname -m)" in aarch64|arm64) CT="$MODDIR/bin/conntrack-arm64" ;; *) CT="$MODDIR/bin/conntrack-arm" ;; esac
# демон передаёт свой (бывает системный conntrack — тогда в bin/ его нет)
[ -n "$2" ] && CT="$2"
LOG_FILE=/data/local/tmp/vpn_tether.log
D=/data/local/tmp/vpn_tether_ytslow     # .state .rj .act .stat
AGE_MAX=15
WIN=600; PAUSE=600; PAUSE_KILLS=30

log() { echo "[$(date '+%H:%M:%S')] $*" >> "$LOG_FILE"; }

cleanup() {
    [ -s "$D.rj" ] && while read -r _e rule; do iptables -w 2 -D FORWARD $rule 2>/dev/null; done < "$D.rj"
    rm -f "$D.rj" "$D.state" "$D.state.n" "$D.act" "$D.ev"
}
trap 'exit 0' INT TERM HUP
trap cleanup EXIT
[ -x "$CT" ] || command -v "$CT" >/dev/null 2>&1 || exit 1
# REJECT прошлого экземпляра (убит без уборки, kill -9) — снять, а не
# потерять их список: иначе висят в FORWARD до перезагрузки
cleanup
: > "$D.state"; : > "$D.rj"; : > "$D.ev"
WIP=""; tick=0; pause_until=0; kills=0; fasts=0; degr=0; sum_t=$(date +%s); sum_k=0; sum_f=0

while kill -0 "$DPID" 2>/dev/null; do
    now=$(date +%s)
    # адрес телефона в сети оператора (меняется с сетью)
    if [ $((tick % 30)) -eq 0 ]; then
        w=$(sed -n 's/^wan=//p' "$MODDIR/status" 2>/dev/null)
        WIP=$(ip -4 addr show "$w" 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')
    fi
    tick=$((tick + 1))
    # снять отслужившие REJECT раздачи
    if [ -s "$D.rj" ]; then
        awk -v n="$now" '$1 <= n' "$D.rj" | while read -r _e rule; do iptables -w 2 -D FORWARD $rule 2>/dev/null; done
        awk -v n="$now" '$1 > n' "$D.rj" > "$D.rj.t"; mv -f "$D.rj.t" "$D.rj"
    fi
    : > "$D.state.n"
    "$CT" -L -p tcp --dport 443 2>/dev/null | awk -v now="$now" -v sf="$D.state" -v amax="$AGE_MAX" '
        BEGIN { while ((getline l < sf) > 0) { split(l, f, " "); k = f[1]; first[k] = f[2]; h[k] = f[3]; kd[k] = f[4]; fast[k] = f[5] } }
        {
            n = 0; mk = 0; rb = 0
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^src=/) { n++; if (n == 1) s = substr($i, 5); if (n == 2) rs = substr($i, 5) }
                else if ($i ~ /^dst=/ && n == 1) d = substr($i, 5)
                else if ($i ~ /^sport=/ && n == 1) sp = substr($i, 7)
                else if ($i ~ /^bytes=/ && n == 2) rb = substr($i, 7)
                else if ($i ~ /^mark=/) mk = substr($i, 6)
            }
            # AdGuard-локальные записи (ответ не от сервера) и без пометки — мимо
            if (rs != d || int(mk / 268435456) % 2 == 0) next
            k = s ":" sp ">" d
            if (!(k in first)) { first[k] = now; h[k] = rb; kd[k] = 0; fast[k] = 0 }
            m = split(h[k], v, ",")
            nh = rb; for (i = m; i >= 1 && i > m - 5; i--) nh = v[i] "," nh
            if (m >= 1 && rb - v[m] > 1000000 && !fast[k]) { fast[k] = 1; print "FAST", s, sp, d }
            m2 = split(nh, w, ",")
            if (m2 >= 4 && !kd[k] && !fast[k] && now - first[k] <= amax && d !~ /\.4$/) {
                g1 = w[m2] - w[m2 - 1]; g2 = w[m2 - 1] - w[m2 - 2]; g3 = w[m2 - 2] - w[m2 - 3]; g = w[m2] - w[m2 - 3]
                if (g1 > 2000 && g2 > 2000 && g3 > 2000 && g >= 40000 && g <= 1200000) { kd[k] = 1; print "SLOW", s, sp, d, g }
            }
            # было быстрым, а теперь 5 с непрерывно медленно — догнали
            if (m2 >= 6 && !kd[k] && fast[k] && d !~ /\.4$/) {
                ok = 1; for (i = m2; i > m2 - 5; i--) if (w[i] - w[i - 1] <= 2000) ok = 0
                g = w[m2] - w[m2 - 5]
                # до ~2 Мбит/с: 22.10 кэш YOTA ровно отдавал 2.7 — это не ТСПУ (тот ~1)
                if (ok && g >= 60000 && g <= 1250000) { kd[k] = 1; print "DEGR", s, sp, d, g, now - first[k] }
            }
            print k, first[k], nh, kd[k], fast[k] > (sf ".n")
        }' > "$D.act"
    mv -f "$D.state.n" "$D.state"
    while read -r tag s sp d g age; do
        case "$tag" in
            FAST) fasts=$((fasts + 1)); echo "$now f" >> "$D.ev" ;;
            SLOW|DEGR)
                [ "$now" -lt "$pause_until" ] && continue
                if [ "$tag" = DEGR ]; then
                    degr=$((degr + 1))
                    log "YouTube: быстрое соединение с $d через ${age:-?}с стало медленным (~$((g * 8 / 5000)) кбит/с) — рву"
                fi
                if [ -n "$WIP" ] && [ "$s" = "$WIP" ]; then
                    ss -K -tn src "$s" sport = ":$sp" dst "$d" dport = :443 >/dev/null 2>&1
                else
                    rule="-s $s -p tcp --sport $sp -d $d --dport 443 -j REJECT --reject-with tcp-reset"
                    iptables -w 2 -I FORWARD 1 $rule 2>/dev/null && echo "$((now + 15)) $rule" >> "$D.rj"
                fi
                kills=$((kills + 1)); echo "$now k" >> "$D.ev" ;;
        esac
    done < "$D.act"
    # окно 10 мин: предохранитель и итог в журнал
    if [ $((tick % 10)) -eq 0 ]; then
        awk -v n="$now" -v w="$WIN" '$1 > n - w' "$D.ev" > "$D.ev.t"; mv -f "$D.ev.t" "$D.ev"
        wk=$(grep -c ' k$' "$D.ev"); wf=$(grep -c ' f$' "$D.ev")
        if [ "$now" -ge "$pause_until" ] && [ "$wk" -ge "$PAUSE_KILLS" ] && [ "$wf" -eq 0 ]; then
            pause_until=$((now + PAUSE))
            log "YouTube: за 10 мин $wk обрывов медленных соединений и ни одного быстрого — режут всё, обрывы на паузе ${PAUSE}с"
            : > "$D.ev"
        fi
        st="on"; [ "$now" -lt "$pause_until" ] && st="pause"
        printf 'state=%s\nkills=%s\nfast=%s\ndegr=%s\n' "$st" "$kills" "$fasts" "$degr" > "$D.stat.t" && mv -f "$D.stat.t" "$D.stat"
        if [ $((now - sum_t)) -ge 600 ]; then
            [ $((kills - sum_k)) -gt 0 ] && log "YouTube: за 10 мин оборвано медленных соединений: $((kills - sum_k)), быстрых поймано: $((fasts - sum_f))"
            sum_t=$now; sum_k=$kills; sum_f=$fasts
        fi
    fi
    sleep 1
done
