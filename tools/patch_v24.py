"""v2.3 -> v2.4: dnsproxy мимо AdGuard (отдельный GID), health-probe, без DoT."""
import sys

p = 'service.sh'
s = open(p, encoding='utf-8').read()


def rep(old, new, count=1):
    global s
    n = s.count(old)
    if n != count:
        sys.exit(f'PATCH FAIL ({n} matches): {old[:80]!r}')
    s = s.replace(old, new)


rep(r'''#   - ФИКС (жил с 3.9.4): после кратковременного обрыва VPN без смены tun
#     guard оставался в hard навсегда — раздача без интернета до ребута/тоггла.
''', r'''#   - ФИКС (жил с 3.9.4): после кратковременного обрыва VPN без смены tun
#     guard оставался в hard навсегда — раздача без интернета до ребута/тоггла.
# ============================================================================
# v3.9.7-hybrid.6 — DoH реально работает на устройстве с AdGuard:
#   - AdGuard (root, HTTPS-фильтр) REDIRECT-ит ВЕСЬ TCP root на свой MITM-
#     прокси -> dnsproxy видел сертификат AdGuard -> "unknown authority",
#     все запросы SERVFAIL. Теперь dnsproxy = root:DNSPROXY_GID (su -g), и
#     правило "nat OUTPUT -m owner --gid-owner GID -j RETURN" стоит ПЕРВЫМ
#     (watchdog возвращает его наверх, если AdGuard перевставил свою цепочку).
#   - DoT (853) к comss режется по дороге (EOF) — по умолчанию только DoH.
#   - После старта — настоящий DNS-запрос к dnsproxy (nc). Не ответил ->
#     откат на DNAT, а не "клиенты без DNS".
''')

rep(r'''DNS_UPSTREAMS="https://dns.comss.one/dns-query tls://dns.comss.one"
''', r'''DNS_UPSTREAMS="https://dns.comss.one/dns-query"
''')
rep(r'''DNS_FALLBACKS="https://dns.google/dns-query tls://1.1.1.1"
''', r'''DNS_FALLBACKS="https://dns.google/dns-query https://cloudflare-dns.com/dns-query"
''')
rep(r'''DNSPROXY_PORT=5354
''', r'''DNSPROXY_PORT=5354
# dnsproxy запускается как root:DNSPROXY_GID; по этому GID его трафик
# исключается из перехвата AdGuard и прочих transparent-proxy (nat OUTPUT).
# Пусто = без исключения (DoH сломается, если HTTPS-фильтр AdGuard включён).
DNSPROXY_GID=3999
''')

rep(r'''DNS_STATE_IFACES=""
''', r'''DNS_STATE_IFACES=""
DNSPROXY_SU_G=""       # "" = не проверяли, 1 = su -g работает, 0 = нет
BUSYBOX=""
for _b in /data/adb/ksu/bin/busybox /data/adb/magisk/busybox /data/adb/ap/bin/busybox; do
    [ -x "$_b" ] && BUSYBOX="$_b" && break
done
''', 1)

# ---------- поиск pid, strays ----------
rep(r'''# Осиротевшие экземпляры от убитого демона (pid-файл мог потеряться)
dnsproxy_kill_strays() {
    local f pid
    for f in $(grep -l "$MODULE_DIR/bin/dnsproxy" /proc/[0-9]*/cmdline 2>/dev/null); do
        pid="${f#/proc/}"; pid="${pid%/cmdline}"
        [ "$pid" = "$$" ] && continue
        kill -9 "$pid" 2>/dev/null && log "Убит осиротевший dnsproxy $pid"
    done
}
''', r'''# PID-ы процессов, чей argv[0] — наш dnsproxy (grep и обёртки su/sh не в счёт)
dnsproxy_pids() {
    local f
    for f in $(grep -l "$MODULE_DIR/bin/dnsproxy" /proc/[0-9]*/cmdline 2>/dev/null); do
        case "$(tr '\0' ' ' < "$f" 2>/dev/null)" in
            "$MODULE_DIR/bin/dnsproxy"*) f="${f#/proc/}"; echo "${f%/cmdline}" ;;
        esac
    done
}

# Осиротевшие экземпляры от убитого демона (pid-файл мог потеряться)
dnsproxy_kill_strays() {
    local pid
    for pid in $(dnsproxy_pids); do
        kill -9 "$pid" 2>/dev/null && log "Убит осиротевший dnsproxy $pid"
    done
}

# Исключение dnsproxy из перехвата AdGuard: RETURN по GID первым в nat OUTPUT.
# AdGuard при перезапуске вставляет свой jump в позицию 1 — поэтому проверяем
# именно позицию, а не наличие.
dnsproxy_exempt() {
    local t want
    [ "$DNSPROXY_SU_G" = "1" ] || return 0
    want="-A OUTPUT -m owner --gid-owner $DNSPROXY_GID -j RETURN"
    for t in "$iptables" "$ip6tables"; do
        [ "$($t -t nat -S OUTPUT 2>/dev/null | sed -n 2p)" = "$want" ] && continue
        local _n=0
        while [ $_n -lt 8 ] && $t -t nat -D OUTPUT -m owner --gid-owner "$DNSPROXY_GID" -j RETURN 2>/dev/null; do _n=$((_n + 1)); done
        $t -t nat -I OUTPUT 1 -m owner --gid-owner "$DNSPROXY_GID" -j RETURN 2>/dev/null
    done
}

dnsproxy_exempt_down() {
    local t _n
    [ -n "$DNSPROXY_GID" ] || return 0
    for t in "$iptables" "$ip6tables"; do
        _n=0
        while [ $_n -lt 8 ] && $t -t nat -D OUTPUT -m owner --gid-owner "$DNSPROXY_GID" -j RETURN 2>/dev/null; do _n=$((_n + 1)); done
    done
}

# Настоящий DNS-запрос (example.com A) к dnsproxy. 0 = NOERROR и есть ответы.
dnsproxy_probe() {
    local out i
    [ -n "$BUSYBOX" ] || return 0   # нечем проверить — не блокируем запуск
    for i in 1 2 3; do
        out=$(printf '\022\064\001\000\000\001\000\000\000\000\000\000\007example\003com\000\000\001\000\001' | \
              $BUSYBOX nc -u -w 4 127.0.0.1 "$DNSPROXY_PORT" 2>/dev/null | \
              $BUSYBOX od -An -tx1 -N8 2>/dev/null)
        # " 12 34 81 80 00 01 00 01": id, флаги (rcode = младшие 4 бита 4-го), qd, an
        set -- $out
        if [ "$1$2" = "1234" ] && [ $(( 0x${4:-ff} & 15 )) -eq 0 ] && [ "$7$8" != "0000" ]; then
            return 0
        fi
    done
    return 1
}
''')

# ---------- запуск ----------
rep(r'''    : > "$DNSPROXY_LOG"
    # Статический Go не находит CA Android 14+ (лежат в APEX conscrypt) ->
    # "x509: certificate signed by unknown authority". Только системные CA:
    # пользовательские (cacerts-added, напр. AdGuard HTTPS-фильтр) не берём.
    SSL_CERT_DIR="/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts" \
        $DNSPROXY_BIN $args -o "$DNSPROXY_LOG" >/dev/null 2>&1 < /dev/null &
    echo $! > "$DNSPROXY_PID_FILE"

    i=0
    while [ $i -lt 25 ]; do
        sleep 0.2
        dnsproxy_alive || break
        if ss -lun''', r'''    : > "$DNSPROXY_LOG"
    # Статический Go не находит CA Android 14+ (лежат в APEX conscrypt) ->
    # "x509: certificate signed by unknown authority". Только системные CA:
    # пользовательские (cacerts-added, напр. AdGuard HTTPS-фильтр) не берём.
    local certs="SSL_CERT_DIR=/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts"

    if [ -z "$DNSPROXY_SU_G" ]; then
        DNSPROXY_SU_G=0
        [ -n "$DNSPROXY_GID" ] && su -g "$DNSPROXY_GID" -c true >/dev/null 2>&1 && DNSPROXY_SU_G=1
        [ -n "$DNSPROXY_GID" ] && [ "$DNSPROXY_SU_G" = "0" ] && \
            log "WARNING: su -g не работает — dnsproxy без своего GID, HTTPS-фильтр AdGuard сломает DoH"
    fi

    if [ "$DNSPROXY_SU_G" = "1" ]; then
        dnsproxy_exempt
        su -g "$DNSPROXY_GID" -c "$certs exec $DNSPROXY_BIN $args -o $DNSPROXY_LOG" >/dev/null 2>&1 < /dev/null &
    else
        env "$certs" $DNSPROXY_BIN $args -o "$DNSPROXY_LOG" >/dev/null 2>&1 < /dev/null &
    fi

    # $! тут — su/env, а не сам dnsproxy: ищем по argv[0]
    i=0
    while [ $i -lt 25 ]; do
        sleep 0.2
        u=$(dnsproxy_pids | head -1)
        [ -n "$u" ] && echo "$u" > "$DNSPROXY_PID_FILE"
        if [ -n "$u" ] && ss -lun''')

rep(r'''            DNSPROXY_SIG="$sig"
            log "dnsproxy запущен (pid $(cat "$DNSPROXY_PID_FILE"), $tag): $ups"
            return 0''', r'''            DNSPROXY_SIG="$sig"
            log "dnsproxy запущен (pid $u, gid ${DNSPROXY_GID:-0}, $tag): $ups"
            return 0''')

# ---------- stop: снимаем исключение ----------
rep(r'''    rm -f "$DNSPROXY_PID_FILE"
    DNSPROXY_SIG=""
}''', r'''    rm -f "$DNSPROXY_PID_FILE"
    DNSPROXY_SIG=""
    dnsproxy_exempt_down
}''')

# ---------- apply: health-probe ----------
rep(r'''        if dnsproxy_start "$mode-$want" $ups; then
            dns_redirect_to_proxy $ifaces''', r'''        if dnsproxy_start "$mode-$want" $ups && dnsproxy_probe; then
            dns_redirect_to_proxy $ifaces''')
rep(r'''        log "WARNING: dnsproxy недоступен, откат на обычный DNAT"''',
    r'''        log "WARNING: dnsproxy не отвечает ($(grep ERROR "$DNSPROXY_LOG" 2>/dev/null | tail -1 | cut -c1-160)), откат на обычный DNAT"''')

# ---------- watchdog: держим исключение первым ----------
rep(r'''    case "$DNS_STATE" in dnsproxy*) ;; *) return 0 ;; esac
    if dnsproxy_alive; then''', r'''    case "$DNS_STATE" in dnsproxy*) ;; *) return 0 ;; esac
    dnsproxy_exempt
    if dnsproxy_alive; then''')

rep('echo "=== VPN Tether v3.9.6-hybrid.5 Started $(date) ===" > "$LOG_FILE"',
    'echo "=== VPN Tether v3.9.7-hybrid.6 Started $(date) ===" > "$LOG_FILE"')
rep('log "Network engine: v3.9.6"', 'log "Network engine: v3.9.7"')

open(p, 'w', encoding='utf-8', newline='\n').write(s)
print('patched OK')
