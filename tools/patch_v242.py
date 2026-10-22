"""v2.4.1 -> v2.4.2: один setup на тоггл (кэш флага), быстрый read_table_index без tun."""
import sys

p = 'service.sh'
s = open(p, encoding='utf-8').read()


def rep(old, new, count=1):
    global s
    n = s.count(old)
    if n != count:
        sys.exit(f'PATCH FAIL ({n} matches): {old[:80]!r}')
    s = s.replace(old, new)


rep(r'''#   - 3.9.7.1: редирект на dnsproxy до проверки (не было окна с DNS оператора),
#     проверка ~1-2с вместо 8-10с (nc -w 1 x5).
''', r'''#   - 3.9.7.1: редирект на dnsproxy до проверки (не было окна с DNS оператора),
#     проверка ~1-2с вместо 8-10с (nc -w 1 x5).
#   - 3.9.7.2: тоггл в direct шёл 20-28с -> action.sh "демон не подтвердил":
#     * флаг режима читается только при обработке USR1. Раньше action.sh
#       менял файл, текущая итерация уже перестраивала всё по новому флагу
#       (без ack), а следующая — ещё раз с FORCE (с ack). Две настройки.
#     * read_table_index при выключенном VPN гонял 15 попыток (~3с на вызов,
#       2 вызова на итерацию); теперь нет tun-ифейса -> сразу выход.
#       Заодно: "sleep 0.1138" вместо 1.138с (printf %03d от 1138).
''')

# ---------- кэш флага ----------
rep(r'''is_vpn_tether_enabled() { [ -f "$FLAG_FILE" ]; }
''', r'''# Режим берётся из кэша, а не из файла: action.sh меняет файл ДО сигнала, и
# итерация, попавшая между ними, перестраивала всё без ack (а потом ещё раз).
# Кэш обновляется только при обработке USR1 и на старте.
VPN_TARGET=""
refresh_vpn_target() { if [ -f "$FLAG_FILE" ]; then VPN_TARGET=1; else VPN_TARGET=0; fi; }
is_vpn_tether_enabled() { [ "$VPN_TARGET" = "1" ]; }
''')

rep(r'''    if [ "$USR1_PENDING" -eq 1 ]; then
        USR1_PENDING=0
        FORCE_UPDATE=1''', r'''    if [ "$USR1_PENDING" -eq 1 ]; then
        USR1_PENDING=0
        refresh_vpn_target
        FORCE_UPDATE=1''')

rep(r'''[ ! -f "$FLAG_FILE" ] && { touch "$FLAG_FILE"; log "VPN mode ENABLED by default after reboot"; }
''', r'''[ ! -f "$FLAG_FILE" ] && { touch "$FLAG_FILE"; log "VPN mode ENABLED by default after reboot"; }
refresh_vpn_target
''')

# ---------- read_table_index ----------
rep(r'''    [ -s /data/misc/net/rt_tables ] || { sleep 1; return 1; }

    while [ $attempts -gt 0 ]; do''', r'''    [ -s /data/misc/net/rt_tables ] || { sleep 1; return 1; }
    # Нет самого ифейса (VPN выключен) — ждать строку в rt_tables бессмысленно.
    # Ретраи нужны только сразу после появления tun, пока netd не дописал таблицу.
    $ip link show "$iface" >/dev/null 2>&1 || return 1

    while [ $attempts -gt 0 ]; do''')

rep(r'''        [ $attempts -gt 0 ] && { sleep 0.$(printf "%03d" $delay_ms); [ $delay_ms -lt 1000 ] && delay_ms=$((delay_ms * 3 / 2)); }''',
    r'''        [ $attempts -gt 0 ] && { sleep 0.$(printf "%03d" $delay_ms); delay_ms=$((delay_ms * 3 / 2)); [ $delay_ms -gt 999 ] && delay_ms=999; }''')

open(p, 'w', encoding='utf-8', newline='\n').write(s)
print('patched OK')
