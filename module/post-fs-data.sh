#!/system/bin/sh
# Ранний этап загрузки (до system_server): net.tethering.noprovisioning
# Tethering читает при старте, а service.sh запускается позже — поэтому
# здесь, как system.prop у tether_unblock, но с учётом переключателя
# TETHER_STEALTH из /data/adb/vpn_tether.conf (по умолчанию включено).
CONF=/data/adb/vpn_tether.conf
# Описание в списке модулей — состояние с прошлого запуска демона (при
# выключении телефона он не успевает вернуть обычное). До старта демона
# пишем «запускается», чтобы не показывать устаревший режим.
P="${0%/*}/module.prop"
if [ -f "$P" ]; then
    awk '/^description=/ {print "description=Модуль запускается — состояние появится после загрузки телефона."; next} {print}' "$P" > "$P.tmp" && \
        grep -q '^id=' "$P.tmp" && cat "$P.tmp" > "$P"
    rm -f "$P.tmp"
fi
# pid демона с прошлой загрузки: номер мог достаться чужому процессу, и
# webctl.sh до старта демона считал бы его демоном (и слал бы ему USR1)
rm -f /data/local/tmp/vpn_tether.pid
# то же для подбора zapret (scan.sh убит перезагрузкой): иначе WebUI вечно
# «идёт подбор», а «Стоп» шлёт TERM чужому процессу
rm -f /data/local/tmp/vpn_tether_zscan.pid
v=$(sed -n 's/^[[:space:]]*TETHER_STEALTH[[:space:]]*=[[:space:]]*["'\'']*\([01]\).*/\1/p' "$CONF" 2>/dev/null | tail -n 1)
[ "$v" = "0" ] && exit 0
for r in /data/adb/ksu/bin/resetprop /data/adb/magisk/resetprop /data/adb/ap/bin/resetprop resetprop; do
    if [ -x "$r" ] || command -v "$r" >/dev/null 2>&1; then
        "$r" -n net.tethering.noprovisioning true >/dev/null 2>&1 && break
    fi
done
exit 0
