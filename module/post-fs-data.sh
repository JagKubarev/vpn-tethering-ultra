#!/system/bin/sh
# Ранний этап загрузки (до system_server): net.tethering.noprovisioning
# Tethering читает при старте, а service.sh запускается позже — поэтому
# здесь, как system.prop у tether_unblock, но с учётом переключателя
# TETHER_STEALTH из /data/adb/vpn_tether.conf (по умолчанию включено).
CONF=/data/adb/vpn_tether.conf
v=$(sed -n 's/^[[:space:]]*TETHER_STEALTH[[:space:]]*=[[:space:]]*["'\'']*\([01]\).*/\1/p' "$CONF" 2>/dev/null | tail -n 1)
[ "$v" = "0" ] && exit 0
for r in /data/adb/ksu/bin/resetprop /data/adb/magisk/resetprop /data/adb/ap/bin/resetprop resetprop; do
    if [ -x "$r" ] || command -v "$r" >/dev/null 2>&1; then
        "$r" -n net.tethering.noprovisioning true >/dev/null 2>&1 && break
    fi
done
exit 0
