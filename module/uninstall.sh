#!/system/bin/sh
# Удаление модуля (KernelSU/Magisk зовут на загрузке, до system_server).
# Демон менял системные настройки, которые переживают перезагрузку:
# аппаратный offload раздачи (tether_offload_disabled, override_bpf_offload)
# и проверку раздачи у оператора (tether_dun_required). Обычно их возвращает
# cleanup_on_exit, но при выключении телефона он не успевает — без этого
# offload раздачи остался бы выключенным навсегда. settings на этом этапе
# ещё недоступен — ждём загрузку в фоне.
# Возвращаем только то, что трогал модуль: нет файла сохранения — offload
# модуль не менял (или уже вернул сам), а tether_dun_required — только если
# скрытие раздачи не было выключено: иначе стёрли бы ручные настройки.
CONF=/data/adb/vpn_tether.conf
st=$(sed -n 's/^[[:space:]]*TETHER_STEALTH[[:space:]]*=[[:space:]]*["'\'']*\([01]\).*/\1/p' "$CONF" 2>/dev/null | tail -n 1)
(
    i=0
    while [ "$(getprop sys.boot_completed)" != "1" ] && [ $i -lt 300 ]; do sleep 2; i=$((i + 1)); done
    F=/data/local/tmp/vpn_tether_offload_orig
    if [ -f "$F" ]; then
        s=$(sed -n 's/^setting=//p' "$F"); b=$(sed -n 's/^bpf=//p' "$F")
        case "$s" in ""|null) settings delete global tether_offload_disabled ;; *) settings put global tether_offload_disabled "$s" ;; esac
        if command -v device_config >/dev/null 2>&1 && grep -q '^bpf=' "$F"; then
            case "$b" in ""|null) device_config delete tethering override_bpf_offload ;; *) device_config put tethering override_bpf_offload "$b" ;; esac
        fi
    fi
    [ "$st" = "0" ] || settings delete global tether_dun_required
    # временные файлы модуля; настройки в /data/adb/vpn_tether* оставляем —
    # при повторной установке они подхватятся
    rm -rf /data/local/tmp/vpn_tether*
) </dev/null >/dev/null 2>&1 &
exit 0
