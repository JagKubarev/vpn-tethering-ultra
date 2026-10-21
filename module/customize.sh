#!/system/bin/sh
# Оставляем бинари под архитектуру устройства ($ARCH ставит Magisk/KSU/Apatch)
case "$ARCH" in
    arm64)
        rm -f "$MODPATH/bin/conntrack-arm" "$MODPATH/bin/dnsproxy-arm" "$MODPATH/bin/nfqws-arm"
        set_perm "$MODPATH/bin/conntrack-arm64" 0 0 0755
        set_perm "$MODPATH/bin/dnsproxy-arm64"  0 0 0755
        set_perm "$MODPATH/bin/nfqws-arm64"     0 0 0755
        ui_print "- conntrack v1.4.8 + dnsproxy v0.86.0 + nfqws (zapret v72.13), arm64"
        ;;
    arm)
        rm -f "$MODPATH/bin/conntrack-arm64" "$MODPATH/bin/dnsproxy-arm64" "$MODPATH/bin/nfqws-arm64"
        set_perm "$MODPATH/bin/conntrack-arm" 0 0 0755
        set_perm "$MODPATH/bin/dnsproxy-arm"  0 0 0755
        set_perm "$MODPATH/bin/nfqws-arm"     0 0 0755
        ui_print "- conntrack v1.4.8 + dnsproxy v0.86.0 + nfqws (zapret v72.13), armv7"
        ;;
    *)
        # неизвестная арх — оставляем оба, service.sh выберет по uname -m
        set_perm "$MODPATH/bin/conntrack-arm64" 0 0 0755
        set_perm "$MODPATH/bin/conntrack-arm"   0 0 0755
        set_perm "$MODPATH/bin/dnsproxy-arm64"  0 0 0755
        set_perm "$MODPATH/bin/dnsproxy-arm"    0 0 0755
        set_perm "$MODPATH/bin/nfqws-arm64"     0 0 0755
        set_perm "$MODPATH/bin/nfqws-arm"       0 0 0755
        ui_print "- conntrack v1.4.8 + dnsproxy v0.86.0 + nfqws (zapret v72.13), arm64+armv7"
        ;;
esac
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh"  0 0 0755
set_perm "$MODPATH/webctl.sh"  0 0 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755

# Настройки пользователя — вне папки модуля, чтобы переживали обновления.
# Существующий файл не трогаем.
CONF=/data/adb/vpn_tether.conf
if [ ! -f "$CONF" ]; then
    cat > "$CONF" <<'EOF'
# ============================================================
#  Настройки VPN Tethering Ultra
#  Применяются после перезагрузки телефона.
#  Файл переживает обновления модуля.
#  Строка с # в начале — выключена (действует значение
#  по умолчанию, оно указано в ней же).
# ============================================================

# --- Свой DNS (dnsproxy) -------------------------------------
# 1 = включено: при раздаче НАПРЯМУЮ и на самом телефоне без
#     VPN DNS идёт через dns.wlrus.cfd по зашифрованному DoH
#     (открывает ChatGPT, Gemini, Claude и т.п.).
# 0 = выключено полностью: DNS как в старых версиях модуля.
#     Ставь 0, если dnsproxy чем-то мешает.
DNSPROXY_ENABLE=1

# DNS самого телефона через DoH, когда VPN выключен (1/0)
#DNS_PHONE=1

# Какой DoH-сервер использовать (можно несколько через пробел)
#DNS_UPSTREAMS=https://dns.wlrus.cfd/dns-query

# Закрыть QUIC (HTTP/3) приложениям — они пойдут по обычному
# HTTPS. Помогает, когда оператор/ТСПУ режет QUIC и у приложения
# не грузится часть картинок. Пакеты через пробел, пусто = выкл.
#QUIC_BLOCK_APPS=com.avito.android

# --- Обход блокировок (zapret) --------------------------------
# Для трафика мимо VPN. Удобнее настраивать в WebUI модуля.
#ZAPRET_ENABLE=1
#ZAPRET_MODE=list
#ZAPRET_STRATEGY=fakeddisorder

# --- Защита -------------------------------------------------
# Выбран режим VPN, а VPN не подключён:
# 1 = раздача на паузе (твой IP не светится)
# 0 = раздача сама переходит на "напрямую"
#KILL_SWITCH_STRICT=0

# --- Внешний вид --------------------------------------------
# Показывать текущее состояние в описании модуля (1/0)
#STATUS_IN_DESCRIPTION=1
EOF
    chmod 600 "$CONF"
    ui_print "- Создан файл настроек: $CONF"
else
    ui_print "- Настройки: $CONF (оставлены как были)"
fi
ui_print "- DNSPROXY_ENABLE=0 в этом файле выключает dnsproxy"
