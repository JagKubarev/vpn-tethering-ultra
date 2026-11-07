#!/system/bin/sh
# Оставляем бинари под архитектуру устройства ($ARCH ставит Magisk/KSU/Apatch)
case "$ARCH" in
    arm64)
        rm -f "$MODPATH/bin/conntrack-arm" "$MODPATH/bin/dnsproxy-arm" "$MODPATH/bin/nfqws-arm" "$MODPATH/bin/opera-proxy-arm" "$MODPATH/bin/hev-socks5-tproxy-arm"               "$MODPATH/bin/amneziawg-go-arm" "$MODPATH/bin/awg-arm"
        set_perm "$MODPATH/bin/conntrack-arm64" 0 0 0755
        set_perm "$MODPATH/bin/dnsproxy-arm64"  0 0 0755
        set_perm "$MODPATH/bin/nfqws-arm64"     0 0 0755
        set_perm "$MODPATH/bin/amneziawg-go-arm64" 0 0 0755
        set_perm "$MODPATH/bin/awg-arm64"       0 0 0755
        set_perm "$MODPATH/bin/opera-proxy-arm64" 0 0 0755
        set_perm "$MODPATH/bin/hev-socks5-tproxy-arm64" 0 0 0755
        ui_print "- conntrack v1.4.8 + dnsproxy v0.86.0 + nfqws (zapret v72.13) + AmneziaWG + curl 8.23.0 + opera-proxy v1.31.0 + hev-socks5-tproxy 2.13.1, arm64"
        ;;
    arm)
        rm -f "$MODPATH/bin/conntrack-arm64" "$MODPATH/bin/dnsproxy-arm64" "$MODPATH/bin/nfqws-arm64" "$MODPATH/bin/opera-proxy-arm64" "$MODPATH/bin/hev-socks5-tproxy-arm64"               "$MODPATH/bin/amneziawg-go-arm64" "$MODPATH/bin/awg-arm64"
        set_perm "$MODPATH/bin/conntrack-arm" 0 0 0755
        set_perm "$MODPATH/bin/dnsproxy-arm"  0 0 0755
        set_perm "$MODPATH/bin/nfqws-arm"     0 0 0755
        set_perm "$MODPATH/bin/amneziawg-go-arm" 0 0 0755
        set_perm "$MODPATH/bin/awg-arm"       0 0 0755
        set_perm "$MODPATH/bin/opera-proxy-arm" 0 0 0755
        set_perm "$MODPATH/bin/hev-socks5-tproxy-arm" 0 0 0755
        ui_print "- conntrack v1.4.8 + dnsproxy v0.86.0 + nfqws (zapret v72.13) + AmneziaWG + curl 8.23.0 + opera-proxy v1.31.0 + hev-socks5-tproxy 2.13.1, armv7"
        ;;
    *)
        # неизвестная арх — оставляем оба, service.sh выберет по uname -m
        set_perm "$MODPATH/bin/conntrack-arm64" 0 0 0755
        set_perm "$MODPATH/bin/conntrack-arm"   0 0 0755
        set_perm "$MODPATH/bin/dnsproxy-arm64"  0 0 0755
        set_perm "$MODPATH/bin/dnsproxy-arm"    0 0 0755
        set_perm "$MODPATH/bin/nfqws-arm64"     0 0 0755
        set_perm "$MODPATH/bin/nfqws-arm"       0 0 0755
        set_perm "$MODPATH/bin/amneziawg-go-arm64" 0 0 0755
        set_perm "$MODPATH/bin/amneziawg-go-arm"   0 0 0755
        set_perm "$MODPATH/bin/awg-arm64"       0 0 0755
        set_perm "$MODPATH/bin/opera-proxy-arm64" 0 0 0755
        set_perm "$MODPATH/bin/hev-socks5-tproxy-arm64" 0 0 0755
        set_perm "$MODPATH/bin/awg-arm"         0 0 0755
        set_perm "$MODPATH/bin/opera-proxy-arm" 0 0 0755
        set_perm "$MODPATH/bin/hev-socks5-tproxy-arm" 0 0 0755
        ui_print "- conntrack v1.4.8 + dnsproxy v0.86.0 + nfqws (zapret v72.13) + AmneziaWG + curl 8.23.0 + opera-proxy v1.31.0 + hev-socks5-tproxy 2.13.1, arm64+armv7"
        ;;
esac
# свой curl — на прошивках без системного (Xiaomi): модуль находит его по PATH
case "$ARCH" in
    arm64) c=arm64 ;;
    arm) c=arm ;;
    *) case "$(uname -m)" in aarch64|arm64) c=arm64 ;; *) c=arm ;; esac ;;
esac
mv -f "$MODPATH/bin/curl-$c" "$MODPATH/bin/curl"
rm -f "$MODPATH/bin/curl-arm64" "$MODPATH/bin/curl-arm"
set_perm "$MODPATH/bin/curl" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh"  0 0 0755
set_perm "$MODPATH/webctl.sh"  0 0 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
# lib/ — части service.sh: подключаются через ".", исполняемыми быть не должны
set_perm_recursive "$MODPATH/lib" 0 0 0755 0644
# WARP: скрипт конфигов зовёт webctl.sh через sh — исполняемость не нужна
set_perm_recursive "$MODPATH/warp" 0 0 0755 0644

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
#     VPN DNS идёт через not-a-dns.quic.best по зашифрованному DoH
#     (открывает ChatGPT, Gemini, Claude и т.п.).
# 0 = выключено полностью: DNS как в старых версиях модуля.
#     Ставь 0, если dnsproxy чем-то мешает.
DNSPROXY_ENABLE=1

# DNS самого телефона через DoH, когда VPN выключен (1/0)
#DNS_PHONE=1

# Какой DoH-сервер использовать (можно несколько через пробел)
#DNS_UPSTREAMS=https://not-a-dns.quic.best/dns-query

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
    # Ключи Opera 3.13–3.15.1 (и блок-подсказка 3.13): новые так называть нельзя,
    # удалятся при установке. Иначе висят
    # в WebUI как «Конфиг: пропущено: ?OPERA_TG». Остальное не трогаем.
    # OPERA_COUNTRY вернулся в 3.24: остаются только EU, AS и AM, прочие значения 3.14 (AUTO) — вон
    awk '
        /^# --- Telegram без VPN \(прокси Opera\)/ { skip = 1 }
        skip { if ($0 ~ /^[ \t\r]*$/) skip = 0; next }
        { s = $0; sub(/^[ \t]*#?[ \t]*/, "", s); sub(/\r$/, "", s) }
        s ~ /^OPERA_(TG|SITES|API_LIST)[ \t]*=/ { next }
        s ~ /^OPERA_COUNTRY[ \t]*=/ && s !~ /^OPERA_COUNTRY[ \t]*=[ \t]*"?(EU|AS|AM)"?[ \t]*$/ { next }
        { print }' "$CONF" > "$CONF.tmp" 2>/dev/null
    if [ -s "$CONF.tmp" ] && ! cmp -s "$CONF" "$CONF.tmp"; then
        cat "$CONF.tmp" > "$CONF"
        ui_print "- Устаревшие настройки Opera убраны из $CONF"
    fi
    rm -f "$CONF.tmp"
fi
ui_print " "
ui_print "VPN Tethering Ultra — что дальше:"
ui_print "- Настройки: значок модуля в KernelSU/APatch, в Magisk — приложение WebUI X"
ui_print "- Кнопка Action: переключить раздачу VPN / напрямую"
ui_print "- Сайты не открываются: вкладка Обход, подбор стратегии"
ui_print "- Telegram и то, что обход не берёт: вкладка «Выходы», WARP"
ui_print "- Закрытые разделы 4PDA: вкладка «Выходы», Opera"
ui_print "- Что-то сломалось: вкладка Сервис, «Отправить логи»"
ui_print "- Новости и помощь: t.me/kubarev_mods, тема на 4PDA"
ui_print " "
