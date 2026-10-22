#!/system/bin/sh
# ============================================================================
# Какая сейчас сеть — для своей стратегии zapret в каждой сети.
#
#   netid.sh <WAN-интерфейс>   ->   "<ключ>|<название>"   (пусто — не понять)
#
#   Wi-Fi:     wifi:<SSID>|<SSID>
#   мобильная: mobile:<MCC MNC>|<оператор>   (сеть SIM, на которой мобильные данные)
#
# Один источник правды для демона (service.sh), подбора (scan.sh) и WebUI.
# Из названия убираются "|", "\" и управляющие символы: ключ лежит в файле
# через "|" и в status (КЛЮЧ=значение).
# ============================================================================
w="$1"

clean() { tr -d '\r\n\t' | sed 's/[|\\]//g; s/^[[:space:]]*//; s/[[:space:]]*$//'; }

# N-е поле (с 0) списка через запятую; пустое -> первое непустое
pick() {
    local list="$1" n="$2" v=""
    [ -n "$n" ] && v=$(echo "$list" | cut -d, -f$((n + 1)) | sed 's/^ *//; s/ *$//')
    [ -n "$v" ] || v=$(echo "$list" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | grep -m1 .)
    echo "$v"
}

case "$w" in
    wlan*|swlan*)
        # cmd wifi status — лёгкий; dumpsys wifi — запасной (тяжёлый, но есть везде)
        s=$(cmd wifi status 2>/dev/null | grep -m1 'SSID: "' | sed -n 's/.*SSID: "\(.*\)", BSSID.*/\1/p')
        [ -n "$s" ] || s=$(dumpsys wifi 2>/dev/null | grep -m1 'mWifiInfo SSID: "' | sed -n 's/.*SSID: "\(.*\)", BSSID.*/\1/p')
        s=$(printf '%s' "$s" | clean)
        [ -n "$s" ] && echo "wifi:$s|$s"
        ;;
    rmnet*|r_rmnet*|ccmni*|wwan*|pdp*|qmi*|seth*|rmnet_data*|v4-rmnet*)
        num=$(getprop gsm.operator.numeric)
        alpha=$(getprop gsm.operator.alpha)
        # Две SIM: свойства — списки по слотам. Слот SIM с мобильными данными:
        # subId из настроек -> sim_id (номер слота) в siminfo.
        slot=""
        case "$num" in
            *,*)
                sub=$(settings get global multi_sim_data_call 2>/dev/null)
                case "$sub" in
                    ''|*[!0-9]*) ;;
                    *) slot=$(content query --uri content://telephony/siminfo --projection sim_id \
                              --where "_id=$sub" 2>/dev/null | sed -n 's/.*sim_id=\([0-9]*\).*/\1/p' | head -1) ;;
                esac ;;
        esac
        n=$(pick "$num" "$slot")
        case "$n" in [0-9][0-9][0-9][0-9][0-9]|[0-9][0-9][0-9][0-9][0-9][0-9]) ;; *)
            # сеть ещё не зарегистрирована — по SIM
            n=$(pick "$(getprop gsm.sim.operator.numeric)" "$slot")
            alpha=$(getprop gsm.sim.operator.alpha) ;;
        esac
        case "$n" in [0-9][0-9][0-9][0-9][0-9]|[0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) exit 0 ;; esac
        a=$(pick "$alpha" "$slot" | clean)
        echo "mobile:$n|${a:-$n}"
        ;;
esac
exit 0
