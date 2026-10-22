#!/system/bin/sh
# Снимок сетевого состояния раз в секунду; печатает только изменения.
# su -c "sh /data/local/tmp/phonemon.sh 300"
DUR=${1:-300}
end=$(( $(date +%s) + DUR ))
prev=""
while [ "$(date +%s)" -lt "$end" ]; do
    cur="addr: $(ip -4 -br addr | grep -E 'wlan|ap|rndis|ncm|rmnet_data|tun' | awk '{print $1"="$3}' | tr '\n' ' ')
rule: $(ip rule | grep -E '^3000:|iif (wlan|ap|rndis|ncm|swlan)[0-9]* lookup' | tr -s '\t ' ' ' | tr '\n' ';')
guard: $(iptables -w -S VPN_TETHER_GUARD 2>/dev/null | grep -- '-A' | tr '\n' ';')
mark: $(iptables -w -t mangle -S VPN_TETHER_MARK 2>/dev/null | grep -- '-i' | tr '\n' ';')
status: $(head -1 /data/adb/modules/vpn-to-hotspot-usb/status 2>/dev/null) | $(tail -1 /data/adb/modules/vpn-to-hotspot-usb/status 2>/dev/null)"
    if [ "$cur" != "$prev" ]; then
        echo "----- $(date '+%H:%M:%S')"
        echo "$cur"
        prev="$cur"
    fi
    sleep 1
done
