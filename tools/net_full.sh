# Полный обзор сети: свежий статус -> провайдер -> подбор (новый критерий) -> Meta через ECS
M=/data/adb/modules/vpn-to-hotspot-usb; T=/data/local/tmp/zs
echo "SSID: $(dumpsys wifi 2>/dev/null | grep -m1 -oE 'mWifiInfo SSID: [^,]+' | cut -d'"' -f2)"
W=$(sed -n 's/^wan=//p' $M/status)
if ! ip -4 addr show "$W" 2>/dev/null | grep -q "inet "; then
  echo "(статус устарел: wan=$W — обновляю)"; r=$(sh $M/webctl.sh apply); t=${r#OK }
  i=0; while [ $i -lt 40 ]; do [ "$(sh $M/webctl.sh ack)" = "$t" ] && break; sleep 0.5; i=$((i+1)); done; sleep 4
fi
cp $M/status $T/status
W=$(sed -n 's/^wan=//p' $M/status)
iptables -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
echo "wan=$W $(ip -4 -o addr show $W | grep -oE 'inet [0-9.]+') v6=$(ip -6 addr show $W scope global | grep -c inet6) :: $(curl -s -m 8 --interface $W 'http://ip-api.com/line/?fields=query,isp,as,city' | tr '\n' ' ')"
iptables -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN
sed -i "s#^M=.*#M=$T#" /data/local/tmp/net_survey.sh
sh /data/local/tmp/net_survey.sh "$1"
sed -i "s#^M=.*#M=$M#" /data/local/tmp/net_survey.sh
echo "-- не открыла каждая стратегия:"; sh /data/local/tmp/det.sh | cut -c1-150
echo "-- Meta через ECS (Амстердам):"; sh /data/local/tmp/igecs.sh | sed -n '/185.15.56/,/1.2.3/p' | grep -v '^ECS 1.2.3'
