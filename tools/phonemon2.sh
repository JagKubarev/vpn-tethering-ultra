#!/system/bin/sh
# Раз в 2с: tun, статус модуля, чей DNS у самого телефона (comss -> ai-pool / 132.243.x)
DUR=${1:-180}; end=$(( $(date +%s) + DUR ))
while [ "$(date +%s)" -lt "$end" ]; do
  n="x$RANDOM$RANDOM.openai.com"
  r=$(ping -c1 -W1 "$n" 2>&1 | head -1 | sed -E 's/^PING [^ ]+ \(([0-9.]+)\).*/\1/; s/^ping: .*/НЕ резолвится/')
  case "$r" in 132.243.*|45.88.*|157.22.*|95.81.*) who="comss" ;; "НЕ резолвится") who="-" ;; *) who="другой" ;; esac
  tun=$(ip -4 -br addr show tun0 2>/dev/null | awk '{print $3}')
  st=$(head -1 /data/adb/modules/vpn-to-hotspot-usb/status | cut -c1-60)
  echo "$(date +%H:%M:%S) tun=${tun:-нет} | DNS телефона: $who ($r) | $st"
  sleep 2
done
