M=/data/adb/modules/vpn-to-hotspot-usb; W=$(sed -n 's/^wan=//p' $M/status); CA=/apex/com.android.conscrypt/cacerts
iptables -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
iptables -t mangle -I VPN_ZAPRET 1 -m owner --uid-owner 0 -j RETURN 2>/dev/null
for n in www.instagram.com scontent.cdninstagram.com www.facebook.com static.xx.fbcdn.net; do
  for r in "dns.google/resolve" "cloudflare-dns.com/dns-query" "dns.comss.one/dns-query"; do
    out=""; for i in 1 2 3; do
      a=$(curl -s -m 6 --interface $W --capath $CA -H 'accept: application/dns-json' "https://$r?name=$n&type=A" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | grep -oE '[0-9.]+' | head -1)
      out="$out ${a:-—}"; done
    echo "$n @ ${r%%/*}:$out"
  done
done
iptables -t mangle -D VPN_ZAPRET -m owner --uid-owner 0 -j RETURN 2>/dev/null
iptables -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN
