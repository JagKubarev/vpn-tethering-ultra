awk -F'|' '{print $1 " " $6 " :: " $7 "  <<  " substr($5,1,90)}' /data/local/tmp/vpn_tether_zscan.results
