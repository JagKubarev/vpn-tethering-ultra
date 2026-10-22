import sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
def rep(old, new):
    global s
    assert s.count(old) == 1, (old[:70], s.count(old))
    s = s.replace(old, new)
rep('''    [ -n "$current_wan" ] && LAST_WAN_IFACE="$current_wan"
    [ -n "$current_wan_ip" ] && LAST_WAN_IP="$current_wan_ip"
    [ -n "$current_gw" ] && LAST_WAN_GW="$current_gw"
    [ -z "$LAST_WAN_IFACE" ] && LAST_WAN_IFACE="$current_wan"
''', '''    [ -n "$current_wan" ] && LAST_WAN_IFACE="$current_wan"
    [ -n "$current_wan_ip" ] && LAST_WAN_IP="$current_wan_ip"
    [ -n "$current_gw" ] && LAST_WAN_GW="$current_gw"
    [ -z "$LAST_WAN_IFACE" ] && LAST_WAN_IFACE="$current_wan"
    # В VPN-режиме смена сети обходится без пересборки -> update_status не
    # звался, и в status оставался старый wan= (WebUI-проверки шли через
    # интерфейс без адреса). Обновляем статус на любой смене сети.
    $net_diff && phone_status_refresh
''')
open(p, 'w', encoding='utf-8', newline='\n').write(s)
p = 'zapret/scan.sh'
s = open(p, encoding='utf-8').read()
rep('''[ -n "$WAN" ] || { st state=error msg="модуль ещё не видел сеть оператора"; exit 1; }''',
'''[ -n "$WAN" ] || { st state=error msg="модуль ещё не видел сеть оператора"; exit 1; }
ip -4 addr show "$WAN" 2>/dev/null | grep -q "inet " || { st state=error msg="у $WAN нет адреса — сеть только что сменилась? Повтори через полминуты"; exit 1; }''')
rep('''st blocked="$(echo $BLOCKED)"''', '''st blocked="$(echo $BLOCKED)"
[ -n "$BASE_OK" ] || { st state=error msg="через $WAN не открылся ни один сайт, даже без блокировок — нет интернета или сеть сменилась"; exit 1; }''')
rep('''    0) echo "--dpi-desync=fake,multidisorder --dpi-desync-autottl --dpi-desync-split-pos=midsld $FAKE"''', '''XX''') if False else None
open(p, 'w', encoding='utf-8', newline='\n').write(s)
print('ok')
