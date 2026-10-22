"""v2.3: CA для dnsproxy, отдельные апстримы для DNS_VPN=doh, фикс залипшего hard-guard."""
import sys

p = 'service.sh'
s = open(p, encoding='utf-8').read()


def rep(old, new, count=1):
    global s
    n = s.count(old)
    if n != count:
        sys.exit(f'PATCH FAIL ({n} matches): {old[:80]!r}')
    s = s.replace(old, new)


rep(r'''DNS_VPN="dnat"         # VPN-режим:    dnat  = DNAT в DNS из VPN (как раньше)
                       #               cache = DNS из VPN через dnsproxy + кэш
                       #               doh   = DNS_UPSTREAMS через туннель
''', r'''DNS_VPN="dnat"         # VPN-режим:    dnat  = DNAT в DNS из VPN (как раньше; нужен,
                       #                       если VPN-клиент роутит по доменам/fakeip)
                       #               cache = DNS из VPN через dnsproxy + кэш
                       #               doh   = DNS_VPN_UPSTREAMS через туннель + кэш
                       #                       (замер: ~200мс вместо ~550мс, кэш ~5мс)
''')

rep(r'''DNS_FALLBACKS="https://dns.google/dns-query tls://1.1.1.1"
''', r'''DNS_FALLBACKS="https://dns.google/dns-query tls://1.1.1.1"
# Апстримы для DNS_VPN=doh (идут через туннель)
DNS_VPN_UPSTREAMS="https://dns.google/dns-query https://cloudflare-dns.com/dns-query"
''')

rep(r'''    : > "$DNSPROXY_LOG"
    $DNSPROXY_BIN $args -o "$DNSPROXY_LOG" >/dev/null 2>&1 < /dev/null &''', r'''    : > "$DNSPROXY_LOG"
    # Статический Go не находит CA Android 14+ (лежат в APEX conscrypt) ->
    # "x509: certificate signed by unknown authority". Только системные CA:
    # пользовательские (cacerts-added, напр. AdGuard HTTPS-фильтр) не берём.
    SSL_CERT_DIR="/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts" \
        $DNSPROXY_BIN $args -o "$DNSPROXY_LOG" >/dev/null 2>&1 < /dev/null &''')

rep(r'''            doh)   want="doh";   ups="$DNS_UPSTREAMS" ;;
        esac''', r'''            doh)   want="doh";   ups="$DNS_VPN_UPSTREAMS" ;;
        esac
        # Каждая пересборка VPN = новый экземпляр: keep-alive DoH-соединение
        # могло открыться через WAN, пока tun пропадал, и так бы и осталось.
        DNSPROXY_SIG=""''')

rep(r'''#   - dnsproxy упал и не поднялся -> откат на обычный DNAT, клиенты не без DNS.
''', r'''#   - dnsproxy упал и не поднялся -> откат на обычный DNAT, клиенты не без DNS.
#   - CA для Go-бинаря берутся из APEX conscrypt (Android 14+), только системные.
#   - ФИКС (жил с 3.9.4): после кратковременного обрыва VPN без смены tun
#     guard оставался в hard навсегда — раздача без интернета до ребута/тоггла.
''')

open(p, 'w', encoding='utf-8', newline='\n').write(s)
print('patched OK')
