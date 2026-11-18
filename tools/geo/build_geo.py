# Гео-список имён для DNS модуля (module/dns/geo.txt) из списка сервисов dns.zapret.moe.
#   python -I -X utf8 tools/geo/build_geo.py services.json svc.json > module/dns/geo.txt
# services.json — сервисы и их имена (hosts: [имя, корень]); svc.json — как сервис открывается через их прокси.
# Берём корневые домены (dnsproxy [/домен/] — с поддоменами) и имена без корня; сервисы, которые прокси сейчас
# не пропускает (refused, not_relayed, challenge, transport_fail), — нет: гео-DoH для них только навредит.
import json, sys, datetime

SKIP_HOSTS = {'o.pki.goog'}   # проверка сертификатов Google — не через чужой прокси

services = json.load(open(sys.argv[1], encoding='utf-8'))
state = json.load(open(sys.argv[2], encoding='utf-8'))
st = state.get('services', {})
names, skipped = set(), []
for s in services:
    v = st.get(s.get('domain'), {}).get('v', 'open')
    if v != 'open':
        skipped.append('%s (%s)' % (s['name'], v))
        continue
    for host, root in s.get('hosts', []):
        n = (root or host).strip().lower().rstrip('.')
        if n and n not in SKIP_HOSTS:
            names.add(n)
# имя, которое уже покрыто своим корнем из списка, — лишнее
def covered(n):
    p = n.split('.')
    return any('.'.join(p[i:]) in names for i in range(1, len(p) - 1))
final = sorted(n for n in names if not covered(n))
out = sys.stdout
out.write('# Гео-список: эти имена DNS модуля спрашивает у гео-DoH (DNS_GEO_UPSTREAMS), остальные — у основного.\n')
out.write('# Источник — список сервисов dns.zapret.moe (services.json, svc.json) на %s; собран tools/geo/build_geo.py.\n'
          % state.get('checked_at', datetime.date.today().isoformat())[:10])
out.write('# Домен — с поддоменами. Без сервисов, которые их прокси тогда не пропускал: %s.\n'
          % ', '.join(skipped))
out.write('# Свои имена — в DNS_GEO_DOMAINS (vpn_tether.conf / WebUI), не здесь: файл заменяется при обновлении.\n')
for n in final:
    out.write(n + '\n')
sys.stderr.write('имён: %d, без сервисов: %d\n' % (len(final), len(skipped)))
