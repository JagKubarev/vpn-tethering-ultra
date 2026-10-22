"""Проверка раздачи со стороны клиента (ноута).

    python check.py vpn|direct

Печатает внешний IP (TCP и UDP/STUN), куда реально уходят DNS-запросы,
перехват DNS мимо шлюза и ответ для домена, который comss подменяет.
Ничего не меняет — только запросы.
"""
import json, os, random, socket, struct, subprocess, sys, time, urllib.request

MODE = sys.argv[1] if len(sys.argv) > 1 else 'vpn'


def gateway():
    out = subprocess.run(['powershell', '-NoProfile', '-Command',
                          '(Get-NetIPConfiguration | ? { $_.IPv4DefaultGateway } | select -First 1).IPv4DefaultGateway.NextHop'],
                         capture_output=True, text=True).stdout.strip()
    return out


def dns(server, name, qtype=1, timeout=4):
    q = os.urandom(2) + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    q += b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00' + struct.pack('>HH', qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t = time.time()
    s.sendto(q, (server, 53))
    r, _ = s.recvfrom(4096)
    s.close()
    ms = int((time.time() - t) * 1000)
    an = struct.unpack('>H', r[6:8])[0]
    i = 12
    while r[i]:
        i += r[i] + 1
    i += 5
    ans = []
    for _ in range(an):
        if r[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while r[i]:
                i += r[i] + 1
            i += 1
        t_, _, _, rl = struct.unpack('>HHIH', r[i:i + 10]); i += 10
        d = r[i:i + rl]; i += rl
        if t_ == 1:
            ans.append(socket.inet_ntoa(d))
        elif t_ == 16:
            ans.append(d[1:].decode(errors='replace'))
    return ms, r[3] & 15, ans


def stun():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    s.sendto(struct.pack('>HHI', 1, 0, 0x2112A442) + os.urandom(12), ('stun.cloudflare.com', 3478))
    r, _ = s.recvfrom(2048)
    i = 20
    while i < len(r):
        t, l = struct.unpack('>HH', r[i:i + 4]); v = r[i + 4:i + 4 + l]
        if t == 0x20:
            return socket.inet_ntoa(bytes(a ^ b for a, b in zip(v[4:8], b'\x21\x12\xa4\x42')))
        i += 4 + l + (-l % 4)


results = []


def check(name, ok, detail):
    results.append(ok)
    print(f'  {"OK  " if ok else "FAIL"} {name:42s} {detail}')


gw = gateway()
print(f'== режим {MODE}, шлюз {gw}')
try:
    info = json.loads(urllib.request.urlopen('http://ip-api.com/json/?fields=query,isp,mobile,hosting', timeout=8).read())
except Exception as e:
    info = {'query': f'ERR {e}'}
tcp_ip = info.get('query')
if MODE == 'vpn':
    check('TCP выход через VPN (хостинг, не мобильный)', info.get('hosting') and not info.get('mobile'), f"{tcp_ip} {info.get('isp')}")
else:
    check('TCP выход напрямую (оператор)', bool(info.get('mobile')), f"{tcp_ip} {info.get('isp')}")
try:
    u = stun()
    check('UDP (STUN/WebRTC) тот же IP, что TCP', u == tcp_ip, u)
except Exception as e:
    check('UDP (STUN/WebRTC)', False, f'ERR {e}')

try:
    ms, rc, a = dns(gw, 'o-o.myaddr.l.google.com', 16)
    ecs = [x for x in a if 'subnet' in x]
    resolver = [x for x in a if 'subnet' not in x]
    if MODE == 'vpn':
        ok = any(tcp_ip and x.split(' ')[-1].startswith('.'.join(tcp_ip.split('.')[:3])) for x in ecs) or not ecs
        check('DNS идёт с VPN-адреса (ECS)', ok, f'{ms}ms {a}')
    else:
        check('DNS резолвер = comss (195.133./212.109./83.220./94.250.)', any(x.startswith(('195.133.', '212.109.', '83.220.', '94.250.')) for x in a), f'{ms}ms {a}')
except Exception as e:
    check('DNS через шлюз', False, f'ERR {e}')

for srv in ('8.8.8.8', '1.1.1.1', '192.0.2.1'):
    try:
        ms, rc, a = dns(srv, f'r{random.randint(10**6, 10**7)}.example.com')
        check(f'DNS на {srv}:53 перехвачен модулем', rc in (0, 3), f'{ms}ms rcode={rc}')
    except Exception as e:
        check(f'DNS на {srv}:53 перехвачен модулем', False, f'ERR {type(e).__name__}')

try:
    ms, rc, a = dns(gw, 'chatgpt.com')
    comss_ip = any(x.startswith(('132.243.', '45.88.', '157.22.', '95.81.')) for x in a)
    if MODE == 'direct':
        check('chatgpt.com -> прокси comss', comss_ip, f'{ms}ms {a}')
    else:
        check('chatgpt.com резолвится', rc == 0 and bool(a), f'{ms}ms {a}')
except Exception as e:
    check('chatgpt.com', False, f'ERR {e}')

print(f'== итого: {sum(results)}/{len(results)} OK')
sys.exit(0 if all(results) else 1)
