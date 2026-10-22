"""Леак-монитор со стороны клиента хотспота.

Раз в ~0.5с спрашивает внешний IP по UDP (STUN) и раз в ~1с по HTTP
(новое TCP-соединение каждый раз, чтобы видеть текущую маршрутизацию,
а не старый conntrack). Печатает только смены состояния + сводку.

    python leakmon.py [секунд] [ожидаемый_VPN_IP]
"""
import os, socket, struct, sys, threading, time, urllib.request

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 300
VPN_IP = sys.argv[2] if len(sys.argv) > 2 else None

lock = threading.Lock()
last = {}
seen = {}


def stun(host='stun.l.google.com', port=19302):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    try:
        s.sendto(struct.pack('>HHI', 1, 0, 0x2112A442) + os.urandom(12), (host, port))
        r, _ = s.recvfrom(2048)
    finally:
        s.close()
    i = 20
    while i < len(r):
        t, l = struct.unpack('>HH', r[i:i + 4])
        v = r[i + 4:i + 4 + l]
        if t == 0x20:
            return socket.inet_ntoa(bytes(a ^ b for a, b in zip(v[4:8], b'\x21\x12\xa4\x42')))
        i += 4 + l + (-l % 4)


def http():
    req = urllib.request.Request('http://icanhazip.com', headers={'Connection': 'close'})
    return urllib.request.urlopen(req, timeout=3).read().decode().strip()


def report(kind, val):
    ts = time.strftime('%H:%M:%S') + f'.{int(time.time() * 10) % 10}'
    with lock:
        seen.setdefault(kind, {}).setdefault(val, 0)
        seen[kind][val] += 1
        if last.get(kind) != val:
            mark = ''
            if VPN_IP and val not in (VPN_IP, 'ERR') and not val.startswith('ERR'):
                mark = '   <<<<<< LEAK (не VPN IP)'
            print(f'[{ts}] {kind:4s} -> {val}{mark}', flush=True)
            last[kind] = val


def loop(kind, fn, period):
    end = time.time() + DURATION
    while time.time() < end:
        t0 = time.time()
        try:
            val = fn() or 'ERR empty'
        except Exception as e:
            val = 'ERR ' + type(e).__name__
        report(kind, val)
        time.sleep(max(0, period - (time.time() - t0)))


print(f'leakmon: {DURATION}s, VPN_IP={VPN_IP}', flush=True)
th = [threading.Thread(target=loop, args=('udp', stun, 0.5)),
      threading.Thread(target=loop, args=('http', http, 1.0))]
for t in th:
    t.start()
for t in th:
    t.join()
print('=== summary ===')
for k, d in seen.items():
    for v, n in sorted(d.items(), key=lambda x: -x[1]):
        print(f'{k:4s} {v:30s} {n}')
