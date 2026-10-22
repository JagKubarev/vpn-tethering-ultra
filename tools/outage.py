"""Тест отката DoH на НАСТОЯЩЕМ демоне (раздача в direct).

Клиент (этот ноут) шлёт DNS раз в секунду (уникальное имя — мимо кэша);
на телефоне на BLOCK_S секунд режем comss только для dnsproxy (gid 3999).
Печатает поминутную картину: ответил ли DNS и за сколько, + события модуля.
"""
import os, random, socket, struct, subprocess, sys, threading, time

ADB = os.path.expandvars(r'%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe')
ENV = dict(os.environ, MSYS_NO_PATHCONV='1')
GW = sys.argv[1]
BLOCK_S = int(sys.argv[2]) if len(sys.argv) > 2 else 60
AFTER_S = int(sys.argv[3]) if len(sys.argv) > 3 else 50
COMSS = '195.133.25.16 212.109.195.93 83.220.169.155 94.250.253.55'
T0 = time.time()


def adb(cmd):
    # одной строкой в кавычках: иначе su -c получает только первую команду до ';'
    assert "'" not in cmd
    return subprocess.run([ADB, 'shell', f"su -c '{cmd}'"], capture_output=True, text=True, env=ENV).stdout.strip()


def q(name, timeout=5):
    pkt = os.urandom(2) + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + \
        b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00\x00\x01\x00\x01'
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    t = time.time()
    try:
        s.sendto(pkt, (GW, 53)); r, _ = s.recvfrom(2048)
        return int((time.time() - t) * 1000), r[3] & 15
    except socket.timeout:
        return None, None
    finally:
        s.close()


samples = []
stop = False


def client():
    while not stop:
        t = time.time() - T0
        ms, rc = q(f'c{random.randint(10**7, 10**8)}.example.com')
        samples.append((t, ms, rc))
        time.sleep(max(0, 1 - (time.time() - T0 - t)))


th = threading.Thread(target=client, daemon=True); th.start()
log_start = adb('wc -l < /data/local/tmp/vpn_tether.log')
time.sleep(8)
block_cmd = '; '.join(f'iptables -w -I OUTPUT 1 -m owner --gid-owner 3999 -d {ip} -j DROP' for ip in COMSS.split())
tb = time.time() - T0
adb(block_cmd)
print(f'[+{tb:5.1f}s] >>> comss режется для dnsproxy (gid 3999), правил: {adb("iptables -w -S OUTPUT | grep -c gid-owner")}', flush=True)
time.sleep(BLOCK_S)
tu = time.time() - T0
adb('; '.join(f'iptables -w -D OUTPUT -m owner --gid-owner 3999 -d {ip} -j DROP' for ip in COMSS.split()))
print(f'[+{tu:5.1f}s] >>> comss снова доступен', flush=True)
time.sleep(AFTER_S)
stop = True; th.join(timeout=6)
left = adb('iptables -w -S OUTPUT | grep -c "gid-owner 3999"')

# картина по 5-секундным окнам
print('\nклиентский DNS (окна по 5с): ok/всего, медиана мс')
for w in range(0, int(samples[-1][0]) + 1, 5):
    win = [s for s in samples if w <= s[0] < w + 5]
    if not win:
        continue
    ok = [s for s in win if s[1] is not None and s[2] in (0, 3)]
    med = sorted(s[1] for s in ok)[len(ok) // 2] if ok else '-'
    mark = ' <- блок' if tb <= w + 5 and w < tu else ''
    print(f'  {w:4d}-{w + 5:<4d}s  {len(ok)}/{len(win)}  {med}{mark}')
fails = [s for s in samples if s[1] is None or s[2] not in (0, 3)]
if fails:
    print(f'неудачные запросы: {len(fails)}, с +{fails[0][0]:.0f}s по +{fails[-1][0]:.0f}s')
else:
    print('неудачных запросов: 0')
ev = adb(f'tail -n +{int(log_start or 0) + 1} /data/local/tmp/vpn_tether.log | grep -E "DoH|dnsproxy|DNS ->|WARNING|ERROR|WATCHDOG"')
print('\nсобытия модуля:\n' + '\n'.join('  ' + l[:150] for l in ev.splitlines()))
print(f'\nтестовых правил осталось: {left}')
