"""Тест watchdog на настоящем демоне (режим VPN): ломаем правила, как netd,
и смотрим (а) через сколько модуль чинит, (б) утекает ли трафик ноута мимо VPN.
"""
import os, subprocess, sys, time

ADB = os.path.expandvars(r'%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe')
ENV = dict(os.environ, MSYS_NO_PATHCONV='1', PYTHONIOENCODING='utf-8')
VPN_IP = sys.argv[1]
HERE = os.path.dirname(os.path.abspath(__file__))


def adb(cmd):
    assert "'" not in cmd
    return subprocess.run([ADB, 'shell', f"su -c '{cmd}'"], capture_output=True, text=True, env=ENV).stdout.strip()


def state():
    r = adb('ip rule | grep -c ^3000: ; iptables -w -S FORWARD | grep -c VPN_TETHER_GUARD')
    return r.replace('\n', '/')


mon = subprocess.Popen([sys.executable, '-u', os.path.join(HERE, 'leakmon.py'), '115', VPN_IP],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=ENV, encoding='utf-8')
T0 = time.time()
log_start = adb('wc -l < /data/local/tmp/vpn_tether.log')
time.sleep(8)


def step(name, cmd, wait):
    t = time.time() - T0
    adb(cmd)
    print(f'[+{t:5.1f}s] >>> {name}; rule3000/guardhook = {state()}', flush=True)
    end = time.time() + wait
    fixed = None
    while time.time() < end:
        s = state()
        if s == '1/1' and fixed is None:
            fixed = time.time() - T0 - t
            print(f'[+{time.time() - T0:5.1f}s]     восстановлено модулем через {fixed:.1f}с', flush=True)
        time.sleep(0.5)
    if fixed is None:
        print(f'          НЕ восстановлено за {wait}с (сейчас {state()})', flush=True)


step('4a: удалено ip rule pref 3000', 'ip rule del pref 3000', 25)
step('4b: удалён переход FORWARD -> VPN_TETHER_GUARD', 'iptables -w -D FORWARD -j VPN_TETHER_GUARD', 25)
step('4c: удалено и правило, и guard', 'ip rule del pref 3000; iptables -w -D FORWARD -j VPN_TETHER_GUARD', 30)

out, _ = mon.communicate(timeout=60)
print('\n--- leakmon (ноут):')
for line in out.splitlines():
    line = line.replace('не VPN IP', 'не VPN IP')
    print('  ' + line)
ev = adb(f'tail -n +{int(log_start or 0) + 1} /data/local/tmp/vpn_tether.log | grep -E "WATCHDOG|Kill-switch|Setup VPN|VPN setup complete|ERROR|WARNING"')
print('\n--- события модуля:\n' + '\n'.join('  ' + l[:140] for l in ev.splitlines()))
