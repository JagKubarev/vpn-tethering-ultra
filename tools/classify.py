# Разбор вывода blockscan.sh: host|ip|tcp|direct|zapret
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
cat = {}
for l in open(sys.argv[1], encoding='utf-8'):
    h, ip, t, d, z = (l.rstrip('\n').split('|') + [''] * 5)[:5]
    if not ip: v = 'нет A-записи'
    elif not d: v = '?'
    else:
        code, _, _, rc = d.split()
        if rc == '0': v = 'открыт'; h += f' ({code})'
        elif t in ('', '0', '0.000000'): v = 'блок по IP (TCP не устанавливается)'
        elif z:
            zc, _, _, zrc = z.split()
            if zrc == '0': v = 'по имени → zapret открывает'; h += f' ({zc})'
            else: v = 'по имени, zapret НЕ помог'; h += f' (rc{zrc})'
        else: v = '?'
    cat.setdefault(v, []).append(h)
for k, v in cat.items():
    print(f'== {k}: {len(v)}\n   ' + ', '.join(v))
