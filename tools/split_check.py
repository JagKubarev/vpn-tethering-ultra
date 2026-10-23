# Проверка разбиения service.sh на lib/ (23.10): собрать обратно и сравнить.
#   python3 tools/split_check.py <старый service.sh> module <куда собрать>
# Тела lib/ подставляются вместо строк подключения (в их порядке, без шапки
# lib-файла) и сравниваются с исходным: строки, функции, верхнеуровневый код.
import re, sys, collections
orig = open(sys.argv[1], encoding='utf-8').read().split('\n')
mod = sys.argv[2]
svc = open(mod + '/service.sh', encoding='utf-8').read().split('\n')
out = []
i = 0
src_re = re.compile(r'^\. "\$MODULE_DIR/lib/([a-z]+)\.sh"$')
libs = []
while i < len(svc):
    l = svc[i]
    if l.startswith('# Функции демона — в lib/'):
        # убираем рамку блока (строка над ним) и комментарии блока
        assert out[-1].startswith('# ----'); out.pop()
        i += 1
        while not svc[i].startswith('# shellcheck source='): i += 1
        continue
    if l.startswith('# shellcheck source=lib/'): i += 1; continue
    m = src_re.match(l)
    if m:
        libs.append(m.group(1))
        body = open(f'{mod}/lib/{m.group(1)}.sh', encoding='utf-8').read().split('\n')
        assert body[-1] == ''; body = body[:-1]
        k = body.index('')            # шапка lib-файла — до первой пустой строки
        assert all(x.startswith('#') for x in body[:k])
        out += body[k+1:]
        i += 1; continue
    out.append(l); i += 1
open(sys.argv[3], 'w', encoding='utf-8', newline='\n').write('\n'.join(out))
print('порядок подключения:', ' '.join(libs))
print('строк: исходный', len(orig), '/ собранный', len(out))
print('мультимножество строк совпадает:', collections.Counter(orig) == collections.Counter(out))

FN = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\(\) *\{')
def parse(lines):
    funcs, top, n = {}, [], 0
    while n < len(lines):
        l = lines[n]; m = FN.match(l)
        if m:
            name = m.group(1)
            if re.search(r'\}\s*(#.*)?$', l) and l.count('{') == l.count('}'):
                body = [l]; n += 1
            else:
                body = [l]; n += 1
                while lines[n] != '}': body.append(lines[n]); n += 1
                body.append('}'); n += 1
            assert name not in funcs, name
            funcs[name] = body
            top.append(('FUNC', name))
        else:
            top.append(('LINE', l)); n += 1
    return funcs, top
fa, ta = parse(orig); fb, tb = parse(out)
print('функций: было', len(fa), '/ стало', len(fb), '; множества имён равны:', set(fa) == set(fb))
print('тела всех функций побайтно равны:', all(fa[k] == fb[k] for k in fa))
code = lambda t: [x for x in t if x[0] == 'LINE' and x[1].strip() and not x[1].lstrip().startswith('#')]
print('верхнеуровневый код (без комментариев/пустых) в том же порядке:', code(ta) == code(tb), '(%d строк)' % len(code(ta)))
