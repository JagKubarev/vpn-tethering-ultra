import sys

p = sys.argv[1]
s = open(p, encoding='utf-8').read()


def rep(old, new):
    global s
    assert s.count(old) == 1, (old[:70], s.count(old))
    s = s.replace(old, new)


rep(r"""  'STATUS_IN_DESCRIPTION','QUIC_BLOCK_APPS'];""",
    r"""  'STATUS_IN_DESCRIPTION','QUIC_BLOCK_APPS','ZAPRET_ENABLE','ZAPRET_MODE','ZAPRET_PHONE','ZAPRET_STRATEGY','ZAPRET_QUIC_BLOCK'];""")

rep(r"""  if (s.quic_uids) h += kvRow('Без QUIC',""",
    r"""  if (s.zapret === 'on') h += kvRow('Обход DPI', 'включён' + (+s.zapret_auto > 0 ? ', найдено сайтов: ' + esc(s.zapret_auto) : ''), 'green');
  else if (s.zapret === 'fail') h += kvRow('Обход DPI', 'nfqws не запустился, повтор через минуту', 'red');
  if (s.quic_uids) h += kvRow('Без QUIC',""")

rep(r"""function changedKeys() { return KEYS.filter((k) => (CUR[k] || '') !== (saved(k) || '')); }
function renderBar() {
  const n = changedKeys().length;""",
    r"""function changedKeys() { return KEYS.filter((k) => (CUR[k] || '') !== (saved(k) || '')); }
const normList = (t) => t.toLowerCase().split(/[\s,;]+/).filter(Boolean).join('\n');
let ZL_SAVED = '';
const zlistDirty = () => normList($('#zlist').value) !== ZL_SAVED;
function renderBar() {
  const n = changedKeys().length + (zlistDirty() ? 1 : 0);""")

rep(r"""$('#directDoh').addEventListener('change',""",
    r"""$('#zlist').addEventListener('input', () => { $('#zlistErr').style.display = 'none'; renderBar(); });
$('#directDoh').addEventListener('change',""")

rep(r"""    for (const k of changedKeys()) {""",
    r"""    if (zlistDirty()) {
      const r = await ctl('zlist-set ' + q(normList($('#zlist').value)));
      if (!/^OK/.test(r.out.trim())) {
        const e = $('#zlistErr'); e.textContent = r.out.trim().replace(/^ERR /, '') || 'ошибка'; e.style.display = '';
        toast('Список сайтов: ' + e.textContent); return;
      }
    }
    for (const k of changedKeys()) {""")

rep(r"""    await loadConf(); await loadStatus();
  } finally {""",
    r"""    await loadConf(); await loadZ(); await loadStatus();
  } finally {""")

rep(r"""$('#revertBtn').addEventListener('click', () => { KEYS.forEach((k) => { CUR[k] = saved(k); }); renderForm(); });""",
    r"""$('#revertBtn').addEventListener('click', () => { KEYS.forEach((k) => { CUR[k] = saved(k); }); $('#zlist').value = ZL_SAVED; renderForm(); });""")

rep(r"""// ---------------------------------------------------------------- старт""",
    r"""// ---------------------------------------------------------------- zapret: списки и проверка
async function loadZ() {
  const [u, d, a] = await Promise.all([ctl('zlist'), ctl('zdefault'), ctl('zauto')]);
  ZL_SAVED = normList(u.out);
  $('#zlist').value = ZL_SAVED;
  const dl = d.out.split('\n').filter(Boolean), al = a.out.split('\n').filter(Boolean);
  $('#zdef').textContent = dl.join('\n'); $('#zdefN').textContent = dl.length;
  $('#zauto').textContent = al.join('\n') || 'пока пусто'; $('#zautoN').textContent = al.length;
  renderBar();
}
$('#zautoClear').addEventListener('click', async () => {
  if (!confirm('Очистить список сайтов, найденных автоматически?')) return;
  await ctl('zauto-clear'); await loadZ(); toast('Автосписок очищен');
});

const ST_RC = { '28': 'нет ответа (молча режут)', '35': 'обрыв при установке HTTPS', '7': 'не подключается (блок по IP?)',
  '6': 'адрес не найден', '60': 'чужой сертификат (подмена)', '56': 'соединение сброшено', '52': 'пустой ответ' };
const stOk = (v) => { const m = /^(\d{3}) ([\d.]+) (\d+)/.exec(v || ''); return !!m && m[3] === '0' && m[1] !== '000'; };
function stLine(label, v) {
  const m = /^(\d{3}) ([\d.]+) (\d+)/.exec(v || '');
  if (!m) return '<div class="st-line"><span class="dot"></span>' + label + ': нет данных</div>';
  const ok = stOk(v);
  const t = ok ? 'открывается, ' + (+m[2]).toFixed(1) + ' с' : (ST_RC[m[3]] || 'ошибка ' + esc(m[3]));
  return '<div class="st-line"><span class="dot ' + (ok ? 'green' : 'red') + '"></span>' + label + ': ' + t + '</div>';
}
$('#stBtn').addEventListener('click', async () => {
  const host = $('#stHost').value.trim();
  if (!host) return;
  const btn = $('#stBtn'), res = $('#stRes');
  btn.disabled = true; res.innerHTML = '<span class="muted">Проверяю, до 20 секунд…</span>';
  try {
    const r = await ctl('sitetest ' + q(host));
    const out = r.out.trim();
    if (/^ERR/m.test(out)) {
      res.innerHTML = '<div class="st-line"><span class="dot red"></span>' + esc(out.replace(/^[\s\S]*?ERR /, '')) + '</div>';
      return;
    }
    const o = {};
    out.split('\n').forEach((l) => { const i = l.indexOf(' '); if (i > 0) o[l.slice(0, i)] = l.slice(i + 1); });
    const dOk = stOk(o.direct), zOk = stOk(o.zapret);
    res.innerHTML = stLine('Без обхода', o.direct) + stLine('С обходом', o.zapret) +
      '<div class="muted mt8" style="font-size:13px">' + (dOk ? 'Сайт и так открывается, обход не нужен.'
        : zOk ? 'Обход помогает. В режиме «из списка» добавь сайт в свой список, если его нет во встроенном.'
        : 'С этой стратегией не помогло. Попробуй другую; если ни одна не поможет — скорее всего, блок по IP, тут нужен VPN.') + '</div>';
  } finally { btn.disabled = false; }
});

// ---------------------------------------------------------------- старт""")

rep(r"""  await Promise.all([loadStatus(), loadConf()]);""",
    r"""  await Promise.all([loadStatus(), loadConf(), loadZ()]);""")

# --- предпросмотр без KernelSU
rep(r"""'\ndns_degraded=0\nphone_dns=0""", r"""'\nzapret=on\nzapret_auto=2\ndns_degraded=0\nphone_dns=0""")
rep(r"""D QUIC_BLOCK_APPS=com.avito.android\n' + M.conf };""",
    r"""D QUIC_BLOCK_APPS=\nD ZAPRET_ENABLE=0\nD ZAPRET_MODE=list\nD ZAPRET_PHONE=1\nD ZAPRET_STRATEGY=md5sig\nD ZAPRET_QUIC_BLOCK=1\n' + M.conf };""")
rep(r"""  if (a === 'doh') return { errno: 0, out: 'ok 184' };""",
    r"""  if (a === 'doh') return { errno: 0, out: 'ok 184' };
  if (a === 'zlist') return { errno: 0, out: '' };
  if (a === 'zdefault') return { errno: 0, out: 'youtube.com\ngooglevideo.com\ndiscord.com\nx.com\n' };
  if (a === 'zauto') return { errno: 0, out: 'example.org\nfoo.net\n' };
  if (/^zlist-set /.test(a)) return { errno: 0, out: 'OK 1' };
  if (a === 'zauto-clear') return { errno: 0, out: 'OK' };
  if (/^sitetest /.test(a)) return { errno: 0, out: 'ip 142.251.155.4\ndirect 000 8.001 28\nzapret 200 1.02 0\n' };""")

open(p, 'w', encoding='utf-8', newline='\n').write(s)
print('ok')
