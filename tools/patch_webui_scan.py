import sys

p = sys.argv[1]
s = open(p, encoding='utf-8').read()


def rep(old, new):
    global s
    assert s.count(old) == 1, (old[:70], s.count(old))
    s = s.replace(old, new)


# --- стратегия: вариант "своя" + поле аргументов
rep(r"""      <option value="disorder">4 · disorder, без подделок</option>
    </select>
  </div>""", r"""      <option value="disorder">4 · disorder, без подделок</option>
      <option value="custom">Своя (из подбора)</option>
    </select>
    <div id="zArgsBox" style="display:none">
      <input type="text" data-key="ZAPRET_ARGS" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="--dpi-desync=...">
      <div class="s muted" style="font-size:12px;margin-top:4px">Только параметры --dpi-desync…; @G — встроенная подделка ClientHello google.com.</div>
    </div>
  </div>""")

# --- карточка подбора после "Проверить сайт"
rep(r"""  <div id="stRes" class="mt8" style="font-size:14px"></div>
</div>""", r"""  <div id="stRes" class="mt8" style="font-size:14px"></div>
</div>
<div class="card pad" style="margin-top:10px">
  <div class="t" style="font-weight:500">Подбор стратегии</div>
  <div class="s muted" style="font-size:13px;margin-top:2px">Перебирает стратегии и проверяет их на твоём операторе по сайтам ниже. Работает в фоне, страницу можно закрыть. Трафик телефона и раздачи не трогается.</div>
  <textarea id="scSites" rows="2" autocapitalize="off" autocorrect="off" spellcheck="false"></textarea>
  <div class="btn-row mt8">
    <button class="btn" id="scQuick">Быстрый · ~2 мин</button>
    <button class="btn" id="scFull">Полный · ~7 мин</button>
    <button class="btn" id="scStop" style="display:none">Остановить</button>
  </div>
  <div id="scProg" class="mt8" style="font-size:14px"></div>
  <div id="scRes" class="mt8"></div>
</div>""")

rep(r"""  'STATUS_IN_DESCRIPTION','QUIC_BLOCK_APPS','ZAPRET_ENABLE','ZAPRET_MODE','ZAPRET_PHONE','ZAPRET_STRATEGY','ZAPRET_QUIC_BLOCK'];""",
    r"""  'STATUS_IN_DESCRIPTION','QUIC_BLOCK_APPS','ZAPRET_ENABLE','ZAPRET_MODE','ZAPRET_PHONE','ZAPRET_STRATEGY','ZAPRET_ARGS','ZAPRET_QUIC_BLOCK'];""")

# поле аргументов видно только для "своей"
rep(r"""function renderDeps() {
  $$('[data-dep]').forEach((row) => { row.classList.toggle('off', CUR[row.dataset.dep] !== '1'); });
}""", r"""function renderDeps() {
  $$('[data-dep]').forEach((row) => { row.classList.toggle('off', CUR[row.dataset.dep] !== '1'); });
  $('#zArgsBox').style.display = CUR.ZAPRET_STRATEGY === 'custom' ? '' : 'none';
}""")

rep(r"""// ---------------------------------------------------------------- старт""", r"""// ---------------------------------------------------------------- подбор стратегии
const SC_DEFAULT = 'www.youtube.com i.ytimg.com discord.com gateway.discord.gg x.com www.facebook.com rutracker.org www.linkedin.com ya.ru www.google.com';
$('#scSites').value = SC_DEFAULT;
let scTimer = null;

function stratLabel(a) {
  const g = (re) => { const m = re.exec(a); return m ? m[1] : ''; };
  const mode = g(/--dpi-desync=(\S+)/).replace(/,/g, ' + ');
  const fool = g(/--dpi-desync-fooling=(\S+)/) || (g(/--dpi-desync-ttl=(\d+)/) ? 'ttl ' + g(/--dpi-desync-ttl=(\d+)/) : '') || (/--dpi-desync-autottl/.test(a) ? 'autottl' : '');
  const pos = g(/--dpi-desync-split-pos=(\S+)/);
  const ex = [];
  if (/seqovl=/.test(a)) ex.push('seqovl');
  if (/sni=/.test(a)) ex.push('sni google');
  else if (/fake-tls-mod=rnd/.test(a)) ex.push('случайный ClientHello');
  const rep = g(/--dpi-desync-repeats=(\d+)/); if (rep) ex.push('×' + rep);
  return [mode, fool, pos && 'разрез ' + pos].concat(ex).filter(Boolean).join(' · ');
}

function scAggregate(text, blockedN) {
  const by = {};
  text.split('\n').filter(Boolean).forEach((l) => {
    const f = l.split('|'); if (f.length < 6) return;
    const a = f[4], ok = +f[0], ns = +f[1], brk = +f[2], ms = +f[3];
    const r = by[a] || (by[a] = { a, runs: 0, minOk: 1e9, maxBrk: 0, ms: 0, ns, det: '' });
    r.runs++; r.minOk = Math.min(r.minOk, ok); r.maxBrk = Math.max(r.maxBrk, brk); r.ms += ms; r.det = f[6] || r.det;
  });
  return Object.values(by).map((r) => {
    r.ms = Math.round(r.ms / r.runs);
    r.open = Math.max(0, r.minOk - (r.ns - blockedN));   // из заблокированных
    return r;
  }).sort((x, y) => (x.maxBrk > 0) - (y.maxBrk > 0) || y.open - x.open || y.runs - x.runs || x.ms - y.ms);
}

async function scRefresh() {
  const [st, rs] = await Promise.all([ctl('zscan-status'), ctl('zscan-results')]);
  const s = parseKV(st.out);
  const running = s.alive === '1';
  $('#scStop').style.display = running ? '' : 'none';
  $('#scQuick').disabled = $('#scFull').disabled = running;
  const blocked = (s.blocked || '').split(/\s+/).filter(Boolean);
  let prog = '';
  if (s.state === 'running' || running) {
    prog = '<div class="st-line"><span class="dot amber"></span>' + esc(s.stage || 'идёт') +
      (+s.total ? ' · ' + esc(s.done) + ' из ' + esc(s.total) : '') + '</div>';
  } else if (s.state === 'done') {
    prog = '<div class="st-line"><span class="dot green"></span>Готово' + (s.msg ? ': ' + esc(s.msg) : '') + '</div>';
  } else if (s.state === 'error') {
    prog = '<div class="st-line"><span class="dot red"></span>' + esc(s.msg || 'ошибка') + '</div>';
  } else if (s.state === 'stopped') {
    prog = '<div class="st-line"><span class="dot"></span>Остановлено</div>';
  }
  if (blocked.length) prog += '<div class="muted" style="font-size:13px;margin-top:4px">Заблокировано без обхода: ' + esc(blocked.join(', ')) + '</div>';
  $('#scProg').innerHTML = prog;

  const rows = scAggregate(rs.out, blocked.length).slice(0, 8);
  $('#scRes').innerHTML = rows.length ? rows.map((r, i) => {
    const full = r.maxBrk === 0 && r.open === blocked.length && blocked.length > 0;
    const dot = r.maxBrk > 0 ? 'red' : full ? 'green' : r.open > 0 ? 'amber' : '';
    const info = r.maxBrk > 0 ? 'ломает обычные сайты' : 'открыл ' + r.open + ' из ' + blocked.length + (r.ms ? ' · ' + (r.ms / 1000).toFixed(1) + ' с' : '') + (r.runs > 1 ? ' · проверена ' + r.runs + '×' : '');
    return '<div class="row" style="padding:10px 0;border-top:' + (i ? '1px solid var(--line)' : '0') + '">' +
      '<span class="dot ' + dot + '"></span><div class="txt"><div class="t" style="font-size:14px">' + esc(stratLabel(r.a)) + '</div>' +
      '<div class="s">' + esc(info) + (r.det && !full ? ' · не открылись: ' + esc(r.det) : '') + '</div></div>' +
      (r.maxBrk === 0 && r.open > 0 ? '<button class="btn small" data-apply="' + esc(r.a) + '">Применить</button>' : '') + '</div>';
  }).join('') : '';

  clearTimeout(scTimer);
  if (running) scTimer = setTimeout(scRefresh, 3000);
}

async function scStart(mode) {
  const r = await ctl('zscan-start ' + mode + ' ' + q($('#scSites').value.trim().replace(/\s+/g, ' ')));
  if (!/^OK/.test(r.out.trim())) { toast(r.out.trim().replace(/^ERR /, '') || 'Не запустился'); return; }
  $('#scRes').innerHTML = ''; setTimeout(scRefresh, 800);
}
$('#scQuick').addEventListener('click', () => scStart('quick'));
$('#scFull').addEventListener('click', () => scStart('full'));
$('#scStop').addEventListener('click', async () => { await ctl('zscan-stop'); setTimeout(scRefresh, 800); });
$('#scRes').addEventListener('click', (e) => {
  const a = e.target.dataset && e.target.dataset.apply; if (!a) return;
  CUR.ZAPRET_STRATEGY = 'custom'; CUR.ZAPRET_ARGS = a; CUR.ZAPRET_ENABLE = '1';
  renderForm();
  $('#applyBtn').click();
});

// ---------------------------------------------------------------- старт""")

rep(r"""  await Promise.all([loadStatus(), loadConf(), loadZ()]);""",
    r"""  await Promise.all([loadStatus(), loadConf(), loadZ()]);
  scRefresh();""")

# предпросмотр
rep(r"""  if (/^sitetest /.test(a))""", r"""  if (a === 'zscan-status') return { errno: 0, out: 'state=done\nmode=quick\ndone=21\ntotal=21\nstage=готово\nmsg=\nblocked=www.youtube.com i.ytimg.com discord.com gateway.discord.gg x.com www.facebook.com rutracker.org www.linkedin.com\nalive=0\n' };
  if (a === 'zscan-results') return { errno: 0, out:
    '10|10|0|980|--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@G|быстрый|\n' +
    '10|10|0|1020|--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@G|проверка|\n' +
    '7|10|0|900|--dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld|быстрый| facebook.com:x35 rutracker.org:x35 linkedin.com:x35\n' +
    '0|10|2|0|--dpi-desync=fake,multisplit --dpi-desync-autottl --dpi-desync-split-pos=1 --dpi-desync-fake-tls=@G|быстрый| ya.ru:x28 google.com:x28\n' };
  if (/^zscan-start /.test(a)) return { errno: 0, out: 'OK' };
  if (/^sitetest /.test(a))""")
rep(r"""D ZAPRET_STRATEGY=md5sig\nD ZAPRET_QUIC_BLOCK=1\n""", r"""D ZAPRET_STRATEGY=md5sig\nD ZAPRET_ARGS=\nD ZAPRET_QUIC_BLOCK=1\n""")

open(p, 'w', encoding='utf-8', newline='\n').write(s)
print('ok')
