import sys
s = open('service.sh', encoding='utf-8').read()
def rep(old, new, src=None):
    global s
    assert s.count(old) == 1, (old[:70], s.count(old))
    s = s.replace(old, new)
rep('ZAPRET_STRATEGY=md5sig  # md5sig | badseq | disorder | seqovl | custom (ZAPRET_ARGS)\n',
    'ZAPRET_STRATEGY=fakeddisorder  # fakeddisorder | md5sig | md5sig2 | badseq | disorder | seqovl | custom (ZAPRET_ARGS)\n')
rep('        ZAPRET_STRATEGY) case "$val" in md5sig|badseq|disorder|seqovl|custom) ;; *) ok=0 ;; esac ;;\n',
    '        ZAPRET_STRATEGY) case "$val" in fakeddisorder|md5sig|md5sig2|badseq|disorder|seqovl|custom) ;; *) ok=0 ;; esac ;;\n')
rep('''# Стратегии подобраны вживую на мобильном операторе (лог 2.8, 20:4x):
# md5sig — 12/12 (YouTube, Discord, X, facebook, rutracker...), badseq и
# seqovl — 7/12 (без facebook/rutracker...), disorder (без подделок) — 7/12.''',
'''# Стратегии проверены сканером в 10 сетях (МегаФон, Дом.ру x2, Сибирский
# телеком x3, Сибирские сети x3): fakeddisorder — полная или почти полная
# везде; md5sig (midsld) теряет facebook у "Сибирских сетей"; md5sig2
# (1,midsld) там идеальна, но у "Сибирского телекома" иногда рвёт TLS.''')
rep('''        badseq)   echo''', '''        md5sig)   echo "--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$g" ;;
        md5sig2)  echo "--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=1,midsld --dpi-desync-fake-tls=@$g" ;;
        badseq)   echo''')
rep('''                echo "--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$g"
            fi ;;
        *)        echo "--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$g" ;;''',
'''                echo "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$g"
            fi ;;
        *)        echo "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$g" ;;''')
open('service.sh', 'w', encoding='utf-8', newline='\n').write(s)

s = open('webroot/index.html', encoding='utf-8').read()
rep('''      <option value="md5sig">1 · md5sig — подобрана у тебя</option>
      <option value="badseq">2 · badseq</option>
      <option value="seqovl">3 · seqovl</option>
      <option value="disorder">4 · disorder, без подделок</option>''',
'''      <option value="fakeddisorder">1 · fakeddisorder — лучшая в среднем</option>
      <option value="md5sig">2 · md5sig, разрез midsld</option>
      <option value="md5sig2">3 · md5sig, разрез 1,midsld</option>
      <option value="badseq">4 · badseq</option>
      <option value="seqovl">5 · seqovl</option>
      <option value="disorder">6 · disorder, без подделок</option>''')
rep(r'''D ZAPRET_STRATEGY=md5sig\n''', r'''D ZAPRET_STRATEGY=fakeddisorder\n''')
open('webroot/index.html', 'w', encoding='utf-8', newline='\n').write(s)

s = open('customize.sh', encoding='utf-8').read()
rep('#ZAPRET_STRATEGY=md5sig\n', '#ZAPRET_STRATEGY=fakeddisorder\n')
open('customize.sh', 'w', encoding='utf-8', newline='\n').write(s)
print('ok')
