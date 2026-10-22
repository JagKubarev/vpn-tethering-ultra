import sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
def rep(old, new):
    global s
    assert s.count(old) == 1, (old[:70], s.count(old))
    s = s.replace(old, new)

rep('ZAPRET_STRATEGY=md5sig  # md5sig | badseq | disorder | seqovl\n',
    'ZAPRET_STRATEGY=md5sig  # md5sig | badseq | disorder | seqovl | custom (ZAPRET_ARGS)\n'
    'ZAPRET_ARGS=""          # для custom: аргументы --dpi-desync*, файлы подделок только @G/@Q (подбирает сканер в WebUI)\n')
rep('        ZAPRET_STRATEGY) case "$val" in md5sig|badseq|disorder|seqovl) ;; *) ok=0 ;; esac ;;\n',
    '        ZAPRET_STRATEGY) case "$val" in md5sig|badseq|disorder|seqovl|custom) ;; *) ok=0 ;; esac ;;\n'
    '        ZAPRET_ARGS)\n'
    '            # только --dpi-desync*; @ — лишь встроенные подделки (=@G / =@Q),\n'
    '            # никаких путей: строка уходит в nfqws, запущенный от root\n'
    '            case "$val" in *[!A-Za-z0-9,.:+_@=\ -]*) ok=0 ;; esac\n'
    '            for _t in $val; do\n'
    '                case "$_t" in --dpi-desync|--dpi-desync=*|--dpi-desync-*) ;; *) ok=0 ;; esac\n'
    '                case "$_t" in *@*) case "$_t" in *=@G|*=@Q) ;; *) ok=0 ;; esac ;; esac\n'
    '            done ;;\n')
rep('QUIC_BLOCK_APPS ZAPRET_ENABLE ZAPRET_MODE ZAPRET_PHONE ZAPRET_STRATEGY ZAPRET_QUIC_BLOCK"',
    'QUIC_BLOCK_APPS ZAPRET_ENABLE ZAPRET_MODE ZAPRET_PHONE ZAPRET_STRATEGY ZAPRET_ARGS ZAPRET_QUIC_BLOCK"')
rep('''        *)        echo "--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$g" ;;
    esac''', '''        custom)
            if [ -n "$ZAPRET_ARGS" ]; then
                echo "$ZAPRET_ARGS" | sed "s#=@G#=@$g#g; s#=@Q#=@$1/quic_initial_www_google_com.bin#g"
            else
                echo "--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$g"
            fi ;;
        *)        echo "--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$g" ;;
    esac''')
open(p, 'w', encoding='utf-8', newline='\n').write(s)
print('ok')
