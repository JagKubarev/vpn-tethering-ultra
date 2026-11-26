#!/system/bin/sh
# ============================================================================
# Конфиги WARP (AmneziaWG): хранилище, импорт, генерация, удаление.
# Зовётся из webctl.sh (warp-*) и демоном (ensure). Ключи наружу не выводит,
# кроме export — им страница отдаёт конфиг пользователю.
#
#   warp.sh list                 имя|endpoint|откуда|дата   (без ключей)
#   warp.sh import ИМЯ BASE64    конфиг .conf (AmneziaVPN / WireGuard) в base64
#   warp.sh gen [N]              зарегистрировать в Cloudflare N новых (1..5)
#   warp.sh ensure [N]           первый запуск: нет ни одного — создать N (3)
#   warp.sh del ИМЯ
#   warp.sh export ИМЯ           текст конфига
#   warp.sh save ИМЯ             копия в «Загрузки» (ИМЯ.conf) -> «OK путь»
#   warp.sh saveall              все конфиги одним zip в «Загрузки» -> «OK путь число»
#   warp.sh i1gen ИМЯ            свой I1 с этим именем (свои DCID и ключи) -> i1/ИМЯ.txt, «OK ИМЯ»;
#                                «dns_ИМЯ» — I1 в виде DNS-запроса A этого имени (без nfqws2)
#   warp.sh i1list               имена своих I1
#   warp.sh i1del ИМЯ
#
# Регистрация — по тому же API, что у warp-generation.github.io и
# zapret2-android (идея оттуда, реализация своя): POST reg с публичным
# ключом, PATCH warp_enabled, адреса и ключ пира — из ответа. Параметры
# AmneziaWG (Jc/Jmin/Jmax, H1–H4, I1 из i1.txt) — как в конфигах, которые
# годами работают на YOTA.
# I1 — поддельный QUIC Initial, по его SNI оператор опознаёт весь UDP-поток туннеля.
# 08.11: с bag.itunes.apple.com YOTA днём резала туннель до 2,4–2,5 Мбит/с (ночью 25);
# с apteka.ru (как в WARPv1_50/76) — 20–30 Мбит/с на тех же аккаунте и эндпоинте.
# ============================================================================

MODDIR="${0%/*}"; MODDIR="${MODDIR%/warp}"
[ -f "$MODDIR/service.sh" ] || MODDIR=/data/adb/modules/vpn-to-hotspot-usb
PATH="$PATH:$MODDIR/bin"; export PATH   # curl: нет системного — свой из модуля
BB=/data/adb/ksu/bin/busybox
[ -x "$BB" ] || BB=/data/adb/magisk/busybox
[ -x "$BB" ] || BB=/data/adb/ap/bin/busybox
# в Android 8 нет awk (MT6580, 04.11): этот скрипт идёт под mksh, не под busybox. А awk 20121220
# (Android 9, Redmi 4X, 09.11) падает (SIGSEGV) на любом унарном «!»: !s[$1]++, !/…/, exit !(…)
( echo x | awk '!/y/' ) >/dev/null 2>&1 || awk() { "$BB" awk "$@"; }
WARP_DIR=/data/adb/vpn_tether_warp
STATUS_FILE="$MODDIR/status"
ZSCAN=/data/local/tmp/vpn_tether_zscan
GEN_LOCK=/data/local/tmp/vpn_tether_warpgen.lock
API=https://api.cloudflareclient.com/v0i1909051800
case "$(uname -m)" in aarch64|arm64) AWG="$MODDIR/bin/awg-arm64"; NQ="$MODDIR/bin/nfqws-arm64"; NQ2="$MODDIR/bin/nfqws2-arm64" ;;
                     *) AWG="$MODDIR/bin/awg-arm"; NQ="$MODDIR/bin/nfqws-arm"; NQ2="$MODDIR/bin/nfqws2-arm" ;; esac
CA=/apex/com.android.conscrypt/cacerts
[ -d "$CA" ] || CA=/system/etc/security/cacerts
B64=base64
command -v base64 >/dev/null 2>&1 || for b in /data/adb/ksu/bin/busybox /data/adb/magisk/busybox /data/adb/ap/bin/busybox; do
    [ -x "$b" ] && { B64="$b base64"; break; }
done

umask 077
mkdir -p "$WARP_DIR" && chmod 700 "$WARP_DIR"

valid_name() {
    case "$1" in ''|*[!A-Za-z0-9_.-]*|.*) return 1 ;; esac
    [ ${#1} -le 40 ]
}

# Конфиг -> нормализованный: только известные ключи AmneziaWG/WireGuard
# (PostUp, ExcludedApplications и т.п. отбрасываем — awg их не знает, а
# исполнять мы ничего не собираемся), значения — из безопасного набора.
# stdout — конфиг, stderr — «skip N»; ошибка — «ERR …» в stdout и код 1.
normalize() {
    awk '
        BEGIN { bom = sprintf("%c%c%c", 239, 187, 191) }
        { sub(/\r$/, "") }
        NR == 1 && substr($0, 1, 3) == bom { $0 = substr($0, 4) }
        /^[ \t]*($|#|;)/ { next }
        /^[ \t]*\[[A-Za-z]+\][ \t]*$/ {
            s = $0; gsub(/[][]/, "", s); gsub(/[ \t]/, "", s)   # скобки — отдельно, как ниже: busybox awk (Android 8)
            if (s == "Interface") { ni++; sec = "i" }
            else if (s == "Peer") { np++; sec = "p" }
            else { err = "секция [" s "]"; exit }
            out = out "\n[" s "]\n"; next
        }
        {
            i = index($0, "=")
            if (!i) { err = "строка " NR " без «=»"; exit }
            k = substr($0, 1, i - 1); v = substr($0, i + 1)
            gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", v)
            # J1–J3/Itime (AmneziaWG 1.5) awg v3.1 не знает — «Line unrecognized»: в пропущенные
            # ключи AWG 3 awg v3.1 знает: без HeaderProtectionKey рукопожатия со своим сервером нет
            if (sec == "i") ok = k ~ /^(PrivateKey|Address|DNS|MTU|ListenPort|Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|RandomTrailers|DisableCookies)$/
            else if (sec == "p") ok = k ~ /^(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive|AdvancedSecurity)$/
            else { err = "строка " NR " до [Interface]"; exit }
            # «(off)» — параметр выключен; awg такое значение не принимает
            if (!ok || v == "(off)") { skip++; next }
            t = v; gsub(/[][]/, "", t)   # скобки — отдельно: в классе с ними busybox awk ошибается
            if (v == "" || t ~ /[^A-Za-z0-9+\/=.:,<> _-]/) { err = "недопустимое значение " k; exit }
            if (k ~ /Key$/ && (length(v) != 44 || v !~ /^[A-Za-z0-9+\/]+=$/)) { err = "неверный " k; exit }
            # шаблон с заглушкой (server.example.com:51820): такой конфиг не поднимется
            # никогда, а WARP пробовал его первым при каждом подъёме (27.10 импорт, −2–3 с)
            if (k == "Endpoint" && tolower(v) ~ /(^|\.)example\.(com|net|org)(:|$)/) { err = "Endpoint — заглушка " v ", а не адрес сервера"; exit }
            seen[sec k] = 1; out = out k " = " v "\n"
        }
        END {
            if (err != "") { print "ERR " err; exit 1 }
            if (ni != 1 || np != 1) { print "ERR нужен один [Interface] и один [Peer]"; exit 1 }
            if (!seen["iPrivateKey"] || !seen["pPublicKey"] || !seen["pEndpoint"]) { print "ERR нет PrivateKey, PublicKey или Endpoint"; exit 1 }
            printf "%s", substr(out, 2)
            if (skip) print "skip " skip > "/dev/stderr"
        }'
}

# имя -> свободное имя: «warp», «warp-2», …
free_name() {
    local n="$1" i=2
    [ -e "$WARP_DIR/$n.conf" ] || { echo "$n"; return; }
    while [ -e "$WARP_DIR/$n-$i.conf" ]; do i=$((i + 1)); done
    echo "$n-$i"
}

# --- доступ к API Cloudflare -------------------------------------------------
# api.cloudflareclient.com у ТСПУ режется по имени. Мимо VPN — свой nfqws2 с приёмом DoH через обход
# (DNS_VIA_ZAPRET: 2 нулевые подделки с плохим ack + разрез посередине имени; 19.11 YOTA: API 6/6, без
# обхода 0/9) — от стратегии сети не зависит; нет nfqws2 или не запустился (старое ядро) — nfqws1 с
# текущей стратегией сети, как раньше. Всё — на curl от root (как sitetest в webctl.sh); при VPN
# правило -o <WAN> не совпадёт, и запрос просто уйдёт в туннель. В обоих
# случаях — мимо прокси AdGuard (подменяет сертификаты).
Q=204   # 202 — sitetest, 203 — scan.sh
# свои соединения (root, кроме dnsproxy) — по биту connmark из OUTPUT, как у scan.sh: владелец в POSTROUTING на
# части ядер совпадает со всеми пакетами (17.11 MT6580, ядро 3.18) — обход снимался бы со всего трафика
RULE_MK="-m owner --uid-owner 0 ! --gid-owner 3999 -j CONNMARK --set-xmark 0x08000000/0x08000000"
bypass_on() {
    local wan nk nl
    iptables -w 2 -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
    iptables -w 2 -t mangle -I OUTPUT 1 $RULE_MK 2>/dev/null
    iptables -w 2 -t mangle -I VPN_ZAPRET 1 -m connmark --mark 0x08000000/0x08000000 -j RETURN 2>/dev/null
    wan=$(sed -n 's/^wan=//p' "$STATUS_FILE" 2>/dev/null)
    [ -n "$wan" ] && { [ -x "$NQ2" ] || [ -x "$NQ" ]; } || return 0
    # ядро без connbytes (zapret_caps демона) — без него
    CB_OUT="-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:40"   # как у демона (ZAPRET_CB_OUT)
    grep -q '^cb=0' /data/local/tmp/vpn_tether_zcaps 2>/dev/null && CB_OUT=""
    RULE_NFQ="-o $wan -m connmark --mark 0x08000000/0x08000000 -p tcp --dport 443 $CB_OUT -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass"
    iptables -w 2 -t mangle -I POSTROUTING 1 $RULE_NFQ
    local L="$MODDIR/zapret2/lua" QF=/proc/net/netfilter/nfnetlink_queue i=0
    # демон откатился на nfqws1 (nfqws2 на этом ядре не работает, статус zapret_engine) — сразу nfqws1, как ytspeed в webctl
    if [ -x "$NQ2" ] && [ -f "$L/zapret-antidpi.lua" ] && ! grep -q '^zapret_engine=nfqws1$' "$STATUS_FILE" 2>/dev/null; then
        # приём — как у DoH через обход (zapret2_args в lib/zapret.sh, DNS_VIA_ZAPRET): менять вместе
        "$NQ2" --qnum=$Q --uid=0:3998 --bind-fix4 --lua-init=@$L/zapret-lib.lua --lua-init=@$L/zapret-antidpi.lua \
            --filter-tcp=443 --filter-l7=tls --payload=tls_client_hello \
            --lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tcp_ts_up:repeats=2 --lua-desync=multisplit:pos=midsld >/dev/null 2>&1 &
        NQPID=$!
        # готов — когда занял очередь: до неё пакеты идут мимо (--queue-bypass), а запрос к API не повторяется.
        # 19.11: 13T ~50 мс, Redmi 4X ~100–170; ждём до 3 с (MT6580 под нагрузкой)
        if [ -r "$QF" ]; then
            while ! grep -q "^ *$Q " "$QF" 2>/dev/null && kill -0 "$NQPID" 2>/dev/null && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done
        else
            sleep 0.7
        fi
        kill -0 "$NQPID" 2>/dev/null && { [ ! -r "$QF" ] || grep -q "^ *$Q " "$QF" 2>/dev/null; } && return 0
        kill "$NQPID" 2>/dev/null; NQPID=""
    fi
    [ -x "$NQ" ] || return 0
    nk=$(sh "$MODDIR/zapret/netid.sh" "$wan" 2>/dev/null | head -1); nl=${nk#*"|"}; nk=${nk%%"|"*}
    "$NQ" --qnum=$Q --uid=0:3998 --bind-fix4 $(sh "$MODDIR/service.sh" --zapret-strategy "$nk" "$nl" full) >/dev/null 2>&1 &
    NQPID=$!
    sleep 0.7
}
bypass_off() {
    [ -n "$NQPID" ] && kill "$NQPID" 2>/dev/null
    [ -n "$RULE_NFQ" ] && iptables -w 2 -t mangle -D POSTROUTING $RULE_NFQ 2>/dev/null
    iptables -w 2 -t mangle -D VPN_ZAPRET -m connmark --mark 0x08000000/0x08000000 -j RETURN 2>/dev/null
    iptables -w 2 -t mangle -D OUTPUT $RULE_MK 2>/dev/null
    iptables -w 2 -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null
    NQPID=""; RULE_NFQ=""
}

# api МЕТОД ПУТЬ ТОКЕН JSON -> тело ответа
api() {
    curl -s -m 15 --capath "$CA" -X "$1" \
        -H 'User-Agent: CloudflareWarp/1.0' \
        -H 'Content-Type: application/json; charset=UTF-8' \
        ${3:+-H "Authorization: Bearer $3"} -d "$4" "$API/$2" 2>/dev/null
}
jstr() { grep -o "\"$1\":\"[^\"]*\"" | head -1 | sed 's/.*:"//; s/"$//'; }

# gen_one ИМЯ -> файл WARP_DIR/ИМЯ.conf; ошибка — текст в stdout, код 1
gen_one() {
    local priv pub r id tok ppub addr v4 v6
    priv=$("$AWG" genkey) && pub=$(printf '%s\n' "$priv" | "$AWG" pubkey) || { echo "awg genkey"; return 1; }
    r=$(api POST reg "" "{\"install_id\":\"\",\"tos\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\",\"key\":\"$pub\",\"fcm_token\":\"\",\"type\":\"ios\",\"locale\":\"en_US\"}")
    [ -n "$r" ] || { echo "нет ответа от api.cloudflareclient.com"; return 1; }
    id=$(printf '%s' "$r" | jstr id); tok=$(printf '%s' "$r" | jstr token)
    [ -n "$id" ] && [ -n "$tok" ] || { echo "регистрация: $(printf '%s' "$r" | head -c 120)"; return 1; }
    r=$(api PATCH "reg/$id" "$tok" '{"warp_enabled":true}')
    ppub=$(printf '%s' "$r" | jstr public_key)
    addr=$(printf '%s' "$r" | grep -o '"addresses":{[^}]*}' | head -1)
    v4=$(printf '%s' "$addr" | jstr v4); v6=$(printf '%s' "$addr" | jstr v6)
    # по отдельности: склеенные проходили, если пусто одно из двух, — конфиг с
    # пустым PublicKey или «Address = /32» (ревью PR #20). Ключ — base64 32
    # байт (44 знака), адрес — IPv4
    case "$ppub" in *[!A-Za-z0-9+/=]*|'') ppub="" ;; esac
    [ ${#ppub} -eq 44 ] || ppub=""
    case "$v4" in *[!0-9.]*|'') v4="" ;; *.*.*.*) ;; *) v4="" ;; esac
    if [ -z "$ppub" ] || [ -z "$v4" ]; then echo "включение WARP: $(printf '%s' "$r" | head -c 120)"; return 1; fi
    {
        echo "# vpn_tether: gen $(date '+%Y-%m-%d %H:%M')"
        echo "[Interface]"
        echo "PrivateKey = $priv"
        echo "Address = $v4/32${v6:+, $v6/128}"
        echo "DNS = 1.1.1.1, 1.0.0.1"
        echo "MTU = 1280"
        echo "Jc = 5"; echo "Jmin = 100"; echo "Jmax = 200"
        echo "H1 = 1"; echo "H2 = 2"; echo "H3 = 3"; echo "H4 = 4"
        echo "I1 = $(cat "$MODDIR/warp/i1.txt")"
        echo ""
        echo "[Peer]"
        echo "PublicKey = $ppub"
        echo "AllowedIPs = 0.0.0.0/0, ::/0"
        echo "Endpoint = engage.cloudflareclient.com:4500"
        echo "PersistentKeepalive = 25"
    } > "$WARP_DIR/.$1.tmp" && mv -f "$WARP_DIR/.$1.tmp" "$WARP_DIR/$1.conf"
}

# gen N: N конфигов подряд; печатает «OK имя…» или «ERR причина»
gen() {
    local n="${1:-1}" i=0 made="" name e
    case "$n" in [1-5]) ;; *) echo "ERR число 1..5"; return 1 ;; esac
    [ -x "$AWG" ] || { echo "ERR нет $AWG"; return 1; }
    # scan.sh: его curl от root попали бы в нашу очередь (и наоборот)
    # жив и это scan.sh (cmdline): pid убитого мог достаться чужому (ревью PR #20)
    pid=$(cat "$ZSCAN.pid" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        case "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" in
            # «идёт подбор» и «уже идёт» (ниже) разбирает демон (warp_ensure): занято — повтор
            # через 30 с, а не пауза с удвоением. Меняя текст — поменять и там
            *zapret/scan.sh*) echo "ERR идёт подбор обхода — повторите позже"; return 1 ;;
        esac
    fi
    mkdir "$GEN_LOCK" 2>/dev/null || {
        # замок от убитого процесса — старше 3 минут (живой gen обновляет его на каждом конфиге)
        [ -n "$(find "$GEN_LOCK" -maxdepth 0 -mmin +3 2>/dev/null)" ] && rm -rf "$GEN_LOCK" && mkdir "$GEN_LOCK" 2>/dev/null \
            || { echo "ERR генерация уже идёт"; return 1; }
    }
    trap 'bypass_off; rm -rf "$GEN_LOCK"' EXIT
    trap 'exit 1' INT TERM HUP
    bypass_on
    while [ $i -lt "$n" ]; do
        name=$(free_name warp)
        touch "$GEN_LOCK"   # живой: замок свежий (gen 5 бывает дольше 2 мин)
        e=$(gen_one "$name") || { rm -f "$WARP_DIR/.$name.tmp"; break; }
        made="$made $name"; i=$((i + 1))
        [ $i -lt "$n" ] && sleep 1
    done
    if [ -n "$made" ]; then echo "OK$made${e:+ (дальше: $e)}"; else echo "ERR $e"; return 1; fi
}

case "$1" in
    list)
        # одним stat и одним awk: по sed/sed/date на файл — ~0,6 с на 19 конфигов,
        # а WebUI (ksu.exec синхронный) всё это время не отвечал
        ls "$WARP_DIR"/*.conf >/dev/null 2>&1 || exit 0
        # печать — в END по списку stat: у пустого файла нет строки FNR == 1, и
        # он пропадал из списка (а с ним из WebUI — ни увидеть, ни удалить)
        stat -c '%n|%y' "$WARP_DIR"/*.conf 2>/dev/null | awk '
            FILENAME == "-" { i = index($0, "|"); f = substr($0, 1, i - 1); o[++no] = f; d[f] = substr($0, i + 1, 16); next }
            FNR == 1 && /^# vpn_tether: [a-z]/ { v = substr($0, 15); sub(/[^a-z].*/, "", v); src[FILENAME] = v }
            !(FILENAME in ep) && /^Endpoint[ \t]*=/ { v = $0; sub(/^Endpoint[ \t]*=[ \t]*/, "", v); ep[FILENAME] = v }
            END {
                for (j = 1; j <= no; j++) {
                    f = o[j]; n = f; sub(/.*\//, "", n); sub(/\.conf$/, "", n)
                    print n "|" ep[f] "|" (src[f] != "" ? src[f] : "import") "|" d[f]
                }
            }' - "$WARP_DIR"/*.conf ;;
    import)
        n="$2"; valid_name "$n" || { echo "ERR имя: латиница, цифры, _ . - (до 40)"; exit 1; }
        [ ${#3} -le 32000 ] || { echo "ERR конфиг больше 24 КБ"; exit 1; }
        t=$(printf '%s' "$3" | $B64 -d 2>/dev/null) || { echo "ERR не base64"; exit 1; }
        c=$(printf '%s\n' "$t" | normalize 2>"$WARP_DIR/.skip") || { echo "$c"; rm -f "$WARP_DIR/.skip"; exit 1; }
        sk=$(sed -n 's/^skip //p' "$WARP_DIR/.skip"); rm -f "$WARP_DIR/.skip"
        # тот же ключ уже есть — второй туннель с ним Cloudflare всё равно не пустит
        pk=$(printf '%s
' "$c" | sed -n 's/^PrivateKey = //p')
        d=$(grep -Flx "PrivateKey = $pk" "$WARP_DIR"/*.conf 2>/dev/null | head -1)
        [ -z "$d" ] || { d=${d##*/}; echo "ERR этот конфиг уже есть: ${d%.conf}"; exit 1; }
        # free_name допишет «-2», «-3»: оставляем место, чтобы имя осталось в 40
        n=$(free_name "$(printf '%s' "$n" | cut -c1-36)")
        { echo "# vpn_tether: import $(date '+%Y-%m-%d %H:%M')"; printf '%s\n' "$c"; } > "$WARP_DIR/.$n.tmp" \
            && mv -f "$WARP_DIR/.$n.tmp" "$WARP_DIR/$n.conf" || { echo "ERR запись"; exit 1; }
        echo "OK $n${sk:+ (пропущено строк: $sk)}" ;;
    gen)
        gen "$2" ;;
    ensure)
        # один раз: пользователь мог удалить все — заново не создаём
        [ -f "$WARP_DIR/.init" ] && exit 0
        ls "$WARP_DIR"/*.conf >/dev/null 2>&1 && { : > "$WARP_DIR/.init"; exit 0; }
        r=$(gen "${2:-3}"); echo "$r"
        case "$r" in OK*) : > "$WARP_DIR/.init" ;; *) exit 1 ;; esac ;;
    i1gen)
        # I1 с любым именем на этой установке (WARP_I1): warp/i1gen.lua на Lua nfqws2. Хранится рядом с
        # конфигами — переживает обновление модуля; демон ищет здесь раньше готовых warp/i1
        n=$(printf '%s' "$2" | tr 'A-Z' 'a-z'); dns=""
        case "$n" in dns_*) dns=1; n=${n#dns_} ;; esac
        case "$n" in ''|*[!a-z0-9.-]*|[.-]*|*[.-]|*..*) echo "ERR имя: латиница, цифры, точки и дефисы (.рф — в виде xn--)"; exit 1 ;; esac
        case "$n" in *.*) ;; *) echo "ERR нужно имя с точкой, например max.ru"; exit 1 ;; esac
        [ ${#n} -le 100 ] || { echo "ERR имя длиннее 100 знаков"; exit 1; }
        if [ -n "$dns" ]; then
            # DNS-запрос (как у ZapretKVN v0.6.56): ID случайный (<r 2>), RD, вопрос A IN, EDNS0 на 1232 байта —
            # как у обычного резолвера; имени сайта для классификации в нём нет, криптографии не нужно
            h="01000001000000000001"
            for l in $(echo "$n" | tr '.' ' '); do
                [ ${#l} -le 63 ] || { echo "ERR часть имени длиннее 63 знаков"; exit 1; }
                h="$h$(printf '%02x' ${#l})$(printf '%s' "$l" | od -An -tx1 | tr -d ' \n')"
            done
            n="dns_$n"
            mkdir -p "$WARP_DIR/i1" && printf '<r 2><b 0x%s000001000100002904d0000000000000>\n' "$h" > "$WARP_DIR/i1/.$n.tmp" &&
                mv -f "$WARP_DIR/i1/.$n.tmp" "$WARP_DIR/i1/$n.txt" || { echo "ERR не записался"; exit 1; }
            echo "OK $n"; exit 0
        fi
        [ -x "$NQ2" ] || { echo "ERR нет nfqws2 — собрать I1 нечем"; exit 1; }
        src=$(head -1 "$MODDIR/warp/i1.txt" 2>/dev/null | tr -d '\r')
        case "$src" in "<b 0x"*">") ;; *) echo "ERR нет образца warp/i1.txt — переустановите модуль"; exit 1 ;; esac
        o=$("$NQ2" --intercept=0 --uid=0:3998 --lua-init="I1_NAME='$n' I1_SRC='$src'" --lua-init=@"$MODDIR/warp/i1gen.lua" 2>&1)
        r=$(printf '%s\n' "$o" | grep -E '^(<b 0x|ERR )' | head -1)
        # ни I1, ни нашей ошибки — nfqws2 не дошёл до скрипта: его последняя строка (на armv7 не проверяли)
        case "$r" in "<b 0x"*">") ;; ERR*) echo "$r"; exit 1 ;;
            *) echo "ERR nfqws2 не собрал I1: $(printf '%s\n' "$o" | grep . | tail -1 | cut -c1-120)"; exit 1 ;; esac
        mkdir -p "$WARP_DIR/i1" && printf '%s\n' "$r" > "$WARP_DIR/i1/.$n.tmp" && mv -f "$WARP_DIR/i1/.$n.tmp" "$WARP_DIR/i1/$n.txt" ||
            { echo "ERR не записался"; exit 1; }
        echo "OK $n" ;;
    i1list)
        for f in "$WARP_DIR"/i1/*.txt; do [ -f "$f" ] && { f=${f##*/}; echo "${f%.txt}"; }; done ;;
    i1del)
        case "${2#dns_}" in ''|*[!a-z0-9.-]*|.*) echo "ERR нет такого"; exit 1 ;; esac
        [ -f "$WARP_DIR/i1/$2.txt" ] || { echo "ERR нет такого"; exit 1; }
        rm -f "$WARP_DIR/i1/$2.txt" && echo "OK" ;;
    del)
        valid_name "$2" && [ -f "$WARP_DIR/$2.conf" ] || { echo "ERR нет такого"; exit 1; }
        rm -f "$WARP_DIR/$2.conf" && echo "OK" ;;
    export)
        valid_name "$2" && [ -f "$WARP_DIR/$2.conf" ] || { echo "ERR нет такого"; exit 1; }
        sed '1{/^# vpn_tether:/d;}' "$WARP_DIR/$2.conf" ;;
    save)
        # для AmneziaVPN и других устройств; в файле закрытый ключ
        valid_name "$2" && [ -f "$WARP_DIR/$2.conf" ] || { echo "ERR нет такого"; exit 1; }
        F="/storage/emulated/0/Download/$2.conf"
        sed '1{/^# vpn_tether:/d;}' "$WARP_DIR/$2.conf" > "$F" 2>/dev/null && [ -s "$F" ] || { echo "ERR не удалось записать в «Загрузки»"; exit 1; }
        chmod 644 "$F" 2>/dev/null
        ( content call --uri content://media --method scan_file --arg "$F" >/dev/null 2>&1 & )
        echo "OK $F" ;;
    saveall)
        # все конфиги одним zip в «Загрузки» — как экспорт AmneziaVPN (импорт
        # туда и на другой телефон). zip без сжатия, собираем сами: zip на
        # телефоне нет. CRC32 — из хвоста gzip (там он уже little-endian, как в
        # zip): busybox crc32 есть не везде, а awk режет xor до 32 бит со знаком
        set -- "$WARP_DIR"/*.conf
        [ -f "$1" ] || { echo "ERR конфигов нет"; exit 1; }
        BB=""; for b in /data/adb/ksu/bin/busybox /data/adb/magisk/busybox /data/adb/ap/bin/busybox; do [ -x "$b" ] && { BB="$b"; break; }; done
        [ -n "$BB" ] || { echo "ERR нет busybox"; exit 1; }
        GZ="$BB gzip"; command -v gzip >/dev/null 2>&1 && GZ=gzip
        # «число ширина ...» -> байты little-endian (один awk на заголовок, а не процесс на байт)
        le() { printf "$("$BB" awk 'BEGIN { for (i = 1; i < ARGC; i += 2) { v = ARGV[i]; for (k = 0; k < ARGV[i+1]; k++) { printf "\\%03o", v % 256; v = int(v / 256) } } }' "$@")"; }
        T="$WARP_DIR/.zip"; rm -rf "$T"; mkdir "$T" || { echo "ERR временная папка"; exit 1; }
        # время DOS — сейчас
        set -- $(date '+%Y %m %d %H %M %S')
        [ "$1" -lt 1980 ] && set -- 1980 01 01 00 00 00   # часы не выставлены (1970)
        dd=$(( (($1 - 1980) << 9) | (${2#0} << 5) | ${3#0} )); dt=$(( (${4#0} << 11) | (${5#0} << 5) | (${6#0} / 2) ))
        off=0; n=0
        : > "$T/local"; : > "$T/central"
        for f in "$WARP_DIR"/*.conf; do
            nm=${f##*/}
            sed '1{/^# vpn_tether:/d;}' "$f" > "$T/data"
            sz=$(wc -c < "$T/data")
            $GZ -c < "$T/data" | tail -c 8 | head -c 4 > "$T/crc"
            [ "$(wc -c < "$T/crc")" -eq 4 ] || { rm -rf "$T"; echo "ERR не удалось посчитать CRC (gzip)"; exit 1; }
            # версия, флаги, метод (0 — без сжатия), время, дата | CRC | размеры, длина имени, extra
            { printf 'PK\003\004'; le 10 2 0 2 0 2 $dt 2 $dd 2; cat "$T/crc"; le $sz 4 $sz 4 ${#nm} 2 0 2
              printf '%s' "$nm"; cat "$T/data"; } >> "$T/local"
            { printf 'PK\001\002'; le 20 2 10 2 0 2 0 2 $dt 2 $dd 2; cat "$T/crc"; le $sz 4 $sz 4 ${#nm} 2 0 2 0 2 0 2 0 2 0 4 $off 4
              printf '%s' "$nm"; } >> "$T/central"
            off=$((off + 30 + ${#nm} + sz)); n=$((n + 1))
        done
        F="/storage/emulated/0/Download/warp-configs_$(date +%Y%m%d_%H%M).zip"
        { cat "$T/local" "$T/central"; printf 'PK\005\006'; le 0 2 0 2 $n 2 $n 2 $(wc -c < "$T/central") 4 $off 4 0 2; } > "$F" 2>/dev/null
        rm -rf "$T"
        [ -s "$F" ] || { echo "ERR не удалось записать в «Загрузки»"; exit 1; }
        chmod 644 "$F" 2>/dev/null
        ( content call --uri content://media --method scan_file --arg "$F" >/dev/null 2>&1 & )
        echo "OK $F $n" ;;
    *)
        echo "ERR команда"; exit 1 ;;
esac
