# shellcheck shell=sh
# lib/opera.sh — Telegram через прокси Opera (OPERA_TG): opera-proxy и
# hev-socks5-tproxy, прозрачное перенаправление TCP к подсетям Telegram.
# Часть демона service.sh: подключается из него через ".", сам не запускается.
# Настройки (USER CONFIG) и общие переменные — в service.sh.

# ============================================================================
# YOTA и другие закрывают Telegram по IP — обход DPI тут не помогает. Пока
# VPN не поднят, TCP к подсетям Telegram (zapret/list-telegram-cidr.txt) с
# телефона и с раздачи (только режим «напрямую») уходит в бесплатный прокси
# Opera. Остальной трафик — как был.
#  - opera-proxy (root:OPERA_GID) регистрируется в API Opera через бесплатные
#    прокси из OPERA_API_LIST (из РФ API напрямую закрыт) и слушает SOCKS5 на
#    127.0.0.1:OPERA_PORT. Старт 7-8с, иногда до 2 мин — идёт в фоне.
#  - hev-socks5-tproxy принимает перехваченные соединения (127.0.0.1:
#    OPERA_TP_PORT) и отдаёт их в SOCKS5. Адрес назначения он берёт из самого
#    сокета (getsockname), SO_ORIGINAL_DST не умеет — поэтому TPROXY, а не
#    nat REDIRECT (после REDIRECT назначение = 127.0.0.1).
#  - mangle PREROUTING -> VPN_OPERA_IN: TCP с раздачи и вернувшиеся через lo
#    пакеты телефона -> VPN_OPERA_TP (подсети Telegram -> TPROXY).
#  - mangle OUTPUT -> VPN_OPERA_OUT: TCP приложений телефона к подсетям
#    Telegram получает бит OPERA_MARK; ip rule pref OPERA_PREF уводит его в
#    таблицу OPERA_TABLE (local default dev lo) — пакет возвращается через lo
#    в PREROUTING и попадает в TPROXY. Своя группа opera-proxy, nfqws,
#    dnsproxy и VPN-клиенты не помечаются.
#  - TPROXY без слушателя ДРОПАЕТ пакеты: умер hev или opera-proxy — правила
#    снимаются сразу (прямой таймаут лучше чёрной дыры), перезапуск с паузой.
#  - Только TCP: звонки (UDP) не пойдут. Только IPv4.
#  - VPN поднят — правила снимаются (Telegram и так через VPN), а процессы
#    остаются: повторная регистрация бывает долгой.
# ============================================================================
OPERA_PORT=18080            # SOCKS5 opera-proxy
OPERA_TP_PORT=18088         # hev-socks5-tproxy
OPERA_MARK=0x20000000       # бит метки (zapret — 0x40000000, YouTube — 0x10000000, scan.sh — 0x08000000)
OPERA_TABLE=3997
OPERA_PREF=2990             # раньше правил раздачи (3000) и всех правил netd
OPERA_CIDR_FILE="$ZAPRET_DIR/list-telegram-cidr.txt"
OPERA_LOG="/data/local/tmp/vpn_tether_opera.log"
OPERA_HEV_LOG="/data/local/tmp/vpn_tether_hev.log"
OPERA_HEV_CONF="/data/local/tmp/vpn_tether_hev.yml"
OPERA_CA="/data/local/tmp/vpn_tether_opera_ca.pem"
OPERA_API_CACHE="/data/adb/vpn_tether_opera_api"           # удачные прокси API, новые сверху (переживает перезагрузку)
OPERA_API_FILE="/data/local/tmp/vpn_tether_opera_api.txt"  # -api-proxy-file: кэш + запасной список
OPERA_API_SPARE="/data/local/tmp/vpn_tether_opera_spare.txt"
# Запасной список: строки "ip:port" (SOCKS5). opera-proxy такие строки считает
# HTTP-прокси, поэтому качаем сами и дописываем socks5://
OPERA_API_SPARE_URL="https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"
CHAIN_OPERA_IN="VPN_OPERA_IN"     # mangle PREROUTING
CHAIN_OPERA_OUT="VPN_OPERA_OUT"   # mangle OUTPUT
CHAIN_OPERA_TP="VPN_OPERA_TP"     # подсети Telegram -> TPROXY
OPERA_STATE="off"       # off | starting | on | fail
OPERA_ENDPOINT=""       # сервер Opera, выбранный opera-proxy
OPERA_ERR=""            # почему fail (для WebUI)
OPERA_SCOPE=""          # для кого стоят правила: "" | phone | "phone tether"
OPERA_RULES_SIG=""      # что стоит: "телефон|интерфейсы|исключения", "" = правил нет
OPERA_EXCL=""           # uid VPN-клиентов (как у zapret)
OPERA_RETRY=0           # пропустить N итераций до повтора
OPERA_FAILS=0           # неудачных стартов подряд
OPERA_START_TS=0
OPERA_TICK=0
OPERA_SU_G=""           # "" = не проверяли, 1 = su -g работает, 0 = нет
OPERA_CA_INFO=""
OPERA_NOSUPPORT=0       # 1 = ядро без TPROXY/бинарей нет — не пытаться до перечитывания настроек
OPERA_WAN=""            # WAN, на котором последний раз проверяли сервер Opera
OPERA_PROBE_DC="149.154.167.51:443"   # DC2 Telegram: проверка «через Opera доходит»
# Серверы Opera: «регион ip» по строке. 24.10: регистрация даёт по 2 сервера
# на регион, а ТСПУ режет часть адресов 77.111.x по IP (на Dom.ru 8 из 18) —
# повезёт ли с парой, случайно. Но учётка региона принимается ЛЮБЫМ его
# сервером (-override-proxy-address), поэтому держим список известных
# адресов (встроенные + всё, что отдавал discover), меряем TCP-подключение к
# каждому через WAN и берём самый быстрый живой.
OPERA_POOL_FILE="/data/adb/vpn_tether_opera_pool"
OPERA_POOL_SEED="EU 77.111.244.37 EU 77.111.244.47 EU 77.111.244.209 EU 77.111.244.210 EU 77.111.247.19 EU 77.111.247.23 EU 77.111.247.32 EU 77.111.247.42 EU 77.111.247.78 EU 77.111.247.79 EU 77.111.247.80 EU 77.111.247.106 AS 77.111.245.10 AS 77.111.245.11 AS 77.111.245.12 AS 77.111.245.17 AM 77.111.246.14 AM 77.111.246.26 AM 77.111.246.28 AM 77.111.246.40 AM 77.111.246.62"
OPERA_RANK=""           # живые серверы региона: «мс ip» по возрастанию (последний замер)
OPERA_RANK_TS=0
OPERA_BAD=""            # серверы, не пропустившие Telegram в этой сети (до смены сети / 10 мин)
OPERA_BADREG=""         # регионы, где отказали два сервера подряд (AUTO их не берёт; столько же живут)
OPERA_LASTFAIL_REG=""
OPERA_HOPS=0            # переездов подряд без удачной проверки
OPERA_PROBE_WHY=""      # почему не прошла проверка: tcp (сервер недоступен) | upstream (502)
OPERA_WANT_PREV=0       # want прошлой итерации: 0 -> 1 = VPN только что выключили
OPERA_OVERRIDE=""       # сервер, заданный opera-proxy через -override-proxy-address
OPERA_REGION=""         # регион, в котором зарегистрирован opera-proxy (при AUTO — регион лучшего сервера)
OPERA_RERANK=0

opera_cidrs() {
    sed 's/#.*//' "$OPERA_CIDR_FILE" 2>/dev/null | tr -d ' \t\r' | \
        grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$'
    [ "$OPERA_SITES" = "1" ] && opera_site_ips | sed 's#$#/32#'
}

# ============================================================================
# Сайты, которые не открывает обход (OPERA_SITES). Проверка сайтов (scan.sh
# sites) кладёт «не открылись ничем» в ZSKIP. Фоновая задача перепроверяет
# каждый: напрямую (мимо AdGuard и nfqws) не открылся, а через Opera открылся
# — его адреса (как их отдаёт наш DNS), закрытые ПО IP (TCP не соединяется),
# идут в то же перенаправление, что и Telegram. Сайт на общем адресе CDN,
# который режут по DPI, не берём (3.15 брал — через Opera пошли соседи). 24.10, Wi-Fi Dom.ru: из 259 заблокированных сайтов zapret открыл
# 148, ещё 21 открылся только через Opera (bsky.app, notion.so, spiegel.de…).
# Реклама и телеметрия, которые режет AdGuard, напрямую открываются — не берём.
# ============================================================================
OPERA_SITES_FILE="/data/adb/vpn_tether_opera_sites_ip"    # хост|ip ip|epoch проверки (только адреса, закрытые по IP)
# список 3.15 (с общими адресами CDN) — не переносить
rm -f /data/adb/vpn_tether_opera_sites /data/adb/vpn_tether_opera_sites.new 2>/dev/null
OPERA_SITES_SKIP="/data/adb/vpn_tether_opera_sites_skip"  # убранные вручную (WebUI ✕)
OPERA_SITES_PID="/data/local/tmp/vpn_tether_opera_sites.pid"
OPERA_SITES_MAX=128     # адресов в перенаправлении
OPERA_SITES_TICK=0
OPERA_SITES_SIG=""      # адреса сайтов в перенаправлении — менялись ли
OPERA_ZSKIP_SIG=""      # cksum ZSKIP — прошла ли новая проверка сайтов
OPERA_ZSKIP="/data/adb/vpn_tether_zapret_altskip"
# Телеметрия и реклама — не через Opera, даже если «не открылись ничем»
# (24.10 в список попал ums-telemetry-sgp.heytapmobi.com — телеметрия Oppo)
OPERA_SITES_NOISE='telemetry|analytic|metric|measure|stats\.|tracking|(^|[.-])tracker|beacon|crashlytics|sentry|appsflyer|adjust\.|doubleclick|googlead|googlesyndication|adservice|adsystem|(^|\.)ads?[0-9]*\.|heytap|allawnos|umeng|app-measurement|branch\.io'

opera_site_ips() {
    [ -s "$OPERA_SITES_FILE" ] || return 0
    cut -d'|' -f2 "$OPERA_SITES_FILE" | tr ' ' '\n' | \
        grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | sort -u | head -n "$OPERA_SITES_MAX"
}

# pid идущей фоновой задачи. Файл переживает перезагрузку: pid мог достаться
# чужому процессу (opera_down при старте демона его бы убил) — сверяем cmdline.
opera_sites_pid() {
    local p
    p=$(cat "$OPERA_SITES_PID" 2>/dev/null)
    case "$p" in ''|*[!0-9]*) return 1 ;; esac
    [ "$p" != "$$" ] || return 1
    case "$(tr '\0' ' ' 2>/dev/null < "/proc/$p/cmdline")" in
        *service.sh*) echo "$p" ;;
        *) return 1 ;;
    esac
}

# Фоновая проверка (до ~10 мин на 40 сайтов; цикл не держит). Записи старше
# 6 ч перепроверяются (адреса CDN меняются); чего нет в ZSKIP — выпадает. Больше 40 к проверке — 40 случайных, остальные записи — как
# были (по алфавиту дальние не проверялись бы никогда).
opera_sites_job() {
    opera_sites_pid >/dev/null && return 0
    (
        now=$(date +%s); out="$OPERA_SITES_FILE.new"; : > "$out"
        g=""; [ "$DNSPROXY_SU_G" = "1" ] && [ -n "$DNSPROXY_GID" ] && g="$DNSPROXY_GID"
        # Контроль «прямой путь вообще работает»: TCP к заведомо доступным адресам
        # через WAN. 25.10: при поднятом VPN curl --interface wlan0 не доходил ни до
        # чего (даже до ya.ru) — все адреса выглядели «закрытыми по IP», в список
        # попал бы и API Claude. Контроль не прошёл до или после прогона — результат
        # выбрасываем, старый список остаётся.
        # TCP до $1:443 напрямую устанавливается. Смотрим time_connect, а не
        # http_code: на «голый» HTTP в порт 443 TLS-сервер (не nginx/Cloudflare)
        # рвёт соединение или молчит — код 000 при живом TCP (проверено на
        # openssl s_server: curl exit 52/28, time_connect > 0). Не соединилось —
        # 0.000000.
        tcp_ok() {
            local c
            if [ -n "$g" ]; then
                c=$(su -g "$g" -c "curl -s -o /dev/null -m 3 ${LAST_WAN_IFACE:+--interface $LAST_WAN_IFACE} -w '%{time_connect}' http://$1:443/" 2>/dev/null)
            else
                c=$(curl -s -o /dev/null -m 3 ${LAST_WAN_IFACE:+--interface $LAST_WAN_IFACE} -w '%{time_connect}' "http://$1:443/" 2>/dev/null)
            fi
            case "$c" in *[1-9]*) return 0 ;; esac
            return 1
        }
        ctl_ok() { tcp_ok 77.88.8.8 || tcp_ok 1.1.1.1; }
        ctl_ok || { rm -f "$out" "$OPERA_SITES_PID"; exit 0; }
        # только то, что сейчас в ZSKIP этой сети (сеть не определилась — весь
        # ZSKIP): сайт, который zapret снова открывает (проверка сайтов идёт
        # мимо Opera), выпадает из ZSKIP — а с ним и отсюда
        hosts=$( K="$NET_KEY" awk -F'|' 'ENVIRON["K"] == "" || $1 == ENVIRON["K"] {print $2}' "$OPERA_ZSKIP" 2>/dev/null | \
                 grep -E '^[a-z0-9.-]+\.[a-z]+$' | grep -vE "$OPERA_SITES_NOISE" | sort -u | \
                 awk 'BEGIN {srand()} {print rand() " " $0}' | sort -n | cut -d' ' -f2)
        n=0
        for h in $hosts; do
            grep -qxF "$h" "$OPERA_SITES_SKIP" 2>/dev/null && continue
            old=$(grep "^$h|" "$OPERA_SITES_FILE" 2>/dev/null | head -n 1)
            t=$(echo "$old" | cut -d'|' -f3)
            if [ -n "$t" ] && [ $((now - t)) -lt 21600 ] 2>/dev/null; then echo "$old" >> "$out"; continue; fi
            if [ "$n" -ge 40 ]; then [ -n "$old" ] && echo "$old" >> "$out"; continue; fi
            n=$((n + 1))
            # напрямую открылся — не блокировка (или режет только AdGuard)
            if [ -n "$g" ]; then
                c=$(su -g "$g" -c "curl -s -o /dev/null -m 5 ${LAST_WAN_IFACE:+--interface $LAST_WAN_IFACE} -w '%{http_code}' https://$h/" 2>/dev/null)
            else
                c=$(curl -s -o /dev/null -m 5 ${LAST_WAN_IFACE:+--interface $LAST_WAN_IFACE} -w '%{http_code}' "https://$h/" 2>/dev/null)
            fi
            [ -n "$c" ] && [ "$c" != "000" ] && continue
            c=$(curl -s -o /dev/null -m 8 --socks5-hostname "127.0.0.1:$OPERA_PORT" -w '%{http_code}' "https://$h/" 2>/dev/null)
            [ -n "$c" ] && [ "$c" != "000" ] || continue
            # адреса — как их видят клиенты: запрос на :53 от root уходит в наш dnsproxy
            ips=$(${BUSYBOX:-busybox} nslookup "$h" 8.8.8.8 2>/dev/null | \
                  awk '/^Name:/ {n=1; next} n && /^Address/ {print $NF}' | \
                  grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | \
                  grep -vE '^(10|127|0)\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.' | \
                  sort -u | head -n 4 | tr '\n' ' ')
            # Только адреса, закрытые по IP: напрямую не устанавливается даже TCP.
            # Адрес, до которого TCP доходит (сайт режут по DPI), — общий адрес CDN:
            # 25.10 через 8.47.69.0/8.6.112.0 (Cloudflare) в Opera ушли и чужие
            # сервисы, включая API Claude, — такие не берём.
            blk=""
            for a in $ips; do
                tcp_ok "$a" || blk="$blk $a"
            done
            ips="${blk# }"
            # прямой путь пропал посреди прогона (поднялся VPN — задачу тогда
            # никто не снимает, сменилась сеть): «закрыты» оказались бы все
            # адреса, а контроль после прогона VPN мог уже не застать — бросаем
            [ -n "$ips" ] && ! ctl_ok && { rm -f "$out" "$OPERA_SITES_PID"; exit 0; }
            [ -n "$ips" ] && echo "$h|$ips|$now" >> "$out"
        done
        # убранные в WebUI (opsite-del), пока шла проверка, — не возвращать
        [ -s "$OPERA_SITES_SKIP" ] && awk -F'|' 'NR == FNR {s[$0]; next} !($1 in s)' "$OPERA_SITES_SKIP" "$out" > "$out.2" && mv -f "$out.2" "$out"
        ctl_ok && mv -f "$out" "$OPERA_SITES_FILE"
        rm -f "$out" "$OPERA_SITES_PID"
    ) </dev/null >/dev/null 2>&1 &
    echo $! > "$OPERA_SITES_PID"
}

# PID-ы процессов, чей argv[0] начинается с $1, а в аргументах есть $2
# (обёртки su/sh не в счёт: у них argv[0] — su/sh)
_opera_pids() {
    local f
    for f in $(grep -l "$1" /proc/[0-9]*/cmdline 2>/dev/null); do
        case "$(tr '\0' ' ' 2>/dev/null < "$f")" in
            "$1"*"$2"*) f="${f#/proc/}"; echo "${f%/cmdline}" ;;
        esac
    done
}
opera_proxy_pids() { _opera_pids "$MODULE_DIR/bin/opera-proxy" "-bind-address 127.0.0.1:$OPERA_PORT "; }
opera_hev_pids()   { _opera_pids "$MODULE_DIR/bin/hev-socks5-tproxy" "$OPERA_HEV_CONF"; }
# hev слушает AF_INET6-сокетом: в ss он «[::ffff:127.0.0.1]:порт»
_opera_listening() { ss -ltn 2>/dev/null | grep -qE "(127\.0\.0\.1|\[::ffff:127\.0\.0\.1\]):$1[[:space:]]"; }

_opera_kill() {
    local p
    for p in "$@"; do kill "$p" 2>/dev/null; done
    [ -n "$*" ] || return 0
    sleep 0.3
    for p in "$@"; do kill -9 "$p" 2>/dev/null; done
}

# Go на Android не видит системные сертификаты: собираем PEM сами.
# Пользовательские (cacerts-added) — в DER, переводим в PEM: без них не
# работает у тех, у кого HTTPS-фильтр AdGuard («AdGuard Personal CA»).
opera_ca_build() {
    local d f n=0 u=0 b64=""
    command -v base64 >/dev/null 2>&1 && b64="base64"
    [ -z "$b64" ] && [ -n "$BUSYBOX" ] && b64="$BUSYBOX base64"
    : > "$OPERA_CA.tmp" 2>/dev/null || return 1
    for d in /apex/com.android.conscrypt/cacerts /system/etc/security/cacerts; do
        for f in "$d"/*.0; do
            [ -f "$f" ] || continue
            sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$f" >> "$OPERA_CA.tmp" && n=$((n + 1))
        done
        [ "$n" -gt 0 ] && break
    done
    for f in /data/misc/user/0/cacerts-added/*; do
        [ -f "$f" ] || continue
        if grep -q 'BEGIN CERTIFICATE' "$f" 2>/dev/null; then
            sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$f" >> "$OPERA_CA.tmp"
        elif [ -n "$b64" ]; then
            { echo "-----BEGIN CERTIFICATE-----"; $b64 < "$f"; echo "-----END CERTIFICATE-----"; } >> "$OPERA_CA.tmp"
        else
            continue
        fi
        u=$((u + 1))
    done
    mv -f "$OPERA_CA.tmp" "$OPERA_CA"
    OPERA_CA_INFO="$n системных, $u пользовательских"
    [ "$n" -gt 0 ]
}

# Исключение opera-proxy из перехвата AdGuard (как у dnsproxy): RETURN по
# группе в начале nat OUTPUT. Не строго первым: первое место держит
# dnsproxy_exempt, а AdGuard свой переход вставляет в позицию 1.
opera_exempt() {
    [ "$OPERA_SU_G" = "1" ] || return 0
    local want="-A OUTPUT -m owner --gid-owner $OPERA_GID -j RETURN"
    $iptables -t nat -S OUTPUT 2>/dev/null | sed -n '2,3p' | grep -qxF -- "$want" && return 0
    opera_exempt_down
    $iptables -t nat -I OUTPUT 1 -m owner --gid-owner "$OPERA_GID" -j RETURN 2>/dev/null
}
opera_exempt_down() {
    local _n=0
    [ -n "$OPERA_GID" ] || return 0
    while [ $_n -lt 8 ] && $iptables -t nat -D OUTPUT -m owner --gid-owner "$OPERA_GID" -j RETURN 2>/dev/null; do _n=$((_n + 1)); done
}

# Список кандидатов для -api-proxy-file: удачные раньше + запасной список
opera_api_file() {
    : > "$OPERA_API_FILE"
    [ -s "$OPERA_API_CACHE" ] && grep '://' "$OPERA_API_CACHE" >> "$OPERA_API_FILE"
    [ -s "$OPERA_API_SPARE" ] && cat "$OPERA_API_SPARE" >> "$OPERA_API_FILE"
    [ -s "$OPERA_API_FILE" ]
}

# Запасной список — в фоне (curl до 30с не держит цикл); пригодится на следующей попытке
opera_spare_fetch() {
    command -v curl >/dev/null 2>&1 || return 0
    setsid sh -c 'curl -s -m 30 --capath /apex/com.android.conscrypt/cacerts -o "$1.dl" "$2" || curl -s -m 30 -o "$1.dl" "$2"
        grep -E "^[0-9.]+:[0-9]+\$" "$1.dl" | head -n 3000 | sed "s#^#socks5://#" > "$1.new" && [ -s "$1.new" ] && mv -f "$1.new" "$1"
        rm -f "$1.dl" "$1.new"' opera "$OPERA_API_SPARE" "$OPERA_API_SPARE_URL" </dev/null >/dev/null 2>&1 &
}

# Адреса пула для региона (встроенные + выученные), по одному в строке
# «регион ip» для выбранного региона (AUTO — все регионы)
opera_pool_list() {
    { echo "$OPERA_POOL_SEED" | awk '{for (i = 1; i < NF; i += 2) print $i, $(i + 1)}'
      cat "$OPERA_POOL_FILE" 2>/dev/null; } | \
        awk -v r="$OPERA_COUNTRY" '(r == "AUTO" || $1 == r) && $1 ~ /^(EU|AS|AM)$/ && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && !s[$2]++ {print $1, $2}'
}
opera_pool_ips() { opera_pool_list | awk '{print $2}'; }
opera_ip_region() { opera_pool_list | awk -v a="$1" '$2 == a {print $1; exit}'; }

# Запомнить серверы, которые отдал discover (строка лога opera-proxy)
opera_pool_learn() {
    local a
    for a in $(sed -n 's/.*Discovered endpoints: \[\(.*\)\].*/\1/p' "$OPERA_LOG" 2>/dev/null | tail -n 1 | sed 's/:443//g'); do
        case "$a" in *[!0-9.]*|"") continue ;; esac
        opera_pool_ips | grep -qxF "$a" || echo "${OPERA_REGION:-$OPERA_COUNTRY} $a" >> "$OPERA_POOL_FILE"
    done
}

# Замер: TCP-подключение к каждому серверу региона через WAN (параллельно,
# ~2с на всё). Живой — ответил (HTTP 400 на голый запрос). OPERA_RANK = «мс ip».
opera_pool_rank() {
    local d a w="" g="" pids="" _n
    command -v curl >/dev/null 2>&1 || return 1
    d="/data/local/tmp/vpn_tether_opera_rank"
    rm -rf "$d"; mkdir -p "$d" || return 1
    [ -n "$LAST_WAN_IFACE" ] && w="--interface $LAST_WAN_IFACE"
    # от группы dnsproxy: мимо AdGuard, nfqws и нашего перенаправления
    [ "$DNSPROXY_SU_G" = "1" ] && [ -n "$DNSPROXY_GID" ] && g="$DNSPROXY_GID"
    for a in $(opera_pool_ips); do
        if [ -n "$g" ]; then
            su -g "$g" -c "curl -s -o /dev/null -m 2 $w -w '%{http_code} %{time_connect}' http://$a:443/" > "$d/$a" 2>/dev/null &
            pids="$pids $!"
        else
            curl -s -o /dev/null -m 2 $w -w '%{http_code} %{time_connect}' "http://$a:443/" > "$d/$a" 2>/dev/null &
            pids="$pids $!"
        fi
    done
    # только свои замеры: голый wait ждал бы и opera-proxy/hev (дети демона).
    # wait прерывается сигналом (USR1 — тоггл/WebUI, rc > 128) — ждём дальше,
    # иначе замер неполный и перемер решит, что текущий сервер умер
    _n=0
    while [ -n "$pids" ] && [ $_n -lt 5 ]; do
        wait $pids; [ $? -gt 128 ] || break
        _n=$((_n + 1))
    done
    OPERA_RANK=$(for a in "$d"/*; do
        [ -f "$a" ] || continue
        set -- $(cat "$a")
        [ "${1:-000}" != "000" ] && [ -n "$2" ] && echo "$2 ${a##*/}"
    done | awk '{printf "%d %s\n", $1 * 1000, $2}' | sort -n)
    rm -rf "$d"
    OPERA_RANK_TS=$(date +%s)
    [ -n "$OPERA_RANK" ]
}

# Лучший живой сервер, кроме уже не пропустивших Telegram в этой сети
opera_pool_best() {
    echo "$OPERA_RANK" | while read -r ms a; do
        [ -n "$a" ] || continue
        case " $OPERA_BAD " in *" $a "*) continue ;; esac
        [ -n "$OPERA_BADREG" ] && case " $OPERA_BADREG " in *" $(opera_ip_region "$a") "*) continue ;; esac
        echo "$a"; break
    done
}

opera_start() {
    local args via="" cand best
    _opera_kill $(opera_proxy_pids)
    if [ -z "$OPERA_SU_G" ]; then
        OPERA_SU_G=0
        [ "$DNSPROXY_SU_G" != "0" ] && [ -n "$OPERA_GID" ] && su -g "$OPERA_GID" -c true >/dev/null 2>&1 && OPERA_SU_G=1
        [ "$OPERA_SU_G" = "1" ] || log "WARNING: opera: su -g не работает — opera-proxy без своей группы (исключение из перенаправления — по uid 0, nfqws и AdGuard его не пропустят)"
    fi
    # регистрация в API — уже мимо AdGuard
    opera_exempt
    opera_ca_build || log "WARNING: opera: системные сертификаты не найдены — opera-proxy может не проверить TLS"
    # -server-selection first: «fastest» меряет скачивание с ajax.googleapis.com
    # через каждый сервер, а Google через Opera с YOTA почти не качается —
    # opera-proxy молча завершался через ~17с (24.10, 4 из 4 запусков)
    # самый быстрый живой сервер из пула (замер свежий — иначе мерим сейчас).
    # Учётка выдаётся на регион, поэтому при AUTO регион — по этому серверу.
    # пустой замер (например, сделан при поднятом VPN — через WAN тогда не
    # доходит ничего) — перемерить
    [ -n "$OPERA_RANK" ] && [ $(( $(date +%s) - OPERA_RANK_TS )) -lt 120 ] || opera_pool_rank
    best=$(opera_pool_best)
    OPERA_OVERRIDE="$best"
    OPERA_REGION="$OPERA_COUNTRY"
    [ "$OPERA_REGION" = "AUTO" ] && { OPERA_REGION=$(opera_ip_region "$best"); [ -n "$OPERA_REGION" ] || OPERA_REGION=EU; }
    args="-bind-address 127.0.0.1:$OPERA_PORT -socks-mode -country $OPERA_REGION -server-selection first -verbosity 20 -cafile $OPERA_CA"
    [ -n "$best" ] && args="$args -override-proxy-address $best:443"
    args="$args -bootstrap-dns https://dns.comss.one/dns-query,https://dns.adguard-dns.com/dns-query,tls://9.9.9.9:853,https://1.1.1.3/dns-query"
    # Чётная попытка — список по ссылке (не скачался — файл); нечётная (после
    # сбоя) — только файл: удачные раньше + запасной список.
    if [ -n "$OPERA_API_LIST" ] && [ $((OPERA_FAILS % 2)) -eq 0 ]; then
        args="$args -api-proxy-list-url '$OPERA_API_LIST'"
        via="список по ссылке"
        opera_api_file && { args="$args -api-proxy-file $OPERA_API_FILE"; via="$via, запасной — файл"; }
    elif opera_api_file; then
        args="$args -api-proxy-file $OPERA_API_FILE"
        via="файл ($(wc -l < "$OPERA_API_FILE" | tr -d ' ') прокси)"
    elif [ -n "$OPERA_API_LIST" ]; then
        args="$args -api-proxy-list-url '$OPERA_API_LIST'"
        via="список по ссылке"
    else
        via="без прокси (API напрямую)"
    fi
    # последний удачный кандидат — первым
    cand=$(head -n 1 "$OPERA_API_CACHE" 2>/dev/null | grep -E "^[a-z0-9]+://[^' ]+$")
    [ -n "$cand" ] && [ "$via" != "без прокси (API напрямую)" ] && { args="$args -api-proxy '$cand'"; via="$via, первым — $cand"; }
    : > "$OPERA_LOG"
    # setsid: с nohup opera-proxy умирал вместе с сессией
    if [ "$OPERA_SU_G" = "1" ]; then
        setsid su -g "$OPERA_GID" -c "exec $OPERA_BIN $args" </dev/null >> "$OPERA_LOG" 2>&1 &
    else
        eval "setsid \"\$OPERA_BIN\" $args" </dev/null >> "$OPERA_LOG" 2>&1 &
    fi
    OPERA_START_TS=$(date +%s)
    OPERA_STATE="starting"
    OPERA_ENDPOINT=""
    OPERA_ERR=""
    log "opera: запускаю opera-proxy (регион $([ "$OPERA_COUNTRY" = AUTO ] && echo "самый быстрый → $OPERA_REGION" || echo "$OPERA_REGION"), сервер ${best:-по выбору Opera}$([ -n "$OPERA_RANK" ] && echo " — живых $(echo "$OPERA_RANK" | grep -c .) из $(opera_pool_ips | grep -c .), $(echo "$OPERA_RANK" | awk -v b="$best" '$2 == b {print $1 "мс"}')"), gid $([ "$OPERA_SU_G" = 1 ] && echo "$OPERA_GID" || echo 0), прокси API: $via; CA: $OPERA_CA_INFO)"
    phone_status_refresh
}

# opera-proxy слушает — запомнить удачный прокси API и сервер
opera_started() {
    local c ep secs
    secs=$(( $(date +%s) - OPERA_START_TS ))
    c=$(sed -n 's/.*Using API proxy candidate: \([^ ]*\).*/\1/p' "$OPERA_LOG" 2>/dev/null | tail -n 1)
    if [ -n "$c" ]; then
        { echo "$c"; grep -vxF -- "$c" "$OPERA_API_CACHE" 2>/dev/null; } | head -n 20 > "$OPERA_API_CACHE.tmp" && \
            mv -f "$OPERA_API_CACHE.tmp" "$OPERA_API_CACHE"
        chmod 600 "$OPERA_API_CACHE" 2>/dev/null
    fi
    ep=$(sed -n 's/.*Selected endpoint address: \([^ ]*\).*/\1/p; s/.*Endpoint override: \([^ ]*\).*/\1/p' "$OPERA_LOG" 2>/dev/null | tail -n 1)
    # с -override-proxy-address строки «Selected endpoint» нет
    [ -z "$ep" ] && [ -n "$OPERA_OVERRIDE" ] && ep="$OPERA_OVERRIDE:443"
    OPERA_ENDPOINT="$ep"
    OPERA_WAN="$LAST_WAN_IFACE"
    OPERA_RERANK=0      # перемер — через 10 мин от старта, а не сразу после долгой регистрации
    opera_pool_learn
    OPERA_FAILS=0
    log "opera: opera-proxy готов за ${secs}с (pid $(opera_proxy_pids | head -n 1), сервер ${ep:-?}${c:+, прокси API $c})"
}

opera_hev_start() {
    local i
    _opera_kill $(opera_hev_pids)
    cat > "$OPERA_HEV_CONF" <<EOF
main:
  workers: 1
socks5:
  port: $OPERA_PORT
  address: 127.0.0.1
  udp: 'tcp'
tcp:
  port: $OPERA_TP_PORT
  address: 127.0.0.1
misc:
  log-file: $OPERA_HEV_LOG
  log-level: warn
  limit-nofile: 8192
EOF
    : > "$OPERA_HEV_LOG"
    # журнал hev пишет сам (log-file); сюда — только ошибки до чтения конфига
    setsid "$OPERA_HEV_BIN" "$OPERA_HEV_CONF" </dev/null >/dev/null 2>> "$OPERA_HEV_LOG" &
    i=0
    while [ $i -lt 10 ]; do
        sleep 0.2
        [ -n "$(opera_hev_pids)" ] && _opera_listening "$OPERA_TP_PORT" && return 0
        i=$((i + 1))
    done
    return 1
}

opera_rules_off() {
    local _n
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null; do _n=$((_n + 1)); done
    _n=0; while [ $_n -lt 8 ] && $iptables -t mangle -D OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null; do _n=$((_n + 1)); done
    $iptables -t mangle -F "$CHAIN_OPERA_IN" 2>/dev/null;  $iptables -t mangle -X "$CHAIN_OPERA_IN" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_OUT" 2>/dev/null; $iptables -t mangle -X "$CHAIN_OPERA_OUT" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_TP" 2>/dev/null;  $iptables -t mangle -X "$CHAIN_OPERA_TP" 2>/dev/null
    _n=0; while [ $_n -lt 8 ] && $ip rule del fwmark "$OPERA_MARK/$OPERA_MARK" lookup "$OPERA_TABLE" pref "$OPERA_PREF" 2>/dev/null; do _n=$((_n + 1)); done
    $ip route flush table "$OPERA_TABLE" 2>/dev/null
    OPERA_RULES_SIG=""
    OPERA_SCOPE=""
}

# opera_rules_on <1|0 — телефон> [интерфейсы раздачи...]
opera_rules_on() {
    local phone="$1" c u i cidrs; shift
    cidrs=$(opera_cidrs)
    [ -n "$cidrs" ] || { OPERA_ERR="пустой список подсетей Telegram"; return 1; }
    $iptables -t mangle -N "$CHAIN_OPERA_TP" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_TP" 2>/dev/null
    for c in $cidrs; do
        $iptables -t mangle -A "$CHAIN_OPERA_TP" -p tcp -d "$c" -j TPROXY \
            --on-ip 127.0.0.1 --on-port "$OPERA_TP_PORT" --tproxy-mark "$OPERA_MARK/$OPERA_MARK" 2>/dev/null || {
            OPERA_ERR="ядро без TPROXY (iptables -j TPROXY не встаёт)"; return 2; }
    done
    $iptables -t mangle -N "$CHAIN_OPERA_IN" 2>/dev/null
    $iptables -t mangle -F "$CHAIN_OPERA_IN" 2>/dev/null
    [ "$phone" = "1" ] && \
        $iptables -t mangle -A "$CHAIN_OPERA_IN" -i lo -p tcp -m mark --mark "$OPERA_MARK/$OPERA_MARK" -j "$CHAIN_OPERA_TP" 2>/dev/null
    for i in "$@"; do
        $iptables -t mangle -A "$CHAIN_OPERA_IN" -i "$i" -p tcp -j "$CHAIN_OPERA_TP" 2>/dev/null
    done
    # В конец: TPROXY завершает обход таблицы, системные цепочки — раньше
    $iptables -t mangle -C PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null || \
        $iptables -t mangle -A PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null

    if [ "$phone" = "1" ]; then
        $iptables -t mangle -N "$CHAIN_OPERA_OUT" 2>/dev/null
        $iptables -t mangle -F "$CHAIN_OPERA_OUT" 2>/dev/null
        $iptables -t mangle -A "$CHAIN_OPERA_OUT" -o lo -j RETURN 2>/dev/null
        # сам opera-proxy — мимо (иначе петля), nfqws и dnsproxy (и проверки WebUI от его группы) — тоже
        for u in $OPERA_GID $ZAPRET_GID $DNSPROXY_GID; do
            $iptables -t mangle -A "$CHAIN_OPERA_OUT" -m owner --gid-owner "$u" -j RETURN 2>/dev/null
        done
        # root — всегда мимо: проверка сайтов (scan.sh, curl от root) иначе пошла
        # бы к адресам из списка сайтов и к общим адресам CDN через Opera и
        # «открывала» бы их стратегиями zapret — подбор и ZSKIP были бы ложными.
        # Приложениям телефона (Telegram, AdGuard) это не мешает — они не root.
        $iptables -t mangle -A "$CHAIN_OPERA_OUT" -m owner --uid-owner 0 -j RETURN 2>/dev/null
        for u in $OPERA_EXCL; do
            $iptables -t mangle -A "$CHAIN_OPERA_OUT" -m owner --uid-owner "$u" -j RETURN 2>/dev/null
        done
        for c in $cidrs; do
            $iptables -t mangle -A "$CHAIN_OPERA_OUT" -p tcp -d "$c" -j MARK --set-xmark "$OPERA_MARK/$OPERA_MARK" 2>/dev/null
        done
        $iptables -t mangle -C OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null || \
            $iptables -t mangle -A OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null
    else
        while $iptables -t mangle -D OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null; do :; done
        $iptables -t mangle -F "$CHAIN_OPERA_OUT" 2>/dev/null; $iptables -t mangle -X "$CHAIN_OPERA_OUT" 2>/dev/null
    fi

    # помеченное — доставить локально (в TPROXY)
    $ip route replace local 0.0.0.0/0 dev lo table "$OPERA_TABLE" 2>/dev/null || {
        OPERA_ERR="не встал маршрут local в таблицу $OPERA_TABLE"; return 1; }
    $ip rule show 2>/dev/null | grep -q "^$OPERA_PREF:.*lookup $OPERA_TABLE" || \
        $ip rule add fwmark "$OPERA_MARK/$OPERA_MARK" lookup "$OPERA_TABLE" pref "$OPERA_PREF" 2>/dev/null || {
        OPERA_ERR="не встало ip rule fwmark"; return 1; }
    OPERA_SCOPE=$( { [ "$phone" = 1 ] && echo phone; [ -n "$*" ] && echo tether; } | tr '\n' ' ')
    OPERA_SCOPE="${OPERA_SCOPE% }"
    return 0
}

# хуки и ip rule на месте? (netd перетряхивает цепочки)
opera_rules_ok() {
    $iptables -t mangle -C PREROUTING -j "$CHAIN_OPERA_IN" 2>/dev/null || return 1
    case "$OPERA_SCOPE" in phone*) $iptables -t mangle -C OUTPUT -j "$CHAIN_OPERA_OUT" 2>/dev/null || return 1 ;; esac
    $ip rule show 2>/dev/null | grep -q "^$OPERA_PREF:.*lookup $OPERA_TABLE" || return 1
    $ip route show table "$OPERA_TABLE" 2>/dev/null | grep -q . || return 1
}

# Сервер Opera доходит? Запрос к DC Telegram через SOCKS opera-proxy (curl от
# группы opera — мимо перенаправления и nfqws). 24.10: на Wi-Fi Dom.ru часть
# серверов 77.111.x не отвечала, а opera-proxy жил — Telegram висел.
# Серверы Opera через раз отвечают 502 (перегружены) — до 3 попыток до первой
# удачной; 502 приходит быстро. Но сначала TCP до самого сервера (2с): если он
# закрыт по IP, три попытки по 4с — зря.
opera_probe() {
    local code n=0 g="sh -c" a="${OPERA_ENDPOINT%:*}"
    command -v curl >/dev/null 2>&1 || return 0
    [ "$OPERA_SU_G" = "1" ] && g="su -g $OPERA_GID -c"
    if [ -n "$a" ]; then
        code=$($g "curl -s -o /dev/null -m 2 ${LAST_WAN_IFACE:+--interface $LAST_WAN_IFACE} -w '%{http_code}' http://$a:443/" 2>/dev/null)
        OPERA_PROBE_WHY="tcp"
        [ -n "$code" ] && [ "$code" != "000" ] || return 1
    fi
    OPERA_PROBE_WHY="upstream"   # сервер доступен, но дальше не пускает (502)
    while [ $n -lt 3 ]; do
        code=$($g "curl -s -o /dev/null -m 4 --socks5 127.0.0.1:$OPERA_PORT -w '%{http_code}' http://$OPERA_PROBE_DC/" 2>/dev/null)
        [ -n "$code" ] && [ "$code" != "000" ] && return 0
        n=$((n + 1))
    done
    return 1
}

opera_fail() {   # причина [fast — сервер не отвечает: сразу другой]
    local p
    opera_rules_off
    _opera_kill $(opera_hev_pids)
    _opera_kill $(opera_proxy_pids)
    OPERA_FAILS=$((OPERA_FAILS + 1))
    case "$OPERA_FAILS" in 1) p=30 ;; 2) p=60 ;; *) p=150 ;; esac   # итераций по ~2с
    [ "$2" = "fast" ] && p=2
    OPERA_RETRY=$p
    OPERA_STATE="fail"
    OPERA_ERR="$1"
    OPERA_ENDPOINT=""
    log "WARNING: opera: $1 — Telegram напрямую, повтор через $([ "$p" -lt 30 ] && echo "~$((p * 2))с" || echo "~$((p * 2 / 60)) мин")"
    # после сбоя пригодится запасной список (не скачан или старше суток)
    if [ ! -s "$OPERA_API_SPARE" ] || [ -n "$(find "$OPERA_API_SPARE" -mmin +1440 2>/dev/null)" ]; then
        opera_spare_fetch
    fi
    phone_status_refresh
}

opera_down() {   # [quiet]
    local p
    p=$(opera_sites_pid) && kill "$p" 2>/dev/null; rm -f "$OPERA_SITES_PID"
    OPERA_SITES_SIG=""
    opera_rules_off
    _opera_kill $(opera_hev_pids)
    _opera_kill $(opera_proxy_pids)
    opera_exempt_down
    [ "$OPERA_STATE" != "off" ] && [ "$1" != "quiet" ] && log "opera: выключен"
    OPERA_STATE="off"
    OPERA_ENDPOINT=""
    OPERA_ERR=""
    OPERA_RETRY=0
    OPERA_FAILS=0
    phone_status_refresh
}

# журнал opera-proxy — не больше ~256 КБ (дописывается через >>, обрезка на ходу)
opera_log_trim() {
    local f s
    for f in "$OPERA_LOG" "$OPERA_HEV_LOG"; do
        s=$(wc -c < "$f" 2>/dev/null) || continue
        [ "${s:-0}" -gt 262144 ] || continue
        tail -n 1000 "$f" > "$f.tmp" && cat "$f.tmp" > "$f"
        rm -f "$f.tmp"
    done
}

# Каждая итерация цикла (после phone_dns_reconcile: он считает PHONE_VPN_STABLE)
opera_reconcile() {
    local want=0 ifaces="" sig rc _b _cm _bm _z
    if [ "$OPERA_TG" != "1" ]; then
        [ "$OPERA_STATE" != "off" ] && opera_down
        return 0
    fi
    [ "$OPERA_NOSUPPORT" = "1" ] && return 0
    if [ -z "$OPERA_BIN" ] || [ -z "$OPERA_HEV_BIN" ]; then
        OPERA_NOSUPPORT=1
        OPERA_STATE="fail"
        OPERA_ERR="нет bin/opera-proxy или bin/hev-socks5-tproxy для $(uname -m)"
        log "WARNING: opera: $OPERA_ERR"
        phone_status_refresh
        return 0
    fi
    # VPN не поднят (phone_dns_reconcile: подтверждено и в последнем замере):
    # появление VPN снимает перенаправление сразу, без второго замера
    [ "$PHONE_VPN_STABLE" = "0" ] && [ "$PHONE_VPN_SEEN" = "0" ] && want=1

    case "$OPERA_STATE" in
        off|fail)
            [ "$want" = "1" ] && [ -n "$LAST_WAN_IFACE" ] || return 0
            if [ "$OPERA_RETRY" -gt 0 ]; then OPERA_RETRY=$((OPERA_RETRY - 1)); return 0; fi
            opera_start
            return 0 ;;
        starting)
            if [ -z "$(opera_proxy_pids)" ]; then
                opera_fail "opera-proxy не запустился: $(grep -iE 'critical|error' "$OPERA_LOG" 2>/dev/null | tail -n 1 | cut -c1-160)"
                return 0
            fi
            if ! _opera_listening "$OPERA_PORT"; then
                [ $(( $(date +%s) - OPERA_START_TS )) -ge 180 ] && opera_fail "opera-proxy не зарегистрировался в Opera за 3 мин"
                return 0
            fi
            opera_started
            if ! opera_hev_start; then
                opera_fail "hev-socks5-tproxy не запустился: $(tail -n 2 "$OPERA_HEV_LOG" 2>/dev/null | tr '\n' ' ' | cut -c1-160)"
                return 0
            fi
            OPERA_STATE="on"
            OPERA_TICK=12   # первая проверка через ~6с: сразу после старта сервер ещё «прогревается»
            OPERA_WANT_PREV="$want"   # иначе первый старт (want ещё 0) сочтётся выключением VPN — проверка сразу
            phone_status_refresh ;;
        on)
            if [ -z "$(opera_proxy_pids)" ]; then
                opera_fail "opera-proxy завершился"
                return 0
            fi
            if [ -z "$(opera_hev_pids)" ]; then
                opera_rules_off
                log "WARNING: opera: hev-socks5-tproxy умер, перезапускаю"
                opera_hev_start || { opera_fail "hev-socks5-tproxy не перезапустился"; return 0; }
            fi ;;
    esac

    OPERA_TICK=$((OPERA_TICK + 1))
    OPERA_RERANK=$((OPERA_RERANK + 1))
    # сменилась сеть — сервер Opera мог стать недоступен: проверить сразу,
    # прошлые «не пропустил Telegram» и замер пула — от старой сети
    if [ "$OPERA_STATE" = "on" ] && [ "$LAST_WAN_IFACE" != "$OPERA_WAN" ]; then
        OPERA_TICK=15; OPERA_BAD=""; OPERA_BADREG=""; OPERA_RANK_TS=0
        OPERA_ZSKIP_SIG=""   # список сайтов — под новую сеть сразу, а не через ~10 мин
        # при поднятом VPN проверки нет и OPERA_WAN не обновлялся бы — блок
        # «~30с» шёл бы каждую итерацию до выключения VPN
        OPERA_WAN="$LAST_WAN_IFACE"
    fi
    # VPN только что выключили — проверить сервер до того, как вернём правила
    # (не прошла — сразу лучший живой из пула)
    [ "$want" = "1" ] && [ "$OPERA_WANT_PREV" = "0" ] && [ "$OPERA_STATE" = "on" ] && OPERA_TICK=15
    OPERA_WANT_PREV="$want"
    # ~10 мин: перемерить пул (через WAN — работает и при поднятом VPN, к его
    # выключению лучший сервер уже известен). Текущий умер или есть заметно
    # быстрее (вдвое и на 40+ мс) — переехать.
    if [ "$OPERA_RERANK" -ge 300 ] && [ "$OPERA_STATE" = "on" ]; then
        OPERA_RERANK=0
        OPERA_BAD=""; OPERA_BADREG=""
        if opera_pool_rank && [ "$want" = "1" ] && [ -n "$OPERA_OVERRIDE" ]; then
            _b=$(opera_pool_best)
            _cm=$(echo "$OPERA_RANK" | awk -v a="$OPERA_OVERRIDE" '$2 == a {print $1}')
            _bm=$(echo "$OPERA_RANK" | awk -v a="$_b" '$2 == a {print $1}')
            if [ -n "$_b" ] && [ "$_b" != "$OPERA_OVERRIDE" ] && \
               { { [ -z "$_cm" ] && ! opera_probe; } || { [ -n "$_cm" ] && [ $((_bm * 2)) -lt "$_cm" ] && [ $((_cm - _bm)) -gt 40 ]; }; }; then
                log "opera: перехожу на $_b (${_bm}мс) — $OPERA_OVERRIDE $([ -z "$_cm" ] && echo "больше не отвечает" || echo "${_cm}мс")"
                opera_rules_off
                opera_start
                return 0
            fi
        fi
    fi
    if [ "$OPERA_TICK" -ge 15 ]; then   # ~30с: дорогое (stat пакетов, iptables -C)
        OPERA_TICK=0
        if [ "$OPERA_STATE" = "on" ] && [ "$want" = "1" ]; then
            OPERA_WAN="$LAST_WAN_IFACE"
            # не пропустил Telegram (проверка сама делает до 3 попыток) — сервер
            # в чёрный список сети и сразу лучший живой из пула. Два отказа
            # подряд в одном регионе — отказывает регион (24.10: EU и AM
            # отвечали 502 на всё, AS работал) — при AUTO его серверы не берём.
            # 6 переездов подряд — пауза с нарастанием, чтобы не долбить Opera.
            if ! opera_probe; then
                [ -n "$OPERA_OVERRIDE" ] && OPERA_BAD="$OPERA_BAD $OPERA_OVERRIDE"
                # сервер доступен, а Telegram не пропускает (502) — так отказывает
                # весь регион (24.10: EU 25 мин работал, потом 502 у его серверов;
                # два отказа подряд стоили ~70с без Telegram) — выводим сразу
                [ "$OPERA_COUNTRY" = "AUTO" ] && { [ "$OPERA_LASTFAIL_REG" = "$OPERA_REGION" ] || [ "$OPERA_PROBE_WHY" = "upstream" ]; } && \
                    case " $OPERA_BADREG " in *" $OPERA_REGION "*) ;; *) OPERA_BADREG="$OPERA_BADREG $OPERA_REGION" ;; esac
                OPERA_LASTFAIL_REG="$OPERA_REGION"
                OPERA_HOPS=$((OPERA_HOPS + 1))
                OPERA_RANK_TS=0
                if [ "$OPERA_HOPS" -ge 6 ]; then
                    OPERA_HOPS=0; OPERA_BAD=""; OPERA_BADREG=""; OPERA_LASTFAIL_REG=""
                    opera_fail "серверы Opera не пропускают Telegram (6 подряд)"
                    return 0
                fi
                opera_fail "сервер Opera ${OPERA_ENDPOINT:-?} не отвечает${OPERA_WAN:+ (сеть $OPERA_WAN)}" fast
                OPERA_RETRY=0
                return 0
            fi
            OPERA_HOPS=0; OPERA_LASTFAIL_REG=""
        fi
        OPERA_EXCL=$(zapret_vpn_uids)
        opera_exempt
        opera_log_trim
        # сайты, которые не открывает обход: проверка — после новой проверки
        # сайтов (ZSKIP изменился) или раз в ~10 мин; список изменился —
        # перестроить перенаправление (по адресам: смена одного времени
        # проверки — не повод перестраивать, это рвёт и соединения Telegram)
        if [ "$OPERA_SITES" = "1" ] && [ "$OPERA_STATE" = "on" ] && [ "$want" = "1" ]; then
            OPERA_SITES_TICK=$((OPERA_SITES_TICK + 1))
            _z=$(cksum < "$OPERA_ZSKIP" 2>/dev/null)
            if [ "$_z" != "$OPERA_ZSKIP_SIG" ] || [ "$OPERA_SITES_TICK" -ge 20 ]; then
                OPERA_ZSKIP_SIG="$_z"; OPERA_SITES_TICK=0
                opera_sites_job
            fi
            _z=$(opera_site_ips | tr '\n' ' ')
            if [ "$_z" != "$OPERA_SITES_SIG" ]; then
                OPERA_SITES_SIG="$_z"
                [ -n "$OPERA_RULES_SIG" ] && OPERA_RULES_SIG=""
                [ -s "$OPERA_SITES_FILE" ] && log "opera: сайты только через Opera: $(grep -c . "$OPERA_SITES_FILE") ($(cut -d'|' -f1 "$OPERA_SITES_FILE" | head -n 6 | tr '\n' ' ' | sed 's/ $//')), адресов $(opera_site_ips | grep -c .)"
            fi
        fi
        [ -n "$OPERA_RULES_SIG" ] && ! opera_rules_ok && {
            log "WATCHDOG: opera: правила пропали, ставлю заново"; OPERA_RULES_SIG=""; }
    fi

    if [ "$want" = "0" ]; then
        if [ -n "$OPERA_RULES_SIG" ]; then
            opera_rules_off
            log "opera: VPN поднят — Telegram через VPN, перенаправление снято"
            phone_status_refresh
        fi
        return 0
    fi
    # раздача — только в режиме «напрямую»: в blocked и VPN её трогать нельзя
    [ "$VPN_TETHER_MODE" = "off" ] && ifaces="$LAST_TETHER_IFACES"
    sig="1|$ifaces|$OPERA_EXCL"
    [ "$sig" = "$OPERA_RULES_SIG" ] && return 0
    opera_rules_on 1 $ifaces; rc=$?
    if [ "$rc" = 0 ]; then
        OPERA_RULES_SIG="$sig"
        log "opera: Telegram через Opera (${OPERA_ENDPOINT:-?}): телефон$([ -n "$ifaces" ] && echo " + раздача [$ifaces]")${OPERA_EXCL:+; мимо VPN-клиенты: $OPERA_EXCL}"
        phone_status_refresh
        return 0
    fi
    opera_rules_off
    if [ "$rc" = 2 ]; then
        # ядро без TPROXY: повторять бессмысленно, процессы не держим
        _opera_kill $(opera_hev_pids)
        _opera_kill $(opera_proxy_pids)
        OPERA_NOSUPPORT=1
        OPERA_STATE="fail"
        log "WARNING: opera: $OPERA_ERR — функция недоступна на этом ядре"
        phone_status_refresh
    else
        opera_fail "${OPERA_ERR:-правила не встали}"
    fi
}
