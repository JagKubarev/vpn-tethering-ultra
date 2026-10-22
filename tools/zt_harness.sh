# стенд: функции zapret из нового service.sh, настоящие iptables/nfqws
T=/data/local/tmp/zh; MODULE_DIR=$T
iptables="/system/bin/iptables -w 2"; ip6tables="/system/bin/ip6tables -w 2"
log() { echo "LOG: $*"; }
phone_status_refresh() { :; }
vpn_up_now() { ip addr show tun0 2>/dev/null | grep -q "inet "; }
DNSPROXY_GID=3999
ZAPRET_ENABLE=1; ZAPRET_MODE=list; ZAPRET_PHONE=1; ZAPRET_STRATEGY=md5sig; ZAPRET_QUIC_BLOCK=1
NFQWS_BIN=$T/bin/nfqws-arm64
zapret_strategy_args() {
    local g="$1/tls_clienthello_www_google_com.bin"
    case "$ZAPRET_STRATEGY" in
        badseq)   echo "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq --dpi-desync-fake-tls=@$g" ;;
        disorder) echo "--dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld" ;;
        seqovl)   echo "--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=@$g --dpi-desync-fake-tls=@$g" ;;
        *)        echo "--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$g" ;;
    esac
}
ZAPRET_DIR="$MODULE_DIR/zapret"
ZAPRET_LIST_DEFAULT="$ZAPRET_DIR/list-default.txt"
ZAPRET_LIST_USER="/data/local/tmp/zh/vpn_tether_zapret.txt"        # свой список (WebUI)
ZAPRET_LIST_AUTO="/data/local/tmp/zh/vpn_tether_zapret_auto.txt"   # nfqws пополняет сам
ZAPRET_VPN_UIDS_FILE="/data/local/tmp/zh/vpn_tether_vpn_uids"      # uid VPN-клиентов, замеченных владельцами VPN
ZAPRET_PID_FILE="/data/local/tmp/vpn_tether_nfqws.pid"
ZAPRET_LOG="/data/local/tmp/vpn_tether_nfqws.log"
ZAPRET_QNUM=200
ZAPRET_MARK=0x40000000     # метка поддельных пакетов nfqws (по умолчанию у nfqws)
CHAIN_ZAPRET="VPN_ZAPRET"          # mangle POSTROUTING: исходящие -> nfqws
CHAIN_ZAPRET_IN="VPN_ZAPRET_IN"    # mangle PREROUTING: ответы -> nfqws (автосписок)
CHAIN_ZAPRET_QUIC="VPN_ZAPRET_QUIC" # filter FORWARD: QUIC раздачи
# VPN-клиенты: их собственное соединение с сервером (часто TLS на 443) zapret
# трогать не должен — иначе можно сломать переподключение VPN.
VPN_CLIENT_PKGS="llc.itdev.incy com.happproxy org.amnezia.vpn org.amnezia.awg com.wireguard.android com.zaneschepke.wireguardautotunnel com.zaneschepke.wireguardautotunnel.nightly com.v2ray.ang app.hiddify.com moe.nb4a io.nekohasekai.sfa com.github.dyhkwong.sagernet io.github.saeeddev94.xray com.github.kr328.clash com.github.metacubex.clash.meta de.blinkt.openvpn net.openvpn.openvpn org.outline.android.client com.cloudflare.onedotonedotonedotone com.v2raytun.android dev.hexasoftware.v2box com.exclave.exclave"
ZAPRET_STATE="off"     # off | on | fail
ZAPRET_SIG=""          # аргументы + исключения запущенного экземпляра
ZAPRET_RETRY=0
ZAPRET_TICK=0
ZAPRET_ARGS_RUN=""
ZAPRET_EXCL_RUN=""

zapret_alive() {
    local pid
    pid=$(cat "$ZAPRET_PID_FILE" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && grep -q nfqws "/proc/$pid/cmdline" 2>/dev/null
}

# Все nfqws на нашей очереди, в т.ч. оставшиеся от убитого демона
zapret_kill_all() {
    local p
    for p in $(pgrep -f "nfqws.*--qnum=$ZAPRET_QNUM " 2>/dev/null); do kill "$p" 2>/dev/null; done
    sleep 0.3
    for p in $(pgrep -f "nfqws.*--qnum=$ZAPRET_QNUM " 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
    rm -f "$ZAPRET_PID_FILE"
}

# uid VPN-клиентов: известные пакеты + владельцы VPN, замеченные раньше
zapret_vpn_uids() {
    local p u out=""
    for p in $VPN_CLIENT_PKGS; do
        u=$(stat -c %u "/data/data/$p" 2>/dev/null)
        case "$u" in ''|*[!0-9]*) continue ;; esac
        out="$out $u"
    done
    [ -f "$ZAPRET_VPN_UIDS_FILE" ] && out="$out $(tr -c '0-9' ' ' < "$ZAPRET_VPN_UIDS_FILE")"
    echo $out | tr ' ' '\n' | awk '$1 ~ /^[0-9]+$/ && $1 >= 10000' | sort -un | tr '\n' ' '
}

# Владелец поднятого VPN (любой клиент, даже не из списка) — запоминаем
zapret_learn_vpn_owner() {
    local u
    u=$(dumpsys connectivity 2>/dev/null | grep -A3 'VPN CONNECTED' | grep -oE 'OwnerUid: [0-9]+' | head -1 | grep -oE '[0-9]+$')
    case "$u" in ''|*[!0-9]*) return 0 ;; esac
    [ "$u" -ge 10000 ] || return 0
    grep -qx "$u" "$ZAPRET_VPN_UIDS_FILE" 2>/dev/null && return 0
    echo "$u" >> "$ZAPRET_VPN_UIDS_FILE"
    log "zapret: uid $u (владелец VPN) — в исключения"
}

zapret_args() {
    local a="--qnum=$ZAPRET_QNUM --uid=0:0 --bind-fix4 --bind-fix6 --filter-tcp=443"
    if [ "$ZAPRET_MODE" = "list" ]; then
        a="$a --hostlist=$ZAPRET_LIST_DEFAULT"
        # пустой список не передаём: не полагаемся на то, как nfqws его трактует
        grep -q '[a-z0-9]' "$ZAPRET_LIST_USER" 2>/dev/null && a="$a --hostlist=$ZAPRET_LIST_USER"
        a="$a --hostlist-auto=$ZAPRET_LIST_AUTO"
    fi
    echo "$a $(zapret_strategy_args "$ZAPRET_DIR")"
}

zapret_start() {
    local pid
    zapret_kill_all
    [ -f "$ZAPRET_LIST_AUTO" ] || { : > "$ZAPRET_LIST_AUTO"; chmod 600 "$ZAPRET_LIST_AUTO"; }
    : > "$ZAPRET_LOG"
    # $1 без кавычек: это список аргументов, собранный zapret_args
    "$NFQWS_BIN" $1 >> "$ZAPRET_LOG" 2>&1 &
    pid=$!
    sleep 0.5
    if kill -0 "$pid" 2>/dev/null; then
        echo "$pid" > "$ZAPRET_PID_FILE"
        log "zapret: nfqws запущен (pid $pid, стратегия $ZAPRET_STRATEGY, режим $ZAPRET_MODE)"
        return 0
    fi
    log "WARNING: zapret: nfqws не запустился: $(tail -n 2 "$ZAPRET_LOG" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    return 1
}

zapret_rules_on() {
    local excl="$1" t u lan rj
    for t in "$iptables" "$ip6tables"; do
        if [ "$t" = "$iptables" ]; then
            lan="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16"
            rj="icmp-port-unreachable"
        else
            lan="fc00::/7,fe80::/10,::1/128"
            rj="icmp6-port-unreachable"
        fi
        # исходящие
        $t -t mangle -N "$CHAIN_ZAPRET" 2>/dev/null
        $t -t mangle -F "$CHAIN_ZAPRET" 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET" -o tun+ -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET" -o lo -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET" -d "$lan" -j RETURN 2>/dev/null
        $t -t mangle -A "$CHAIN_ZAPRET" -m mark --mark "$ZAPRET_MARK/$ZAPRET_MARK" -j RETURN 2>/dev/null
        if [ "$ZAPRET_PHONE" = "1" ]; then
            for u in $excl; do
                $t -t mangle -A "$CHAIN_ZAPRET" -m owner --uid-owner "$u" -j RETURN 2>/dev/null
            done
            [ -n "$DNSPROXY_GID" ] && \
                $t -t mangle -A "$CHAIN_ZAPRET" -m owner --gid-owner "$DNSPROXY_GID" -j RETURN 2>/dev/null
        else
            # только раздача: у её пакетов нет локального сокета
            $t -t mangle -A "$CHAIN_ZAPRET" -m owner --socket-exists -j RETURN 2>/dev/null
        fi
        $t -t mangle -A "$CHAIN_ZAPRET" -p tcp --dport 443 \
            -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 \
            -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null
        $t -t mangle -C POSTROUTING -j "$CHAIN_ZAPRET" 2>/dev/null || \
            $t -t mangle -A POSTROUTING -j "$CHAIN_ZAPRET" 2>/dev/null

        # ответы (для автосписка)
        $t -t mangle -N "$CHAIN_ZAPRET_IN" 2>/dev/null
        $t -t mangle -F "$CHAIN_ZAPRET_IN" 2>/dev/null
        if [ "$ZAPRET_MODE" = "list" ]; then
            $t -t mangle -A "$CHAIN_ZAPRET_IN" -i tun+ -j RETURN 2>/dev/null
            $t -t mangle -A "$CHAIN_ZAPRET_IN" -i lo -j RETURN 2>/dev/null
            $t -t mangle -A "$CHAIN_ZAPRET_IN" -s "$lan" -j RETURN 2>/dev/null
            $t -t mangle -A "$CHAIN_ZAPRET_IN" -p tcp --sport 443 \
                -m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:3 \
                -j NFQUEUE --queue-num "$ZAPRET_QNUM" --queue-bypass 2>/dev/null
        fi
        $t -t mangle -C PREROUTING -j "$CHAIN_ZAPRET_IN" 2>/dev/null || \
            $t -t mangle -A PREROUTING -j "$CHAIN_ZAPRET_IN" 2>/dev/null

        # QUIC раздачи мимо VPN
        $t -N "$CHAIN_ZAPRET_QUIC" 2>/dev/null
        $t -F "$CHAIN_ZAPRET_QUIC" 2>/dev/null
        if [ "$ZAPRET_QUIC_BLOCK" = "1" ]; then
            $t -A "$CHAIN_ZAPRET_QUIC" -o tun+ -j RETURN 2>/dev/null
            $t -A "$CHAIN_ZAPRET_QUIC" -p udp --dport 443 -j REJECT --reject-with "$rj" 2>/dev/null
            $t -C FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null || \
                $t -I FORWARD 1 -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null
        else
            while $t -D FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null; do :; done
        fi
    done
}

zapret_rules_off() {
    local t _n
    for t in "$iptables" "$ip6tables"; do
        _n=0; while [ $_n -lt 8 ] && $t -t mangle -D POSTROUTING -j "$CHAIN_ZAPRET" 2>/dev/null; do _n=$((_n + 1)); done
        _n=0; while [ $_n -lt 8 ] && $t -t mangle -D PREROUTING -j "$CHAIN_ZAPRET_IN" 2>/dev/null; do _n=$((_n + 1)); done
        _n=0; while [ $_n -lt 8 ] && $t -D FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null; do _n=$((_n + 1)); done
        $t -t mangle -F "$CHAIN_ZAPRET" 2>/dev/null;    $t -t mangle -X "$CHAIN_ZAPRET" 2>/dev/null
        $t -t mangle -F "$CHAIN_ZAPRET_IN" 2>/dev/null; $t -t mangle -X "$CHAIN_ZAPRET_IN" 2>/dev/null
        $t -F "$CHAIN_ZAPRET_QUIC" 2>/dev/null;         $t -X "$CHAIN_ZAPRET_QUIC" 2>/dev/null
    done
}

zapret_down() {
    zapret_rules_off
    zapret_kill_all
    [ "$ZAPRET_STATE" = "on" ] && log "zapret: выключен"
    ZAPRET_STATE="off"
    ZAPRET_ARGS_RUN=""
    ZAPRET_EXCL_RUN=""
    ZAPRET_RETRY=0
    ZAPRET_TICK=0
    phone_status_refresh
}

# Каждая итерация цикла. Дорогое (dumpsys, stat пакетов) — раз в ~30с.
zapret_reconcile() {
    local args excl
    if [ "$ZAPRET_ENABLE" != "1" ] || [ -z "$NFQWS_BIN" ]; then
        [ "$ZAPRET_STATE" != "off" ] && zapret_down
        return 0
    fi
    if [ "$ZAPRET_RETRY" -gt 0 ]; then
        ZAPRET_RETRY=$((ZAPRET_RETRY - 1))
        return 0
    fi
    args="$ZAPRET_ARGS_RUN"
    excl="$ZAPRET_EXCL_RUN"
    ZAPRET_TICK=$((ZAPRET_TICK + 1))
    if [ "$ZAPRET_TICK" -ge 15 ] || [ "$ZAPRET_STATE" != "on" ]; then
        ZAPRET_TICK=0
        vpn_up_now && zapret_learn_vpn_owner
        args=$(zapret_args)
        excl=$(zapret_vpn_uids)
    fi

    # nfqws: не запущен / умер / сменились аргументы (свой список появился)
    if [ "$args" != "$ZAPRET_ARGS_RUN" ] || ! zapret_alive; then
        [ "$ZAPRET_STATE" = "on" ] && [ "$args" = "$ZAPRET_ARGS_RUN" ] && \
            log "WARNING: zapret: nfqws умер, перезапускаю"
        if ! zapret_start "$args"; then
            zapret_rules_off
            ZAPRET_STATE="fail"
            ZAPRET_ARGS_RUN=""
            ZAPRET_EXCL_RUN=""
            ZAPRET_RETRY=30          # повтор через ~минуту
            phone_status_refresh
            return 0
        fi
        ZAPRET_ARGS_RUN="$args"
        ZAPRET_STATE="starting"
    fi

    # правила: впервые / сменились исключения / хук снесли (netd пересобрал цепочки)
    if [ "$ZAPRET_STATE" != "on" ] || [ "$excl" != "$ZAPRET_EXCL_RUN" ] || \
       ! $iptables -t mangle -C POSTROUTING -j "$CHAIN_ZAPRET" 2>/dev/null || \
       { [ "$ZAPRET_QUIC_BLOCK" = "1" ] && ! $iptables -C FORWARD -j "$CHAIN_ZAPRET_QUIC" 2>/dev/null; }; then
        zapret_rules_on "$excl"
        if [ "$ZAPRET_STATE" != "on" ]; then
            log "zapret: включён (режим $ZAPRET_MODE, телефон: $ZAPRET_PHONE, QUIC раздачи: $([ "$ZAPRET_QUIC_BLOCK" = 1 ] && echo закрыт || echo открыт); VPN-клиенты в исключениях: ${excl:-нет})"
        elif [ "$excl" != "$ZAPRET_EXCL_RUN" ]; then
            log "zapret: исключения VPN-клиентов: ${excl:-нет}"
        else
            log "WATCHDOG: zapret: правила пропали, ставлю заново"
        fi
        ZAPRET_EXCL_RUN="$excl"
        ZAPRET_STATE="on"
        phone_status_refresh
    fi
}

CA=/apex/com.android.conscrypt/cacerts; WAN=rmnet_data1
probe() {
  iptables -w 2 -t nat -I OUTPUT 1 -m owner --uid-owner 0 -p tcp -j RETURN
  for hh in "www.youtube.com 142.251.150.4" "discord.com 162.159.135.232" "x.com 172.66.0.227" "rutracker.org 104.21.32.39" "www.linkedin.com 104.18.41.41" "ya.ru 5.255.255.242"; do
    set -- $hh
    r=$(curl -s -o /dev/null -m 7 --interface $WAN --capath $CA --resolve $1:443:$2 -w '%{http_code}' https://$1/ 2>/dev/null); echo -n " $1:$r/$?"
  done; echo
  iptables -w 2 -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp -j RETURN
}
echo "== до: $(probe)"
zapret_reconcile
echo "state=$ZAPRET_STATE pid=$(cat $ZAPRET_PID_FILE) excl=[$ZAPRET_EXCL_RUN]"
echo "args: $ZAPRET_ARGS_RUN" | cut -c1-260
iptables -t mangle -S VPN_ZAPRET; echo; iptables -t mangle -S VPN_ZAPRET_IN; iptables -S VPN_ZAPRET_QUIC
echo "hooks: post=$(iptables -t mangle -S POSTROUTING | grep -n VPN_ZAPRET | cut -d: -f1)/$(iptables -t mangle -S POSTROUTING | wc -l) pre=$(iptables -t mangle -S PREROUTING | grep -c VPN_ZAPRET_IN) fwd=$(iptables -S FORWARD | grep -n VPN_ZAPRET_QUIC | cut -d: -f1) v6post=$(ip6tables -t mangle -S POSTROUTING | grep -c VPN_ZAPRET)"
echo "== с zapret (по списку): $(probe)"
sleep 1; echo "== ещё раз: $(probe)"
echo "counters: $(iptables -t mangle -L VPN_ZAPRET -v -n | awk '/NFQUEUE/{print $1}') out / $(iptables -t mangle -L VPN_ZAPRET_IN -v -n | awk '/NFQUEUE/{print $1}') in"
zapret_reconcile; echo "повторный reconcile без изменений: state=$ZAPRET_STATE"
zapret_down
echo "после down: post=$(iptables -t mangle -S POSTROUTING | grep -c VPN_ZAPRET) pre=$(iptables -t mangle -S PREROUTING | grep -c VPN_ZAPRET) fwd=$(iptables -S FORWARD | grep -c VPN_ZAPRET) v6=$(ip6tables -t mangle -S POSTROUTING | grep -c VPN_ZAPRET) nfqws=$(pgrep -f 'nfqws.*--qnum=200 ' | wc -l)"
echo "nfqws log:"; head -5 $ZAPRET_LOG
