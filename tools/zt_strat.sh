# Подбор стратегии nfqws на телефоне: только запросы root через мобильный
# интерфейс (curl --interface), трафик телефона/раздачи не трогается.
ZT=/data/local/tmp/zt; WAN=${WAN:-rmnet_data1}; CA=/apex/com.android.conscrypt/cacerts; Q=201
G=$ZT/tls_google.bin
SITES="${SITES:-www.youtube.com i.ytimg.com discord.com gateway.discord.gg x.com www.facebook.com rutracker.org www.linkedin.com medium.com www.patreon.com ya.ru www.google.com}"
BB=/data/adb/ksu/bin/busybox
: > $ZT/ips
for h in $SITES; do echo "$h $($BB nslookup $h 1.1.1.1 2>/dev/null | sed -n '/^Name/,$p' | grep -oE 'Address 1: [0-9.]+' | awk '{print $3}')" >> $ZT/ips; done

ipt() { # $1 = -I | -D
  iptables -t nat $1 OUTPUT $([ "$1" = -I ] && echo 1) -m owner --uid-owner 0 -p tcp -j RETURN 2>/dev/null
  iptables -t mangle $1 POSTROUTING $([ "$1" = -I ] && echo 1) -o $WAN -m owner --uid-owner 0 -p tcp --dport 443 \
    -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9 \
    -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num $Q --queue-bypass 2>/dev/null
}
cleanup() { pkill -f "nfqws --qnum=$Q" 2>/dev/null; ipt -D; ipt -D; }
trap cleanup EXIT INT TERM

run_sites() {
  rm -f $ZT/r.*
  while read -r h ip; do
    ( r=$(curl -s -o /dev/null -m 6 --interface $WAN --capath $CA ${ip:+--resolve $h:443:$ip} -w '%{http_code}' https://$h/ 2>/dev/null); rc=$?
      if [ $rc = 0 ] && [ "$r" != 000 ]; then echo ok > $ZT/r.$h; else echo "x$rc" > $ZT/r.$h; fi ) &
  done < $ZT/ips
  wait
  ok=0; line=""
  for h in $SITES; do v=$(cat $ZT/r.$h); [ "$v" = ok ] && ok=$((ok+1)); line="$line ${h%%.*}${h#www.}:$v"; done
  echo "$ok/$(echo $SITES | wc -w) |$line" | sed 's/www//g'
}

ipt -I
echo "== без nfqws: $(run_sites)"
n=0
while IFS= read -r s; do
  [ -z "$s" ] && continue; n=$((n+1))
  $ZT/nfqws --qnum=$Q --uid=0:0 --bind-fix4 $s > $ZT/nfqws.log 2>&1 &
  sleep 1
  if ! kill -0 $! 2>/dev/null; then echo "S$n FAILED START: $(tail -2 $ZT/nfqws.log)"; continue; fi
  echo "S$n $(run_sites)   [$s]"
  kill $! 2>/dev/null; wait $! 2>/dev/null
done <<STRATS
--dpi-desync=multisplit --dpi-desync-split-pos=1,sniext+1
--dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld
--dpi-desync=fake --dpi-desync-fooling=badseq --dpi-desync-fake-tls=@$G
--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq --dpi-desync-fake-tls=@$G
--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=@$G --dpi-desync-fake-tls=@$G
--dpi-desync=fake,fakedsplit --dpi-desync-fooling=badseq --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com
--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=www.google.com --dpi-desync-fooling=badseq
--dpi-desync=fake,multidisorder --dpi-desync-fooling=md5sig --dpi-desync-split-pos=midsld --dpi-desync-fake-tls=@$G
--dpi-desync=fake,multisplit --dpi-desync-autottl --dpi-desync-split-pos=1 --dpi-desync-fake-tls=@$G
--dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=@$G
STRATS
