#!/system/bin/sh
for p in $(ps -A -o PID,ARGS | awk '/[t]34\.sh/ { print $1 }'); do kill -9 $p; done
for p in $(ps -A -o PID,ARGS | awk '/qnum=21[1]/ || /curl -sk -m 10 .*47000-47999/ { print $1 }'); do kill -9 $p; done
sleep 1
ps -A -o PID,ARGS | grep -c -e '[t]34.sh' -e 'qnum=21[1]' -e 'curl -sk -m 1[0]'
iptables -t mangle -S | grep -c 47000:47999
