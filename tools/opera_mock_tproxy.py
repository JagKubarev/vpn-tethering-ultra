#!/usr/bin/env python3
# Замена hev-socks5-tproxy для tools/opera_smoke.sh, где ядро без IPv6 (hev
# открывает только AF_INET6). Делает то же, что hev: слушает с IP_TRANSPARENT,
# адрес назначения берёт из getsockname() принятого сокета, соединение — в
# SOCKS5. Конфиг — тот же YAML демона (берутся tcp.port и socks5.port).
import re, socket, struct, sys, threading
conf = open(sys.argv[1]).read()
sec = lambda n: re.search(r"^%s:\n((?:  .*\n)+)" % n, conf, re.M).group(1)
tport = int(re.search(r"port: (\d+)", sec("tcp")).group(1))
sport = int(re.search(r"port: (\d+)", sec("socks5")).group(1))

def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d: break
            b.sendall(d)
    except Exception: pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except Exception: pass

def serve(c):
    dst, dport = c.getsockname()
    u = socket.create_connection(("127.0.0.1", sport))
    u.sendall(b"\x05\x01\x00"); u.recv(2)
    u.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(dst) + struct.pack("!H", dport)); u.recv(10)
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    pipe(u, c)

s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_IP, 19, 1)   # IP_TRANSPARENT
s.bind(("127.0.0.1", tport)); s.listen(64)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
