#!/usr/bin/env python3
# Мок opera-proxy для tools/opera_smoke.sh: SOCKS5 (без пароля, только CONNECT)
# на адресе из -bind-address. Наружу не ходит: на любой CONNECT отвечает
# HTTP-ответом "via-opera <адрес>:<порт>" — по нему видно, что соединение
# дошло через hev-socks5-tproxy, и куда клиент на самом деле шёл.
import socket, struct, sys, threading
bind = "127.0.0.1:18080"
a = sys.argv[1:]
for i, x in enumerate(a):
    if x == "-bind-address" and i + 1 < len(a):
        bind = a[i + 1]
host, port = bind.rsplit(":", 1)

def rd(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            raise EOFError
        b += d
    return b

def serve(c):
    try:
        _, n = rd(c, 2); rd(c, n); c.sendall(b"\x05\x00")
        _, cmd, _, at = rd(c, 4)
        if at == 1: dst = socket.inet_ntoa(rd(c, 4))
        elif at == 3: dst = rd(c, rd(c, 1)[0]).decode()
        else: dst = socket.inet_ntop(socket.AF_INET6, rd(c, 16))
        dport = struct.unpack("!H", rd(c, 2))[0]
        c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
        c.settimeout(3)
        try: c.recv(4096)
        except Exception: pass
        body = ("via-opera %s:%d\n" % (dst, dport)).encode()
        c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        print("CONNECT %s:%d" % (dst, dport), flush=True)
    except Exception as e:
        print("ERR", e, flush=True)
    finally:
        c.close()

s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, int(port))); s.listen(64)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
