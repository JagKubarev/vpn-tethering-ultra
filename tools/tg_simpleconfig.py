# Запасной конфиг Telegram (TXT apv3.stel.com) — расшифровка по Datacenter::decodeSimpleConfig
# (DrKLO/Telegram, tgnet). Там адреса ретрансляторов, к которым приложение идёт, когда DC не
# отвечают. Нужен pycryptodome. Ответ DoH в JSON:
#   curl -s -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=apv3.stel.com&type=TXT' > txt.json
#   python tools/tg_simpleconfig.py txt.json
# Остальные ретрансляторы приходят от сервера (dc_options) — смотреть в files/tgnet.dat приложения.
import sys, json, base64, hashlib, struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

PUB = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyr+18Rex2ohtVy8sroGPBwXD3DOoKCSpjDqYoXgCqB7ioln4eDCF
fOBUlfXUEvM/fnKCpF46VkAftlb4VuPDeQSS/ZxZYEGqHaywlroVnXHIjgqoxiAd
192xRGreuXIaUKmkwlM9JID9WS2jUsTpzQ91L8MEPLJ/4zrBwZua8W5fECwCCh2c
9G5IzzBm+otMS/YKwmR1olzRCyEkyAEjXWqBI9Ftv5eG8m0VkBzOG655WIYdyV0H
fDK/NWcvGqa0w/nriMD6mDjKOryamw0OP9QuYgMN0C9xMW9y8SmP4h92OAWodTYg
Y1hZCxdv6cs5UnW9+PWvS+WIbkh+GaWYxwIDAQAB
-----END RSA PUBLIC KEY-----"""

def decode(path):
    j = json.load(open(path, encoding="utf-8"))
    parts = [a["data"] for a in j.get("Answer", []) if a.get("type") == 16]
    parts.sort(key=len, reverse=True)
    raw = base64.b64decode("".join(p.replace('"', "") for p in parts))
    key = RSA.import_key(PUB)
    y = pow(int.from_bytes(raw[:256], "big"), key.e, key.n).to_bytes(256, "big")
    dec = AES.new(y[:32], AES.MODE_CBC, y[16:32]).decrypt(y[32:256])
    b = y[:32] + dec
    assert hashlib.sha256(b[32:256 - 16]).digest()[:16] == b[256 - 16:], "sha mismatch"
    pos = 36
    def u32():
        nonlocal pos
        v = struct.unpack_from("<I", b, pos)[0]; pos += 4; return v
    def i32():
        nonlocal pos
        v = struct.unpack_from("<i", b, pos)[0]; pos += 4; return v
    def tlstr():
        nonlocal pos
        l = b[pos]; pos += 1
        if l == 254:
            l = int.from_bytes(b[pos:pos + 3], "little"); pos += 3
            s = b[pos:pos + l]; pos += l; pad = (4 - (l % 4)) % 4
        else:
            s = b[pos:pos + l]; pos += l; pad = (4 - ((l + 1) % 4)) % 4
        pos += pad
        return s
    def vec_count():
        v = u32()
        return u32() if v == 0x1cb5c415 else v
    ctor = u32()
    date, expires = i32(), i32()
    out = {"ctor": hex(ctor), "date": date, "expires": expires, "rules": []}
    for _ in range(vec_count()):
        rc = u32()
        prefix = tlstr().decode()
        dc = i32()
        ips = []
        for _ in range(vec_count()):
            ic = u32()
            ip = u32()
            port = i32()
            ipstr = ".".join(str((ip >> s) & 255) for s in (24, 16, 8, 0))
            if ic == 0x37982646:
                tlstr()
                ips.append(f"{ipstr}:{port}+secret")
            else:
                ips.append(f"{ipstr}:{port}")
        out["rules"].append({"prefix": prefix, "dc": dc, "ips": ips})
    return out

import datetime
for p in sys.argv[1:]:
    r = decode(p)
    print(p.split("/")[-1], r["ctor"], datetime.datetime.utcfromtimestamp(r["date"]), "->", datetime.datetime.utcfromtimestamp(r["expires"]))
    for x in r["rules"]:
        print(f"  dc{x['dc']} prefix='{x['prefix']}': {' '.join(x['ips'])}")
