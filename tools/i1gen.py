#!/usr/bin/env python3
"""I1 для AmneziaWG (WARP) с любым именем: поддельный QUIC Initial.

I1 — настоящий зашифрованный QUIC v1 Initial: ТСПУ расшифровывает его ключами
из DCID (они открыты, RFC 9001) и по SNI внутри ClientHello опознаёт весь
UDP-поток туннеля (08.11: bag.itunes.apple.com днём — 2,5 Мбит/с, apteka.ru — 20–30).

Берём образец (module/warp/i1.txt, сейчас apteka.ru), расшифровываем, меняем имя
и шифруем обратно. Раскладка как у образца: те же кадры CRYPTO в том же порядке
(Chrome режет ClientHello на куски), их границы сдвигаются на разницу длин имени,
PADDING подгоняется — размер пакета прежний. Новые DCID/SCID, random, session id и
ключи key_share ClientHello — у каждого файла свои (но файл один на всех пользователей
модуля: I1 на каждую установку — только сборкой на телефоне) (--keep — как в образце: тогда тот же SNI даёт тот же пакет
байт в байт, проверка самого генератора).

  python -I tools/i1gen.py show [файл]              — что внутри (имя, размер, кадры)
  python -I tools/i1gen.py gen ИМЯ [файл] [--keep]  — новый I1 в stdout
Нужен пакет cryptography. ПАРНЫЙ с module/warp/i1gen.lua (тот же алгоритм на Lua nfqws2, сборка
на телефоне — warp.sh i1gen): правка раскладки — в обоих, проверка — оба с --keep/I1_KEEP дают i1.txt
байт в байт, tshark читает имя.
"""
import os
import re
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hmac

SALT_V1 = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')
DEF = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'module', 'warp', 'i1.txt')


def hkdf_extract(salt, ikm):
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def expand_label(secret, label, length):
    full = b'tls13 ' + label.encode()
    info = struct.pack('>H', length) + bytes([len(full)]) + full + b'\x00'
    return HKDFExpand(hashes.SHA256(), length, info).derive(secret)


def keys(dcid):
    cs = expand_label(hkdf_extract(SALT_V1, dcid), 'client in', 32)
    return expand_label(cs, 'quic key', 16), expand_label(cs, 'quic iv', 12), expand_label(cs, 'quic hp', 16)


def hp_mask(hp, sample):
    e = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    return e.update(sample) + e.finalize()


def rd_varint(b, i):
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3f
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def wr_varint(v, n):
    pre = {1: 0, 2: 0x40, 4: 0x80, 8: 0xc0}[n]
    assert v < (1 << (8 * n - 2)), (v, n)
    out = v.to_bytes(n, 'big')
    return bytes([out[0] | pre]) + out[1:]


def load(path):
    t = open(path, encoding='ascii').read()
    m = re.search(r'0x([0-9a-fA-F]+)', t)
    return bytes.fromhex(m.group(1))


def parse(pkt):
    """-> словарь: заголовок, ключи, открытый текст"""
    assert pkt[0] & 0x80 and pkt[1:5] == b'\x00\x00\x00\x01', 'не QUIC v1 long header'
    i = 5
    dl = pkt[i]; dcid = pkt[i + 1:i + 1 + dl]; i += 1 + dl
    sl = pkt[i]; scid = pkt[i + 1:i + 1 + sl]; i += 1 + sl
    tl, i = rd_varint(pkt, i); token = pkt[i:i + tl]; i += tl
    ln_at = i
    ln, i = rd_varint(pkt, i)
    ln_size = i - ln_at
    pn_off = i
    key, iv, hp = keys(dcid)
    mask = hp_mask(hp, pkt[pn_off + 4:pn_off + 20])
    b0 = pkt[0] ^ (mask[0] & 0x0f)
    assert (b0 & 0x30) == 0, 'не Initial'
    pnl = (b0 & 3) + 1
    pnb = bytes(x ^ y for x, y in zip(pkt[pn_off:pn_off + pnl], mask[1:1 + pnl]))
    pn = int.from_bytes(pnb, 'big')
    hdr = bytes([b0]) + pkt[1:pn_off] + pnb
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, 'big')))
    end = pn_off + ln
    plain = AESGCM(key).decrypt(nonce, pkt[pn_off + pnl:end], hdr)
    return dict(b0=b0, dcid=dcid, scid=scid, token=token, ln=ln, ln_size=ln_size, pnl=pnl, pn=pn,
                plain=plain, tail=pkt[end:], size=len(pkt))


def frames(plain):
    """-> [(тип, смещение, данные, размер_смещения, размер_длины)]; PADDING — ('pad', n)"""
    out, i = [], 0
    while i < len(plain):
        t = plain[i]
        if t == 0:
            j = i
            while j < len(plain) and plain[j] == 0:
                j += 1
            out.append(('pad', j - i)); i = j
        elif t == 1:
            out.append(('ping',)); i += 1
        elif t == 6:
            j = i + 1
            off, k = rd_varint(plain, j); os_ = k - j
            ln, m = rd_varint(plain, k); ls_ = m - k
            out.append(('crypto', off, plain[m:m + ln], os_, ls_)); i = m + ln
        else:
            raise SystemExit('кадр 0x%02x не умею' % t)
    return out


def client_hello(fr):
    buf = {}
    for f in fr:
        if f[0] == 'crypto':
            for k, x in enumerate(f[2]):
                buf[f[1] + k] = x
    n = max(buf) + 1
    assert len(buf) == n, 'ClientHello с дырами'
    return bytes(buf[k] for k in range(n))


def sni_pos(ch):
    """-> (смещение имени, длина имени, смещения полей длины [(поз, размер)])"""
    assert ch[0] == 1
    i = 4 + 2 + 32
    i += 1 + ch[i]                                     # session id
    i += 2 + struct.unpack('>H', ch[i:i + 2])[0]       # cipher suites
    i += 1 + ch[i]                                     # compression
    ext_len_at = i; i += 2
    end = i + struct.unpack('>H', ch[ext_len_at:ext_len_at + 2])[0]
    while i < end:
        et, el = struct.unpack('>HH', ch[i:i + 4])
        if et == 0:
            # ext: длина(2) список(2) тип(1) длина имени(2) имя
            nl = struct.unpack('>H', ch[i + 7:i + 9])[0]
            return i + 9, nl, [(1, 3), (ext_len_at, 2), (i + 2, 2), (i + 4, 2), (i + 7, 2)]
        i += 4 + el
    raise SystemExit('в ClientHello нет SNI')


def build(p, fr, new_ch, pos, old_l, new_l, dcid, scid):
    d = new_l - old_l

    def f(x):
        if x <= pos:
            return x
        if x >= pos + old_l:
            return x + d
        return pos + min(x - pos, new_l)
    body, pad_idx = [], []
    for fx in fr:
        if fx[0] == 'pad':
            pad_idx.append(len(body)); body.append([0, fx[1]])
        elif fx[0] == 'ping':
            body.append([1])
        else:
            a, b = f(fx[1]), f(fx[1] + len(fx[2]))
            if b - a >= 1 << (8 * fx[4] - 2) or a >= 1 << (8 * fx[3] - 2):
                raise SystemExit('имя длинное: кусок ClientHello не влезает в раскладку образца')
            if b > a:
                body.append([6, a, new_ch[a:b], fx[3], fx[4]])
    enc = lambda x: (b'\x00' * x[1] if x[0] == 0 else b'\x01' if x[0] == 1 else
                     b'\x06' + wr_varint(x[1], x[3]) + wr_varint(len(x[2]), x[4]) + x[2])
    need = len(p['plain']) - sum(len(enc(x)) for x in body if x[0] != 0)
    have = sum(body[k][1] for k in pad_idx)
    if not pad_idx or need < 0:
        raise SystemExit('имя длинное: не влезает в пакет')
    body[pad_idx[-1]][1] += need - have               # разница — в последний PADDING
    if body[pad_idx[-1]][1] < 0:
        raise SystemExit('имя длинное: не хватает PADDING')
    plain = b''.join(enc(x) for x in body if not (x[0] == 0 and x[1] == 0))
    assert len(plain) == len(p['plain'])
    key, iv, hp = keys(dcid)
    pnb = p['pn'].to_bytes(p['pnl'], 'big')
    hdr = (bytes([p['b0']]) + b'\x00\x00\x00\x01' + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid +
           wr_varint(len(p['token']), 1 if len(p['token']) < 64 else 2) + p['token'] +
           wr_varint(p['ln'], p['ln_size']) + pnb)
    nonce = bytes(a ^ b for a, b in zip(iv, p['pn'].to_bytes(12, 'big')))
    ct = AESGCM(key).encrypt(nonce, plain, hdr)
    pn_off = len(hdr) - p['pnl']
    pkt = bytearray(hdr + ct)
    mask = hp_mask(hp, bytes(pkt[pn_off + 4:pn_off + 20]))
    pkt[0] ^= mask[0] & 0x0f
    for k in range(p['pnl']):
        pkt[pn_off + k] ^= mask[1 + k]
    return bytes(pkt) + p['tail']


def shares(ch):
    """-> [(смещение, длина)] ключей key_share и session id в ClientHello"""
    out = []
    i = 4 + 2 + 32
    if ch[i]:
        out.append((i + 1, ch[i]))
    i += 1 + ch[i]
    i += 2 + struct.unpack('>H', ch[i:i + 2])[0]
    i += 1 + ch[i]
    end = i + 2 + struct.unpack('>H', ch[i:i + 2])[0]
    i += 2
    while i < end:
        et, el = struct.unpack('>HH', ch[i:i + 4])
        if et == 0x33:
            j, e2 = i + 6, i + 4 + el
            while j < e2:
                kl = struct.unpack('>H', ch[j + 2:j + 4])[0]
                out.append((j + 4, kl)); j += 4 + kl
        i += 4 + el
    return out


def gen(name, path, keep):
    if not re.fullmatch(r'[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+', name):
        raise SystemExit('имя: латиница, цифры, точки (xn-- для .рф)')
    p = parse(load(path))
    fr = frames(p['plain'])
    ch = client_hello(fr)
    pos, old_l, lens = sni_pos(ch)
    nb = name.encode()
    d = len(nb) - old_l
    new = bytearray(ch[:pos] + nb + ch[pos + old_l:])
    for at, sz in lens:                                # длины до имени: на месте, +d
        v = int.from_bytes(new[at:at + sz], 'big') + d
        new[at:at + sz] = v.to_bytes(sz, 'big')
    dcid, scid = p['dcid'], p['scid']
    if not keep:
        new[6:38] = os.urandom(32)                     # random ClientHello
        for at, ln in shares(bytes(new)):              # ключи key_share, session id: сервер их не читает
            new[at:at + ln] = os.urandom(ln)
        dcid, scid = os.urandom(len(dcid)), os.urandom(len(scid))
    return build(p, fr, bytes(new), pos, old_l, len(nb), dcid, scid)


def show(pkt):
    p = parse(pkt)
    fr = frames(p['plain'])
    ch = client_hello(fr)
    pos, l, _ = sni_pos(ch)
    kinds = ' '.join('C%d+%d' % (x[1], len(x[2])) if x[0] == 'crypto' else 'P%d' % x[1] if x[0] == 'pad' else 'ping'
                     for x in fr)
    return '%s | %d Б | DCID %s | CH %d Б | %s' % (ch[pos:pos + l].decode(), p['size'], p['dcid'].hex(), len(ch), kinds)


def main(a):
    if len(a) >= 1 and a[0] == 'show':
        print(show(load(a[1] if len(a) > 1 else DEF)))
    elif len(a) >= 2 and a[0] == 'gen':
        rest = [x for x in a[2:] if x != '--keep']
        pkt = gen(a[1].lower(), rest[0] if rest else DEF, '--keep' in a)
        assert len(pkt) == len(load(rest[0] if rest else DEF))
        sys.stdout.buffer.write(('<b 0x%s>\n' % pkt.hex()).encode())   # без \r на Windows
    else:
        print(__doc__)


if __name__ == '__main__':
    main(sys.argv[1:])
