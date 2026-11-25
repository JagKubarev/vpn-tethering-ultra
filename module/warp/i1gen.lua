-- I1 для AmneziaWG (WARP) с любым именем — на телефоне, криптографией nfqws2 (порт tools/i1gen.py).
-- Зовёт warp/warp.sh i1gen: nfqws2 --intercept=0 выполняет скрипт и выходит, к очереди не цепляется.
--   nfqws2 --intercept=0 --uid=0:3998 --lua-init="I1_NAME='max.ru' I1_SRC='<b 0x…>'" --lua-init=@i1gen.lua
-- --uid=0 — как у демона: иначе nfqws2 до Lua сбрасывает root и не читает файлы в /data/adb.
-- I1_SRC — образец (warp/i1.txt) строкой. I1_KEEP=1 — DCID/ключи как в образце (проверка: то же имя
-- даёт образец байт в байт). Новые DCID, SCID, random, session id и ключи key_share — свои на каждый вызов.
-- В nfqws2 есть aes, aes_gcm, hash, bcryptorandom; hkdf — только extract+expand целиком, поэтому
-- HKDF-Expand-Label (QUIC, RFC 9001) — через свой HMAC на hash. Печатает «<b 0x…>» или «ERR причина».
local B = bit

local function sub0(s, i, j) return s:sub(i + 1, j) end      -- как s[i:j] в питоне
local function byte0(s, i) return s:byte(i + 1) end
local function hexs(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local function unhex(h) return (h:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end)) end
local function xorstr(a, b)
    local t = {}
    for i = 1, #a do t[i] = string.char(B.bxor(a:byte(i), b:byte(i) or 0)) end
    return table.concat(t)
end
local function be(v, n)   -- число -> n байт big-endian
    local t = {}
    for i = n, 1, -1 do t[i] = string.char(v % 256); v = math.floor(v / 256) end
    return table.concat(t)
end
local function num(s) local v = 0; for i = 1, #s do v = v * 256 + s:byte(i) end; return v end

-- HMAC-SHA256 и HKDF-Expand-Label (RFC 8446): hkdf() nfqws2 — только extract+expand целиком
local function hmac(key, msg)
    if #key > 64 then key = hash("sha256", key) end
    key = key .. string.rep("\0", 64 - #key)
    return hash("sha256", xorstr(key, string.rep("\92", 64)) .. hash("sha256", xorstr(key, string.rep("\54", 64)) .. msg))
end
local function expand_label(secret, label, len)
    local full = "tls13 " .. label
    return hmac(secret, be(len, 2) .. string.char(#full) .. full .. "\0" .. "\1"):sub(1, len)
end
local SALT_V1 = unhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
local function keys(dcid)
    local cs = expand_label(hmac(SALT_V1, dcid), "client in", 32)
    return expand_label(cs, "quic key", 16), expand_label(cs, "quic iv", 12), expand_label(cs, "quic hp", 16)
end

local function rdv(s, i)   -- varint с позиции i (0-based) -> значение, новая позиция
    local n = B.lshift(1, B.rshift(byte0(s, i), 6))
    local v = B.band(byte0(s, i), 0x3f)
    for k = 1, n - 1 do v = v * 256 + byte0(s, i + k) end
    return v, i + n
end
local function wrv(v, n)
    local pre = ({ [1] = 0, [2] = 0x40, [4] = 0x80, [8] = 0xc0 })[n]
    assert(v < 2 ^ (8 * n - 2), "varint")
    local s = be(v, n)
    return string.char(B.bor(s:byte(1), pre)) .. s:sub(2)
end

local function parse(pkt)
    assert(B.band(byte0(pkt, 0), 0x80) ~= 0 and sub0(pkt, 1, 5) == "\0\0\0\1", "образец не QUIC v1")
    local i = 5
    local dl = byte0(pkt, i); local dcid = sub0(pkt, i + 1, i + 1 + dl); i = i + 1 + dl
    local sl = byte0(pkt, i); local scid = sub0(pkt, i + 1, i + 1 + sl); i = i + 1 + sl
    local tl; local t0 = i; tl, i = rdv(pkt, i); local tl_size = i - t0
    local token = sub0(pkt, i, i + tl); i = i + tl
    local ln_at = i; local ln; ln, i = rdv(pkt, i)
    local p = { dcid = dcid, scid = scid, token = token, tl_size = tl_size, ln = ln, ln_size = i - ln_at, size = #pkt }
    local pn_off = i
    local key, iv, hp = keys(dcid)
    local mask = aes(true, hp, sub0(pkt, pn_off + 4, pn_off + 20))
    p.b0 = B.bxor(byte0(pkt, 0), B.band(mask:byte(1), 0x0f))
    assert(B.band(p.b0, 0x30) == 0, "образец не Initial")
    p.pnl = B.band(p.b0, 3) + 1
    p.pnb = xorstr(sub0(pkt, pn_off, pn_off + p.pnl), mask:sub(2, 1 + p.pnl))
    local hdr = string.char(p.b0) .. sub0(pkt, 1, pn_off) .. p.pnb
    local nonce = xorstr(iv, string.rep("\0", 12 - p.pnl) .. p.pnb)
    local fin = pn_off + ln
    local ct, tag = sub0(pkt, pn_off + p.pnl, fin - 16), sub0(pkt, fin - 16, fin)
    local plain, tag2 = aes_gcm(false, key, nonce, ct, hdr)
    assert(tag2 == tag, "образец не расшифровался (тег)")
    p.plain = plain; p.tail = sub0(pkt, fin, #pkt)
    return p
end

local function frames(plain)
    local out, i = {}, 0
    while i < #plain do
        local t = byte0(plain, i)
        if t == 0 then
            local j = i
            while j < #plain and byte0(plain, j) == 0 do j = j + 1 end
            out[#out + 1] = { t = 0, n = j - i }; i = j
        elseif t == 1 then
            out[#out + 1] = { t = 1 }; i = i + 1
        elseif t == 6 then
            local off, k = rdv(plain, i + 1)
            local ln, m = rdv(plain, k)
            out[#out + 1] = { t = 6, off = off, data = sub0(plain, m, m + ln), os = k - (i + 1), ls = m - k }
            i = m + ln
        else
            error(string.format("кадр 0x%02x не умею", t))
        end
    end
    return out
end

local function client_hello(fr)
    local parts, n = {}, 0
    for _, f in ipairs(fr) do
        if f.t == 6 then parts[#parts + 1] = f; if f.off + #f.data > n then n = f.off + #f.data end end
    end
    table.sort(parts, function(a, b) return a.off < b.off end)
    local s, at = {}, 0
    for _, f in ipairs(parts) do
        assert(f.off == at, "ClientHello с дырами"); s[#s + 1] = f.data; at = at + #f.data
    end
    return table.concat(s)
end

local function u16(s, i) return byte0(s, i) * 256 + byte0(s, i + 1) end
local function ext_start(ch)
    assert(byte0(ch, 0) == 1, "не ClientHello")
    local i = 4 + 2 + 32
    local sid = i
    i = i + 1 + byte0(ch, i)
    i = i + 2 + u16(ch, i)
    i = i + 1 + byte0(ch, i)
    return i, sid
end
local function sni_pos(ch)
    local i = ext_start(ch)
    local ext_len_at = i; i = i + 2
    local fin = i + u16(ch, ext_len_at)
    while i < fin do
        local et, el = u16(ch, i), u16(ch, i + 2)
        if et == 0 then
            return i + 9, u16(ch, i + 7), { { 1, 3 }, { ext_len_at, 2 }, { i + 2, 2 }, { i + 4, 2 }, { i + 7, 2 } }
        end
        i = i + 4 + el
    end
    error("в ClientHello нет SNI")
end
local function shares(ch)   -- ключи key_share и session id: {смещение, длина}
    local out = {}
    local i, sid = ext_start(ch)
    if byte0(ch, sid) > 0 then out[#out + 1] = { sid + 1, byte0(ch, sid) } end
    local fin = i + 2 + u16(ch, i); i = i + 2
    while i < fin do
        local et, el = u16(ch, i), u16(ch, i + 2)
        if et == 0x33 then
            local j, e2 = i + 6, i + 4 + el
            while j < e2 do local kl = u16(ch, j + 2); out[#out + 1] = { j + 4, kl }; j = j + 4 + kl end
        end
        i = i + 4 + el
    end
    return out
end

local function build(p, fr, new_ch, pos, old_l, new_l, dcid, scid)
    local d = new_l - old_l
    local function f(x)
        if x <= pos then return x end
        if x >= pos + old_l then return x + d end
        return pos + math.min(x - pos, new_l)
    end
    local body, pads = {}, {}
    for _, fx in ipairs(fr) do
        if fx.t == 0 then pads[#pads + 1] = #body + 1; body[#body + 1] = { t = 0, n = fx.n }
        elseif fx.t == 1 then body[#body + 1] = { t = 1 }
        else
            local a, b = f(fx.off), f(fx.off + #fx.data)
            if b - a >= 2 ^ (8 * fx.ls - 2) or a >= 2 ^ (8 * fx.os - 2) then error("имя длинное: кусок не влезает в раскладку образца") end
            if b > a then body[#body + 1] = { t = 6, off = a, data = sub0(new_ch, a, b), os = fx.os, ls = fx.ls } end
        end
    end
    local function enc(x)
        if x.t == 0 then return string.rep("\0", x.n) end
        if x.t == 1 then return "\1" end
        return "\6" .. wrv(x.off, x.os) .. wrv(#x.data, x.ls) .. x.data
    end
    local used = 0
    for _, x in ipairs(body) do if x.t ~= 0 then used = used + #enc(x) end end
    local need, have = #p.plain - used, 0
    for _, k in ipairs(pads) do have = have + body[k].n end
    if #pads == 0 or need < 0 then error("имя длинное: не влезает в пакет") end
    local last = body[pads[#pads]]
    last.n = last.n + need - have
    if last.n < 0 then error("имя длинное: не хватает PADDING") end
    local t = {}
    for _, x in ipairs(body) do if not (x.t == 0 and x.n == 0) then t[#t + 1] = enc(x) end end
    local plain = table.concat(t)
    assert(#plain == #p.plain, "размер")
    local key, iv, hp = keys(dcid)
    local hdr = string.char(p.b0) .. "\0\0\0\1" .. string.char(#dcid) .. dcid .. string.char(#scid) .. scid ..
        wrv(#p.token, p.tl_size) .. p.token .. wrv(p.ln, p.ln_size) .. p.pnb
    local nonce = xorstr(iv, string.rep("\0", 12 - p.pnl) .. p.pnb)
    local ct, tag = aes_gcm(true, key, nonce, plain, hdr)
    local pkt = hdr .. ct .. tag
    local pn_off = #hdr - p.pnl
    local mask = aes(true, hp, sub0(pkt, pn_off + 4, pn_off + 20))
    local b0 = B.bxor(byte0(pkt, 0), B.band(mask:byte(1), 0x0f))
    local pnp = xorstr(sub0(pkt, pn_off, pn_off + p.pnl), mask:sub(2, 1 + p.pnl))
    return string.char(b0) .. sub0(pkt, 1, pn_off) .. pnp .. sub0(pkt, pn_off + p.pnl, #pkt) .. p.tail
end

local function gen(name, src, keep)
    assert(name:match("^[a-z0-9][a-z0-9.-]*[a-z0-9]$") and name:find(".", 1, true) and not name:find("..", 1, true),
        "имя: латиница, цифры, точки (xn-- для .рф)")
    local pkt = unhex(assert(src:match("0x(%x+)"), "в образце нет 0x…"))
    local p = parse(pkt)
    local fr = frames(p.plain)
    local ch = client_hello(fr)
    local pos, old_l, lens = sni_pos(ch)
    local d = #name - old_l
    local new = sub0(ch, 0, pos) .. name .. sub0(ch, pos + old_l, #ch)
    for _, l in ipairs(lens) do   -- длины до имени: на месте, +d
        local at, sz = l[1], l[2]
        new = sub0(new, 0, at) .. be(num(sub0(new, at, at + sz)) + d, sz) .. sub0(new, at + sz, #new)
    end
    local dcid, scid = p.dcid, p.scid
    if not keep then
        new = sub0(new, 0, 6) .. bcryptorandom(32) .. sub0(new, 38, #new)
        for _, s in ipairs(shares(new)) do
            new = sub0(new, 0, s[1]) .. bcryptorandom(s[2]) .. sub0(new, s[1] + s[2], #new)
        end
        dcid, scid = bcryptorandom(#dcid), bcryptorandom(#scid)
    end
    local out = build(p, fr, new, pos, old_l, #name, dcid, scid)
    assert(#out == #pkt, "размер пакета")
    return out
end

local ok, res = pcall(gen, tostring(I1_NAME or ""):lower(), tostring(I1_SRC or ""), I1_KEEP == 1 or I1_KEEP == "1")
if ok then print("<b 0x" .. hexs(res) .. ">") else print("ERR " .. tostring(res):gsub("^.-:%d+: ", "")) end
