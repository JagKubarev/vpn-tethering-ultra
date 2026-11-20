# DoH-серверы: что работает, что умерло

Сводка замеров с 30.10 по 20.11.2026, в основном YOTA (13T), часть — Дом.ру и МТС. Состояние серверов меняется
за часы: «мёртв» значит «был мёртв в такой-то день», а не навсегда. Перед добавлением сервера в список —
`webctl.sh geocheck <адрес>` (проверка гео в WebUI) и, если его режут по имени, проверка через обход.

Обозначения: **прокси** — гео-DoH отдаёт для ChatGPT/Gemini/Claude свой адрес (SNI-прокси за рубежом);
**настоящие адреса** — прокси нет, сервис видит Россию; `loc=` — страна выхода по `/cdn-cgi/trace`.

## 1. Обычные DoH (основной и запасные, без гео)

| Сервер | Где у нас | Состояние |
|---|---|---|
| `https://dns.google/dns-query` | основной по умолчанию, Meta (ECS), DNS через VPN | работает; `https://8.8.4.4/dns-query` тоже, ECS работает |
| `https://dns.adguard-dns.com/dns-query` | запасной; у Kubarev основной | работает |
| `https://cloudflare-dns.com/dns-query` | запасной, DNS через VPN | с 18.11 YOTA режет по имени; `1.1.1.1` по адресу — 200 |
| `https://dns.quad9.net/dns-query` | запасной | работает; curl HTTP/1.1 даёт 505 (это «жив») |
| `https://doh.libredns.gr/dns-query` | запасной, список WebUI | напрямую работает, **через обход DoH ломается** (любой fake) |
| DNS4EU unfiltered | список WebUI | 02.11 ~265 мс; 08–09.11 мёртв обоими путями; рвёт TLS по ALPN |
| `https://dns.nextdns.io/...` | — | напрямую тайм-аут, через обход 200 (08–09.11) |
| Control D (`freedns.controld.com/p0`) | — | 02.11 YOTA режет TCP; 09.11 жив; гео нет |
| Mullvad | — | подмена ТСПУ (WRONG_VERSION_NUMBER) |

Бутстрап (обычный DNS для имён DoH): `77.88.8.8:53 1.1.1.1:53 8.8.8.8:53`, шифрованный — `https://1.1.1.1/dns-query
https://8.8.8.8/dns-query https://8.8.4.4/dns-query`.

## 2. Гео-DoH в списке по умолчанию (`DNS_GEO_UPSTREAMS`, v3.27)

| Сервер | Последнее, что видели |
|---|---|
| `https://dns.semqka.xyz/dns-query` | 18.11 8/8, PL; x.com и discord.com — своим прокси; **20.11 с 16:40 не отвечает** |
| `https://doh.fuckingspeedtest.com/dns-query` | новое имя zapret.moe; 18.11 8/8, US; 20.11 16:50 не отвечал, позже работал |
| `https://dns.commonnet.work/dns-query` | 08–12.11 лежал (TCP 443 нет), 18.11 ожил 6/8 DE; **20.11 «ИИ не открываются»** (16:51, 17:31) |
| `https://not-a-dns.quic.best/dns-query` | был основным; 12.11 лежал; 18.11 6/8 PL; **20.11 17:30 не отвечал**; отдаёт свой прокси на www.googleapis.com |
| `https://w.quic.best/dns-query` | 18.11 6/8 PL; тоже переписывает googleapis |
| `https://sync.bezmezhau.com/dns-query` | 12.11 прокси 31.58.216.201 / 185.236.9.58; 18.11 6–7/8 NL; 20.11 17:31 работал |
| `https://dns.geodema.love/dns-query` | **20.11 работает**: ChatGPT, Claude, Grok, Notion, DeepL, Spotify через 179.236.130.10 (GB); Gemini и JetBrains — настоящие адреса |
| `https://dns.dagami.ru/dns-query` | 30.10 мёртв, 08.11 ожил (Gemini 7 с), 18.11 4–5/8 US; через обход DoH 0/8 → `ZAPRET_DOH_ASIS` |
| `https://dns.zapret.moe/dns-query` | прокси 5.129.221.64; YOTA режет по имени (`188.114.96/97.1`), через обход DoH — только нулевой подделкой |
| `https://dns.keyoneday.ru/dns-query` | 18.11 2–4/8 FR; весь www.google.com через свой прокси 2.58.127.63 |
| `https://d.webshiftvpn.ru/dns-query` | взят из форка; 12.11 отвечал 400; только HTTP/2 |
| `https://cf.dns-ai.ru/dns-query` | последний в списке (20.11) |

## 3. Видели или использовали — сейчас умерли или не годятся

| Сервер | Что было | Почему не годится |
|---|---|---|
| `dns.wlrus.cfd` | основной/первый запасной 30.10–09.11 (60–84 мс) | 03.11 и 09.11 пустой ответ на github.com; 12.11 прокси ИИ мертвы, 4pda/Instagram — настоящие |
| `api.magicdns.ru`, `de.magicdns.ru`, `dns.magicdns.ru` | 08.11 прокси для ИИ, 12.11 de.magicdns в запасных | 09.11 api.github.com через свой прокси → 403; 12.11 api/dns не отвечают; 18.11 оба IP мертвы |
| `api.magicinfo.art` (новый DoH MagicDNS — `/rpc`) | 12.11 в запасных, «чистый» | 18.11 IP с YOTA мертвы |
| `tamaev-gifts.xyz` | 12.11 в запасных, youtube/github своим прокси | через обход DoH 0/5; 18.11 прокси молчат |
| `dns.geohide.ru`, `dns.geohide.ru:444`, `geohide.ru` | 30.10 первый запасной (Gemini открывался) | плавают (0,1 с … 5 с, 503 по HTTP/1.1), прокси 193.233.112.x с YOTA молчат (12.11, 20.11) |
| `eu.geohide.ru` | — | Gemini → Google `/sorry`; 18.11 3/8 плавает; 20.11 ChatGPT — настоящий адрес |
| `us.geohide.ru` | — | напрямую режут; прокси 192.255.159.241 / 37.221.93.128 молчат (08.11, 20.11) |
| `dns.comss.one` (и `router.comss.one`) | был в запасных до 18.11 | настоящие адреса (ChatGPT 8.47.69.0, Gemini — Google); 08.11 TCP 4–6 с и RST |
| `dns.malw.link`, malw через `*.cloudflare-gateway.com` | — | только HTTP/2; прокси 179.254.166.x / 62.133.62.97 / 48.102.233.174 с YOTA молчат |
| `dns.bezmezhau.com` | — | 08.11 и 12.11 не отвечает (живой только `sync.`) |
| `dns.dns-ai.ru`, `dns-ai.ru` | — | только HTTP/2; сборщик чужих прокси; 20.11 прокси 48.102.233.174 молчит |
| `dns.astracat.ru`, `dns.astracat.network` | — | 30.10–09.11 мертвы / SERVFAIL; 20.11 прокси 48.102.233.174 молчит |
| `dns.mafioznik.xyz` | — | SERVFAIL / не отвечает (30.10–20.11) |
| `free.shecan.ir` | — | SERVFAIL (30.10, 08.11, 20.11); иранский «против санкций» (Docker Hub, Android dev) |
| `dns.akile.ai` | — | 20.11 нет адреса на ИИ |
| `dns.nullsproxy.com` | — | прокси только ChatGPT, только HTTP/2 |
| `xbox-dns.ru` | — | 0.0.0.0 на ИИ |
| `dns.zombiez.ru`, `dnsdoh.art`, `d.kekew.info`, `ru-mow.doh.sb` | — | настоящие адреса |
| «Перевал» `153.80.200.170` | — | только обычный DNS (прокси DE работает), DoH не нашли |
| SERVFAIL, нужен ключ или мертвы (30.10) | — | `dns.speed-benz.co.uk`, `dns.dnsrender.info`, `dns.bizonre.co.im`, `host.white-dns.info`, `*.geodns.info`, `jqdns.dns-ai.ru`, `yj0dns.nullsproxy.com`, `*.abrdns.com`, `dns.geohide.ru:8443` |

## 4. Подводные камни

- **Свои прокси не только для ИИ.** quic.best (not-a-dns, w.) и bezmezhau отдают свой прокси на `www.googleapis.com`;
  MagicDNS — на `api.github.com` (403); keyoneday — на весь `www.google.com`; tamaev — на YouTube и GitHub;
  semqka — на x.com и discord.com. Поэтому гео-DoH получает только имена гео-списка (`dns/geo.txt`), а запасные
  `-f` — тоже через него (`DNS_GEO_STRICT`), иначе YouTube и Google шли бы через чужие прокси.
- **Режут по имени, не по адресу:** zapret.moe, cloudflare-dns.com (YOTA, с 18.11). Через обход DoH (`DNS_VIA_ZAPRET`)
  проходят нулевой подделкой; LibreDNS и dagami через обход, наоборот, ломаются (`ZAPRET_DOH_ASIS`).
- **Только HTTP/2** (curl на телефонах HTTP/2 не умеет): malw, dns-ai, webshift, nullsproxy. Проверять через временный
  dnsproxy (так делает `webctl.sh geocheck <адрес>`).
- **Claude через любой прокси curl-ом — 403** (проверка ботов Cloudflare); ChatGPT и Claude проверяются по `/cdn-cgi/trace`.
- **Gemini по странице не проверить:** из России `gemini.google.com/app` на настоящем адресе отдаёт 200 без признаков
  отказа (20.11), поэтому «настоящий адрес Google» = закрыт.
- **Проверка без обхода врёт для серверов, которых режут по имени:** 20.11 geocheck «нет адреса» у 7 из 10 серверов
  QuickDNS, а через обход телефона почти все отдали адреса (но их прокси молчали).
