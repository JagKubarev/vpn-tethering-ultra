# Исходники для `module/bin/amneziawg-go-*` и `module/bin/awg-*`

Снимки официальных тегов [amnezia-vpn](https://github.com/amnezia-vpn), из которых
собраны бинари WARP-туннеля (без каталога `.git`). Лежат здесь ради условия GPL-2
о доступности исходников вместе с бинарём (`awg`). В zip модуля не входят.

Проверка: `sha256sum -c SHA256SUMS`. Как собрано и sha256 бинарей — в
`module/bin/amneziawg.SOURCE` и `.github/workflows/build-awg.yml`.

| Файл | Лицензия | Бинарь |
|---|---|---|
| `amneziawg-go-v3.1.20260828.tar.gz` | MIT | `amneziawg-go-arm64`, `amneziawg-go-arm` |
| `amneziawg-tools-v3.1.20260812.tar.gz` | GPL-2.0 | `awg-arm64`, `awg-arm` |

`awg` слинкован динамически с системной libc Android (bionic).
