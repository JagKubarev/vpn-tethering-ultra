# Исходники для `module/bin/conntrack-*`

Копии исходников, из которых собраны статические `conntrack-arm64` и `conntrack-arm`
(conntrack-tools 1.4.8, GPL-2.0). Лежат здесь, чтобы выполнять условие GPL-2 о
доступности исходников вместе с бинарём. В zip модуля не входят — он собирается из `module/`.

Проверка: `sha256sum -c SHA256SUMS`. Рецепт сборки, лицензии каждой библиотеки и
sha256 бинарей — в `module/bin/conntrack.SOURCE`.

| Файл | Лицензия | В бинаре |
|---|---|---|
| `conntrack-tools-1.4.8.tar.xz` | GPL-2.0 | да |
| `libnetfilter_conntrack-1.0.9.tar.bz2` | GPL-2.0+ | да |
| `libnfnetlink-1.0.2.tar.bz2` | GPL-2.0 | да |
| `libmnl-1.0.5.tar.bz2` | LGPL-2.1+ | да |
| `libnetfilter_cttimeout-1.0.1.tar.bz2` | GPL-2.0 | нет, только для configure |
| `libnetfilter_cthelper-1.0.1.tar.bz2` | GPL-2.0 | нет, только для configure |
| `libnetfilter_queue-1.0.5.tar.bz2` | GPL-2.0 | нет, только для configure |
| `libtirpc-1.3.4.tar.bz2` | BSD-подобная (Sun/Bull) | нет, собиралась для armv7 configure |

glibc (статически, из кросс-тулчейна Ubuntu 24.04, LGPL-2.1+) — исходники в пакете
`glibc` Ubuntu noble.
