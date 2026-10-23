# VPN Tethering Ultra — контекст для сессий Claude

KernelSU/Magisk-модуль (id `vpn-to-hotspot-usb`, автор Kubarev, тема на 4PDA
`showtopic=915158`). Раздаёт Wi-Fi/USB через VPN телефона или напрямую: kill-switch,
свой DNS через dnsproxy (DoH), обход DPI ТСПУ через zapret/nfqws, приёмы для YouTube.
Лицензия кода — GPL-3.0 (`LICENSE`, копия в `module/LICENSE`).

- **Что умеет и все настройки** — `README.md`.
- **Вся история с апреля, соответствие нумераций, что откатывали** — `CHANGELOG.md`.
  Прочитай раздел «Уроки» перед любым изменением сетевой логики.

## Устройство

- `module/service.sh` (~4900 строк) — демон: журнал изменений в шапке, блок
  `USER CONFIG`, правила, DNS, zapret, YouTube. Служебные вызовы из WebUI:
  `--defaults | --check | --get | --zapret-strategy`; с любым другим аргументом —
  выход (защита от второго демона).
- `module/action.sh` — кнопка Action (тоггл VPN ↔ напрямую, ждёт ack от демона).
- `module/webctl.sh` + `module/webroot/index.html` — WebUI, только фиксированные команды.
- `module/zapret/` — `scan.sh` (подбор / сторож / сайты), `ytslow.sh`, `netid.sh`, списки.
- `module/bin/` — `nfqws`, `dnsproxy`, `conntrack` (arm64 + armv7).
- `third_party/conntrack/` — тарболы исходников `bin/conntrack-*` (GPL), в zip не входят.
- `tools/` — стенды и замеры для разработки (`zt_harness.sh`, `leakmon.py`,
  `blockscan.sh`, `patch_*.py` …), в модуль не входят.
- Конфиг пользователя: `/data/adb/vpn_tether.conf` (не исполняется, ключи из `CONF_KEYS`
  с проверкой). Лог: `/data/local/tmp/vpn_tether.log` (+ `.prev`, logcat `vpn_tether`).

## Версии — как поднимать

Нумерация одна — `X.Y.Z` (с 3.8.1): **X** — этап (0 — до репозитория, 1 — основа и
свой DNS, 2 — WebUI и обход DPI, 3 — YouTube и автоподстройка), **Y** — заметная
функция, **Z** — исправления без новой функциональности. Старые номера (внешние 2.x,
внутренние 3.x-hybrid) не использовать — таблица соответствия в `CHANGELOG.md`.

На каждый релиз меняются **три места** и ставится тег `vX.Y.Z`:
1. `module/module.prop`: `version=vX.Y.Z` и `versionCode` = X·10000 + Y·100 + Z
   (сейчас 30900 у v3.9).
2. Баннер в `service.sh`: `=== VPN Tether vX.Y.Z Started ...`.
3. Запись в шапке `service.sh` (по хронологии: новая — в конец журнала, перед строкой `# ====`) **и** в `CHANGELOG.md`.

## Среда выполнения (важно)

- Шелл — `/system/bin/sh` (mksh/toybox), **не bash**. Никаких bashism
  (`${x//...}`, `[[ ]]`, массивы). toybox `grep` без `\b` и PCRE, `nc` без `-z`.
- Пути `$ip`/`$iptables` — абсолютные переменные, не голые `ip`/`iptables`.
- Перед сборкой: `sh -n` для всех `.sh`; `bash -n` не в счёт — он пропустит bashism.
- KernelSU, Magisk и APatch — разные пути модулей (`/data/adb/modules`, `/data/adb/ap`).
- Сборка: `cd module && zip -r ../vpn-tethering-ultra.zip .`

## Тестовые условия

- Основной: OnePlus 13T (SM8750, Android 15 / OOS15, KernelSU), точка `wlan2`,
  USB — CDC-NCM. Второй — MT6580. У юзеров 4PDA бывают MTK (`ccmni*`), Samsung
  Exynos (`swlan0`, `rmnet4`).
- VPN: AmneziaWG/WARP, VLESS (Incy, NekoBox+, sing-box), часто два tun одновременно.
- На телефоне AdGuard с root-прокси и HTTPS-фильтром, split-tunnel по приложениям
  и доменам. Операторы: YOTA (мобильный, ТСПУ жёстко), МТС Wi-Fi и др.
- Клиенты раздачи: Windows 7/10/11 (TTL 127), ноутбук по USB и Wi-Fi.

## Как Kubarev хочет, чтобы работали

- Минимальные точечные правки с объяснением **каждой**, без рефакторинга ради красоты.
- Изменения «в теории лучше, но могут сломать» — не вносить, а предложить.
- Диагноз — по логам и замерам, с цифрами. Сомнительные выводы помечать.
- Патчи от других ИИ — ревьюить критически, применять выборочно.
- Общение на русском, неформально, по-деловому.

## Открытые хвосты

- Хвосты из июля: IPv6 для клиентов (NDP proxy), ConnectivityManager вместо опроса
  `dumpsys`, фейловер двух аплинков, сторож апстрима с перезапуском VPN-клиента.
