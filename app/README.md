# VPN Tether — WebUI модуля отдельным приложением

Открывает WebUI модуля VPN Tethering Ultra без менеджера KernelSU: на KernelSU,
Magisk и APatch, Android 8.0+ (в том числе MT6580 с Magisk на Android 8.1, где
WebUI раньше открыть было негде).

Страница — та же, что в менеджере KernelSU: `/data/adb/modules/vpn-to-hotspot-usb/webroot/index.html`
установленного модуля. Приложение читает её через root при каждом открытии, поэтому
после обновления модуля приложение обновлять не нужно.

## Установка

1. Поставить APK (артефакт `vpn-tether` из Actions → **build-app**, или собрать самому).
2. Выдать root:
   - **KernelSU / APatch** — менеджер → «Суперпользователь» → «VPN Tether» → включить
     (сами они не спрашивают, без этого приложение пишет «Нет root-доступа»);
   - **Magisk** — при первом запуске появится окно запроса → «Разрешить».
3. Открыть «VPN Tether» на лаунчере.

### MT6580 (Android 8.1, Magisk)

```
adb install VPN_Tether_v1.0.0.apk
```

или скопировать APK на телефон и открыть файловым менеджером (разрешить установку
из этого источника). При первом запуске Magisk спросит root — «Разрешить» (окно
ждёт 10 с; не успели — «Повторить» в приложении, или выдать в Magisk → «Суперпользователь»).

WebView на Android 8 обновляется через Play Маркет («Android System WebView»).
Если страница пустая или кнопки не работают — сначала обновить WebView.
Без Play Маркета — APK Android System WebView с той же архитектурой (armeabi-v7a у MT6580).

Тост Magisk «получил права суперпользователя» будет один раз при открытии:
приложение держит один root-шелл, а не запускает `su` на каждую команду.

## Что умеет мост `ksu`

Совместим с менеджером KernelSU (страница не отличает):

| вызов | что делает |
|---|---|
| `ksu.exec(cmd, options, callback)` | `cmd` в root-шелле, ответ `window[callback](errno, stdout, stderr)`; команды по одной, как в KernelSU, но страница не замирает |
| `ksu.exec(cmd)` | то же синхронно, возвращает stdout |
| `ksu.listPackages('user'|'system'|'all')` | JSON-массив пакетов |
| `ksu.getPackagesInfo(json)` | `packageName, versionName, versionCode, appLabel, isSystem, uid` |
| `ksu.toast`, `ksu.fullScreen`, `ksu.moduleInfo` | как в KernelSU |
| `<img src="ksu://icon/ПАКЕТ">` | значок приложения |
| `<input type=file>` | системный выбор файлов (импорт настроек и конфигов WARP) |

Свёрнутое приложение ставит таймеры страницы на паузу — опрос статуса в фоне не идёт.

## Сборка

Нужны JDK 17+ и Android SDK (platform 34). Без библиотек, только Android SDK.

```
cd app
gradle assembleRelease      # Gradle 8.7
```

На Windows с JDK из Android Studio:
`JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"`, в `app/local.properties` —
`sdk.dir=C:/Users/<имя>/AppData/Local/Android/Sdk`. Если Gradle падает с
«Unable to establish loopback connection» — `JAVA_TOOL_OPTIONS=-Djdk.net.unixdomain.tmpdir=C:/tmp`.

Подпись release: `app/keystore.properties` (`storeFile`, `storePassword`, `keyAlias`,
`keyPassword`) или переменные `VT_KEYSTORE`, `VT_KEYSTORE_PASS`, `VT_KEY_ALIAS`
(в Actions — секреты `VT_KEYSTORE_B64`, `VT_KEYSTORE_PASS`, `VT_KEY_ALIAS`; если у ключа
свой пароль — ещё `VT_KEY_PASS`).
Без ключа APK подписывается отладочным: ставится, но обновление поверх APK с другим
ключом не встанет — удалить и поставить заново.

## Лицензия

GPL-3.0, как модуль. Идеи моста — из менеджера KernelSU и
[KsuWebUIStandalone](https://github.com/5ec1cff/KsuWebUIStandalone) (оба GPL-3.0);
значок — тот же, что в шапке WebUI.
