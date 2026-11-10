# SYBAU-CORE

Прокси-ядро на Rust для приложения v2raysybau. Работает двумя способами:

- отдельный процесс `sybau.exe` (в диспетчере задач — «SYBAU-CORE»);
- библиотека `sybaucore` с C API (`include/sybau.h`) — для Android и встраивания.

Платформы: Windows x64/ARM64, Linux, Android.

> Проект в активной разработке. Таблица ниже честно показывает, что уже
> работает, а что ещё нет. «Проверено» означает, что есть автоматический тест.

## Статус

| Область | Состояние |
|---|---|
| `sybau.exe`: иконка, версия и название в свойствах файла | готово, проверка в CI на Windows |
| Одиночный экземпляр на профиль (второй запуск выходит с кодом 3) | готово, проверено на Linux; Windows — в CI |
| Inbound `mixed` / `socks` / `http`: SOCKS5 + UDP ASSOCIATE, SOCKS4/4a, HTTP CONNECT и обычный HTTP, логин/пароль | готово, проверено |
| Outbound `direct`, `block`, цепочки `detour` | готово, проверено |
| Управляющий API (JSON-RPC через named pipe / unix-сокет) | готово, проверено на Linux; Windows — в CI |
| C API: `start` / `stop` / `call`, callbacks событий и `protect` | готово, проверено C-программой на Linux |
| Перезагрузка конфига без остановки (`core.reload`, `SIGHUP`) с откатом при ошибке | готово, проверено |
| VLESS, VMess, Trojan, Shadowsocks, транспорты WS/gRPC/H2/HTTPUpgrade | в работе (этап 1) |
| uTLS-отпечатки, REALITY, XTLS Vision, Mux | не начато (этап 2) |
| Роутинг по правилам, geosite/geoip, sniffing, DNS | не начато (этап 3) |
| Конфиги Xray / sing-box, ссылки, подписки, `convert`, системный прокси Windows | не начато (этап 4) |
| TUN (Wintun, auto-route, kill switch) | не начато (этап 5) |
| Hysteria2, Hysteria, TUIC, XHTTP, mKCP | не начато (этап 6) |
| Серверные inbound, REALITY-сервер, TProxy | не начато (этап 7) |
| ShadowTLS, AnyTLS, Snell, SSH, Tor, WireGuard, ECH, обход DPI | не начато (этап 8) |
| Фаззинг, оптимизации, подписанные релизы | не начато (этап 9) |

## Сборка

```bash
cargo build --release -p sybau        # target/release/sybau(.exe)
```

```bash
cargo build --release -p sybau-ffi    # libsybaucore.so / sybaucore.dll + staticlib
```

Иконка лежит в `assets/sybau.ico` (сейчас заглушка — замените своим файлом).

## Запуск

```bash
sybau run -c config.json
```

Минимальный конфиг (комментарии `//` и `/* */` разрешены):

```json
{
  "log": { "level": "info" },
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": 2080 }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": { "final": "direct" }
}
```

Команды:

| Команда | Что делает |
|---|---|
| `sybau run -c FILE [--profile NAME] [--log-level LEVEL]` | запускает ядро |
| `sybau check -c FILE` | проверяет конфиг |
| `sybau ctl METHOD [JSON] [--follow]` | запрос к работающему ядру |

Несколько ядер одновременно запускаются с разными `--profile`.

## Управляющий API

Строки JSON-RPC 2.0 через `\\.\pipe\sybau-core-<profile>` (Windows) или
`$XDG_RUNTIME_DIR/sybau-core-<profile>.sock` (Linux). Тот же набор методов
доступен в библиотеке через `sybau_call`.

```json
{"id": 1, "method": "stats.get", "params": {}}
```

| Метод | Параметры | Результат |
|---|---|---|
| `core.version` | — | название, версия, версия протокола |
| `core.status` | — | pid, профиль, аптайм, счётчики, список inbound |
| `core.reload` | `{"path": "..."}` или `{"config": {...}}` или ничего | перечитывает конфиг; при ошибке остаётся старый |
| `core.stop` | — | завершает процесс |
| `log.set_level` | `{"level": "debug"}` | меняет уровень логов на лету |
| `stats.get` | — | трафик всего и по outbound |
| `stats.subscribe` | `{"interval_ms": 1000}` | поток уведомлений `stats` со скоростью |
| `logs.subscribe` | `{"level": "info"}` | поток уведомлений `log` |
| `connections.list` | — | активные соединения |
| `connections.close` | `{"id": N}` или `{"all": true}` | закрывает соединения |
| `outbounds.list` | — | outbound-ы и их трафик |

## Тесты

```bash
cargo test --workspace
```

```bash
tests/ffi/run.sh
```

## Лицензия

GPL-3.0-or-later.
