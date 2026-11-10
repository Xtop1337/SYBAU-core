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
| VLESS (TCP и UDP) | готово, проверено против Xray и sing-box |
| VMess AEAD (alterId 0): aes-128-gcm, chacha20-poly1305, none, zero; TCP и UDP | готово, проверено против Xray и sing-box |
| Trojan (TCP и UDP) | готово, проверено против Xray и sing-box |
| Shadowsocks AEAD (aes-128/192/256-gcm, chacha20, xchacha20) и 2022 (blake3), multi-user, TCP и UDP | готово, проверено против Xray и sing-box |
| SOCKS5 (с UDP) и HTTP CONNECT как upstream-прокси | готово, проверено против sing-box |
| Транспорты: TCP с HTTP-обфускацией, WebSocket с early data, HTTPUpgrade, gRPC (gun и multi), HTTP/2 | готово, проверено против Xray и sing-box |
| TLS 1.2/1.3 (rustls): SNI, ALPN, `insecure`, пиннинг сертификата | готово, проверено |
| uTLS-отпечатки: `chrome`, `firefox`, `safari`, `ios`, `edge`, `qq`, `random`, `randomized` (шаблоны ClientHello выгружены из uTLS, которую использует Xray) | готово, проверено против Xray и sing-box |
| REALITY-клиент (public key, short id) | готово, проверено против Xray и sing-box |
| XTLS Vision (`xtls-rprx-vision`, `-udp443`), включая direct copy | готово, проверено против Xray и sing-box |
| XUDP (`packet_encoding: xudp`) | готово, проверено против Xray и sing-box |
| Фрагментация ClientHello (`fragment`: `tlshello` или диапазон пакетов) для прокси и для `direct` | готово, проверено против Xray и sing-box |
| Свой TLS 1.3 клиент: X25519, P-256, X25519MLKEM768, HelloRetryRequest, KeyUpdate, сжатые сертификаты | готово, проверено (rustls, Go TLS) |
| Отпечатки `360` и `android` (предлагают только TLS 1.2), TLS 1.2 с отпечатком | не начато |
| Mux.Cool, VMess `authenticated_length`, REALITY spiderX, ML-DSA-проверка REALITY | не начато |
| Роутинг: домен (точно, суффикс, ключевое слово, regex), IP/CIDR, порт, сеть, протокол, inbound, пользователь, процесс, логические правила `and`/`or`, `invert`, действие `reject` | готово, проверено |
| `geosite.dat`/`geoip.dat` (Xray) и rule-set `.srs` v1–v5 / `.json` (sing-box), локальные и inline | готово, проверено на эталонных данных Xray и sing-box |
| Sniffing: TLS SNI, HTTP Host, QUIC SNI, BitTorrent, DNS; `override_destination` | готово, проверено |
| `domain_strategy`: `as_is`, `ip_if_non_match`, `ip_on_demand` | готово, проверено (резолвер пока системный) |
| Удалённые rule-set с автообновлением, подписки по URL, urltest | не начато |
| Группы: `selector` (переключение через API, выбор переживает перезагрузку конфига) и `balancer` (`round_robin`, `random`, `fallback`, `least_ping`) с автоматическим обходом упавшего сервера | готово, проверено |
| Активная проверка задержки по URL (urltest) | не начато: `least_ping` и обход сбоев опираются на реальные соединения |
| DNS: UDP (с переходом на TCP), TCP, DoT, DoH, `local`, `rcode://`; сервер через любой outbound (`detour`); правила выбора сервера; кеш; hosts; fake-IP; ECS; стратегии `prefer_ipv4`/`ipv4_only` и др. | готово, проверено |
| DoQ, DoH3 | не начато (этап 6, вместе с QUIC) |
| Чтение конфигов Xray (JSON) и sing-box (JSON) напрямую: `run`, `check`, C API и `core.reload` определяют формат сами | готово, проверено настоящими Xray и sing-box (см. ниже) |
| `sybau convert --from xray\|sing-box\|auto` | готово, проверено |
| Ссылки `vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`/`hysteria2://`, `tuic://`, `wireguard://` | готово, проверено (для Hysteria2/TUIC/WireGuard пока только разбор: сами протоколы — этапы 6 и 8) |
| Подписки: base64, списки ссылок, Clash/mihomo YAML, sing-box/Xray JSON — по содержимому (`sybau import`, `subscriptions.parse`) | готово, проверено |
| Скачивание подписок по URL и автообновление по таймеру | не начато: содержимое пока передаёт приложение |
| Системный прокси Windows: включается на время работы `sybau.exe`, восстанавливается при выходе, после падения (сторожевой процесс) и при следующем запуске | готово; проверка — Windows-смоук-тест в CI |
| TUN (Wintun, auto-route, kill switch) | не начато (этап 5) |
| Hysteria2, Hysteria, TUIC, XHTTP, mKCP | не начато (этап 6) |
| Серверные inbound, REALITY-сервер, TProxy | не начато (этап 7) |
| ShadowTLS, AnyTLS, Snell, SSH, Tor, WireGuard, ECH, обход DPI | не начато (этап 8) |
| Фаззинг, оптимизации, подписанные релизы | не начато (этап 9) |

Импорт проверяется на том же стенде: для каждого сценария клиентский конфиг
записывается в формате Xray, sing-box или как ссылка, сначала принимается самой
программой (`xray run -test`, `sing-box check`), затем переводится
`sybau convert` / `sybau import`, и трафик должен пройти через настоящий сервер:
`tests/interop/run.py --client-format xray|sing-box|link`. Результат на момент
коммита: через Xray-конфиг 87/87, через sing-box-конфиг 91/91, через ссылки 85/85
(сценарии без аналога в формате пропускаются).

Полная таблица проверенных сочетаний протокол × транспорт — в
[docs/INTEROP.md](docs/INTEROP.md): 98 сценариев против настоящих Xray-core
26.3.27 и sing-box 1.14.4.

Известные ограничения текущего этапа:

- UDP у VLESS и VMess открывает отдельный поток на каждый адрес назначения
  (XUDP появится на этапе 2);
- HTTP/2 и gRPC соединения не посылают keepalive-ping: оборванное соединение
  заменяется при следующем обращении;
- корневые сертификаты — встроенный набор Mozilla (`webpki-roots`), системное
  хранилище не читается;
- с `fingerprint`, REALITY и Vision работает собственный TLS-клиент, он умеет
  только TLS 1.3: если сервер согласует TLS 1.2, соединение завершится понятной
  ошибкой (без `fingerprint` используется rustls с TLS 1.2 и 1.3);
- при неудачной проверке REALITY соединение закрывается; имитация обхода сайта
  (spiderX) не реализована.

Конфиг разбирается строго: неизвестное поле — ошибка с указанием, в каком
inbound/outbound она находится.

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

Пример outbound-ов (общие блоки `tls` и `transport` одинаковы для VLESS,
VMess и Trojan):

```json
{
  "outbounds": [
    {
      "type": "vless", "tag": "proxy",
      "server": "example.com", "port": 443,
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
      "tls": { "server_name": "example.com", "alpn": ["http/1.1"] },
      "transport": {
        "type": "ws", "path": "/ws",
        "max_early_data": 2048,
        "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    },
    { "type": "vmess", "tag": "vm", "server": "1.2.3.4", "port": 10086,
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "security": "auto" },
    { "type": "trojan", "tag": "tj", "server": "example.com", "port": 443,
      "password": "secret", "tls": {},
      "transport": { "type": "grpc", "service_name": "Svc" } },
    { "type": "shadowsocks", "tag": "ss", "server": "1.2.3.4", "port": 8388,
      "method": "2022-blake3-aes-128-gcm", "password": "<base64 ключ>" },
    { "type": "socks", "tag": "up", "server": "127.0.0.1", "port": 1080 },
    { "type": "direct", "tag": "chained", "detour": "proxy" }
  ],
  "route": { "final": "proxy" }
}
```

| Блок | Поля |
|---|---|
| `tls` | `enabled`, `server_name`, `alpn`, `insecure`, `pinned_cert_sha256` (SHA-256 сертификата сервера; совпадения достаточно), `pinned_cert_chain_sha256` (как `pinnedPeerCertificateChainSha256` в Xray), `fingerprint`, `reality` (`public_key`, `short_id`), `fragment` (`packets`, `length`, `interval`, `max_split`) |
| `vless` | `uuid`, `flow` (`xtls-rprx-vision`), `packet_encoding` (`xudp`) |
| `transport` | `tcp` (+`http_obfs`), `ws`, `httpupgrade`, `grpc` (`service_name`, `multi_mode`, `authority`), `http` (HTTP/2) |

VLESS + Vision + REALITY с отпечатком Chrome и фрагментацией ClientHello:

```json
{
  "type": "vless", "tag": "reality",
  "server": "203.0.113.10", "port": 443,
  "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
  "flow": "xtls-rprx-vision",
  "tls": {
    "server_name": "www.example.com",
    "fingerprint": "chrome",
    "reality": { "public_key": "<pbk>", "short_id": "0123abcd" },
    "fragment": { "packets": "tlshello", "length": "100-200", "interval": "10-20" }
  }
}
```

Роутинг (формат sing-box; `geosite`/`geoip` читаются из файлов Xray):

```json
{
  "inbounds": [
    { "type": "mixed", "tag": "in", "port": 2080,
      "sniff": { "enabled": true, "override_destination": false, "timeout_ms": 300 } }
  ],
  "route": {
    "final": "proxy",
    "geosite": "geosite.dat",
    "geoip": "geoip.dat",
    "domain_strategy": "ip_if_non_match",
    "rule_set": [
      { "tag": "ads", "type": "local", "path": "geosite-category-ads.srs" }
    ],
    "rules": [
      { "rule_set": "ads", "action": "reject" },
      { "protocol": "bittorrent", "outbound": "direct" },
      { "process_name": ["Discord.exe"], "outbound": "proxy" },
      { "process_name": ["cs2.exe", "dota2.exe"], "outbound": "direct" },
      { "geosite": ["category-ru", "private"], "geoip": ["ru", "private"], "outbound": "direct" },
      { "type": "logical", "mode": "and",
        "rules": [{ "network": "udp" }, { "port": 443 }], "action": "reject" }
    ]
  }
}
```

DNS (формат sing-box). `direct` и `domain_strategy` резолвят через этот модуль;
у прокси-протоколов домен по-прежнему уходит на сервер без локального резолва:

```json
"dns": {
  "servers": [
    { "tag": "remote", "address": "https://1.1.1.1/dns-query", "detour": "proxy" },
    { "tag": "local", "address": "udp://77.88.8.8" },
    { "tag": "google", "address": "tls://dns.google", "address_resolver": "local" },
    { "tag": "fake", "address": "fakeip" }
  ],
  "rules": [
    { "geosite": "category-ru", "server": "local" },
    { "domain_suffix": ["ru", "su"], "server": "local" }
  ],
  "final": "remote",
  "strategy": "prefer_ipv4",
  "hosts": { "router.lan": ["192.168.1.1"] },
  "cache": { "enabled": true, "max_entries": 4096, "min_ttl": 30, "max_ttl": 86400 },
  "client_subnet": "95.84.0.0/24"
}
```

Fake-IP отдаётся только приложениям (через `dns.query` и, позже, перехват DNS
в TUN); запросы самого ядра всегда идут на настоящие серверы. Соединение на
fake-адрес превращается обратно в домен до роутинга.

Системный прокси Windows (по умолчанию объявляется первый `mixed`/`http` inbound):

```json
"system_proxy": { "enabled": true, "bypass": ["localhost", "*.local", "<local>"] }
```

Пока прокси включён, рядом с ядром работает второй процесс `sybau.exe`
(сторож): если ядро аварийно завершится, он вернёт прежние настройки.

Группы outbound:

```json
{ "type": "selector", "tag": "manual", "outbounds": ["nl", "de"], "default": "nl" },
{ "type": "balancer", "tag": "auto", "outbounds": ["nl", "de", "fi"],
  "strategy": "fallback", "failure_cooldown": "30s" }
```

Балансировщик пробует участников по порядку стратегии; при ошибке подключения
участник откладывается на `failure_cooldown`, а соединение уходит следующему.
`least_ping` выбирает участника с наименьшим временем установления соединения
на реальном трафике. В `connections.list` поле `chain` показывает, через какого
участника группы пошло соединение.

Внутри правила условия одной группы объединяются через «или»
(`domain`/`domain_suffix`/`domain_keyword`/`domain_regex`/`geosite`/`ip_cidr`/`geoip`/`rule_set`),
а разные группы — через «и» (порт, сеть, протокол, процесс и т.д.), как в sing-box.
`geosite.dat`/`geoip.dat` ищутся рядом с конфигом, рядом с `sybau.exe`, в
`SYBAU_ASSET_DIR` и `XRAY_LOCATION_ASSET`.

Команды:

| Команда | Что делает |
|---|---|
| `sybau run -c FILE [--profile NAME] [--log-level LEVEL]` | запускает ядро (конфиг SYBAU, Xray или sing-box) |
| `sybau check -c FILE` | проверяет конфиг |
| `sybau convert [--from xray\|sing-box\|auto] FILE [-o OUT]` | переводит конфиг в формат SYBAU и печатает, что не удалось перенести |
| `sybau import ССЫЛКА\|ФАЙЛ\|-` | превращает ссылки или содержимое подписки в outbound-ы |
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
| `outbounds.list` | — | outbound-ы, их трафик и состояние групп |
| `subscriptions.parse` | `{"content": "..."}` | outbound-ы из содержимого подписки и предупреждения |
| `config.convert` | `{"text": "...", "from": "xray"}` | конфиг в формате SYBAU и предупреждения |
| `dns.query` | `{"name": "example.com", "type": "A"}` | ответ DNS-модуля |
| `dns.flush` | — | очищает кеш DNS |
| `outbounds.select` | `{"group": "sel", "outbound": "b", "close_connections": false}` | переключает selector |

## Тесты

```bash
cargo test --workspace
```

```bash
tests/ffi/run.sh
```

Шаблоны отпечатков (`crates/sybau-tls/src/fingerprints.json`) пересоздаются из
uTLS той же ревизии, что в Xray:

```bash
cd tools/utls-dump && go run . > ../../crates/sybau-tls/src/fingerprints.json
```

Стенд совместимости (нужны Go, curl, openssl и python3):

```bash
tests/interop/build-refs.sh
```

```bash
cargo build -p sybau && tests/interop/run.py
```

То же в Docker, с официальными образами Xray и sing-box:

```bash
docker build -f tests/interop/Dockerfile -t sybau-interop . && docker run --rm sybau-interop
```

## Лицензия

GPL-3.0-or-later.
