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
| Роутинг по правилам, geosite/geoip, sniffing, DNS | не начато (этап 3) |
| Конфиги Xray / sing-box, ссылки, подписки, `convert`, системный прокси Windows | не начато (этап 4) |
| TUN (Wintun, auto-route, kill switch) | не начато (этап 5) |
| Hysteria2, Hysteria, TUIC, XHTTP, mKCP | не начато (этап 6) |
| Серверные inbound, REALITY-сервер, TProxy | не начато (этап 7) |
| ShadowTLS, AnyTLS, Snell, SSH, Tor, WireGuard, ECH, обход DPI | не начато (этап 8) |
| Фаззинг, оптимизации, подписанные релизы | не начато (этап 9) |

Полная таблица проверенных сочетаний протокол × транспорт — в
[docs/INTEROP.md](docs/INTEROP.md): 98 сценариев против настоящих Xray-core
26.3.27 и sing-box 1.14.4.

Известные ограничения текущего этапа:

- правила роутинга ещё нет: весь трафик идёт в `route.final`;
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
