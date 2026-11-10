# Совместимость с Xray и sing-box

Таблица создаётся командой `tests/interop/run.py --report docs/INTEROP.md`.
SYBAU-CORE работает клиентом, сервером — настоящий Xray-core 26.3.27 или sing-box 1.14.4.

- TCP: GET, скачивание 8 МиБ и загрузка 2 МиБ со сверкой SHA-256 — и по HTTPS (TLS 1.3 внутри туннеля), и по HTTP; плюс сервис, который говорит первым.
- UDP: SOCKS5 UDP ASSOCIATE на два эхо-сервера, датаграммы 1, 100 и 1200 байт.
- «rejected, as it must be» — негативный сценарий: соединение обязано быть отвергнуто.

| Case | TCP | UDP |
|---|---|---|
| `xray/vless/tcp` | pass | pass |
| `xray/vless/tcp+tls` | pass | pass |
| `xray/vless/tcp+http-obfs` | pass | pass |
| `xray/vless/ws` | pass | pass |
| `xray/vless/ws+tls` | pass | pass |
| `xray/vless/ws+tls+early-data` | pass | pass |
| `xray/vless/httpupgrade` | pass | pass |
| `xray/vless/httpupgrade+tls` | pass | pass |
| `xray/vless/grpc` | pass | pass |
| `xray/vless/grpc+tls` | pass | pass |
| `xray/vless/grpc-multi+tls` | pass | pass |
| `xray/vmess/tcp/auto` | pass | pass |
| `xray/vmess/tcp/aes-128-gcm` | pass | pass |
| `xray/vmess/tcp/chacha20-poly1305` | pass | pass |
| `xray/vmess/tcp/none` | pass | pass |
| `xray/vmess/tcp/zero` | pass | pass |
| `xray/vmess/tcp/no-global-padding` | pass | pass |
| `xray/vmess/ws+tls` | pass | pass |
| `xray/vmess/grpc+tls` | pass | pass |
| `xray/trojan/tcp+tls` | pass | pass |
| `xray/trojan/ws+tls` | pass | pass |
| `xray/trojan/grpc+tls` | pass | pass |
| `xray/shadowsocks/aes-128-gcm` | pass | pass |
| `xray/shadowsocks/aes-256-gcm` | pass | pass |
| `xray/shadowsocks/chacha20-ietf-poly1305` | pass | pass |
| `xray/shadowsocks/xchacha20-ietf-poly1305` | pass | pass |
| `xray/shadowsocks/2022-blake3-aes-128-gcm` | pass | pass |
| `xray/shadowsocks/2022-blake3-aes-256-gcm` | pass | pass |
| `xray/shadowsocks/2022-blake3-chacha20-poly1305` | pass | pass |
| `xray/shadowsocks/2022-blake3-aes-128-gcm/multi-user` | pass | pass |
| `xray/shadowsocks/2022-blake3-aes-256-gcm/multi-user` | pass | pass |
| `sing-box/vless/tcp` | pass | pass |
| `sing-box/vless/tcp+tls` | pass | pass |
| `sing-box/vless/ws+tls` | pass | pass |
| `sing-box/vless/ws+early-data` | pass | pass |
| `sing-box/vless/ws+early-data-in-path` | pass | pass |
| `sing-box/vless/httpupgrade+tls` | pass | pass |
| `sing-box/vless/grpc+tls` | pass | pass |
| `sing-box/vless/http2+tls` | pass | pass |
| `sing-box/vmess/tcp/auto` | pass | pass |
| `sing-box/vmess/tcp/chacha20-poly1305` | pass | pass |
| `sing-box/vmess/tcp/none` | pass | pass |
| `sing-box/vmess/tcp/zero` | pass | pass |
| `sing-box/trojan/tcp+tls` | pass | pass |
| `sing-box/shadowsocks/aes-128-gcm` | pass | pass |
| `sing-box/shadowsocks/chacha20-ietf-poly1305` | pass | pass |
| `sing-box/shadowsocks/xchacha20-ietf-poly1305` | pass | pass |
| `sing-box/shadowsocks/none` | pass | pass |
| `sing-box/shadowsocks/2022-blake3-aes-128-gcm` | pass | pass |
| `sing-box/shadowsocks/2022-blake3-aes-256-gcm` | pass | pass |
| `sing-box/shadowsocks/2022-blake3-chacha20-poly1305` | pass | pass |
| `sing-box/shadowsocks/2022-blake3-aes-128-gcm/multi-user` | pass | pass |
| `sing-box/socks5/auth` | pass | pass |
| `sing-box/socks5/no-auth` | pass | pass |
| `sing-box/http-connect/auth` | pass | — |
| `sing-box/http-connect+tls` | pass | — |
| `xray/vless/tcp+tls/fingerprint-chrome` | pass | pass |
| `xray/vless/tcp+tls/fingerprint-firefox` | pass | pass |
| `xray/vless/tcp+tls/fingerprint-safari` | pass | pass |
| `xray/vless/tcp+tls/fingerprint-ios` | pass | pass |
| `xray/vless/tcp+tls/fingerprint-edge` | pass | pass |
| `xray/vless/tcp+tls/fingerprint-qq` | pass | pass |
| `xray/vless/tcp+tls/fingerprint-random` | pass | pass |
| `xray/vless/tcp+tls/fingerprint-randomized` | pass | pass |
| `xray/vless/ws+tls/fingerprint-chrome` | pass | pass |
| `xray/trojan/grpc+tls/fingerprint-firefox` | pass | pass |
| `sing-box/vless/tcp+tls/fingerprint-chrome` | pass | pass |
| `sing-box/vless/tcp+tls/fingerprint-firefox` | pass | pass |
| `sing-box/vless/tcp+tls/fingerprint-safari` | pass | pass |
| `tls/fingerprint-with-wrong-pin-is-rejected` | rejected, as it must be | — |
| `tls/fingerprint-self-signed-without-pin-is-rejected` | rejected, as it must be | — |
| `xray/vless/tcp+tls/fragment-tlshello` | pass | pass |
| `xray/vless/tcp+tls/fragment-tlshello-rustls` | pass | pass |
| `xray/vless/tcp+tls/fragment-packets` | pass | pass |
| `sing-box/vless/tcp+tls/fragment-tlshello` | pass | pass |
| `xray/vless/vision+tls` | pass | pass |
| `xray/vless/vision+tls/default-fingerprint` | pass | pass |
| `sing-box/vless/vision+tls` | pass | pass |
| `xray/vless/tcp/xudp` | pass | pass |
| `sing-box/vless/tcp+tls/xudp` | pass | pass |
| `xray/vless/reality/fingerprint-chrome` | pass | pass |
| `xray/vless/reality/fingerprint-firefox` | pass | pass |
| `xray/vless/reality/fingerprint-safari` | pass | pass |
| `xray/vless/reality/fingerprint-ios` | pass | pass |
| `xray/vless/reality/fingerprint-edge` | pass | pass |
| `xray/vless/vision+reality` | pass | pass |
| `xray/vless/vision+reality/fragment-tlshello` | pass | pass |
| `xray/vless/reality/empty-short-id` | pass | pass |
| `xray/vless/grpc+reality` | pass | pass |
| `xray/trojan/reality` | pass | pass |
| `sing-box/vless/reality` | pass | pass |
| `sing-box/vless/vision+reality` | pass | pass |
| `reality/wrong-public-key-is-rejected` | rejected, as it must be | — |
| `reality/wrong-short-id-is-rejected` | rejected, as it must be | — |
| `tls/insecure-accepts-self-signed` | pass | pass |
| `tls/wrong-pin-is-rejected` | rejected, as it must be | — |
| `tls/self-signed-without-pin-is-rejected` | rejected, as it must be | — |
| `auth/wrong-uuid-is-rejected` | rejected, as it must be | — |
