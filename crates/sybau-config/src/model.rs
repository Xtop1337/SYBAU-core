use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}
fn default_listen() -> String {
    "127.0.0.1".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub log: LogConfig,
    pub control: ControlConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<crate::route::DnsConfig>,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub route: RouteConfig,
    /// Windows system proxy, set while `sybau.exe` runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_proxy: Option<SystemProxyConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SystemProxyConfig {
    pub enabled: bool,
    /// `host:port` to announce. Default: the first mixed or http inbound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Hosts that bypass the proxy (WinINet syntax). Default: local
    /// and private addresses.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bypass: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    /// `trace`, `debug`, `info`, `warn`, `error` or `off`.
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
        }
    }
}

/// Control channel (JSON-RPC over a named pipe / unix socket).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ControlConfig {
    pub enabled: bool,
    /// Overrides the endpoint. Default: `\\.\pipe\sybau-core-<profile>` on
    /// Windows, `<runtime dir>/sybau-core-<profile>.sock` elsewhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InboundConfig {
    pub tag: String,
    #[serde(flatten)]
    pub kind: InboundKind,
}

/// Takes an optional string field out of a JSON object.
fn take_string<E: serde::de::Error>(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<String>, E> {
    match map.remove(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(E::custom(format!("`{key}` must be a string"))),
    }
}

// Written by hand instead of `#[serde(flatten)]` so that unknown fields
// are rejected: a typo in a config must not be silently ignored.
impl<'de> Deserialize<'de> for InboundConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let mut map = serde_json::Map::deserialize(deserializer)?;
        let tag = take_string(&mut map, "tag")?.unwrap_or_default();
        let kind = InboundKind::deserialize(serde_json::Value::Object(map))
            .map_err(|e| D::Error::custom(format!("inbound `{tag}`: {e}")))?;
        Ok(Self { tag, kind })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InboundKind {
    /// SOCKS5 (with UDP ASSOCIATE), SOCKS4a and HTTP proxy on one port.
    Mixed(LocalProxyInbound),
    Socks(LocalProxyInbound),
    Http(LocalProxyInbound),
    /// Virtual network interface that captures the system's traffic.
    Tun(Box<TunInbound>),
}

impl InboundKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            InboundKind::Mixed(_) => "mixed",
            InboundKind::Socks(_) => "socks",
            InboundKind::Http(_) => "http",
            InboundKind::Tun(_) => "tun",
        }
    }
}

fn default_tun_name() -> String {
    if cfg!(windows) {
        "SYBAU".into()
    } else {
        "sybau0".into()
    }
}
fn default_tun_address() -> Vec<String> {
    vec!["172.19.0.1/30".into(), "fdfe:dcba:9876::1/126".into()]
}
fn default_tun_mtu() -> u16 {
    9000
}
fn default_tun_fwmark() -> u32 {
    0x2023
}
fn default_tun_table() -> u32 {
    2022
}
/// TCP through the OS where the core supports it (faster), otherwise the
/// userspace stack.
fn default_tun_stack() -> String {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        "mixed".into()
    } else {
        "userspace".into()
    }
}

/// TUN inbound. Field names follow sing-box where they exist there.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunInbound {
    #[serde(default = "default_tun_name")]
    pub interface_name: String,
    /// Addresses of the interface, IPv4 and/or IPv6 in CIDR form.
    #[serde(default = "default_tun_address")]
    pub address: Vec<String>,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    /// Install routes that send all traffic (or `route_address`) into the
    /// interface. Ignored when `file_descriptor` is set: the platform
    /// (Android VpnService) owns the routes then.
    #[serde(default = "default_true")]
    pub auto_route: bool,
    /// Without it, routes of the local networks still win over the TUN
    /// (LAN stays reachable); with it, everything goes into the TUN.
    #[serde(default)]
    pub strict_route: bool,
    /// Route only these destinations into the TUN.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_address: Vec<String>,
    /// Never route these destinations into the TUN.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_exclude_address: Vec<String>,
    /// Linux: only traffic of these users goes into the TUN.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_uid: Vec<u32>,
    /// Linux: traffic of these users bypasses the TUN.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_uid: Vec<u32>,
    /// Only connections of these programs (name or full path) are proxied;
    /// the rest go out directly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_process: Vec<String>,
    /// Connections of these programs go out directly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_process: Vec<String>,
    /// Answer DNS queries sent to any server on port 53 with the core's
    /// DNS module.
    #[serde(default = "default_true")]
    pub dns_hijack: bool,
    /// Block traffic that would leave outside the TUN. The block stays if
    /// the core dies and is lifted by a clean exit or `sybau tun-cleanup`.
    #[serde(default)]
    pub kill_switch: bool,
    /// `userspace` (TCP/IP in the core), `system` or `mixed` (TCP through
    /// the OS stack, UDP in the core; the two are the same here). Default:
    /// `mixed` on Linux and Android, `userspace` elsewhere.
    #[serde(default = "default_tun_stack")]
    pub stack: String,
    /// Open TUN descriptor handed over by the platform (Android).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_descriptor: Option<i32>,
    /// Linux: mark on the core's own sockets, so they bypass the TUN.
    #[serde(default = "default_tun_fwmark")]
    pub fwmark: u32,
    /// Linux: policy routing table for the TUN routes.
    #[serde(default = "default_tun_table")]
    pub table: u32,
    /// How long an idle UDP flow is kept, e.g. `5m`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<String>,
    /// Windows: path of `wintun.dll` (default: next to the executable,
    /// then the copy built into it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wintun_file: Option<String>,
    #[serde(default)]
    pub sniff: SniffConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProxyInbound {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    /// Username/password accounts; empty means no authentication.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<UserPass>,
    /// Allow SOCKS5 UDP ASSOCIATE.
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default)]
    pub sniff: SniffConfig,
}

/// Protocol sniffing of an inbound.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SniffConfig {
    /// Look at the first bytes of every connection (TLS SNI, HTTP Host,
    /// QUIC SNI, BitTorrent) so that rules can match domains and protocols.
    pub enabled: bool,
    /// Replace an IP target with the sniffed domain, so that the domain
    /// is resolved at the end of the tunnel (Xray `routeOnly: false`).
    pub override_destination: bool,
    /// How long to wait for the client's first bytes, in milliseconds.
    pub timeout_ms: u64,
}

impl Default for SniffConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            override_destination: false,
            timeout_ms: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPass {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundConfig {
    pub tag: String,
    /// Dial this outbound through another one (proxy chain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    #[serde(flatten)]
    pub kind: OutboundKind,
}

impl<'de> Deserialize<'de> for OutboundConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let mut map = serde_json::Map::deserialize(deserializer)?;
        let tag = take_string(&mut map, "tag")?
            .ok_or_else(|| D::Error::custom("outbound without `tag`"))?;
        let detour = take_string(&mut map, "detour")?;
        let kind = OutboundKind::deserialize(serde_json::Value::Object(map))
            .map_err(|e| D::Error::custom(format!("outbound `{tag}`: {e}")))?;
        Ok(Self { tag, detour, kind })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutboundKind {
    Direct(DirectOutbound),
    Block,
    /// Answers DNS queries with the core's DNS module (Xray `dns`
    /// outbound, sing-box `hijack-dns`).
    Dns,
    /// SOCKS5 upstream proxy.
    Socks(UpstreamProxy),
    /// HTTP CONNECT upstream proxy.
    Http(UpstreamProxy),
    Vless(VlessOutbound),
    Vmess(VmessOutbound),
    Trojan(TrojanOutbound),
    Shadowsocks(ShadowsocksOutbound),
    /// Parsed and converted; the protocol itself arrives in stage 6.
    Hysteria2(Hysteria2Outbound),
    /// Parsed and converted; the protocol itself arrives in stage 6.
    Tuic(TuicOutbound),
    /// Parsed and converted; the protocol itself arrives in stage 8.
    Wireguard(WireguardOutbound),
    /// Group whose active member is chosen by hand (control API).
    Selector(SelectorOutbound),
    /// Group that spreads or fails over connections between members.
    Balancer(BalancerOutbound),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorOutbound {
    pub outbounds: Vec<String>,
    /// Member used until another one is selected. Default: the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BalancerOutbound {
    pub outbounds: Vec<String>,
    /// `round_robin` (default), `random`, `fallback` (first healthy member
    /// in order) or `least_ping` (lowest handshake time seen on real
    /// connections).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    /// A member whose connection fails is skipped for this long, e.g. `30s`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_cooldown: Option<String>,
}

impl OutboundKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            OutboundKind::Direct(_) => "direct",
            OutboundKind::Block => "block",
            OutboundKind::Dns => "dns",
            OutboundKind::Socks(_) => "socks",
            OutboundKind::Http(_) => "http",
            OutboundKind::Vless(_) => "vless",
            OutboundKind::Vmess(_) => "vmess",
            OutboundKind::Trojan(_) => "trojan",
            OutboundKind::Shadowsocks(_) => "shadowsocks",
            OutboundKind::Hysteria2(_) => "hysteria2",
            OutboundKind::Tuic(_) => "tuic",
            OutboundKind::Wireguard(_) => "wireguard",
            OutboundKind::Selector(_) => "selector",
            OutboundKind::Balancer(_) => "balancer",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DirectOutbound {
    /// Bind outgoing sockets to this interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
    /// Linux `SO_MARK` for outgoing sockets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fwmark: Option<u32>,
    /// Split the first packets of every TCP connection (DPI evasion for
    /// direct connections).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<FragmentConfig>,
}

pub use crate::route::RouteConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProxy {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// TLS to the proxy itself (HTTPS proxy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessOutbound {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    /// `xtls-rprx-vision`, or `xtls-rprx-vision-udp443` to also allow
    /// UDP to port 443 (QUIC). Needs TLS or REALITY over plain TCP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    /// `xudp`: all UDP destinations share one stream with full cone NAT.
    /// Unset: one stream per destination. Vision always uses `xudp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmessOutbound {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    /// `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none` or `zero`.
    #[serde(default = "default_auto")]
    pub security: String,
    /// Only 0 (AEAD header) is supported; legacy MD5 authentication is not.
    #[serde(default)]
    pub alter_id: u32,
    /// Random padding in every chunk (Xray enables it by default).
    #[serde(default = "default_true")]
    pub global_padding: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanOutbound {
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksOutbound {
    pub server: String,
    pub port: u16,
    /// `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`,
    /// `xchacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`,
    /// `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`, `none`.
    pub method: String,
    /// Password; for 2022 methods base64 keys, `iPSK:uPSK` for multi-user servers.
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Outbound {
    pub server: String,
    pub port: u16,
    pub password: String,
    /// Port hopping ranges, e.g. `20000-30000`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_ports: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hop_interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,
    /// Salamander obfuscation password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TuicOutbound {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub password: String,
    /// `cubic`, `new_reno` or `bbr`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion_control: Option<String>,
    /// `native` or `quic`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_relay_mode: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub zero_rtt_handshake: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireguardOutbound {
    pub server: String,
    pub port: u16,
    /// Base64 keys.
    pub private_key: String,
    pub peer_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<String>,
    /// Interface addresses, e.g. `10.0.0.2/32`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_address: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Cloudflare WARP client id bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reserved: Vec<u8>,
}

fn default_auto() -> String {
    "auto".to_string()
}

/// TLS towards the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    pub enabled: bool,
    /// SNI and the name the certificate is checked against.
    /// Default: the server address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    /// Accept any certificate. Dangerous: allows interception.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub insecure: bool,
    /// SHA-256 of a certificate, hex or base64 (Xray `pinnedPeerCertSha256`).
    /// A pinned leaf is accepted without CA checks, so self-signed
    /// certificates can be pinned; a pinned CA in the chain becomes the
    /// only trusted root.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pinned_cert_sha256: Vec<String>,
    /// Xray `pinnedPeerCertificateChainSha256`: base64 hash of the whole
    /// chain, checked in addition to normal verification.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pinned_cert_chain_sha256: Vec<String>,
    /// Check the certificate against these names instead of the SNI
    /// (Xray `verifyPeerCertByName`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verify_names: Vec<String>,
    /// Imitate the ClientHello of a browser (uTLS): `chrome`, `firefox`,
    /// `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`,
    /// `randomized`. Requires a TLS 1.3 server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// REALITY instead of certificate validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityConfig>,
    /// Split the ClientHello to get past DPI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<FragmentConfig>,
}

/// Fragmentation of outgoing TCP data (Xray `fragment`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentConfig {
    /// `tlshello`: split the TLS ClientHello into several TLS records.
    /// `1-3`: cut writes number 1 to 3 into TCP segments.
    pub packets: String,
    /// Size of a piece in bytes, e.g. `100-200`.
    pub length: String,
    /// Pause between pieces in milliseconds, e.g. `10-20`.
    pub interval: String,
    /// Upper bound of pieces per write, e.g. `3-5`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_split: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityConfig {
    /// Server public key (base64url), `pbk` in share links.
    pub public_key: String,
    /// Hex short id, `sid` in share links. May be empty.
    #[serde(default)]
    pub short_id: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            server_name: None,
            alpn: Vec::new(),
            insecure: false,
            pinned_cert_sha256: Vec::new(),
            pinned_cert_chain_sha256: Vec::new(),
            verify_names: Vec::new(),
            fingerprint: None,
            reality: None,
            fragment: None,
        }
    }
}

/// How the proxy protocol is carried to the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransportConfig {
    /// Plain TCP, optionally disguised with a fake HTTP exchange.
    Tcp(TcpTransport),
    Ws(WsTransport),
    #[serde(rename = "httpupgrade")]
    HttpUpgrade(HttpUpgradeTransport),
    Grpc(GrpcTransport),
    /// HTTP/2 stream (`h2` in Xray, `http` in sing-box).
    #[serde(alias = "h2")]
    Http(Http2Transport),
}

pub type Headers = std::collections::BTreeMap<String, String>;

fn default_path() -> String {
    "/".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TcpTransport {
    /// Xray `tcpSettings.header.type = "http"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_obfs: Option<HttpObfs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpObfs {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host: Vec<String>,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Headers::is_empty")]
    pub headers: Headers,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WsTransport {
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Headers::is_empty")]
    pub headers: Headers,
    /// Send up to this many bytes of the first payload inside the
    /// handshake request (0-RTT). 0 disables early data.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_early_data: usize,
    /// Header that carries early data (`Sec-WebSocket-Protocol` for Xray
    /// servers). When unset, early data is appended to the path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_data_header_name: Option<String>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpUpgradeTransport {
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Headers::is_empty")]
    pub headers: Headers,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GrpcTransport {
    pub service_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// Xray `multiMode`: several buffers per gRPC message.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub multi_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http2Transport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host: Vec<String>,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Headers::is_empty")]
    pub headers: Headers,
}
