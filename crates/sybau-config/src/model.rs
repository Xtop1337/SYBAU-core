use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}
fn default_listen() -> String {
    "127.0.0.1".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub log: LogConfig,
    pub control: ControlConfig,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub route: RouteConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    #[serde(default)]
    pub tag: String,
    #[serde(flatten)]
    pub kind: InboundKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InboundKind {
    /// SOCKS5 (with UDP ASSOCIATE), SOCKS4a and HTTP proxy on one port.
    Mixed(LocalProxyInbound),
    Socks(LocalProxyInbound),
    Http(LocalProxyInbound),
}

impl InboundKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            InboundKind::Mixed(_) => "mixed",
            InboundKind::Socks(_) => "socks",
            InboundKind::Http(_) => "http",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPass {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub tag: String,
    /// Dial this outbound through another one (proxy chain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    #[serde(flatten)]
    pub kind: OutboundKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutboundKind {
    Direct(DirectOutbound),
    Block,
    /// SOCKS5 upstream proxy.
    Socks(UpstreamProxy),
    /// HTTP CONNECT upstream proxy.
    Http(UpstreamProxy),
    Vless(VlessOutbound),
    Vmess(VmessOutbound),
    Trojan(TrojanOutbound),
    Shadowsocks(ShadowsocksOutbound),
}

impl OutboundKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            OutboundKind::Direct(_) => "direct",
            OutboundKind::Block => "block",
            OutboundKind::Socks(_) => "socks",
            OutboundKind::Http(_) => "http",
            OutboundKind::Vless(_) => "vless",
            OutboundKind::Vmess(_) => "vmess",
            OutboundKind::Trojan(_) => "trojan",
            OutboundKind::Shadowsocks(_) => "shadowsocks",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DirectOutbound {
    /// Bind outgoing sockets to this interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
    /// Linux `SO_MARK` for outgoing sockets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fwmark: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteConfig {
    /// Outbound for traffic no rule matched. Default: the first outbound.
    #[serde(rename = "final", skip_serializing_if = "Option::is_none")]
    pub r#final: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct VlessOutbound {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

fn default_auto() -> String {
    "auto".to_string()
}

/// TLS towards the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
    /// SHA-256 of the server (leaf) certificate, hex or base64. A match is
    /// sufficient: the CA chain is not checked, so self-signed
    /// certificates can be pinned.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pinned_cert_sha256: Vec<String>,
    /// Xray `pinnedPeerCertificateChainSha256`: base64 hash of the whole
    /// chain, checked in addition to normal verification.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pinned_cert_chain_sha256: Vec<String>,
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
#[serde(default)]
pub struct TcpTransport {
    /// Xray `tcpSettings.header.type = "http"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_obfs: Option<HttpObfs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct HttpUpgradeTransport {
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Headers::is_empty")]
    pub headers: Headers,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
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
