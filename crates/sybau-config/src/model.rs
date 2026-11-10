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
}

impl OutboundKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            OutboundKind::Direct(_) => "direct",
            OutboundKind::Block => "block",
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
