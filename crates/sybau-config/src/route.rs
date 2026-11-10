//! Routing section of the config (`route`), in sing-box's vocabulary.

use serde::{Deserialize, Deserializer, Serialize};

/// Accepts `"x"` as well as `["x", "y"]`, like sing-box's listable fields.
pub fn one_or_many<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Listable<T> {
        One(T),
        Many(Vec<T>),
    }
    Ok(match Option::<Listable<T>>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(Listable::One(v)) => vec![v],
        Some(Listable::Many(v)) => v,
    })
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Conditions of a rule; used for route rules and inside rule-sets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HeadlessRule {
    /// `logical` for a rule combining `rules` with `mode`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// `and` or `or`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<HeadlessRule>,

    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domain: Vec<String>,
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domain_suffix: Vec<String>,
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domain_keyword: Vec<String>,
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub domain_regex: Vec<String>,
    /// Xray `geosite.dat` entries: `cn`, `google@ads`, `ext:file.dat:tag`.
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub geosite: Vec<String>,
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ip_cidr: Vec<String>,
    /// Xray `geoip.dat` entries: `ru`, `!cn`, `private`, `ext:file.dat:tag`.
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub geoip: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub ip_is_private: bool,
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub source_ip_cidr: Vec<String>,
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub source_geoip: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub source_ip_is_private: bool,
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub port: Vec<u16>,
    /// `1000:2000`, `:100`, `100:`.
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub port_range: Vec<String>,
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub source_port: Vec<u16>,
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub source_port_range: Vec<String>,
    /// `tcp`, `udp`.
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub network: Vec<String>,
    /// Sniffed protocol: `tls`, `http`, `quic`, `bittorrent`, `dns`.
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub protocol: Vec<String>,
    /// Inbound tags.
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub inbound: Vec<String>,
    /// Authenticated inbound users.
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub auth_user: Vec<String>,
    /// Executable name, e.g. `Discord.exe` (case-insensitive on Windows).
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub process_name: Vec<String>,
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub process_path: Vec<String>,
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub process_path_regex: Vec<String>,
    /// Android package names.
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub package_name: Vec<String>,
    /// Tags of `route.rule_set` entries.
    #[serde(
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub rule_set: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub invert: bool,
}

/// A route rule: conditions plus what to do with matching traffic.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RouteRule {
    #[serde(flatten)]
    pub conditions: HeadlessRule,
    /// `route` (default; needs `outbound`) or `reject`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
}

impl<'de> Deserialize<'de> for RouteRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let mut map = serde_json::Map::deserialize(deserializer)?;
        let mut take = |key: &str| -> Result<Option<String>, D::Error> {
            match map.remove(key) {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(serde_json::Value::String(s)) => Ok(Some(s)),
                Some(_) => Err(D::Error::custom(format!("`{key}` must be a string"))),
            }
        };
        let action = take("action")?;
        let outbound = take("outbound")?;
        let conditions =
            HeadlessRule::deserialize(serde_json::Value::Object(map)).map_err(D::Error::custom)?;
        Ok(Self {
            conditions,
            action,
            outbound,
        })
    }
}

/// A named rule-set (sing-box `route.rule_set`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetConfig {
    pub tag: String,
    /// `local`, `remote` or `inline`.
    #[serde(rename = "type")]
    pub kind: String,
    /// `binary` (.srs) or `source` (.json). Default: from the file extension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Outbound used to download a remote rule-set. Default: `route.final`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_detour: Option<String>,
    /// How often a remote rule-set is refreshed, e.g. `1d`, `12h`. Default `1d`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_interval: Option<String>,
    /// Rules of an `inline` rule-set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<HeadlessRule>,
}

/// Source form of a rule-set file (`sing-box rule-set compile` input).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetSource {
    pub version: u8,
    #[serde(default)]
    pub rules: Vec<HeadlessRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RouteConfig {
    /// Outbound for traffic no rule matched. Default: the first outbound.
    #[serde(rename = "final", skip_serializing_if = "Option::is_none")]
    pub r#final: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RouteRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<RuleSetConfig>,
    /// Path of `geosite.dat`. Default: looked up next to the config, next
    /// to the executable and in `SYBAU_ASSET_DIR` / `XRAY_LOCATION_ASSET`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geosite: Option<String>,
    /// Path of `geoip.dat`, looked up like `geosite`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip: Option<String>,
    /// How domain targets meet IP rules: `as_is` (default, IP rules only
    /// see IP targets), `ip_if_non_match` (resolve when no rule matched by
    /// domain) or `ip_on_demand` (resolve before matching).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<String>,
    /// Directory for downloaded rule-sets and other state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<String>,
}

/// Parses durations like `1d`, `12h`, `90s`, `1h30m`.
pub fn parse_duration(text: &str) -> anyhow::Result<std::time::Duration> {
    humantime::parse_duration(text.trim())
        .map_err(|e| anyhow::anyhow!("bad duration `{text}`: {e}"))
}

/// DNS section (`dns`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnsConfig {
    pub servers: Vec<DnsServerConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsRule>,
    /// Server for queries no rule matched. Default: the first server.
    #[serde(rename = "final", skip_serializing_if = "Option::is_none")]
    pub r#final: Option<String>,
    /// `as_is` (default), `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    /// Static answers: name → addresses.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub hosts: std::collections::BTreeMap<String, Vec<String>>,
    pub cache: DnsCacheConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fakeip: Option<FakeIpConfig>,
    /// EDNS Client Subnet sent with every query, e.g. `95.84.0.0/24`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServerConfig {
    pub tag: String,
    /// `1.1.1.1`, `udp://`, `tcp://`, `tls://`, `https://host/dns-query`,
    /// `local` (system resolver), `fakeip`, `rcode://refused`.
    pub address: String,
    /// Outbound used to reach the server. Default: direct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    /// Server that resolves this server's own domain. Default: the system resolver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_resolver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<String>,
    /// TLS settings for `tls://` and `https://` servers (SNI, pinning).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<crate::model::TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnsCacheConfig {
    pub enabled: bool,
    pub max_entries: usize,
    /// Seconds.
    pub min_ttl: u32,
    pub max_ttl: u32,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 4096,
            min_ttl: 30,
            max_ttl: 86400,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FakeIpConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inet4_range: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inet6_range: Option<String>,
}

impl Default for FakeIpConfig {
    fn default() -> Self {
        Self {
            inet4_range: Some("198.18.0.0/15".into()),
            inet6_range: Some("fc00::/18".into()),
        }
    }
}

/// A DNS rule: conditions plus the server to ask.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsRule {
    #[serde(flatten)]
    pub conditions: HeadlessRule,
    /// `A`, `AAAA`, `HTTPS`, ... or numbers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub query_type: Vec<String>,
    pub server: String,
}

impl<'de> Deserialize<'de> for DnsRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let mut map = serde_json::Map::deserialize(deserializer)?;
        let server = match map.remove("server") {
            Some(serde_json::Value::String(s)) => s,
            _ => return Err(D::Error::custom("DNS rule needs a `server` string")),
        };
        let query_type = match map.remove("query_type") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(items)) => items
                .into_iter()
                .map(|v| match v {
                    serde_json::Value::String(s) => Ok(s),
                    serde_json::Value::Number(n) => Ok(n.to_string()),
                    _ => Err(D::Error::custom(
                        "`query_type` entries must be strings or numbers",
                    )),
                })
                .collect::<Result<_, _>>()?,
            Some(serde_json::Value::String(s)) => vec![s],
            Some(serde_json::Value::Number(n)) => vec![n.to_string()],
            Some(_) => return Err(D::Error::custom("bad `query_type`")),
        };
        let conditions =
            HeadlessRule::deserialize(serde_json::Value::Object(map)).map_err(D::Error::custom)?;
        Ok(Self {
            conditions,
            query_type,
            server,
        })
    }
}
