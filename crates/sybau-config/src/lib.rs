//! Configuration of SYBAU-CORE.
//!
//! The native format is JSON with the top-level sections
//! `log / control / inbounds / outbounds / route`. Foreign formats
//! (Xray, sing-box) are translated into this model by importer modules.

pub mod import;
pub mod links;
pub mod model;
pub mod route;
pub mod subscription;

pub use model::*;

use anyhow::{bail, Context, Result};

/// Parses a config of any supported format (SYBAU, Xray, sing-box) and
/// returns it with notes about settings that were not carried over.
pub fn parse_any(text: &str) -> Result<import::Imported> {
    import::load(text, None)
}

/// Parses a native SYBAU config and validates cross references.
pub fn parse_native(text: &str) -> Result<Config> {
    let cfg: Config =
        serde_json::from_str(&strip_json_comments(text)).context("invalid SYBAU config")?;
    cfg.validate()?;
    Ok(cfg)
}

impl Config {
    /// Checks everything that can be checked without touching the network.
    pub fn validate(&self) -> Result<()> {
        let mut tags = std::collections::HashSet::new();
        for ob in &self.outbounds {
            if ob.tag.is_empty() {
                bail!("outbound without a tag");
            }
            if !tags.insert(ob.tag.as_str()) {
                bail!("duplicate outbound tag `{}`", ob.tag);
            }
        }
        for ob in &self.outbounds {
            if let Some(d) = &ob.detour {
                if !tags.contains(d.as_str()) {
                    bail!("outbound `{}`: detour `{d}` does not exist", ob.tag);
                }
                if d == &ob.tag {
                    bail!("outbound `{}`: detour points to itself", ob.tag);
                }
            }
        }
        for ob in &self.outbounds {
            let members = match &ob.kind {
                OutboundKind::Selector(g) => &g.outbounds,
                OutboundKind::Balancer(g) => &g.outbounds,
                _ => continue,
            };
            if members.is_empty() {
                bail!("outbound `{}`: `outbounds` is empty", ob.tag);
            }
            for m in members {
                if !tags.contains(m.as_str()) {
                    bail!("outbound `{}`: member `{m}` does not exist", ob.tag);
                }
            }
            if let OutboundKind::Selector(SelectorOutbound {
                default: Some(d),
                outbounds,
            }) = &ob.kind
            {
                if !outbounds.contains(d) {
                    bail!("outbound `{}`: default `{d}` is not a member", ob.tag);
                }
            }
        }
        let mut in_tags = std::collections::HashSet::new();
        for ib in &self.inbounds {
            if !ib.tag.is_empty() && !in_tags.insert(ib.tag.as_str()) {
                bail!("duplicate inbound tag `{}`", ib.tag);
            }
        }
        let tuns: Vec<&TunInbound> = self
            .inbounds
            .iter()
            .filter_map(|ib| match &ib.kind {
                InboundKind::Tun(t) => Some(&**t),
                _ => None,
            })
            .collect();
        if tuns.len() > 1 {
            bail!("only one tun inbound is allowed");
        }
        if let Some(t) = tuns.first() {
            validate_tun(t)?;
        }
        if let Some(f) = &self.route.r#final {
            if !tags.contains(f.as_str()) {
                bail!("route.final `{f}` does not exist");
            }
        }
        if let Some(dns) = &self.dns {
            let mut servers = std::collections::HashSet::new();
            for srv in &dns.servers {
                if !servers.insert(srv.tag.as_str()) {
                    bail!("duplicate DNS server tag `{}`", srv.tag);
                }
                if let Some(d) = &srv.detour {
                    if !tags.contains(d.as_str()) {
                        bail!("DNS server `{}`: detour `{d}` does not exist", srv.tag);
                    }
                }
            }
            for srv in &dns.servers {
                if let Some(r) = &srv.address_resolver {
                    if !servers.contains(r.as_str()) || r == &srv.tag {
                        bail!(
                            "DNS server `{}`: address_resolver `{r}` is not another DNS server",
                            srv.tag
                        );
                    }
                }
            }
            if dns.servers.is_empty() {
                bail!("dns.servers is empty");
            }
            if let Some(f) = &dns.r#final {
                if !servers.contains(f.as_str()) {
                    bail!("dns.final `{f}` does not exist");
                }
            }
            for (i, rule) in dns.rules.iter().enumerate() {
                if !servers.contains(rule.server.as_str()) {
                    bail!("dns.rules[{i}]: server `{}` does not exist", rule.server);
                }
            }
        }
        let mut sets = std::collections::HashSet::new();
        for rs in &self.route.rule_set {
            if !sets.insert(rs.tag.as_str()) {
                bail!("duplicate rule-set tag `{}`", rs.tag);
            }
            if let Some(d) = &rs.download_detour {
                if !tags.contains(d.as_str()) {
                    bail!(
                        "rule-set `{}`: download_detour `{d}` does not exist",
                        rs.tag
                    );
                }
            }
        }
        for (i, rule) in self.route.rules.iter().enumerate() {
            match rule.action.as_deref().unwrap_or("route") {
                "route" => match &rule.outbound {
                    Some(o) if tags.contains(o.as_str()) => {}
                    Some(o) => bail!("route.rules[{i}]: outbound `{o}` does not exist"),
                    None => bail!("route.rules[{i}]: `outbound` is required"),
                },
                "reject" => {}
                other => bail!("route.rules[{i}]: unknown action `{other}` (use route or reject)"),
            }
        }
        Ok(())
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("config is always serializable")
    }
}

/// Removes `//` and `/* */` comments (outside of strings) so that configs
/// written for Xray, which tolerates them, can be parsed as plain JSON.
pub fn strip_json_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                '\\' => {
                    if let Some(n) = chars.next() {
                        out.push(n);
                    }
                }
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = ' ';
                for n in chars.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
            }
            _ => out.push(c),
        }
    }
    out
}

fn validate_tun(t: &TunInbound) -> Result<()> {
    if t.interface_name.is_empty() || (t.interface_name.len() > 15 && !cfg!(windows)) {
        bail!("tun: interface_name must be 1-15 characters");
    }
    if t.address.is_empty() && t.file_descriptor.is_none() {
        bail!("tun: `address` is empty");
    }
    for cidr in t
        .address
        .iter()
        .chain(&t.route_address)
        .chain(&t.route_exclude_address)
    {
        parse_cidr(cidr).map_err(|e| anyhow::anyhow!("tun: {e}"))?;
    }
    if t.address.iter().filter(|a| !a.contains(':')).count() > 1
        || t.address.iter().filter(|a| a.contains(':')).count() > 1
    {
        bail!("tun: at most one IPv4 and one IPv6 address");
    }
    // `gvisor` is sing-box's name for a userspace stack.
    if !matches!(
        t.stack.as_str(),
        "userspace" | "system" | "mixed" | "gvisor"
    ) {
        bail!("tun: stack must be `userspace`, `system` or `mixed`");
    }
    if t.mtu < 1280 && t.address.iter().any(|a| a.contains(':')) {
        bail!("tun: IPv6 needs an mtu of at least 1280");
    }
    if t.mtu < 576 {
        bail!("tun: mtu {} is too small", t.mtu);
    }
    if let Some(d) = &t.udp_timeout {
        route::parse_duration(d).map_err(|e| anyhow::anyhow!("tun: udp_timeout: {e}"))?;
    }
    Ok(())
}

/// Parses `172.19.0.1/30` into the address and prefix length.
pub fn parse_cidr(text: &str) -> Result<(std::net::IpAddr, u8)> {
    let (a, p) = text
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("`{text}` is not in address/prefix form"))?;
    let ip: std::net::IpAddr = a
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("bad address in `{text}`"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix: u8 = p
        .trim()
        .parse()
        .ok()
        .filter(|p| *p <= max)
        .ok_or_else(|| anyhow::anyhow!("bad prefix in `{text}`"))?;
    Ok((ip, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_are_stripped_outside_strings() {
        let src = r#"{ // line
            "a": "http://x/*y*/", /* block */ "b": 1 }"#;
        let v: serde_json::Value = serde_json::from_str(&strip_json_comments(src)).unwrap();
        assert_eq!(v["a"], "http://x/*y*/");
        assert_eq!(v["b"], 1);
    }

    #[test]
    fn sing_box_tun_and_hijack_dns_are_imported() {
        let imported = parse_any(
            r#"{
              "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": "tun0",
                            "inet4_address": "172.18.0.1/30", "auto_route": true,
                            "strict_route": true, "stack": "mixed",
                            "include_package": ["org.example"]}],
              "outbounds": [{"type": "direct", "tag": "direct"}],
              "route": {"rules": [{"protocol": "dns", "action": "hijack-dns"}]}
            }"#,
        )
        .unwrap();
        let cfg = imported.config;
        let InboundKind::Tun(t) = &cfg.inbounds[0].kind else {
            panic!("not a tun inbound");
        };
        assert_eq!(t.interface_name, "tun0");
        assert_eq!(t.address, ["172.18.0.1/30"]);
        assert!(t.strict_route && !t.dns_hijack);
        assert_eq!(t.stack, "mixed");
        assert!(matches!(cfg.outbounds[1].kind, OutboundKind::Dns));
        assert_eq!(cfg.route.rules[0].outbound.as_deref(), Some("hijack-dns"));
        assert!(imported
            .warnings
            .iter()
            .any(|w| w.contains("include_package")));
    }

    #[test]
    fn native_configs_with_rule_actions_stay_native() {
        let native = r#"{
          "inbounds": [{"type": "tun", "tag": "tun"}],
          "outbounds": [{"type": "direct", "tag": "direct"}],
          "route": {"rules": [{"process_name": ["curl.exe"], "action": "reject"}]}
        }"#;
        let imported = parse_any(native).unwrap();
        assert!(imported.warnings.is_empty(), "{:?}", imported.warnings);
        let InboundKind::Tun(t) = &imported.config.inbounds[0].kind else {
            panic!("not a tun inbound");
        };
        assert!(t.dns_hijack, "native defaults kept");
        // The same shape with sing-box-only fields is sing-box.
        let sing_box = r#"{
          "outbounds": [{"type": "direct", "tag": "direct"}],
          "route": {"rules": [{"protocol": "dns", "action": "hijack-dns"}]}
        }"#;
        let cfg = parse_any(sing_box).unwrap().config;
        assert!(cfg
            .outbounds
            .iter()
            .any(|o| matches!(o.kind, OutboundKind::Dns)));
    }

    #[test]
    fn xray_dns_outbound_is_imported() {
        let imported = parse_any(
            r#"{
              "inbounds": [{"protocol": "socks", "port": 1080, "listen": "127.0.0.1"}],
              "outbounds": [{"protocol": "freedom", "tag": "direct"},
                            {"protocol": "dns", "tag": "dns-out"}],
              "routing": {"rules": [{"type": "field", "port": "53", "outboundTag": "dns-out"}]}
            }"#,
        )
        .unwrap();
        let cfg = imported.config;
        assert!(matches!(cfg.outbounds[1].kind, OutboundKind::Dns));
        assert_eq!(cfg.outbounds[1].tag, "dns-out");
        let tun = parse_any(
            r#"{"inbounds": [{"protocol": "tun", "tag": "t", "settings": {"name": "xtun", "MTU": 1400}}],
                "outbounds": [{"protocol": "freedom"}]}"#,
        )
        .unwrap()
        .config;
        let InboundKind::Tun(t) = &tun.inbounds[0].kind else {
            panic!("not a tun inbound");
        };
        assert_eq!((t.interface_name.as_str(), t.mtu), ("xtun", 1400));
        assert!(!t.dns_hijack);
        assert_eq!(cfg.route.rules[0].outbound.as_deref(), Some("dns-out"));
    }

    #[test]
    fn minimal_config_parses() {
        let cfg = parse_native(
            r#"{
              "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "port": 2080}],
              "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}],
              "route": {"final": "direct"}
            }"#,
        )
        .unwrap();
        assert_eq!(cfg.inbounds.len(), 1);
        assert_eq!(cfg.outbounds[1].kind.type_name(), "block");
    }

    #[test]
    fn unknown_fields_are_errors_with_context() {
        let err = |text: &str| format!("{:#}", parse_native(text).unwrap_err());
        assert!(err(r#"{"inbound": []}"#).contains("inbound"));
        assert!(err(r#"{"log": {"levle": "info"}}"#).contains("levle"));
        let e = err(r#"{"outbounds":[{"type":"direct","tag":"d","bind_iface":"eth0"}]}"#);
        assert!(
            e.contains("outbound `d`") && e.contains("bind_iface"),
            "{e}"
        );
        let e = err(
            r#"{"outbounds":[{"type":"vless","tag":"v","server":"s","port":1,"uuid":"u","tls":{"sni":"x"}}]}"#,
        );
        assert!(e.contains("outbound `v`") && e.contains("sni"), "{e}");
        let e = err(
            r#"{"outbounds":[{"type":"vless","tag":"v","server":"s","port":1,"uuid":"u","transport":{"type":"ws","pth":"/"}}]}"#,
        );
        assert!(e.contains("pth"), "{e}");
        let e = err(r#"{"inbounds":[{"type":"mixed","tag":"m","port":1,"sniffing":true}]}"#);
        assert!(e.contains("inbound `m`") && e.contains("sniffing"), "{e}");
        assert!(err(r#"{"outbounds":[{"type":"teleport","tag":"t"}]}"#).contains("teleport"));
        assert!(err(r#"{"outbounds":[{"type":"direct"}]}"#).contains("without `tag`"));
    }

    #[test]
    fn config_survives_a_serialization_roundtrip() {
        let text = r#"{
          "inbounds": [{"type": "mixed", "tag": "in", "port": 2080, "users": [{"username": "u", "password": "p"}]}],
          "outbounds": [
            {"type": "vless", "tag": "v", "server": "example.com", "port": 443, "uuid": "u", "flow": "xtls-rprx-vision",
             "tls": {"server_name": "example.com", "fingerprint": "chrome",
                     "reality": {"public_key": "k", "short_id": "ab"},
                     "fragment": {"packets": "tlshello", "length": "10-20", "interval": "1-2"}}},
            {"type": "trojan", "tag": "t", "server": "s", "port": 1, "password": "p", "detour": "v",
             "transport": {"type": "grpc", "service_name": "x"}},
            {"type": "block", "tag": "b"}
          ],
          "route": {"final": "v"}
        }"#;
        let cfg = parse_native(text).unwrap();
        let again = parse_native(&cfg.to_json_pretty()).unwrap();
        assert_eq!(cfg.to_json_pretty(), again.to_json_pretty());
        assert_eq!(again.outbounds[1].detour.as_deref(), Some("v"));
    }

    #[test]
    fn bad_references_are_rejected() {
        assert!(parse_native(
            r#"{"outbounds":[{"type":"direct","tag":"a"},{"type":"direct","tag":"a"}]}"#
        )
        .is_err());
        assert!(
            parse_native(r#"{"outbounds":[{"type":"direct","tag":"a","detour":"zz"}]}"#).is_err()
        );
        assert!(parse_native(
            r#"{"outbounds":[{"type":"direct","tag":"a"}],"route":{"final":"b"}}"#
        )
        .is_err());
    }
}
