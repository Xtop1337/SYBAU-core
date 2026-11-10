//! Configuration of SYBAU-CORE.
//!
//! The native format is JSON with the top-level sections
//! `log / control / inbounds / outbounds / route`. Foreign formats
//! (Xray, sing-box) are translated into this model by importer modules.

pub mod model;
pub mod route;

pub use model::*;

use anyhow::{bail, Context, Result};

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
        let mut in_tags = std::collections::HashSet::new();
        for ib in &self.inbounds {
            if !ib.tag.is_empty() && !in_tags.insert(ib.tag.as_str()) {
                bail!("duplicate inbound tag `{}`", ib.tag);
            }
        }
        if let Some(f) = &self.route.r#final {
            if !tags.contains(f.as_str()) {
                bail!("route.final `{f}` does not exist");
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
