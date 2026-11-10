//! Configuration of SYBAU-CORE.
//!
//! The native format is JSON with the top-level sections
//! `log / control / inbounds / outbounds / route`. Foreign formats
//! (Xray, sing-box) are translated into this model by importer modules.

pub mod model;

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
