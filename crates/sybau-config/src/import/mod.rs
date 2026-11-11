//! Reading configurations written for Xray and sing-box.

pub mod singbox;
pub mod xray;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::{strip_json_comments, Config};

/// Which program a configuration was written for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Sybau,
    Xray,
    SingBox,
}

impl Format {
    pub fn parse(name: &str) -> Result<Self> {
        Ok(match name.to_ascii_lowercase().as_str() {
            "sybau" | "native" => Format::Sybau,
            "xray" | "v2ray" => Format::Xray,
            "sing-box" | "singbox" | "sing_box" => Format::SingBox,
            other => bail!("unknown config format `{other}` (sybau, xray, sing-box)"),
        })
    }
}

/// A converted configuration and what could not be carried over.
#[derive(Debug)]
pub struct Imported {
    pub config: Config,
    pub warnings: Vec<String>,
}

/// Guesses the format from keys only one of the programs uses.
pub fn detect(v: &Value) -> Format {
    let has = |path: &[&str]| {
        let mut cur = v;
        for key in path {
            match cur {
                Value::Object(m) => match m.get(*key) {
                    Some(next) => cur = next,
                    None => return false,
                },
                Value::Array(a) => match a.iter().find(|x| x.get(*key).is_some()) {
                    Some(item) => cur = &item[*key],
                    None => return false,
                },
                _ => return false,
            }
        }
        true
    };
    if has(&["routing"]) || has(&["outbounds", "protocol"]) || has(&["inbounds", "protocol"]) {
        return Format::Xray;
    }
    if has(&["outbounds", "server_port"])
        || has(&["inbounds", "listen_port"])
        || has(&["experimental"])
        || has(&["endpoints"])
    {
        return Format::SingBox;
    }
    // Rule actions exist in both formats (`reject`); typed DNS servers
    // only in sing-box. A config that is valid SYBAU stays SYBAU.
    if (has(&["route", "rules", "action"]) || has(&["dns", "servers", "type"]))
        && !serde_json::from_value::<Config>(v.clone()).is_ok_and(|c| c.validate().is_ok())
    {
        return Format::SingBox;
    }
    Format::Sybau
}

/// Reads a configuration of any supported format.
pub fn load(text: &str, format: Option<Format>) -> Result<Imported> {
    let v: Value =
        serde_json::from_str(&strip_json_comments(text)).context("config is not valid JSON")?;
    let format = format.unwrap_or_else(|| detect(&v));
    match format {
        Format::Sybau => {
            let config: Config = serde_json::from_value(v).context("invalid SYBAU config")?;
            config.validate()?;
            Ok(Imported {
                config,
                warnings: Vec::new(),
            })
        }
        Format::SingBox => singbox::convert(v),
        Format::Xray => xray::convert(v),
    }
}

/// Collects notes about dropped settings.
#[derive(Default)]
pub(crate) struct Notes(pub Vec<String>);

impl Notes {
    pub fn add(&mut self, msg: impl Into<String>) {
        self.0.push(msg.into());
    }
}

/// Removes `key` from an object and returns it.
pub(crate) fn take(v: &mut Value, key: &str) -> Option<Value> {
    v.as_object_mut()?.remove(key).filter(|x| !x.is_null())
}

pub(crate) fn take_str(v: &mut Value, key: &str) -> Option<String> {
    match take(v, key)? {
        Value::String(s) => Some(s),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}
