//! Subscription content: base64 or plain lists of share links,
//! Clash / mihomo YAML, sing-box or Xray JSON. Fetching the content is
//! left to the caller (the application, or a file).

use std::collections::HashSet;

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

use crate::links::{decode_base64, parse_link};
use crate::model::{OutboundConfig, OutboundKind};

#[derive(Debug, Default)]
pub struct Parsed {
    pub outbounds: Vec<OutboundConfig>,
    /// Entries that could not be used, with the reason.
    pub warnings: Vec<String>,
}

fn is_proxy(o: &OutboundConfig) -> bool {
    !matches!(
        o.kind,
        OutboundKind::Direct(_)
            | OutboundKind::Block
            | OutboundKind::Selector(_)
            | OutboundKind::Balancer(_)
    )
}

/// Parses subscription content of any supported kind.
pub fn parse(content: &str) -> Result<Parsed> {
    let text = content.trim().trim_start_matches('\u{feff}');
    if text.is_empty() {
        bail!("the subscription is empty");
    }
    let mut parsed = if text.starts_with('{') || text.starts_with('[') {
        parse_json(text)?
    } else if text.lines().any(|l| l.trim_start().starts_with("proxies:")) {
        parse_clash(text)?
    } else if text.contains("://") {
        parse_links(text)
    } else {
        let decoded = decode_base64(text)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| anyhow!("unrecognised subscription format"))?;
        if !decoded.contains("://") {
            bail!("unrecognised subscription format");
        }
        parse_links(&decoded)
    };
    unique_tags(&mut parsed.outbounds);
    if parsed.outbounds.is_empty() {
        bail!(
            "no usable servers in the subscription ({})",
            parsed.warnings.join("; ")
        );
    }
    Ok(parsed)
}

fn unique_tags(outbounds: &mut [OutboundConfig]) {
    let mut seen = HashSet::new();
    for o in outbounds {
        let base = o.tag.trim().to_string();
        let base = if base.is_empty() {
            "proxy".to_string()
        } else {
            base
        };
        let mut tag = base.clone();
        let mut n = 1;
        while !seen.insert(tag.clone()) {
            n += 1;
            tag = format!("{base} ({n})");
        }
        o.tag = tag;
    }
}

fn parse_links(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        match parse_link(line) {
            Ok(o) => parsed.outbounds.push(o),
            Err(e) => parsed.warnings.push(format!("{e:#}")),
        }
    }
    parsed
}

fn parse_json(text: &str) -> Result<Parsed> {
    let imported = crate::import::load(text, None)?;
    Ok(Parsed {
        outbounds: imported
            .config
            .outbounds
            .into_iter()
            .filter(is_proxy)
            .collect(),
        warnings: imported.warnings,
    })
}

fn s(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(x) => Some(x.clone()).filter(|x| !x.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn b(v: &Value, key: &str) -> bool {
    matches!(v.get(key), Some(Value::Bool(true))) || s(v, key).as_deref() == Some("true")
}

fn clash_tls(p: &Value, default_on: bool) -> Option<Value> {
    if !(b(p, "tls") || default_on || p.get("reality-opts").is_some()) {
        return None;
    }
    let mut t = json!({"enabled": true});
    if let Some(sni) = s(p, "servername").or_else(|| s(p, "sni")) {
        t["server_name"] = json!(sni);
    }
    if b(p, "skip-cert-verify") {
        t["insecure"] = json!(true);
    }
    if let Some(Value::Array(alpn)) = p.get("alpn") {
        t["alpn"] = json!(alpn);
    }
    if let Some(fp) = s(p, "client-fingerprint") {
        t["fingerprint"] = json!(fp);
    }
    if let Some(r) = p.get("reality-opts") {
        t["reality"] = json!({"public_key": s(r, "public-key").unwrap_or_default(), "short_id": s(r, "short-id").unwrap_or_default()});
        if t.get("fingerprint").is_none() {
            t["fingerprint"] = json!("chrome");
        }
    }
    Some(t)
}

fn first_header(h: Option<&Value>, name: &str) -> Option<String> {
    let h = h?.as_object()?;
    let v = h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name))?.1;
    match v {
        Value::String(x) => Some(x.clone()),
        Value::Array(a) => a.first().and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

fn clash_transport(p: &Value) -> Result<Option<Value>> {
    let network = s(p, "network").unwrap_or_else(|| "tcp".into());
    Ok(match network.as_str() {
        "tcp" => match p.get("http-opts") {
            Some(o) => {
                let path = o
                    .get("path")
                    .and_then(|x| x.as_array())
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
                    .unwrap_or("/");
                let hosts: Vec<String> = o
                    .get("headers")
                    .and_then(|h| h.get("Host"))
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                Some(json!({"type": "tcp", "http_obfs": {"path": path, "host": hosts}}))
            }
            None => None,
        },
        "ws" => {
            let o = p.get("ws-opts").cloned().unwrap_or(json!({}));
            let mut t = json!({"type": "ws", "path": s(&o, "path").unwrap_or_else(|| "/".into())});
            if let Some(h) = first_header(o.get("headers"), "host") {
                t["host"] = json!(h);
            }
            if let Some(n) = o.get("max-early-data").and_then(Value::as_u64) {
                t["max_early_data"] = json!(n);
                t["early_data_header_name"] = json!(s(&o, "early-data-header-name")
                    .unwrap_or_else(|| "Sec-WebSocket-Protocol".into()));
            }
            Some(t)
        }
        "grpc" => {
            let o = p.get("grpc-opts").cloned().unwrap_or(json!({}));
            Some(
                json!({"type": "grpc", "service_name": s(&o, "grpc-service-name").unwrap_or_default()}),
            )
        }
        "h2" | "http" => {
            let o = p.get("h2-opts").cloned().unwrap_or(json!({}));
            let hosts: Vec<Value> = o
                .get("host")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            Some(
                json!({"type": "http", "host": hosts, "path": s(&o, "path").unwrap_or_else(|| "/".into())}),
            )
        }
        other => bail!("transport `{other}` is not implemented yet"),
    })
}

/// One Clash proxy into our outbound JSON.
fn clash_proxy(p: &Value) -> Result<Value> {
    let kind = s(p, "type").ok_or_else(|| anyhow!("proxy without type"))?;
    let name = s(p, "name").unwrap_or_else(|| "proxy".into());
    let server = s(p, "server").ok_or_else(|| anyhow!("`{name}` has no server"))?;
    let port: u16 = s(p, "port")
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| anyhow!("`{name}` has no valid port"))?;
    let mut o = json!({"tag": name, "server": server, "port": port});
    match kind.as_str() {
        "vless" => {
            o["type"] = json!("vless");
            o["uuid"] = json!(s(p, "uuid").unwrap_or_default());
            if let Some(flow) = s(p, "flow") {
                o["flow"] = json!(flow);
            }
            if s(p, "packet-encoding").as_deref() == Some("xudp") || b(p, "xudp") {
                o["packet_encoding"] = json!("xudp");
            }
            if s(p, "encryption").is_some_and(|e| e != "none") {
                bail!("`{name}`: VLESS encryption is not implemented yet");
            }
        }
        "vmess" => {
            o["type"] = json!("vmess");
            o["uuid"] = json!(s(p, "uuid").unwrap_or_default());
            o["alter_id"] = json!(s(p, "alterId")
                .and_then(|a| a.parse::<u32>().ok())
                .unwrap_or(0));
            o["security"] = json!(s(p, "cipher").unwrap_or_else(|| "auto".into()));
        }
        "trojan" => {
            o["type"] = json!("trojan");
            o["password"] = json!(s(p, "password").unwrap_or_default());
        }
        "ss" => {
            if p.get("plugin").is_some() {
                bail!("`{name}`: Shadowsocks plugins are not supported");
            }
            o["type"] = json!("shadowsocks");
            o["method"] = json!(s(p, "cipher").unwrap_or_default());
            o["password"] = json!(s(p, "password").unwrap_or_default());
            return Ok(o);
        }
        "socks5" | "http" => {
            o["type"] = json!(if kind == "socks5" { "socks" } else { "http" });
            if let Some(u) = s(p, "username") {
                o["username"] = json!(u);
                o["password"] = json!(s(p, "password").unwrap_or_default());
            }
            if let Some(t) = clash_tls(p, false) {
                o["tls"] = t;
            }
            return Ok(o);
        }
        "hysteria2" | "hy2" => {
            o["type"] = json!("hysteria2");
            o["password"] = json!(s(p, "password").unwrap_or_default());
            if let Some(ports) = s(p, "ports") {
                o["server_ports"] = json!(ports.split(',').map(str::trim).collect::<Vec<_>>());
            }
            if let Some(obfs_pw) = s(p, "obfs-password") {
                o["obfs_password"] = json!(obfs_pw);
            }
            o["tls"] = clash_tls(p, true).expect("tls is on");
            return Ok(o);
        }
        "tuic" => {
            o["type"] = json!("tuic");
            o["uuid"] = json!(s(p, "uuid").unwrap_or_default());
            o["password"] = json!(s(p, "password").unwrap_or_default());
            if let Some(cc) = s(p, "congestion-controller") {
                o["congestion_control"] = json!(cc);
            }
            if let Some(m) = s(p, "udp-relay-mode") {
                o["udp_relay_mode"] = json!(m);
            }
            o["tls"] = clash_tls(p, true).expect("tls is on");
            return Ok(o);
        }
        "wireguard" => {
            o["type"] = json!("wireguard");
            o["private_key"] = json!(s(p, "private-key").unwrap_or_default());
            o["peer_public_key"] = json!(s(p, "public-key").unwrap_or_default());
            if let Some(psk) = s(p, "pre-shared-key") {
                o["pre_shared_key"] = json!(psk);
            }
            let addrs: Vec<String> = [s(p, "ip"), s(p, "ipv6")]
                .into_iter()
                .flatten()
                .map(|a| {
                    if a.contains('/') {
                        a
                    } else if a.contains(':') {
                        format!("{a}/128")
                    } else {
                        format!("{a}/32")
                    }
                })
                .collect();
            o["local_address"] = json!(addrs);
            if let Some(m) = p.get("mtu") {
                o["mtu"] = m.clone();
            }
            if let Some(Value::Array(r)) = p.get("reserved") {
                o["reserved"] = json!(r);
            }
            return Ok(o);
        }
        other => bail!("`{name}`: proxy type `{other}` is not supported"),
    }
    if let Some(t) = clash_tls(p, kind == "trojan") {
        o["tls"] = t;
    }
    if let Some(t) = clash_transport(p).map_err(|e| anyhow!("`{name}`: {e}"))? {
        o["transport"] = t;
    }
    Ok(o)
}

fn parse_clash(text: &str) -> Result<Parsed> {
    let doc: Value = serde_yaml::from_str(text).map_err(|e| anyhow!("invalid Clash YAML: {e}"))?;
    let proxies = doc
        .get("proxies")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Clash config without `proxies`"))?;
    let mut parsed = Parsed::default();
    for p in proxies {
        let converted = clash_proxy(p)
            .and_then(|v| serde_json::from_value::<OutboundConfig>(v).map_err(|e| anyhow!("{e}")));
        match converted {
            Ok(o) => parsed.outbounds.push(o),
            Err(e) => parsed.warnings.push(format!("{e:#}")),
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    const LINKS: &str = "vless://id@1.2.3.4:443?security=tls&sni=a.example#A\ntrojan://pw@b.example:443#B\nbogus://x\n\nss://YWVzLTI1Ni1nY206cHc@5.6.7.8:8388#A";

    #[test]
    fn plain_and_base64_link_lists() {
        let p = parse(LINKS).unwrap();
        let tags: Vec<&str> = p.outbounds.iter().map(|o| o.tag.as_str()).collect();
        assert_eq!(tags, ["A", "B", "A (2)"]);
        assert_eq!(p.warnings.len(), 1);
        let encoded = base64::engine::general_purpose::STANDARD.encode(LINKS);
        assert_eq!(parse(&encoded).unwrap().outbounds.len(), 3);
        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(LINKS);
        assert_eq!(parse(&url_safe).unwrap().outbounds.len(), 3);
        assert!(parse("").is_err());
        assert!(parse("not a subscription").is_err());
    }

    #[test]
    fn clash_yaml() {
        let yaml = r#"
port: 7890
proxies:
  - name: "vless-reality"
    type: vless
    server: 203.0.113.10
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: cBFfpfma55oLsRr7ujFs6FjZ1oAjdXdy4m9whtFWOjw
      short-id: 0123abcd
  - name: vmess-ws
    type: vmess
    server: vm.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /vm
      headers:
        Host: vm.example.com
  - name: ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: AQEBAQEBAQEBAQEBAQEBAQ==
  - name: hy2
    type: hysteria2
    server: hy.example.com
    port: 443
    ports: 20000-30000
    password: pw
    obfs: salamander
    obfs-password: x
  - name: plugin
    type: ss
    server: 1.2.3.4
    port: 1
    cipher: aes-128-gcm
    password: p
    plugin: obfs
proxy-groups: []
"#;
        let p = parse(yaml).unwrap();
        let tags: Vec<&str> = p.outbounds.iter().map(|o| o.tag.as_str()).collect();
        assert_eq!(tags, ["vless-reality", "vmess-ws", "ss", "hy2"]);
        assert_eq!(p.warnings.len(), 1, "{:?}", p.warnings);
        let OutboundKind::Vless(v) = &p.outbounds[0].kind else {
            panic!()
        };
        let tls = v.tls.as_ref().unwrap();
        assert_eq!(tls.reality.as_ref().unwrap().short_id, "0123abcd");
        assert_eq!(v.flow.as_deref(), Some("xtls-rprx-vision"));
        let OutboundKind::Vmess(m) = &p.outbounds[1].kind else {
            panic!()
        };
        assert!(
            matches!(&m.transport, Some(crate::model::TransportConfig::Ws(w)) if w.host.as_deref() == Some("vm.example.com"))
        );
    }

    #[test]
    fn sing_box_json_keeps_only_proxies() {
        let json = r#"{"outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "vless", "tag": "v", "server": "a.example", "server_port": 443, "uuid": "x",
             "tls": {"enabled": true, "server_name": "a.example", "utls": {"enabled": true, "fingerprint": "firefox"}}},
            {"type": "selector", "tag": "s", "outbounds": ["v"]}
        ]}"#;
        let p = parse(json).unwrap();
        assert_eq!(p.outbounds.len(), 1);
        let OutboundKind::Vless(v) = &p.outbounds[0].kind else {
            panic!()
        };
        assert_eq!(
            v.tls.as_ref().unwrap().fingerprint.as_deref(),
            Some("firefox")
        );
    }
}
