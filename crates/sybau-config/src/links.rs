//! Share links: `vless://`, `vmess://`, `trojan://`, `ss://`,
//! `hysteria2://` / `hy2://`, `tuic://`, `wireguard://` / `wg://`.
//!
//! Formats follow what Xray clients (v2rayN, v2rayNG), sing-box clients
//! and the protocol authors publish.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;

use crate::model::*;

/// Decodes `%XX` escapes (and `+` as a space when `plus` is set).
pub fn percent_decode(text: &str, plus: bool) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            b'+' if plus => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Base64 in any of the alphabets and paddings clients use.
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let t: String = text.trim().chars().filter(|c| !c.is_whitespace()).collect();
    let t = t.trim_end_matches('=');
    for engine in [
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(v) = engine.decode(t) {
            return Some(v);
        }
    }
    None
}

/// Pieces of `scheme://userinfo@host:port/path?query#fragment`.
struct Parts {
    userinfo: Option<String>,
    host: String,
    /// The port as written; may be a list or range for Hysteria2.
    port: String,
    query: HashMap<String, String>,
    name: Option<String>,
}

fn split(link: &str, scheme_len: usize) -> Result<Parts> {
    let rest = &link[scheme_len..];
    let (rest, fragment) = match rest.split_once('#') {
        Some((r, f)) => (r, Some(percent_decode(f, false))),
        None => (rest, None),
    };
    let (rest, query_text) = match rest.split_once('?') {
        Some((r, q)) => (r, q),
        None => (rest, ""),
    };
    // A path after the authority (`hy2://pw@h:443/?...`) carries nothing.
    let authority = rest.split('/').next().unwrap_or(rest);
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(percent_decode(u, false)), h),
        None => (None, authority),
    };
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, p) = v6.split_once(']').ok_or_else(|| anyhow!("bad IPv6 host"))?;
        (h.to_string(), p.trim_start_matches(':').to_string())
    } else {
        match hostport.split_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => (hostport.to_string(), String::new()),
        }
    };
    if host.is_empty() {
        bail!("link has no server address");
    }
    let mut query = HashMap::new();
    for pair in query_text.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(percent_decode(k, true), percent_decode(v, true));
    }
    Ok(Parts {
        userinfo,
        host,
        port,
        query,
        name: fragment.filter(|n| !n.trim().is_empty()),
    })
}

impl Parts {
    fn port(&self, default: Option<u16>) -> Result<u16> {
        if self.port.is_empty() {
            return default.ok_or_else(|| anyhow!("link has no port"));
        }
        self.port
            .parse()
            .map_err(|_| anyhow!("bad port `{}`", self.port))
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.query
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    fn flag(&self, keys: &[&str]) -> bool {
        keys.iter()
            .any(|k| matches!(self.get(k), Some("1" | "true" | "True" | "TRUE")))
    }

    fn list(&self, key: &str) -> Vec<String> {
        self.get(key)
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// TLS settings from the common `security`, `sni`, `fp`, `alpn`,
/// `allowInsecure`, `pbk`, `sid` parameters.
fn tls_from(p: &Parts, security: &str) -> Result<Option<TlsConfig>> {
    let mut tls = TlsConfig {
        server_name: p.get("sni").or(p.get("peer")).map(str::to_string),
        alpn: p.list("alpn"),
        ..Default::default()
    };
    tls.insecure = p.flag(&["allowInsecure", "allow_insecure", "insecure"]);
    tls.fingerprint = p.get("fp").filter(|f| *f != "none").map(str::to_string);
    // `pcs` is Xray's pinnedPeerCertSha256, `vcn` its verifyPeerCertByName.
    tls.pinned_cert_sha256 = p.list("pcs");
    tls.verify_names = p.list("vcn");
    match security {
        "" | "none" => Ok(None),
        "tls" | "xtls" => Ok(Some(tls)),
        "reality" => {
            let public_key = p
                .get("pbk")
                .ok_or_else(|| anyhow!("REALITY link without `pbk`"))?;
            tls.reality = Some(RealityConfig {
                public_key: public_key.to_string(),
                short_id: p.get("sid").unwrap_or("").to_string(),
            });
            if tls.fingerprint.is_none() {
                tls.fingerprint = Some("chrome".into());
            }
            Ok(Some(tls))
        }
        other => bail!("unsupported security `{other}`"),
    }
}

/// `/ws?ed=2048`: Xray early data written into the WebSocket path.
fn ws_path(path: &str) -> (String, usize) {
    if let Some((base, query)) = path.split_once('?') {
        for pair in query.split('&') {
            if let Some(v) = pair.strip_prefix("ed=") {
                if let Ok(n) = v.parse::<usize>() {
                    let rest: Vec<&str> =
                        query.split('&').filter(|p| !p.starts_with("ed=")).collect();
                    let path = if rest.is_empty() {
                        base.to_string()
                    } else {
                        format!("{base}?{}", rest.join("&"))
                    };
                    return (path, n);
                }
            }
        }
    }
    (path.to_string(), 0)
}

/// Transport from `type`/`net` and its parameters.
fn transport_from(
    network: &str,
    host: Option<&str>,
    path: Option<&str>,
    header_type: Option<&str>,
    service: Option<&str>,
    mode: Option<&str>,
    authority: Option<&str>,
) -> Result<Option<TransportConfig>> {
    let host_s = host.map(str::to_string).filter(|h| !h.is_empty());
    let path_s = path
        .map(str::to_string)
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/".to_string());
    Ok(match network {
        "" | "tcp" | "raw" => match header_type {
            Some("http") => Some(TransportConfig::Tcp(TcpTransport {
                http_obfs: Some(HttpObfs {
                    host: host_s
                        .map(|h| h.split(',').map(|x| x.trim().to_string()).collect())
                        .unwrap_or_default(),
                    path: path_s.split(',').next().unwrap_or("/").to_string(),
                    method: None,
                    headers: Default::default(),
                }),
            })),
            _ => None,
        },
        "ws" | "websocket" => {
            let (path, early) = ws_path(&path_s);
            Some(TransportConfig::Ws(WsTransport {
                path,
                host: host_s,
                headers: Default::default(),
                max_early_data: early,
                early_data_header_name: (early > 0).then(|| "Sec-WebSocket-Protocol".to_string()),
            }))
        }
        "httpupgrade" => Some(TransportConfig::HttpUpgrade(HttpUpgradeTransport {
            path: path_s,
            host: host_s,
            headers: Default::default(),
        })),
        "grpc" | "gun" => Some(TransportConfig::Grpc(GrpcTransport {
            service_name: service.or(path).unwrap_or("").to_string(),
            authority: authority.map(str::to_string).filter(|a| !a.is_empty()),
            multi_mode: matches!(mode.or(header_type), Some("multi")),
            user_agent: None,
        })),
        "h2" | "http" => Some(TransportConfig::Http(Http2Transport {
            host: host_s
                .map(|h| h.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_default(),
            path: path_s,
            method: None,
            headers: Default::default(),
        })),
        "xhttp" | "splithttp" | "kcp" | "mkcp" | "quic" => {
            bail!("transport `{network}` is not implemented yet")
        }
        other => bail!("unknown transport `{other}`"),
    })
}

fn outbound(tag: Option<String>, kind: OutboundKind) -> OutboundConfig {
    OutboundConfig {
        tag: tag.unwrap_or_else(|| "proxy".into()),
        detour: None,
        kind,
    }
}

fn parse_vless(link: &str) -> Result<OutboundConfig> {
    let p = split(link, "vless://".len())?;
    let uuid = p
        .userinfo
        .clone()
        .ok_or_else(|| anyhow!("vless link without uuid"))?;
    if let Some(enc) = p.get("encryption").filter(|e| *e != "none") {
        bail!("VLESS encryption `{enc}` is not implemented yet");
    }
    let network = p.get("type").unwrap_or("tcp");
    let transport = transport_from(
        network,
        p.get("host"),
        p.get("path"),
        p.get("headerType"),
        p.get("serviceName"),
        p.get("mode"),
        p.get("authority"),
    )?;
    Ok(outbound(
        p.name.clone(),
        OutboundKind::Vless(VlessOutbound {
            server: p.host.clone(),
            port: p.port(Some(443))?,
            uuid,
            flow: p.get("flow").map(str::to_string),
            packet_encoding: p
                .get("packetEncoding")
                .filter(|e| *e != "none")
                .map(str::to_string),
            tls: tls_from(&p, p.get("security").unwrap_or("none"))?,
            transport,
        }),
    ))
}

fn parse_trojan(link: &str) -> Result<OutboundConfig> {
    let p = split(link, "trojan://".len())?;
    let password = p
        .userinfo
        .clone()
        .ok_or_else(|| anyhow!("trojan link without password"))?;
    let network = p.get("type").unwrap_or("tcp");
    let transport = transport_from(
        network,
        p.get("host"),
        p.get("path"),
        p.get("headerType"),
        p.get("serviceName"),
        p.get("mode"),
        p.get("authority"),
    )?;
    Ok(outbound(
        p.name.clone(),
        OutboundKind::Trojan(TrojanOutbound {
            server: p.host.clone(),
            port: p.port(Some(443))?,
            password,
            // Trojan uses TLS unless told otherwise.
            tls: tls_from(&p, p.get("security").unwrap_or("tls"))?,
            transport,
        }),
    ))
}

fn json_str(v: &serde_json::Value, key: &str) -> Option<String> {
    match v.get(key)? {
        serde_json::Value::String(s) => Some(s.clone()).filter(|s| !s.is_empty()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn parse_vmess(link: &str) -> Result<OutboundConfig> {
    let body = link["vmess://".len()..].split('#').next().unwrap_or("");
    let raw = decode_base64(body).ok_or_else(|| anyhow!("vmess link is not base64"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).context("vmess link is not v2rayN JSON")?;
    let get = |k: &str| json_str(&v, k);
    let alter_id: u32 = get("aid").and_then(|a| a.parse().ok()).unwrap_or(0);
    let network = get("net").unwrap_or_else(|| "tcp".into());
    let header = get("type");
    let transport = transport_from(
        &network,
        get("host").as_deref(),
        get("path").as_deref(),
        header.as_deref(),
        get("path").as_deref(),
        header.as_deref(),
        get("authority").as_deref(),
    )?;
    let security = get("tls").unwrap_or_default();
    let tls = match security.as_str() {
        "" | "none" => None,
        "tls" | "reality" => {
            let mut q = HashMap::new();
            for (from, to) in [
                ("sni", "sni"),
                ("alpn", "alpn"),
                ("fp", "fp"),
                ("allowInsecure", "allowInsecure"),
                ("insecure", "insecure"),
                ("pbk", "pbk"),
                ("sid", "sid"),
            ] {
                if let Some(val) = get(from) {
                    q.insert(to.to_string(), val);
                }
            }
            let p = Parts {
                userinfo: None,
                host: String::new(),
                port: String::new(),
                query: q,
                name: None,
            };
            tls_from(&p, &security)?
        }
        other => bail!("unsupported vmess tls `{other}`"),
    };
    let port: u16 = get("port")
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| anyhow!("vmess link without a valid port"))?;
    Ok(outbound(
        get("ps"),
        OutboundKind::Vmess(VmessOutbound {
            server: get("add").ok_or_else(|| anyhow!("vmess link without address"))?,
            port,
            uuid: get("id").ok_or_else(|| anyhow!("vmess link without id"))?,
            security: get("scy").unwrap_or_else(|| "auto".into()),
            alter_id,
            global_padding: true,
            tls,
            transport,
        }),
    ))
}

fn parse_ss(link: &str) -> Result<OutboundConfig> {
    let body = &link["ss://".len()..];
    let (body, name) = match body.split_once('#') {
        Some((b, n)) => (b, Some(percent_decode(n, false)).filter(|n| !n.is_empty())),
        None => (body, None),
    };
    let (main, query) = body.split_once('?').unwrap_or((body, ""));
    if query.split('&').any(|kv| kv.starts_with("plugin=")) {
        bail!("Shadowsocks plugins are not supported");
    }
    let main = main.trim_end_matches('/');
    let (userinfo, hostport) = match main.rsplit_once('@') {
        // SIP002: userinfo is base64 or percent-encoded `method:password`.
        Some((u, h)) => {
            let decoded = decode_base64(u)
                .and_then(|b| String::from_utf8(b).ok())
                .filter(|s| s.contains(':'))
                .unwrap_or_else(|| percent_decode(u, false));
            (decoded, h.to_string())
        }
        // Legacy: base64 of `method:password@host:port`.
        None => {
            let decoded = String::from_utf8(
                decode_base64(main).ok_or_else(|| anyhow!("ss link is not base64"))?,
            )?;
            let (u, h) = decoded
                .rsplit_once('@')
                .ok_or_else(|| anyhow!("ss link without server"))?;
            (u.to_string(), h.to_string())
        }
    };
    let (method, password) = userinfo
        .split_once(':')
        .ok_or_else(|| anyhow!("ss link without method"))?;
    let p = split(&format!("x://{hostport}"), 4)?;
    Ok(outbound(
        name,
        OutboundKind::Shadowsocks(ShadowsocksOutbound {
            server: p.host.clone(),
            port: p.port(None)?,
            method: method.to_ascii_lowercase(),
            password: password.to_string(),
        }),
    ))
}

fn parse_hysteria2(link: &str, scheme_len: usize) -> Result<OutboundConfig> {
    let p = split(link, scheme_len)?;
    // `host:443,20000-30000` or `mport=` carry port hopping ranges.
    let mut ports = p.port.split(',').filter(|s| !s.is_empty());
    let main = ports.next().unwrap_or("443");
    let mut hopping: Vec<String> = Vec::new();
    let port: u16 = if main.contains('-') {
        // A range in the port position: connect to its first port.
        hopping.push(main.to_string());
        main.split('-')
            .next()
            .unwrap_or("")
            .parse()
            .map_err(|_| anyhow!("bad port `{main}`"))?
    } else {
        main.parse().map_err(|_| anyhow!("bad port `{main}`"))?
    };
    hopping.extend(ports.map(str::to_string));
    hopping.extend(p.list("mport"));
    let mut tls = tls_from(&p, "tls")?.expect("tls");
    if let Some(pin) = p.get("pinSHA256") {
        tls.pinned_cert_sha256 = vec![pin.replace(':', "")];
    }
    if p.get("obfs").is_some_and(|o| o != "salamander") {
        bail!(
            "unsupported hysteria2 obfs `{}`",
            p.get("obfs").unwrap_or("")
        );
    }
    Ok(outbound(
        p.name.clone(),
        OutboundKind::Hysteria2(Hysteria2Outbound {
            server: p.host.clone(),
            port,
            password: p.userinfo.clone().unwrap_or_default(),
            server_ports: hopping,
            hop_interval: None,
            up_mbps: None,
            down_mbps: None,
            obfs_password: p.get("obfs-password").map(str::to_string),
            tls: Some(tls),
        }),
    ))
}

fn parse_tuic(link: &str) -> Result<OutboundConfig> {
    let p = split(link, "tuic://".len())?;
    let user = p
        .userinfo
        .clone()
        .ok_or_else(|| anyhow!("tuic link without uuid"))?;
    let (uuid, password) = user
        .split_once(':')
        .ok_or_else(|| anyhow!("tuic link needs uuid:password"))?;
    let mut tls = tls_from(&p, "tls")?.expect("tls");
    if tls.alpn.is_empty() {
        tls.alpn = vec!["h3".into()];
    }
    Ok(outbound(
        p.name.clone(),
        OutboundKind::Tuic(TuicOutbound {
            server: p.host.clone(),
            port: p.port(None)?,
            uuid: uuid.to_string(),
            password: password.to_string(),
            congestion_control: p.get("congestion_control").map(str::to_string),
            udp_relay_mode: p.get("udp_relay_mode").map(str::to_string),
            zero_rtt_handshake: p.flag(&["zero_rtt_handshake", "reduce_rtt"]),
            tls: Some(tls),
        }),
    ))
}

fn parse_wireguard(link: &str, scheme_len: usize) -> Result<OutboundConfig> {
    let p = split(link, scheme_len)?;
    let reserved = match p.get("reserved") {
        Some(r) => r
            .split(',')
            .map(|x| {
                x.trim()
                    .parse::<u8>()
                    .map_err(|_| anyhow!("bad reserved `{r}`"))
            })
            .collect::<Result<_>>()?,
        None => Vec::new(),
    };
    Ok(outbound(
        p.name.clone(),
        OutboundKind::Wireguard(WireguardOutbound {
            server: p.host.clone(),
            port: p.port(Some(51820))?,
            private_key: p
                .userinfo
                .clone()
                .ok_or_else(|| anyhow!("wireguard link without private key"))?,
            peer_public_key: p
                .get("publickey")
                .or(p.get("public_key"))
                .ok_or_else(|| anyhow!("wireguard link without publickey"))?
                .to_string(),
            pre_shared_key: p
                .get("presharedkey")
                .or(p.get("pre_shared_key"))
                .map(str::to_string),
            local_address: {
                let mut a = p.list("address");
                a.extend(p.list("ip"));
                a
            },
            mtu: p.get("mtu").and_then(|m| m.parse().ok()),
            reserved,
        }),
    ))
}

/// Parses one share link into an outbound named after the link's title.
pub fn parse_link(link: &str) -> Result<OutboundConfig> {
    let link = link.trim();
    let lower = link.get(..16).unwrap_or(link).to_ascii_lowercase();
    let result = if lower.starts_with("vless://") {
        parse_vless(link)
    } else if lower.starts_with("vmess://") {
        parse_vmess(link)
    } else if lower.starts_with("trojan://") {
        parse_trojan(link)
    } else if lower.starts_with("ss://") {
        parse_ss(link)
    } else if lower.starts_with("hysteria2://") {
        parse_hysteria2(link, "hysteria2://".len())
    } else if lower.starts_with("hy2://") {
        parse_hysteria2(link, "hy2://".len())
    } else if lower.starts_with("tuic://") {
        parse_tuic(link)
    } else if lower.starts_with("wireguard://") {
        parse_wireguard(link, "wireguard://".len())
    } else if lower.starts_with("wg://") {
        parse_wireguard(link, "wg://".len())
    } else {
        bail!("unknown link type")
    };
    let scheme = link.split("://").next().unwrap_or("");
    result.with_context(|| format!("invalid {scheme}:// link"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls(o: &OutboundConfig) -> TlsConfig {
        match &o.kind {
            OutboundKind::Vless(v) => v.tls.clone().unwrap(),
            OutboundKind::Vmess(v) => v.tls.clone().unwrap(),
            OutboundKind::Trojan(t) => t.tls.clone().unwrap(),
            OutboundKind::Hysteria2(h) => h.tls.clone().unwrap(),
            OutboundKind::Tuic(t) => t.tls.clone().unwrap(),
            other => panic!("no tls on {other:?}"),
        }
    }

    #[test]
    fn vless_reality_vision() {
        let o = parse_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=firefox&pbk=cBFfpfma55oLsRr7ujFs6FjZ1oAjdXdy4m9whtFWOjw&sid=0123abcd&spx=%2F&type=tcp&headerType=none#%F0%9F%87%B3%F0%9F%87%B1%20NL").unwrap();
        assert_eq!(o.tag, "🇳🇱 NL");
        let OutboundKind::Vless(v) = &o.kind else {
            panic!()
        };
        assert_eq!(
            (v.server.as_str(), v.port, v.flow.as_deref()),
            ("203.0.113.10", 443, Some("xtls-rprx-vision"))
        );
        assert!(v.transport.is_none());
        let t = tls(&o);
        assert_eq!(t.server_name.as_deref(), Some("www.example.com"));
        assert_eq!(t.fingerprint.as_deref(), Some("firefox"));
        let r = t.reality.unwrap();
        assert_eq!(
            (r.public_key.as_str(), r.short_id.as_str()),
            ("cBFfpfma55oLsRr7ujFs6FjZ1oAjdXdy4m9whtFWOjw", "0123abcd")
        );
    }

    #[test]
    fn vless_ws_early_data_grpc_and_ipv6() {
        let o = parse_link("vless://id@[2001:db8::1]:8443?security=tls&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1&type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D2048&allowInsecure=1#ws").unwrap();
        let OutboundKind::Vless(v) = &o.kind else {
            panic!()
        };
        assert_eq!((v.server.as_str(), v.port), ("2001:db8::1", 8443));
        let Some(TransportConfig::Ws(ws)) = &v.transport else {
            panic!()
        };
        assert_eq!((ws.path.as_str(), ws.max_early_data), ("/ws", 2048));
        assert_eq!(
            ws.early_data_header_name.as_deref(),
            Some("Sec-WebSocket-Protocol")
        );
        assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
        let t = tls(&o);
        assert!(t.insecure);
        assert_eq!(t.alpn, ["h2", "http/1.1"]);

        let o = parse_link("vless://id@h:443?security=tls&type=grpc&serviceName=Svc&mode=multi")
            .unwrap();
        let OutboundKind::Vless(v) = &o.kind else {
            panic!()
        };
        let Some(TransportConfig::Grpc(g)) = &v.transport else {
            panic!()
        };
        assert_eq!((g.service_name.as_str(), g.multi_mode), ("Svc", true));
        assert!(parse_link("vless://id@h:443?type=xhttp").is_err());
        assert!(
            parse_link("vless://id@h:443?encryption=mlkem768x25519plus.native.0rtt.abc").is_err()
        );
    }

    #[test]
    fn vmess_v2rayn_json() {
        let json = r#"{"v":"2","ps":"VM WS","add":"vm.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","type":"none","host":"vm.example.com","path":"/vm","tls":"tls","sni":"vm.example.com","alpn":"http/1.1","fp":"chrome"}"#;
        let link = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json)
        );
        let o = parse_link(&link).unwrap();
        assert_eq!(o.tag, "VM WS");
        let OutboundKind::Vmess(v) = &o.kind else {
            panic!()
        };
        assert_eq!(
            (v.server.as_str(), v.port, v.alter_id, v.security.as_str()),
            ("vm.example.com", 443, 0, "auto")
        );
        assert!(matches!(&v.transport, Some(TransportConfig::Ws(w)) if w.path == "/vm"));
        assert_eq!(tls(&o).fingerprint.as_deref(), Some("chrome"));
        // Numbers instead of strings, URL-safe base64 without padding.
        let json = r#"{"add":"1.2.3.4","port":10086,"id":"x","aid":0,"net":"tcp","tls":""}"#;
        let link = format!(
            "vmess://{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        );
        let o = parse_link(&link).unwrap();
        let OutboundKind::Vmess(v) = &o.kind else {
            panic!()
        };
        assert_eq!(
            (v.port, v.tls.is_none(), o.tag.as_str()),
            (10086, true, "proxy")
        );
    }

    #[test]
    fn trojan_and_shadowsocks() {
        let o = parse_link(
            "trojan://p%40ss@tj.example.com:443?sni=tj.example.com&type=grpc&serviceName=Tj#TJ",
        )
        .unwrap();
        let OutboundKind::Trojan(t) = &o.kind else {
            panic!()
        };
        assert_eq!(t.password, "p@ss");
        assert!(t.tls.is_some(), "TLS by default");

        let sip002 = format!(
            "ss://{}@ss.example.com:8388#SS",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:secret")
        );
        let OutboundKind::Shadowsocks(s) = parse_link(&sip002).unwrap().kind else {
            panic!()
        };
        assert_eq!(
            (s.method.as_str(), s.password.as_str(), s.port),
            ("aes-256-gcm", "secret", 8388)
        );

        let ss2022 = "ss://2022-blake3-aes-128-gcm:AQEBAQEBAQEBAQEBAQEBAQ%3D%3D@1.2.3.4:443#2022";
        let OutboundKind::Shadowsocks(s) = parse_link(ss2022).unwrap().kind else {
            panic!()
        };
        assert_eq!(
            (s.method.as_str(), s.password.as_str()),
            ("2022-blake3-aes-128-gcm", "AQEBAQEBAQEBAQEBAQEBAQ==")
        );

        let legacy = format!(
            "ss://{}#old",
            base64::engine::general_purpose::STANDARD
                .encode("chacha20-ietf-poly1305:pw@5.6.7.8:1234")
        );
        let OutboundKind::Shadowsocks(s) = parse_link(&legacy).unwrap().kind else {
            panic!()
        };
        assert_eq!((s.server.as_str(), s.port), ("5.6.7.8", 1234));
        assert!(parse_link("ss://YWVzLTI1Ni1nY206cGFzcw@h:1?plugin=obfs-local").is_err());
    }

    #[test]
    fn hysteria2_tuic_wireguard() {
        let o = parse_link("hy2://letmein@hy.example.com:443,20000-30000/?sni=hy.example.com&obfs=salamander&obfs-password=gawr&insecure=1#HY").unwrap();
        let OutboundKind::Hysteria2(h) = &o.kind else {
            panic!()
        };
        assert_eq!(
            (h.port, h.server_ports.as_slice()),
            (443, &["20000-30000".to_string()][..])
        );
        assert_eq!(h.obfs_password.as_deref(), Some("gawr"));
        assert!(tls(&o).insecure);
        let o = parse_link("hysteria2://pw@h:30000-31000?mport=40000-41000").unwrap();
        let OutboundKind::Hysteria2(h) = &o.kind else {
            panic!()
        };
        assert_eq!((h.port, h.server_ports.len()), (30000, 2));

        let o = parse_link("tuic://uuid:pass@tuic.example.com:8443?congestion_control=bbr&udp_relay_mode=native&sni=tuic.example.com#TU").unwrap();
        let OutboundKind::Tuic(t) = &o.kind else {
            panic!()
        };
        assert_eq!(
            (
                t.uuid.as_str(),
                t.password.as_str(),
                t.congestion_control.as_deref()
            ),
            ("uuid", "pass", Some("bbr"))
        );
        assert_eq!(tls(&o).alpn, ["h3"]);

        let o = parse_link("wireguard://cGFzcw%3D%3D@162.159.192.1:2408?publickey=bmo%3D&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A%3A2%2F128&reserved=1%2C2%2C3&mtu=1280#warp").unwrap();
        let OutboundKind::Wireguard(w) = &o.kind else {
            panic!()
        };
        assert_eq!(
            (w.private_key.as_str(), w.peer_public_key.as_str()),
            ("cGFzcw==", "bmo=")
        );
        assert_eq!(w.local_address, ["172.16.0.2/32", "2606:4700:110::2/128"]);
        assert_eq!(
            (w.reserved.as_slice(), w.mtu),
            (&[1u8, 2, 3][..], Some(1280))
        );
    }

    #[test]
    fn junk_is_rejected() {
        for bad in [
            "",
            "http://x",
            "vless://",
            "vless://id@:443",
            "vmess://!!!",
            "ss://bm9wZQ",
            "trojan://p@h:notaport",
        ] {
            assert!(parse_link(bad).is_err(), "{bad}");
        }
        assert_eq!(percent_decode("a%20b%zz+c", true), "a b%zz c");
    }
}
