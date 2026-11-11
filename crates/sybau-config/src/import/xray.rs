//! Xray-core configurations.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};

use super::{take, Imported, Notes};
use crate::Config;

fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// First element of a list setting (`vnext[0]`, `servers[0]`).
fn first(v: &Value, key: &str) -> Option<Value> {
    v.get(key)?.as_array()?.first().cloned()
}

fn port_of(v: &Value) -> Option<u64> {
    match v.get("port")? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn tls(stream: &Value, ctx: &str, notes: &mut Notes) -> Result<Option<Value>> {
    let security = stream
        .get("security")
        .and_then(Value::as_str)
        .unwrap_or("none");
    match security {
        "none" | "" => Ok(None),
        "tls" => {
            let t = stream.get("tlsSettings").cloned().unwrap_or(json!({}));
            let mut out = json!({"enabled": true});
            if let Some(s) = t
                .get("serverName")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                out["server_name"] = json!(s);
            }
            let alpn = str_list(t.get("alpn"));
            if !alpn.is_empty() {
                out["alpn"] = json!(alpn);
            }
            if t.get("allowInsecure").and_then(Value::as_bool) == Some(true) {
                // Removed from Xray in favour of pinning; older configs still carry it.
                out["insecure"] = json!(true);
                notes.add(format!(
                    "{ctx}: allowInsecure disables certificate checks; prefer pinnedPeerCertSha256"
                ));
            }
            let leaf_pins = str_list(t.get("pinnedPeerCertSha256"));
            if !leaf_pins.is_empty() {
                out["pinned_cert_sha256"] = json!(leaf_pins);
            }
            let names = str_list(t.get("verifyPeerCertByName"));
            if !names.is_empty() {
                out["verify_names"] = json!(names);
            }
            if let Some(fp) = t
                .get("fingerprint")
                .and_then(Value::as_str)
                .filter(|f| !f.is_empty() && *f != "unsafe")
            {
                out["fingerprint"] = json!(fp);
            }
            let pins = str_list(t.get("pinnedPeerCertificateChainSha256"));
            if !pins.is_empty() {
                out["pinned_cert_chain_sha256"] = json!(pins);
            }
            for key in [
                "echConfigList",
                "echServerKeys",
                "certificates",
                "masterKeyLog",
                "curvePreferences",
            ] {
                if t.get(key)
                    .is_some_and(|v| !v.is_null() && v != &json!([]) && v != &json!(""))
                {
                    notes.add(format!(
                        "{ctx}: tlsSettings.{key} is not supported and was ignored"
                    ));
                }
            }
            Ok(Some(out))
        }
        "reality" => {
            let r = stream.get("realitySettings").cloned().unwrap_or(json!({}));
            let public_key = r
                .get("publicKey")
                .or_else(|| r.get("password"))
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("{ctx}: realitySettings.publicKey is required"))?;
            let mut out = json!({
                "enabled": true,
                "fingerprint": r.get("fingerprint").and_then(Value::as_str).filter(|f| !f.is_empty()).unwrap_or("chrome"),
                "reality": {"public_key": public_key, "short_id": r.get("shortId").and_then(Value::as_str).unwrap_or("")},
            });
            if let Some(s) = r
                .get("serverName")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                out["server_name"] = json!(s);
            }
            if r.get("mldsa65Verify")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            {
                notes.add(format!(
                    "{ctx}: REALITY ML-DSA-65 verification is not supported yet"
                ));
            }
            Ok(Some(out))
        }
        other => bail!("{ctx}: security `{other}` is not supported"),
    }
}

/// `/ws?ed=2048`: early data in the WebSocket path.
fn ws_early_data(path: &str) -> (String, Option<u64>) {
    let Some((base, query)) = path.split_once('?') else {
        return (path.to_string(), None);
    };
    let mut ed = None;
    let rest: Vec<&str> = query
        .split('&')
        .filter(
            |kv| match kv.strip_prefix("ed=").and_then(|v| v.parse().ok()) {
                Some(n) => {
                    ed = Some(n);
                    false
                }
                None => true,
            },
        )
        .collect();
    let path = if rest.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", rest.join("&"))
    };
    (path, ed)
}

fn headers_without_host(h: Option<&Value>) -> (Option<String>, Option<Value>) {
    let Some(Value::Object(map)) = h else {
        return (None, None);
    };
    let mut host = None;
    let mut rest = Map::new();
    for (k, v) in map {
        let text = match v {
            Value::String(s) => s.clone(),
            Value::Array(a) => a.first().and_then(Value::as_str).unwrap_or("").to_string(),
            _ => continue,
        };
        if k.eq_ignore_ascii_case("host") {
            host = Some(text);
        } else {
            rest.insert(k.clone(), json!(text));
        }
    }
    (host, (!rest.is_empty()).then_some(Value::Object(rest)))
}

fn transport(stream: &Value, ctx: &str) -> Result<Option<Value>> {
    let network = stream
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or("tcp");
    Ok(match network {
        "tcp" | "raw" => {
            let settings = stream
                .get("rawSettings")
                .or_else(|| stream.get("tcpSettings"));
            let header = settings.and_then(|s| s.get("header"));
            match header.and_then(|h| h.get("type")).and_then(Value::as_str) {
                Some("http") => {
                    let req = header
                        .and_then(|h| h.get("request"))
                        .cloned()
                        .unwrap_or(json!({}));
                    let path = str_list(req.get("path"))
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| "/".into());
                    let hosts = req
                        .get("headers")
                        .and_then(|h| h.get("Host").or_else(|| h.get("host")))
                        .map(|h| str_list(Some(h)))
                        .unwrap_or_default();
                    let mut obfs = json!({"path": path});
                    if !hosts.is_empty() {
                        obfs["host"] = json!(hosts);
                    }
                    if let Some(m) = req.get("method").and_then(Value::as_str) {
                        obfs["method"] = json!(m);
                    }
                    Some(json!({"type": "tcp", "http_obfs": obfs}))
                }
                _ => None,
            }
        }
        "ws" | "websocket" => {
            let s = stream.get("wsSettings").cloned().unwrap_or(json!({}));
            let (path, ed) = ws_early_data(s.get("path").and_then(Value::as_str).unwrap_or("/"));
            let (header_host, headers) = headers_without_host(s.get("headers"));
            let mut out = json!({"type": "ws", "path": path});
            if let Some(h) = s
                .get("host")
                .and_then(Value::as_str)
                .filter(|h| !h.is_empty())
                .map(str::to_string)
                .or(header_host)
            {
                out["host"] = json!(h);
            }
            if let Some(h) = headers {
                out["headers"] = h;
            }
            if let Some(n) = ed {
                out["max_early_data"] = json!(n);
                out["early_data_header_name"] = json!("Sec-WebSocket-Protocol");
            }
            Some(out)
        }
        "httpupgrade" => {
            let s = stream
                .get("httpupgradeSettings")
                .cloned()
                .unwrap_or(json!({}));
            let (header_host, headers) = headers_without_host(s.get("headers"));
            let mut out = json!({"type": "httpupgrade", "path": s.get("path").and_then(Value::as_str).unwrap_or("/")});
            if let Some(h) = s
                .get("host")
                .and_then(Value::as_str)
                .filter(|h| !h.is_empty())
                .map(str::to_string)
                .or(header_host)
            {
                out["host"] = json!(h);
            }
            if let Some(h) = headers {
                out["headers"] = h;
            }
            Some(out)
        }
        "grpc" | "gun" => {
            let s = stream.get("grpcSettings").cloned().unwrap_or(json!({}));
            let mut out = json!({"type": "grpc", "service_name": s.get("serviceName").and_then(Value::as_str).unwrap_or("")});
            if s.get("multiMode").and_then(Value::as_bool) == Some(true) {
                out["multi_mode"] = json!(true);
            }
            if let Some(a) = s
                .get("authority")
                .and_then(Value::as_str)
                .filter(|a| !a.is_empty())
            {
                out["authority"] = json!(a);
            }
            if let Some(ua) = s
                .get("user_agent")
                .and_then(Value::as_str)
                .filter(|a| !a.is_empty())
            {
                out["user_agent"] = json!(ua);
            }
            Some(out)
        }
        "h2" | "http" => {
            let s = stream.get("httpSettings").cloned().unwrap_or(json!({}));
            let mut out = json!({"type": "http", "path": s.get("path").and_then(Value::as_str).unwrap_or("/")});
            let hosts = str_list(s.get("host"));
            if !hosts.is_empty() {
                out["host"] = json!(hosts);
            }
            if let Some(m) = s.get("method").and_then(Value::as_str) {
                out["method"] = json!(m);
            }
            Some(out)
        }
        other => bail!("{ctx}: transport `{other}` is not implemented yet"),
    })
}

fn outbound(ob: &Value, notes: &mut Notes) -> Result<Option<Value>> {
    let protocol = ob.get("protocol").and_then(Value::as_str).unwrap_or("");
    let tag = ob
        .get("tag")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    let ctx = format!("outbound `{}`", tag.as_deref().unwrap_or(protocol));
    let settings = ob.get("settings").cloned().unwrap_or(json!({}));
    let stream = ob.get("streamSettings").cloned().unwrap_or(json!({}));
    if ob
        .get("mux")
        .and_then(|m| m.get("enabled"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        notes.add(format!(
            "{ctx}: mux is not implemented yet and was disabled"
        ));
    }
    let mut out = match protocol {
        "freedom" | "direct" => {
            let mut o = json!({"type": "direct"});
            if let Some(f) = settings.get("fragment") {
                let mut frag = json!({
                    "packets": f.get("packets").and_then(Value::as_str).unwrap_or("tlshello"),
                    "length": value_text(f.get("length")).unwrap_or_else(|| "100-200".into()),
                    "interval": value_text(f.get("interval")).unwrap_or_else(|| "10-20".into()),
                });
                if let Some(m) = value_text(f.get("maxSplit")) {
                    frag["max_split"] = json!(m);
                }
                o["fragment"] = frag;
            }
            if settings.get("noises").is_some() {
                notes.add(format!("{ctx}: noises are not implemented yet"));
            }
            if let Some(mark) = stream
                .get("sockopt")
                .and_then(|s| s.get("mark"))
                .and_then(Value::as_u64)
                .filter(|m| *m != 0)
            {
                o["fwmark"] = json!(mark);
            }
            if let Some(i) = stream
                .get("sockopt")
                .and_then(|s| s.get("interface"))
                .and_then(Value::as_str)
                .filter(|i| !i.is_empty())
            {
                o["bind_interface"] = json!(i);
            }
            o
        }
        "blackhole" | "block" => json!({"type": "block"}),
        "dns" => {
            for key in ["network", "address", "port", "nonIPQuery", "blockTypes"] {
                if settings.get(key).is_some() {
                    notes.add(format!(
                        "{ctx}: dns `{key}` is ignored; queries are answered by the DNS module"
                    ));
                }
            }
            json!({"type": "dns"})
        }
        "vless" => {
            let server = first(&settings, "vnext").unwrap_or_else(|| settings.clone());
            let user = first(&server, "users").unwrap_or_else(|| settings.clone());
            if let Some(enc) = user
                .get("encryption")
                .and_then(Value::as_str)
                .filter(|e| !e.is_empty() && *e != "none")
            {
                bail!("{ctx}: VLESS encryption `{enc}` is not implemented yet");
            }
            let mut o = json!({
                "type": "vless",
                "server": server.get("address").and_then(Value::as_str).unwrap_or(""),
                "port": port_of(&server).unwrap_or(0),
                "uuid": user.get("id").and_then(Value::as_str).unwrap_or(""),
            });
            if let Some(flow) = user
                .get("flow")
                .and_then(Value::as_str)
                .filter(|f| !f.is_empty())
            {
                o["flow"] = json!(flow);
            }
            if let Some(pe) = settings
                .get("packetEncoding")
                .and_then(Value::as_str)
                .filter(|p| *p == "xudp")
            {
                o["packet_encoding"] = json!(pe);
            }
            o
        }
        "vmess" => {
            let server = first(&settings, "vnext").unwrap_or_else(|| settings.clone());
            let user = first(&server, "users").unwrap_or_else(|| settings.clone());
            json!({
                "type": "vmess",
                "server": server.get("address").and_then(Value::as_str).unwrap_or(""),
                "port": port_of(&server).unwrap_or(0),
                "uuid": user.get("id").and_then(Value::as_str).unwrap_or(""),
                "security": user.get("security").and_then(Value::as_str).unwrap_or("auto"),
                "alter_id": user.get("alterId").and_then(Value::as_u64).unwrap_or(0),
            })
        }
        "trojan" => {
            let server = first(&settings, "servers").unwrap_or_else(|| settings.clone());
            json!({
                "type": "trojan",
                "server": server.get("address").and_then(Value::as_str).unwrap_or(""),
                "port": port_of(&server).unwrap_or(0),
                "password": server.get("password").and_then(Value::as_str).unwrap_or(""),
            })
        }
        "shadowsocks" => {
            let server = first(&settings, "servers").unwrap_or_else(|| settings.clone());
            if server.get("uot").and_then(Value::as_bool) == Some(true) {
                notes.add(format!("{ctx}: UDP over TCP is not supported"));
            }
            json!({
                "type": "shadowsocks",
                "server": server.get("address").and_then(Value::as_str).unwrap_or(""),
                "port": port_of(&server).unwrap_or(0),
                "method": server.get("method").and_then(Value::as_str).unwrap_or(""),
                "password": server.get("password").and_then(Value::as_str).unwrap_or(""),
            })
        }
        "socks" | "http" => {
            let server = first(&settings, "servers").unwrap_or_else(|| settings.clone());
            let mut o = json!({
                "type": protocol,
                "server": server.get("address").and_then(Value::as_str).unwrap_or(""),
                "port": port_of(&server).unwrap_or(0),
            });
            if let Some(u) = first(&server, "users") {
                o["username"] = json!(u.get("user").and_then(Value::as_str).unwrap_or(""));
                o["password"] = json!(u.get("pass").and_then(Value::as_str).unwrap_or(""));
            }
            o
        }
        "wireguard" => {
            let peer = first(&settings, "peers").ok_or_else(|| anyhow!("{ctx}: no peers"))?;
            let endpoint = peer.get("endpoint").and_then(Value::as_str).unwrap_or("");
            let (host, port) = endpoint
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("{ctx}: bad endpoint `{endpoint}`"))?;
            let mut o = json!({
                "type": "wireguard",
                "server": host.trim_start_matches('[').trim_end_matches(']'),
                "port": port.parse::<u16>().map_err(|_| anyhow!("{ctx}: bad endpoint port"))?,
                "private_key": settings.get("secretKey").and_then(Value::as_str).unwrap_or(""),
                "peer_public_key": peer.get("publicKey").and_then(Value::as_str).unwrap_or(""),
                "local_address": str_list(settings.get("address")),
            });
            if let Some(psk) = peer
                .get("preSharedKey")
                .and_then(Value::as_str)
                .filter(|p| !p.is_empty())
            {
                o["pre_shared_key"] = json!(psk);
            }
            if let Some(m) = settings.get("mtu") {
                o["mtu"] = m.clone();
            }
            if let Some(r) = settings.get("reserved") {
                o["reserved"] = r.clone();
            }
            o
        }
        other => {
            notes.add(format!(
                "{ctx}: protocol `{other}` is not supported yet and was skipped"
            ));
            return Ok(None);
        }
    };
    if matches!(protocol, "vless" | "vmess" | "trojan" | "socks" | "http") {
        if let Some(t) = tls(&stream, &ctx, notes)? {
            out["tls"] = t;
        }
        if let Some(t) = transport(&stream, &ctx)? {
            out["transport"] = t;
        }
    } else if protocol == "shadowsocks"
        && stream
            .get("network")
            .and_then(Value::as_str)
            .is_some_and(|n| n != "tcp" && n != "raw")
    {
        bail!("{ctx}: Shadowsocks over a transport is not supported");
    }
    let detour = ob
        .get("proxySettings")
        .and_then(|p| p.get("tag"))
        .or_else(|| stream.get("sockopt").and_then(|s| s.get("dialerProxy")))
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty());
    if let Some(d) = detour {
        out["detour"] = json!(d);
    }
    out["tag"] = json!(tag.unwrap_or_else(|| protocol.to_string()));
    Ok(Some(out))
}

/// Numbers or strings like `"10-20"`.
fn value_text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Splits Xray domain entries into sing-box style condition lists.
fn domain_conditions(entries: &[String], out: &mut Map<String, Value>, ctx: &str) -> Result<()> {
    let mut lists: [(&str, Vec<String>); 5] = [
        ("domain", vec![]),
        ("domain_suffix", vec![]),
        ("domain_keyword", vec![]),
        ("domain_regex", vec![]),
        ("geosite", vec![]),
    ];
    for e in entries {
        let (key, value) = if let Some(v) = e.strip_prefix("geosite:") {
            (4, v.to_string())
        } else if e.starts_with("ext:") || e.starts_with("ext-domain:") {
            (4, e.clone())
        } else if let Some(v) = e.strip_prefix("full:") {
            (0, v.to_string())
        } else if let Some(v) = e.strip_prefix("domain:") {
            (1, v.to_string())
        } else if let Some(v) = e.strip_prefix("keyword:") {
            (2, v.to_string())
        } else if let Some(v) = e.strip_prefix("regexp:") {
            (3, v.to_string())
        } else if let Some(v) = e.strip_prefix("dotless:") {
            if v.contains('.') {
                bail!("{ctx}: dotless rule `{e}` must not contain a dot");
            }
            (
                3,
                if v.is_empty() {
                    "^[^.]*$".to_string()
                } else {
                    format!("^[^.]*{}[^.]*$", regex_escape(v))
                },
            )
        } else {
            // A plain string matches as a substring in Xray.
            (2, e.clone())
        };
        lists[key].1.push(value);
    }
    for (key, values) in lists {
        if !values.is_empty() {
            out.insert(key.into(), json!(values));
        }
    }
    Ok(())
}

fn regex_escape(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if "\\.+*?()|[]{}^$".contains(c) {
                vec!['\\', c]
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Splits Xray IP entries into CIDRs and geoip codes.
fn ip_conditions(entries: &[String], cidr_key: &str, geo_key: &str, out: &mut Map<String, Value>) {
    let (mut cidrs, mut geo) = (Vec::new(), Vec::new());
    for e in entries {
        if let Some(v) = e.strip_prefix("geoip:") {
            geo.push(v.to_string());
        } else if e.starts_with("ext:") || e.starts_with("ext-ip:") {
            geo.push(e.clone());
        } else {
            cidrs.push(e.clone());
        }
    }
    if !cidrs.is_empty() {
        out.insert(cidr_key.into(), json!(cidrs));
    }
    if !geo.is_empty() {
        out.insert(geo_key.into(), json!(geo));
    }
}

/// `"53,443,1000-2000"` into ports and ranges.
fn ports(
    v: Option<&Value>,
    port_key: &str,
    range_key: &str,
    out: &mut Map<String, Value>,
    ctx: &str,
) -> Result<()> {
    let text = match v {
        None | Some(Value::Null) => return Ok(()),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => bail!("{ctx}: bad port list {other}"),
    };
    let (mut single, mut ranges) = (Vec::new(), Vec::new());
    for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => ranges.push(format!("{}:{}", a.trim(), b.trim())),
            None => single.push(
                part.parse::<u16>()
                    .map_err(|_| anyhow!("{ctx}: bad port `{part}`"))?,
            ),
        }
    }
    if !single.is_empty() {
        out.insert(port_key.into(), json!(single));
    }
    if !ranges.is_empty() {
        out.insert(range_key.into(), json!(ranges));
    }
    Ok(())
}

fn routing_rule(rule: &Value, index: usize, notes: &mut Notes) -> Result<Option<Value>> {
    let ctx = format!("routing.rules[{index}]");
    let target = rule
        .get("outboundTag")
        .or_else(|| rule.get("balancerTag"))
        .and_then(Value::as_str);
    let Some(target) = target else {
        notes.add(format!(
            "{ctx}: no outboundTag or balancerTag; rule dropped"
        ));
        return Ok(None);
    };
    for key in ["attrs", "localIP", "localPort", "vlessRoute", "webhook"] {
        if rule.get(key).is_some() {
            notes.add(format!(
                "{ctx}: condition `{key}` is not supported; rule dropped"
            ));
            return Ok(None);
        }
    }
    let mut domain_part = Map::new();
    domain_conditions(
        &str_list(rule.get("domain").or_else(|| rule.get("domains"))),
        &mut domain_part,
        &ctx,
    )?;
    let mut ip_part = Map::new();
    ip_conditions(&str_list(rule.get("ip")), "ip_cidr", "geoip", &mut ip_part);
    let mut rest = Map::new();
    ports(rule.get("port"), "port", "port_range", &mut rest, &ctx)?;
    ports(
        rule.get("sourcePort"),
        "source_port",
        "source_port_range",
        &mut rest,
        &ctx,
    )?;
    ip_conditions(
        &str_list(rule.get("source").or_else(|| rule.get("sourceIP"))),
        "source_ip_cidr",
        "source_geoip",
        &mut rest,
    );
    for (from, to) in [
        ("network", "network"),
        ("inboundTag", "inbound"),
        ("protocol", "protocol"),
        ("user", "auth_user"),
    ] {
        let list = str_list(rule.get(from));
        if !list.is_empty() {
            rest.insert(to.into(), json!(list));
        }
    }
    let processes = str_list(rule.get("process"));
    if !processes.is_empty() {
        let (paths, names): (Vec<String>, Vec<String>) = processes
            .into_iter()
            .partition(|p| p.contains('/') || p.contains('\\'));
        if !names.is_empty() {
            rest.insert("process_name".into(), json!(names));
        }
        if !paths.is_empty() {
            rest.insert("process_path".into(), json!(paths));
        }
    }
    // Xray requires every field; domain and IP lists are therefore AND-ed,
    // while within one sing-box rule they would be OR-ed.
    let out = if !domain_part.is_empty() && !ip_part.is_empty() {
        let mut second = ip_part;
        second.extend(rest);
        json!({"type": "logical", "mode": "and", "rules": [Value::Object(domain_part), Value::Object(second)]})
    } else {
        let mut all = domain_part;
        all.extend(ip_part);
        all.extend(rest);
        Value::Object(all)
    };
    let mut out = out;
    out["outbound"] = json!(target);
    Ok(Some(out))
}

fn balancer(b: &Value, outbound_tags: &[String], notes: &mut Notes) -> Option<Value> {
    let tag = b.get("tag").and_then(Value::as_str)?.to_string();
    let prefixes = str_list(b.get("selector"));
    let mut members: Vec<String> = outbound_tags
        .iter()
        .filter(|t| prefixes.iter().any(|p| t.starts_with(p.as_str())))
        .cloned()
        .collect();
    let strategy = b
        .get("strategy")
        .and_then(|s| s.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("random");
    let strategy = match strategy {
        "random" => "random",
        "roundRobin" => "round_robin",
        "leastPing" => "least_ping",
        "leastLoad" => {
            notes.add(format!("balancer `{tag}`: leastLoad became least_ping"));
            "least_ping"
        }
        other => {
            notes.add(format!(
                "balancer `{tag}`: strategy `{other}` became random"
            ));
            "random"
        }
    };
    if let Some(f) = b.get("fallbackTag").and_then(Value::as_str) {
        if !members.iter().any(|m| m == f) && outbound_tags.iter().any(|t| t == f) {
            members.push(f.to_string());
            notes.add(format!(
                "balancer `{tag}`: fallback `{f}` is used as an ordinary member"
            ));
        }
    }
    if members.is_empty() {
        notes.add(format!(
            "balancer `{tag}`: selector matches no outbound; balancer dropped"
        ));
        return None;
    }
    Some(json!({"type": "balancer", "tag": tag, "strategy": strategy, "outbounds": members}))
}

fn inbound(ib: &Value, index: usize, notes: &mut Notes) -> Option<Value> {
    let protocol = ib.get("protocol").and_then(Value::as_str).unwrap_or("");
    let tag = ib
        .get("tag")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("{protocol}-{index}"));
    let kind = match protocol {
        // Xray's socks inbound also answers HTTP proxy requests.
        "socks" | "mixed" => "mixed",
        "http" => "http",
        "tun" => return Some(tun_inbound(ib, &tag, notes)),
        other => {
            notes.add(format!(
                "inbound `{tag}`: protocol `{other}` is not supported yet and was skipped"
            ));
            return None;
        }
    };
    let port = port_of(ib)?;
    let settings = ib.get("settings").cloned().unwrap_or(json!({}));
    let listen = ib
        .get("listen")
        .and_then(Value::as_str)
        .unwrap_or("0.0.0.0");
    let mut out = json!({"type": kind, "tag": tag, "listen": listen, "port": port});
    let accounts: Vec<Value> = settings
        .get("accounts")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|u| json!({"username": u.get("user").and_then(Value::as_str).unwrap_or(""), "password": u.get("pass").and_then(Value::as_str).unwrap_or("")})).collect())
        .unwrap_or_default();
    if !accounts.is_empty() {
        out["users"] = json!(accounts);
    }
    if protocol == "socks" && settings.get("udp").and_then(Value::as_bool) == Some(false) {
        out["udp"] = json!(false);
    }
    let sniffing = ib.get("sniffing");
    let enabled = sniffing
        .and_then(|s| s.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let route_only = sniffing
        .and_then(|s| s.get("routeOnly"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Xray sniffs only when asked; when it does, destOverride rewrites
    // the target unless routeOnly is set.
    out["sniff"] = json!({"enabled": enabled, "override_destination": enabled && !route_only});
    Some(out)
}

/// Xray's TUN inbound only creates the interface (`name`, `MTU`); the
/// address and routes are set up outside Xray, and DNS goes through the
/// routing rules.
fn tun_inbound(ib: &Value, tag: &str, notes: &mut Notes) -> Value {
    let settings = ib.get("settings").cloned().unwrap_or(json!({}));
    let name = settings
        .get("name")
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty())
        .unwrap_or("xray0");
    let mtu = settings
        .get("MTU")
        .and_then(Value::as_u64)
        .filter(|m| *m > 0)
        .unwrap_or(1500);
    notes.add(format!(
        "inbound `{tag}` (tun): Xray leaves addresses and routes to the system; here the core sets them up (auto_route), DNS is answered through the routing rules"
    ));
    let sniffing = ib.get("sniffing");
    let enabled = sniffing
        .and_then(|s| s.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let route_only = sniffing
        .and_then(|s| s.get("routeOnly"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    json!({
        "type": "tun", "tag": tag, "interface_name": name, "mtu": mtu,
        "dns_hijack": false,
        "sniff": {"enabled": enabled, "override_destination": enabled && !route_only},
    })
}

/// Xray DNS server string or object into one of our servers.
fn dns_server(
    entry: &Value,
    index: usize,
    default_detour: Option<&str>,
    notes: &mut Notes,
) -> Option<(Value, Vec<String>)> {
    let (address, domains, obj) = match entry {
        Value::String(s) => (s.clone(), Vec::new(), None),
        Value::Object(_) => (
            entry
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            str_list(entry.get("domains")),
            Some(entry),
        ),
        _ => return None,
    };
    let tag = obj
        .and_then(|o| o.get("tag"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("dns-{index}"));
    let port = obj.and_then(port_of);
    let (local, addr) = if let Some(rest) = address.strip_prefix("https+local://") {
        (true, format!("https://{rest}"))
    } else if let Some(rest) = address.strip_prefix("tcp+local://") {
        (true, format!("tcp://{rest}"))
    } else if address == "localhost" {
        (true, "local".to_string())
    } else if address == "fakedns" {
        (true, "fakeip".to_string())
    } else if let Some(rest) = address.strip_prefix("quic+local://") {
        (true, format!("quic://{rest}"))
    } else if address.starts_with("h2c") {
        notes.add(format!(
            "DNS server `{address}` is not supported yet; dropped"
        ));
        return None;
    } else if address.starts_with("https://")
        || address.starts_with("quic://")
        || address.starts_with("tcp://")
        || address.starts_with("udp://")
    {
        (false, address.clone())
    } else {
        let host = if address.contains(':') && !address.starts_with('[') {
            format!("[{address}]")
        } else {
            address.clone()
        };
        (false, format!("udp://{host}:{}", port.unwrap_or(53)))
    };
    let mut out = json!({"tag": tag, "address": addr});
    // Without `+local`, Xray sends DNS traffic through routing, usually
    // the default outbound.
    if let (false, Some(d)) = (local, default_detour) {
        out["detour"] = json!(d);
    }
    if let Some(o) = obj {
        if let Some(ip) = o.get("clientIP").and_then(Value::as_str) {
            out["client_subnet"] = json!(ip);
        }
        if let Some(q) = o.get("queryStrategy").and_then(Value::as_str) {
            out["strategy"] = json!(q);
        }
        if o.get("expectIPs")
            .is_some_and(|v| v.as_array().is_some_and(|a| !a.is_empty()))
        {
            notes.add(format!("DNS server `{tag}`: expectIPs is not supported"));
        }
    }
    Some((out, domains))
}

fn dns(d: &Value, default_detour: Option<&str>, notes: &mut Notes) -> Result<Option<Value>> {
    let mut servers = Vec::new();
    let mut rules = Vec::new();
    for (i, entry) in d
        .get("servers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let Some((server, domains)) = dns_server(entry, i, default_detour, notes) else {
            continue;
        };
        if !domains.is_empty() {
            let mut cond = Map::new();
            domain_conditions(&domains, &mut cond, &format!("dns.servers[{i}]"))?;
            cond.insert("server".into(), server["tag"].clone());
            rules.push(Value::Object(cond));
        }
        servers.push(server);
    }
    if servers.is_empty() {
        return Ok(None);
    }
    let fakeip = servers.iter().any(|s| s["address"] == "fakeip");
    let mut out = json!({"servers": servers, "rules": rules});
    // Xray asks the first plain server when no domain list matched.
    if let Some(final_server) = out["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["address"] != "fakeip")
        .map(|s| s["tag"].clone())
    {
        out["final"] = final_server;
    }
    if let Some(q) = d.get("queryStrategy").and_then(Value::as_str) {
        out["strategy"] = json!(q);
    }
    if let Some(ip) = d.get("clientIp").and_then(Value::as_str) {
        out["client_subnet"] = json!(ip);
    }
    if d.get("disableCache").and_then(Value::as_bool) == Some(true) {
        out["cache"] = json!({"enabled": false});
    }
    if fakeip {
        out["fakeip"] = json!({"inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"});
    }
    let mut hosts = Map::new();
    if let Some(Value::Object(map)) = d.get("hosts") {
        for (name, value) in map {
            let plain = name.strip_prefix("full:").unwrap_or(name);
            let addrs = str_list(Some(value));
            let all_ips = addrs.iter().all(|a| a.parse::<std::net::IpAddr>().is_ok());
            if plain.contains(':') || !all_ips || addrs.is_empty() {
                notes.add(format!(
                    "dns.hosts `{name}`: only exact names mapped to IP addresses are supported"
                ));
                continue;
            }
            hosts.insert(plain.to_string(), json!(addrs));
        }
    }
    if !hosts.is_empty() {
        out["hosts"] = Value::Object(hosts);
    }
    Ok(Some(out))
}

pub fn convert(v: Value) -> Result<Imported> {
    let mut notes = Notes::default();
    let mut v = v;
    let mut out = json!({});
    if let Some(level) = v
        .get("log")
        .and_then(|l| l.get("loglevel"))
        .and_then(Value::as_str)
    {
        out["log"] =
            json!({"level": match level { "warning" => "warn", "none" => "off", other => other }});
    }
    out["inbounds"] = json!(v
        .get("inbounds")
        .and_then(Value::as_array)
        .map(|a| a
            .iter()
            .enumerate()
            .filter_map(|(i, ib)| inbound(ib, i, &mut notes))
            .collect::<Vec<_>>())
        .unwrap_or_default());

    let mut outbounds = Vec::new();
    for ob in v
        .get("outbounds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if let Some(o) = outbound(&ob, &mut notes)? {
            outbounds.push(o);
        }
    }
    if outbounds.is_empty() {
        bail!("the Xray config has no usable outbounds");
    }
    // Generated tags (`protocol` names) may collide.
    let mut seen = std::collections::HashSet::new();
    for o in outbounds.iter_mut() {
        let base = o["tag"].as_str().unwrap_or("").to_string();
        let mut tag = base.clone();
        let mut n = 1;
        while !seen.insert(tag.clone()) {
            n += 1;
            tag = format!("{base}-{n}");
        }
        o["tag"] = json!(tag);
    }
    let tags: Vec<String> = outbounds
        .iter()
        .filter_map(|o| o["tag"].as_str().map(str::to_string))
        .collect();
    let default_outbound = tags[0].clone();

    let routing = take(&mut v, "routing").unwrap_or(json!({}));
    for b in routing
        .get("balancers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if let Some(b) = balancer(&b, &tags, &mut notes) {
            outbounds.push(b);
        }
    }
    let all_tags: Vec<String> = outbounds
        .iter()
        .filter_map(|o| o["tag"].as_str().map(str::to_string))
        .collect();
    let mut rules = Vec::new();
    for (i, rule) in routing
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        if let Some(r) = routing_rule(rule, i, &mut notes)? {
            let target = r["outbound"].as_str().unwrap_or("").to_string();
            if all_tags.contains(&target) {
                rules.push(r);
            } else {
                notes.add(format!(
                    "routing.rules[{i}]: target `{target}` was not converted; rule dropped"
                ));
            }
        }
    }
    let mut route = json!({"rules": rules, "final": default_outbound});
    if let Some(ds) = routing.get("domainStrategy").and_then(Value::as_str) {
        route["domain_strategy"] = json!(match ds {
            "IPIfNonMatch" => "ip_if_non_match",
            "IPOnDemand" => "ip_on_demand",
            _ => "as_is",
        });
    }
    out["route"] = route;

    let default_is_direct = outbounds.first().is_some_and(|o| o["type"] == "direct");
    if let Some(d) = v.get("dns") {
        let detour = (!default_is_direct).then_some(default_outbound.as_str());
        if let Some(d) = dns(d, detour, &mut notes)? {
            out["dns"] = d;
        }
    }
    out["outbounds"] = json!(outbounds);
    for key in [
        "observatory",
        "burstObservatory",
        "api",
        "stats",
        "policy",
        "reverse",
        "fakedns",
        "metrics",
        "transport",
    ] {
        if v.get(key).is_some() {
            notes.add(format!("`{key}` is not supported and was ignored"));
        }
    }
    let config: Config = serde_json::from_value(out).context("converted Xray config")?;
    config.validate().context("converted Xray config")?;
    Ok(Imported {
        config,
        warnings: notes.0,
    })
}
