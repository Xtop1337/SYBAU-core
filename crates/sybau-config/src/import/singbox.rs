//! sing-box configurations (1.10 – 1.14 field names).

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use super::{take, take_str, Imported, Notes};
use crate::Config;

const DROP_INBOUND_KEYS: &[&str] = &[
    "tcp_fast_open",
    "tcp_multi_path",
    "udp_fragment",
    "udp_timeout",
    "set_system_proxy",
    "domain_strategy",
    "sniff_timeout",
    "detour",
];

fn rename(v: &mut Value, from: &str, to: &str) {
    if let Some(x) = take(v, from) {
        v[to] = x;
    }
}

fn inbound(mut ib: Value, notes: &mut Notes) -> Option<Value> {
    let kind = ib["type"].as_str().unwrap_or("").to_string();
    let tag = ib["tag"].as_str().unwrap_or("").to_string();
    match kind.as_str() {
        "mixed" | "socks" | "http" => {}
        other => {
            notes.add(format!(
                "inbound `{tag}` of type `{other}` is not supported yet and was skipped"
            ));
            return None;
        }
    }
    rename(&mut ib, "listen_port", "port");
    let sniff = take(&mut ib, "sniff").and_then(|v| v.as_bool());
    let override_destination =
        take(&mut ib, "sniff_override_destination").and_then(|v| v.as_bool());
    if sniff.is_some() || override_destination.is_some() {
        ib["sniff"] = json!({"enabled": sniff.unwrap_or(true), "override_destination": override_destination.unwrap_or(false)});
    }
    for key in DROP_INBOUND_KEYS {
        if take(&mut ib, key).is_some() {
            notes.add(format!("inbound `{tag}`: `{key}` is ignored"));
        }
    }
    if let Some(Value::Array(users)) = ib.get_mut("users") {
        for u in users {
            take(u, "name");
        }
    }
    Some(ib)
}

fn tls(mut t: Value, ctx: &str, notes: &mut Notes) -> Option<Value> {
    if t.get("enabled").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    let mut out = Map::new();
    out.insert("enabled".into(), json!(true));
    if let Some(sni) = take_str(&mut t, "server_name") {
        out.insert("server_name".into(), json!(sni));
    }
    if let Some(alpn) = take(&mut t, "alpn") {
        out.insert(
            "alpn".into(),
            if alpn.is_string() {
                json!([alpn])
            } else {
                alpn
            },
        );
    }
    if take(&mut t, "insecure").and_then(|v| v.as_bool()) == Some(true) {
        out.insert("insecure".into(), json!(true));
    }
    if let Some(mut utls) = take(&mut t, "utls") {
        if utls.get("enabled").and_then(Value::as_bool) != Some(false) {
            out.insert(
                "fingerprint".into(),
                json!(take_str(&mut utls, "fingerprint").unwrap_or_else(|| "chrome".into())),
            );
        }
    }
    if let Some(mut reality) = take(&mut t, "reality") {
        if reality.get("enabled").and_then(Value::as_bool) != Some(false) {
            out.insert(
                "reality".into(),
                json!({"public_key": take_str(&mut reality, "public_key").unwrap_or_default(), "short_id": take_str(&mut reality, "short_id").unwrap_or_default()}),
            );
            out.entry("fingerprint").or_insert(json!("chrome"));
        }
    }
    // A trusted certificate becomes a pin: as a leaf it is accepted as is,
    // as a CA it becomes the only root, which is what sing-box does with it.
    let mut pems = String::new();
    match take(&mut t, "certificate") {
        Some(Value::String(pem)) => pems.push_str(&pem),
        Some(Value::Array(lines)) => lines.iter().filter_map(Value::as_str).for_each(|l| {
            pems.push_str(l);
            pems.push('\n');
        }),
        _ => {}
    }
    if let Some(path) = take_str(&mut t, "certificate_path") {
        match std::fs::read_to_string(&path) {
            Ok(text) => pems.push_str(&text),
            Err(e) => notes.add(format!("{ctx}: cannot read certificate_path {path}: {e}")),
        }
    }
    let pins = pem_sha256(&pems);
    if !pins.is_empty() {
        out.insert("pinned_cert_sha256".into(), json!(pins));
    }
    if let Some(pins) = take(&mut t, "certificate_public_key_sha256") {
        notes.add(format!("{ctx}: public key pinning is not supported; `certificate_public_key_sha256` ignored ({pins})"));
    }
    if let Some(Value::Object(rest)) = Some(t) {
        for key in rest.keys().filter(|k| *k != "enabled") {
            notes.add(format!("{ctx}: tls `{key}` is ignored"));
        }
    }
    Some(Value::Object(out))
}

/// SHA-256 (hex) of every certificate in PEM text.
fn pem_sha256(text: &str) -> Vec<String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let mut out = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with("-----BEGIN CERTIFICATE") {
            body = Some(String::new());
        } else if line.starts_with("-----END CERTIFICATE") {
            if let Some(der) = body
                .take()
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
            {
                out.push(
                    Sha256::digest(der)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect(),
                );
            }
        } else if let Some(b) = body.as_mut() {
            b.push_str(line);
        }
    }
    out
}

fn transport(mut t: Value, ctx: &str) -> Result<Value> {
    let kind = take_str(&mut t, "type").unwrap_or_default();
    let mut out = Map::new();
    match kind.as_str() {
        "ws" => {
            out.insert("type".into(), json!("ws"));
            out.insert(
                "path".into(),
                json!(take_str(&mut t, "path").unwrap_or_else(|| "/".into())),
            );
            if let Some(mut headers) = take(&mut t, "headers") {
                if let Some(host) =
                    take_str(&mut headers, "Host").or_else(|| take_str(&mut headers, "host"))
                {
                    out.insert("host".into(), json!(host));
                }
                if headers.as_object().is_some_and(|h| !h.is_empty()) {
                    out.insert("headers".into(), headers);
                }
            }
            if let Some(n) = take(&mut t, "max_early_data") {
                out.insert("max_early_data".into(), n);
            }
            if let Some(h) = take_str(&mut t, "early_data_header_name") {
                out.insert("early_data_header_name".into(), json!(h));
            }
        }
        "httpupgrade" => {
            out.insert("type".into(), json!("httpupgrade"));
            out.insert(
                "path".into(),
                json!(take_str(&mut t, "path").unwrap_or_else(|| "/".into())),
            );
            if let Some(host) = take_str(&mut t, "host") {
                out.insert("host".into(), json!(host));
            }
            if let Some(h) = take(&mut t, "headers") {
                out.insert("headers".into(), h);
            }
        }
        "grpc" => {
            out.insert("type".into(), json!("grpc"));
            out.insert(
                "service_name".into(),
                json!(take_str(&mut t, "service_name").unwrap_or_default()),
            );
        }
        "http" => {
            out.insert("type".into(), json!("http"));
            if let Some(host) = take(&mut t, "host") {
                out.insert(
                    "host".into(),
                    if host.is_string() {
                        json!([host])
                    } else {
                        host
                    },
                );
            }
            out.insert(
                "path".into(),
                json!(take_str(&mut t, "path").unwrap_or_else(|| "/".into())),
            );
            if let Some(m) = take_str(&mut t, "method") {
                out.insert("method".into(), json!(m));
            }
            if let Some(h) = take(&mut t, "headers") {
                out.insert("headers".into(), h);
            }
        }
        other => bail!("{ctx}: transport `{other}` is not implemented yet"),
    }
    Ok(Value::Object(out))
}

/// Keys every proxy outbound may carry, handled here.
const DIAL_KEYS: &[&str] = &[
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "routing_mark",
    "reuse_addr",
    "connect_timeout",
    "tcp_fast_open",
    "tcp_multi_path",
    "udp_fragment",
    "domain_strategy",
    "fallback_delay",
    "domain_resolver",
    "network",
];

fn outbound(mut ob: Value, notes: &mut Notes) -> Result<Option<Value>> {
    let kind = ob["type"].as_str().unwrap_or("").to_string();
    let tag = ob["tag"].as_str().unwrap_or("").to_string();
    let ctx = format!("outbound `{tag}`");
    rename(&mut ob, "server_port", "port");
    if let Some(m) = take(&mut ob, "multiplex") {
        if m.get("enabled").and_then(Value::as_bool) == Some(true) {
            notes.add(format!(
                "{ctx}: multiplex is not implemented yet and was disabled"
            ));
        }
    }
    match kind.as_str() {
        "direct" => {
            let interface = take_str(&mut ob, "bind_interface");
            let mark = take(&mut ob, "routing_mark");
            for key in
                DIAL_KEYS
                    .iter()
                    .chain(&["override_address", "override_port", "proxy_protocol"])
            {
                if take(&mut ob, key).is_some() {
                    notes.add(format!("{ctx}: `{key}` is ignored"));
                }
            }
            if let Some(i) = interface {
                ob["bind_interface"] = json!(i);
            }
            if let Some(m) = mark.and_then(|m| m.as_u64()) {
                ob["fwmark"] = json!(m);
            }
            return Ok(Some(ob));
        }
        "block" => return Ok(Some(json!({"type": "block", "tag": tag}))),
        "dns" => {
            notes.add(format!(
                "{ctx}: legacy `dns` outbound dropped; DNS hijacking comes with TUN"
            ));
            return Ok(None);
        }
        "urltest" => {
            let mut out = json!({"type": "balancer", "tag": tag, "strategy": "least_ping"});
            out["outbounds"] = take(&mut ob, "outbounds").unwrap_or(json!([]));
            notes.add(format!("{ctx}: urltest became a least_ping balancer (health is learned from traffic, not from `url`)"));
            return Ok(Some(out));
        }
        "selector" => {
            let mut out = json!({"type": "selector", "tag": tag});
            out["outbounds"] = take(&mut ob, "outbounds").unwrap_or(json!([]));
            if let Some(d) = take_str(&mut ob, "default") {
                out["default"] = json!(d);
            }
            return Ok(Some(out));
        }
        "socks" | "http" | "shadowsocks" | "vmess" | "trojan" | "vless" | "hysteria2" | "tuic"
        | "wireguard" => {}
        other => {
            notes.add(format!(
                "{ctx}: type `{other}` is not supported yet and was skipped"
            ));
            return Ok(None);
        }
    }
    for key in DIAL_KEYS {
        if take(&mut ob, key).is_some() {
            notes.add(format!("{ctx}: `{key}` is ignored"));
        }
    }
    if let Some(t) = take(&mut ob, "tls") {
        if let Some(t) = tls(t, &ctx, notes) {
            ob["tls"] = t;
        }
    }
    if let Some(t) = take(&mut ob, "transport") {
        ob["transport"] = transport(t, &ctx)?;
    }
    match kind.as_str() {
        "socks" => {
            take(&mut ob, "version");
        }
        "shadowsocks" => {
            if take(&mut ob, "plugin").is_some() {
                bail!("{ctx}: Shadowsocks plugins are not supported");
            }
            take(&mut ob, "plugin_opts");
            take(&mut ob, "udp_over_tcp");
        }
        "vmess" => {
            if take(&mut ob, "authenticated_length").and_then(|v| v.as_bool()) == Some(true) {
                notes.add(format!("{ctx}: authenticated_length is not implemented"));
            }
            take(&mut ob, "packet_encoding");
        }
        "hysteria2" => {
            if let Some(mut obfs) = take(&mut ob, "obfs") {
                if let Some(p) = take_str(&mut obfs, "password") {
                    ob["obfs_password"] = json!(p);
                }
            }
            take(&mut ob, "brutal_debug");
        }
        "tuic" => {
            take(&mut ob, "udp_over_stream");
            take(&mut ob, "heartbeat");
        }
        "wireguard" => {
            for (from, to) in [
                ("peer_public_key", "peer_public_key"),
                ("pre_shared_key", "pre_shared_key"),
            ] {
                rename(&mut ob, from, to);
            }
            take(&mut ob, "system_interface");
            take(&mut ob, "interface_name");
            take(&mut ob, "workers");
            take(&mut ob, "gso");
        }
        _ => {}
    }
    Ok(Some(ob))
}

/// `endpoints` of type wireguard (sing-box 1.11+) become outbounds.
fn endpoint(mut ep: Value, notes: &mut Notes) -> Option<Value> {
    let tag = ep["tag"].as_str().unwrap_or("").to_string();
    if ep["type"] != "wireguard" {
        notes.add(format!(
            "endpoint `{tag}` of type {} is not supported",
            ep["type"]
        ));
        return None;
    }
    let mut peer = match take(&mut ep, "peers") {
        Some(Value::Array(mut peers)) if !peers.is_empty() => peers.remove(0),
        _ => {
            notes.add(format!("endpoint `{tag}` has no peers"));
            return None;
        }
    };
    let mut out = json!({"type": "wireguard", "tag": tag});
    out["server"] = take(&mut peer, "address").unwrap_or(json!(""));
    out["port"] = take(&mut peer, "port").unwrap_or(json!(51820));
    out["peer_public_key"] = take(&mut peer, "public_key").unwrap_or(json!(""));
    if let Some(psk) = take(&mut peer, "pre_shared_key") {
        out["pre_shared_key"] = psk;
    }
    if let Some(r) = take(&mut peer, "reserved") {
        out["reserved"] = r;
    }
    out["private_key"] = take(&mut ep, "private_key").unwrap_or(json!(""));
    if let Some(a) = take(&mut ep, "address") {
        out["local_address"] = a;
    }
    if let Some(m) = take(&mut ep, "mtu") {
        out["mtu"] = m;
    }
    Some(out)
}

const UNSUPPORTED_RULE_KEYS: &[&str] = &[
    "clash_mode",
    "wifi_ssid",
    "wifi_bssid",
    "network_type",
    "network_is_expensive",
    "network_is_constrained",
    "user",
    "user_id",
    "ip_accept_any",
    "rule_set_ip_cidr_match_source",
    "rule_set_ip_cidr_accept_empty",
    "source_ip_cidr_match_source",
    "interface_address",
    "network_interface_address",
    "default_interface_address",
    "preferred_by",
    "client",
];

/// Converts a route rule; `None` drops it with a note.
fn route_rule(mut rule: Value, index: usize, notes: &mut Notes) -> Option<Value> {
    let action = rule
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("route")
        .to_string();
    match action.as_str() {
        "route" | "route-options" if rule.get("outbound").is_some() => {
            take(&mut rule, "action");
        }
        "reject" => {
            take(&mut rule, "method");
            take(&mut rule, "no_drop");
        }
        "sniff" => {
            notes.add(format!(
                "route.rules[{index}]: `sniff` action dropped (inbounds sniff by default)"
            ));
            return None;
        }
        other => {
            notes.add(format!(
                "route.rules[{index}]: action `{other}` is not supported yet; rule dropped"
            ));
            return None;
        }
    }
    for key in [
        "override_address",
        "override_port",
        "network_strategy",
        "udp_disable_domain_unmapping",
        "udp_connect",
        "udp_timeout",
        "tls_fragment",
        "tls_record_fragment",
    ] {
        take(&mut rule, key);
    }
    let outbound = take(&mut rule, "outbound");
    let action = take(&mut rule, "action");
    if !strip_unsupported(&mut rule, &format!("route.rules[{index}]"), notes) {
        return None;
    }
    if let Some(o) = outbound {
        rule["outbound"] = o;
    }
    if let Some(a) = action {
        rule["action"] = a;
    }
    Some(rule)
}

/// Removes conditions this core cannot evaluate. A rule that relied on
/// them is dropped, because matching without them would widen it.
fn strip_unsupported(rule: &mut Value, ctx: &str, notes: &mut Notes) -> bool {
    for key in UNSUPPORTED_RULE_KEYS {
        if take(rule, key).is_some() {
            notes.add(format!(
                "{ctx}: condition `{key}` is not supported; rule dropped"
            ));
            return false;
        }
    }
    if let Some(Value::Array(inner)) = rule.get_mut("rules") {
        for r in inner.iter_mut() {
            if !strip_unsupported(r, ctx, notes) {
                return false;
            }
        }
    }
    true
}

/// Legacy (`address`) and typed (sing-box 1.12+) DNS servers.
fn dns_server(mut s: Value, notes: &mut Notes) -> Option<Value> {
    let tag = s["tag"].as_str().unwrap_or("").to_string();
    let mut out = json!({"tag": tag});
    if let Some(address) = take_str(&mut s, "address") {
        if address.starts_with("dhcp://")
            || address.starts_with("quic://")
            || address.starts_with("h3://")
        {
            notes.add(format!(
                "DNS server `{tag}`: `{address}` is not supported yet; server dropped"
            ));
            return None;
        }
        out["address"] = json!(address);
    } else {
        let kind = take_str(&mut s, "type").unwrap_or_default();
        let server = take_str(&mut s, "server").unwrap_or_default();
        let port = take(&mut s, "server_port").and_then(|p| p.as_u64());
        let host = if server.contains(':') {
            format!("[{server}]")
        } else {
            server.clone()
        };
        let with_port = |default: u16| format!("{host}:{}", port.unwrap_or(default as u64));
        out["address"] = json!(match kind.as_str() {
            "udp" => format!("udp://{}", with_port(53)),
            "tcp" => format!("tcp://{}", with_port(53)),
            "tls" => format!("tls://{}", with_port(853)),
            "https" => format!(
                "https://{}{}",
                with_port(443),
                take_str(&mut s, "path").unwrap_or_else(|| "/dns-query".into())
            ),
            "local" => "local".to_string(),
            "fakeip" => "fakeip".to_string(),
            other => {
                notes.add(format!(
                    "DNS server `{tag}` of type `{other}` is not supported yet; server dropped"
                ));
                return None;
            }
        });
        if let Some(r) = take_str(&mut s, "domain_resolver") {
            out["address_resolver"] = json!(r);
        }
        if let Some(mut t) = take(&mut s, "tls") {
            if let Some(sni) = take_str(&mut t, "server_name") {
                out["tls"] = json!({"server_name": sni});
            }
        }
    }
    for key in ["detour", "address_resolver", "strategy", "client_subnet"] {
        if let Some(v) = take(&mut s, key) {
            out[key] = v;
        }
    }
    Some(out)
}

fn dns(mut d: Value, notes: &mut Notes) -> Value {
    let mut out = json!({});
    let fakeip = take(&mut d, "fakeip");
    let mut servers = Vec::new();
    if let Some(Value::Array(list)) = take(&mut d, "servers") {
        for s in list {
            if s["type"] == "fakeip" {
                let mut f = json!({});
                for k in ["inet4_range", "inet6_range"] {
                    if let Some(v) = s.get(k) {
                        f[k] = v.clone();
                    }
                }
                out["fakeip"] = f;
            }
            if let Some(s) = dns_server(s, notes) {
                servers.push(s);
            }
        }
    }
    if let Some(mut f) = fakeip {
        if f.get("enabled").and_then(Value::as_bool) != Some(false) {
            take(&mut f, "enabled");
            out["fakeip"] = f;
        }
    }
    let known: Vec<String> = servers
        .iter()
        .filter_map(|s| s["tag"].as_str().map(str::to_string))
        .collect();
    out["servers"] = json!(servers);
    let mut rules = Vec::new();
    if let Some(Value::Array(list)) = take(&mut d, "rules") {
        for (i, mut r) in list.into_iter().enumerate() {
            let action = take_str(&mut r, "action").unwrap_or_else(|| "route".into());
            if action != "route" {
                notes.add(format!(
                    "dns.rules[{i}]: action `{action}` is not supported; rule dropped"
                ));
                continue;
            }
            for key in ["disable_cache", "rewrite_ttl", "client_subnet", "strategy"] {
                take(&mut r, key);
            }
            let ok = r["server"]
                .as_str()
                .is_some_and(|s| known.iter().any(|k| k == s));
            if !ok {
                notes.add(format!(
                    "dns.rules[{i}]: server {} is not available; rule dropped",
                    r["server"]
                ));
                continue;
            }
            if strip_unsupported(&mut r, &format!("dns.rules[{i}]"), notes) {
                rules.push(r);
            }
        }
    }
    out["rules"] = json!(rules);
    if let Some(f) = take_str(&mut d, "final").filter(|f| known.contains(f)) {
        out["final"] = json!(f);
    }
    for key in ["strategy", "client_subnet"] {
        if let Some(v) = take(&mut d, key) {
            out[key] = v;
        }
    }
    if take(&mut d, "disable_cache").and_then(|v| v.as_bool()) == Some(true) {
        out["cache"] = json!({"enabled": false});
    }
    out
}

pub fn convert(mut v: Value) -> Result<Imported> {
    let mut notes = Notes::default();
    let mut out = json!({});
    if let Some(mut log) = take(&mut v, "log") {
        if log.get("disabled").and_then(Value::as_bool) == Some(true) {
            out["log"] = json!({"level": "off"});
        } else if let Some(level) = take_str(&mut log, "level") {
            out["log"] = json!({"level": if level == "fatal" || level == "panic" { "error".to_string() } else { level }});
        }
    }
    let mut inbounds = Vec::new();
    if let Some(Value::Array(list)) = take(&mut v, "inbounds") {
        inbounds.extend(list.into_iter().filter_map(|ib| inbound(ib, &mut notes)));
    }
    out["inbounds"] = json!(inbounds);

    let mut outbounds = Vec::new();
    if let Some(Value::Array(list)) = take(&mut v, "outbounds") {
        for ob in list {
            if let Some(ob) = outbound(ob, &mut notes)? {
                outbounds.push(ob);
            }
        }
    }
    if let Some(Value::Array(list)) = take(&mut v, "endpoints") {
        outbounds.extend(list.into_iter().filter_map(|ep| endpoint(ep, &mut notes)));
    }
    let tags: Vec<String> = outbounds
        .iter()
        .filter_map(|o| o["tag"].as_str().map(str::to_string))
        .collect();
    // Groups lose members that were dropped.
    for ob in outbounds.iter_mut() {
        if let Some(Value::Array(members)) = ob.get_mut("outbounds") {
            members.retain(|m| m.as_str().is_some_and(|m| tags.iter().any(|t| t == m)));
        }
    }
    out["outbounds"] = json!(outbounds);

    if let Some(mut route) = take(&mut v, "route") {
        let mut r = json!({});
        if let Some(Value::Array(rules)) = take(&mut route, "rules") {
            let converted: Vec<Value> = rules
                .into_iter()
                .enumerate()
                .filter_map(|(i, rule)| route_rule(rule, i, &mut notes))
                .filter(|rule| {
                    rule.get("outbound")
                        .and_then(Value::as_str)
                        .is_none_or(|o| tags.iter().any(|t| t == o))
                })
                .collect();
            r["rules"] = json!(converted);
        }
        if let Some(Value::Array(sets)) = take(&mut route, "rule_set") {
            r["rule_set"] = json!(sets
                .into_iter()
                .map(|mut s| {
                    take(&mut s, "http_client");
                    s
                })
                .collect::<Vec<_>>());
        }
        if let Some(f) = take_str(&mut route, "final").filter(|f| tags.contains(f)) {
            r["final"] = json!(f);
        }
        for key in ["geosite", "geoip"] {
            if take(&mut route, key).is_some() {
                notes.add(format!("route.{key}: sing-box geo databases are not supported; use rule-sets or Xray .dat files"));
            }
        }
        out["route"] = r;
    }
    if let Some(d) = take(&mut v, "dns") {
        let converted = dns(d, &mut notes);
        if converted["servers"]
            .as_array()
            .is_some_and(|s| !s.is_empty())
        {
            out["dns"] = converted;
        }
    }
    for key in [
        "experimental",
        "ntp",
        "certificate",
        "services",
        "providers",
    ] {
        if take(&mut v, key).is_some() {
            notes.add(format!("`{key}` is not supported and was ignored"));
        }
    }
    let config: Config = serde_json::from_value(out).context("converted sing-box config")?;
    config.validate().context("converted sing-box config")?;
    Ok(Imported {
        config,
        warnings: notes.0,
    })
}
