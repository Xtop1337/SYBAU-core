//! DNS module end to end against local test servers whose answers are
//! assembled byte by byte, independently of the core's own encoder.

mod common;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use common::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// What a test server knows and saw.
#[derive(Clone, Default)]
struct Zone {
    /// name -> IPv4 answers.
    a: HashMap<String, Vec<Ipv4Addr>>,
    /// Names answered over UDP with the TC bit and no records.
    truncate: Vec<String>,
    /// Raw queries received.
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// Name and question length of a query, read by hand.
fn question(query: &[u8]) -> (String, u16, usize) {
    let mut pos = 12;
    let mut labels = Vec::new();
    while query[pos] != 0 {
        let len = query[pos] as usize;
        labels.push(String::from_utf8_lossy(&query[pos + 1..pos + 1 + len]).to_ascii_lowercase());
        pos += 1 + len;
    }
    let qtype = u16::from_be_bytes([query[pos + 1], query[pos + 2]]);
    (labels.join("."), qtype, pos + 5 - 12)
}

impl Zone {
    fn answer(&self, query: &[u8], udp: bool) -> Vec<u8> {
        self.seen.lock().unwrap().push(query.to_vec());
        let (name, qtype, qlen) = question(query);
        let truncated = udp && self.truncate.contains(&name);
        let ips: Vec<Ipv4Addr> = if qtype == 1 && !truncated {
            self.a.get(&name).cloned().unwrap_or_default()
        } else {
            vec![]
        };
        let rcode = if self.a.contains_key(&name) || self.truncate.contains(&name) {
            0
        } else {
            3
        };
        let mut out = Vec::new();
        out.extend_from_slice(&query[..2]);
        let flags: u16 = 0x8180 | if truncated { 0x0200 } else { 0 } | rcode;
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&(ips.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&query[12..12 + qlen]);
        for ip in ips {
            // Pointer to the question name, type A, class IN, TTL 300.
            out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x01, 0x2c, 0, 4]);
            out.extend_from_slice(&ip.octets());
        }
        out
    }

    fn count(&self, name: &str) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|q| question(q).0 == name)
            .count()
    }
}

async fn serve_udp(zone: Zone) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            let reply = zone.answer(&buf[..n], true);
            sock.send_to(&reply, from).await.unwrap();
        }
    });
    addr
}

async fn serve_stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut s: S,
    zone: Zone,
) {
    while let Ok(len) = s.read_u16().await {
        let mut q = vec![0u8; len as usize];
        if s.read_exact(&mut q).await.is_err() {
            return;
        }
        let reply = zone.answer(&q, false);
        let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        if s.write_all(&framed).await.is_err() {
            return;
        }
    }
}

/// TCP on the same port number as UDP is not guaranteed free; use the
/// listener's own port and return it.
async fn serve_tcp(zone: Zone) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            tokio::spawn(serve_stream(s, zone.clone()));
        }
    });
    addr
}

struct Cert {
    acceptor_config: Arc<rustls::ServerConfig>,
    pin: String,
}

fn cert(alpn: &[&[u8]]) -> Cert {
    let generated = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
    let der = generated.cert.der().clone();
    let pin: String = Sha256::digest(der.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(generated.key_pair.serialize_der().into());
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der], key)
    .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Cert {
        acceptor_config: Arc::new(cfg),
        pin,
    }
}

async fn serve_dot(zone: Zone, cert: &Cert) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(cert.acceptor_config.clone());
    tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            let (acceptor, zone) = (acceptor.clone(), zone.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(s).await {
                    serve_stream(tls, zone).await;
                }
            });
        }
    });
    addr
}

async fn serve_doh(zone: Zone, cert: &Cert) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(cert.acceptor_config.clone());
    tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            let (acceptor, zone) = (acceptor.clone(), zone.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(s).await else {
                    return;
                };
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let zone = zone.clone();
                    tokio::spawn(async move {
                        let ok = req.method() == http::Method::POST
                            && req.uri().path() == "/dns-query"
                            && req.headers()["content-type"] == "application/dns-message";
                        let mut body = req.into_body();
                        let mut query = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            query.extend_from_slice(&chunk);
                        }
                        let status = if ok { 200 } else { 400 };
                        let resp = http::Response::builder()
                            .status(status)
                            .header("content-type", "application/dns-message")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(resp, false).unwrap();
                        let reply = if ok {
                            zone.answer(&query, false)
                        } else {
                            vec![]
                        };
                        let _ = send.send_data(reply.into(), true);
                    });
                }
            });
        }
    });
    addr
}

fn zone(entries: &[(&str, [u8; 4])]) -> Zone {
    let mut z = Zone::default();
    for (name, ip) in entries {
        z.a.entry(name.to_string())
            .or_default()
            .push(Ipv4Addr::from(*ip));
    }
    z
}

async fn query(core: &Core, name: &str, qtype: &str) -> Value {
    core.engine
        .call("dns.query", &json!({"name": name, "type": qtype}))
        .await
        .unwrap()
}

fn addresses(reply: &Value) -> Vec<String> {
    reply["answers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["data"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn udp_with_tcp_fallback_cache_and_client_subnet() {
    let mut z = zone(&[("a.test", [10, 0, 0, 1]), ("big.test", [10, 0, 0, 9])]);
    z.truncate = vec!["big.test".into()];
    let udp = serve_udp(z.clone()).await;
    // TCP fallback goes to the same address: serve TCP there too.
    let tcp = TcpListener::bind(udp).await.unwrap();
    let z2 = z.clone();
    tokio::spawn(async move {
        loop {
            let (s, _) = tcp.accept().await.unwrap();
            tokio::spawn(serve_stream(s, z2.clone()));
        }
    });
    let core = start_config(json!({
        "dns": {"servers": [{"tag": "u", "address": format!("udp://{udp}")}], "client_subnet": "203.0.113.0/24"},
    }))
    .await;

    assert_eq!(addresses(&query(&core, "a.test", "A").await), ["10.0.0.1"]);
    assert_eq!(addresses(&query(&core, "a.test", "A").await), ["10.0.0.1"]);
    assert_eq!(z.count("a.test"), 1, "second answer comes from the cache");
    let q = sybau_dns::Message::parse(&z.seen.lock().unwrap()[0]).unwrap();
    assert_eq!(q.client_subnet.unwrap().addr.to_string(), "203.0.113.0");

    assert_eq!(
        addresses(&query(&core, "big.test", "A").await),
        ["10.0.0.9"],
        "TC bit leads to TCP"
    );
    assert_eq!(z.count("big.test"), 2);

    assert_eq!(query(&core, "missing.test", "A").await["rcode"], 3);
    core.engine.call("dns.flush", &Value::Null).await.unwrap();
    query(&core, "a.test", "A").await;
    assert_eq!(z.count("a.test"), 2, "flushed");
    core.engine.stop().await;
}

#[tokio::test]
async fn rules_pick_servers_and_hosts_answer_locally() {
    let near = zone(&[
        ("site.ru", [10, 0, 0, 2]),
        ("x.ads.example.net", [10, 0, 0, 2]),
    ]);
    let far = zone(&[("site.ru", [10, 0, 0, 1]), ("site.com", [10, 0, 0, 1])]);
    let (near_addr, far_addr) = (serve_udp(near.clone()).await, serve_udp(far.clone()).await);
    let tcp = serve_tcp(far.clone()).await;
    let core = start_config(json!({
        "route": {"geosite": fixture("geosite.dat")},
        "dns": {
            "servers": [
                {"tag": "far", "address": format!("udp://{far_addr}")},
                {"tag": "near", "address": format!("udp://{near_addr}")},
                {"tag": "tcp", "address": format!("tcp://{tcp}")},
            ],
            "rules": [
                {"domain_suffix": ["ru"], "server": "near"},
                {"geosite": "test@ads", "server": "near"},
                {"domain": "site.com", "query_type": "A", "server": "tcp"},
            ],
            "hosts": {"router.lan": ["192.168.1.1", "fd00::1"]},
        },
    }))
    .await;
    assert_eq!(addresses(&query(&core, "site.ru", "A").await), ["10.0.0.2"]);
    assert_eq!(
        addresses(&query(&core, "x.ads.example.net", "A").await),
        ["10.0.0.2"]
    );
    assert_eq!(
        addresses(&query(&core, "site.com", "A").await),
        ["10.0.0.1"]
    );
    assert_eq!(
        far.count("site.com"),
        1,
        "answered over TCP by the same zone"
    );
    assert_eq!(
        addresses(&query(&core, "router.lan", "A").await),
        ["192.168.1.1"]
    );
    assert_eq!(
        addresses(&query(&core, "router.lan", "AAAA").await),
        ["fd00::1"]
    );
    assert_eq!(near.count("router.lan") + far.count("router.lan"), 0);
    core.engine.stop().await;
}

#[tokio::test]
async fn dot_and_doh_with_pinned_certificates() {
    let z = zone(&[("secure.test", [10, 9, 9, 9])]);
    let dot_cert = cert(&[]);
    let doh_cert = cert(&[b"h2"]);
    let dot = serve_dot(z.clone(), &dot_cert).await;
    let doh = serve_doh(z.clone(), &doh_cert).await;
    let core = start_config(json!({
        "dns": {
            "servers": [
                {"tag": "dot", "address": format!("tls://{dot}"), "tls": {"server_name": "dns.test", "pinned_cert_sha256": [dot_cert.pin]}},
                {"tag": "doh", "address": format!("https://{doh}/dns-query"), "tls": {"server_name": "dns.test", "pinned_cert_sha256": [doh_cert.pin]}},
                {"tag": "bad", "address": format!("tls://{dot}"), "tls": {"server_name": "dns.test"}},
            ],
            "rules": [{"domain": "secure.test", "query_type": "AAAA", "server": "doh"}, {"domain_keyword": "fail", "server": "bad"}],
            "cache": {"enabled": false},
        },
    }))
    .await;
    assert_eq!(
        addresses(&query(&core, "secure.test", "A").await),
        ["10.9.9.9"],
        "DoT"
    );
    let before = z.count("secure.test");
    assert_eq!(query(&core, "secure.test", "AAAA").await["rcode"], 0, "DoH");
    assert_eq!(z.count("secure.test"), before + 1);
    // An unpinned self-signed certificate is not trusted.
    assert_eq!(query(&core, "fail.test", "A").await["rcode"], 2);
    core.engine.stop().await;
}

#[tokio::test]
async fn direct_outbound_resolves_through_the_dns_module_with_strategy() {
    let echo = spawn_echo().await;
    let z = zone(&[("echo.test", [127, 0, 0, 1])]);
    let udp = serve_udp(z.clone()).await;
    let core = start_config(json!({
        "outbounds": [{"type": "direct", "tag": "a"}, {"type": "direct", "tag": "b"}],
        "dns": {"servers": [{"tag": "u", "address": format!("udp://{udp}")}], "strategy": "ipv4_only"},
    }))
    .await;
    assert_eq!(
        core.which("echo.test", echo.port(), b"via dns").await,
        Some("a")
    );
    let seen: Vec<u16> = z
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|q| question(q).1)
        .collect();
    assert_eq!(seen, [1], "ipv4_only asks for A only");
    core.engine.stop().await;
}

#[tokio::test]
async fn fake_ip_maps_back_to_the_domain() {
    let echo = spawn_echo().await;
    let z = zone(&[("fake.test", [127, 0, 0, 1])]);
    let udp = serve_udp(z.clone()).await;
    let core = start_config(json!({
        "outbounds": [{"type": "direct", "tag": "a"}, {"type": "direct", "tag": "b"}],
        "route": {"final": "a", "rules": [{"domain": "fake.test", "outbound": "b"}]},
        "dns": {
            "servers": [{"tag": "real", "address": format!("udp://{udp}")}, {"tag": "fake", "address": "fakeip"}],
            "rules": [{"query_type": ["A", "AAAA"], "server": "fake"}],
            "fakeip": {"inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"},
        },
    }))
    .await;
    let reply = query(&core, "fake.test", "A").await;
    let fake = addresses(&reply)[0].clone();
    assert!(fake.starts_with("198.18."), "{reply}");
    assert_eq!(reply["answers"][0]["ttl"], 1);
    // The application connects to the fake address; the core routes by
    // domain and dials the real address it resolves internally.
    assert_eq!(
        core.which(&fake, echo.port(), b"through fake ip").await,
        Some("b")
    );
    // The internal lookup (A and AAAA) went to the real server.
    let types: Vec<u16> = z
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|q| question(q).1)
        .collect();
    assert_eq!(types.len(), 2, "{types:?}");
    assert!(types.contains(&1) && types.contains(&28));
    // An unassigned fake address is refused.
    assert_eq!(
        core.which("198.19.200.200", echo.port(), b"nobody").await,
        None
    );
    core.engine.stop().await;
}

#[tokio::test]
async fn invalid_dns_configs_are_rejected() {
    let engine = sybau_core::Engine::new(Default::default());
    for bad in [
        json!({"dns": {"servers": []}}),
        json!({"dns": {"servers": [{"tag": "a", "address": "quic://x"}]}}),
        json!({"dns": {"servers": [{"tag": "a", "address": "1.1.1.1"}], "final": "b"}}),
        json!({"dns": {"servers": [{"tag": "a", "address": "1.1.1.1"}], "rules": [{"domain": "x", "server": "zz"}]}}),
        json!({"dns": {"servers": [{"tag": "a", "address": "1.1.1.1"}], "strategy": "ipv5"}}),
        json!({"dns": {"servers": [{"tag": "a", "address": "1.1.1.1", "detour": "nope"}]}}),
        json!({"dns": {"servers": [{"tag": "a", "address": "1.1.1.1"}], "hosts": {"x": ["not-ip"]}}}),
    ] {
        assert!(
            engine
                .start(serde_json::from_value(bad.clone()).unwrap())
                .await
                .is_err(),
            "{bad}"
        );
    }
}
