//! Routing end to end: sniffing, rules, rule-sets, geo files, process
//! rules, rejection, destination override and domain strategy.
//!
//! Two `direct` outbounds `a` (final) and `b` reach the same local
//! servers; per-outbound traffic counters show which one was used.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use serde_json::{json, Value};
use sybau_core::{Engine, EngineOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

fn tls_client_hello(sni: &str) -> Vec<u8> {
    use sybau_tls::fingerprint::{ClientHello, Fingerprint, HelloParams};
    let hello = ClientHello::build(
        &Fingerprint::by_name("chrome").unwrap(),
        &HelloParams {
            server_name: sni.into(),
            alpn: None,
        },
    );
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(hello.raw.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello.raw);
    record
}

#[tokio::test]
async fn domain_rules_use_sniffed_http_host_and_tls_sni() {
    let echo = spawn_echo().await;
    let core = start(
        json!({"final": "a", "rules": [
            {"domain_suffix": ["to-b.test"], "outbound": "b"},
            {"domain_keyword": "kw-b", "outbound": "b"},
        ]}),
        json!({}),
    )
    .await;
    let p = echo.port();
    assert_eq!(
        core.which("127.0.0.1", p, &http_request("www.to-b.test"))
            .await,
        Some("b")
    );
    assert_eq!(
        core.which("127.0.0.1", p, &http_request("other.test"))
            .await,
        Some("a")
    );
    assert_eq!(
        core.which("127.0.0.1", p, &tls_client_hello("api.to-b.test"))
            .await,
        Some("b")
    );
    assert_eq!(
        core.which("127.0.0.1", p, &tls_client_hello("x-kw-b-y.example"))
            .await,
        Some("b")
    );
    assert_eq!(
        core.which("127.0.0.1", p, &tls_client_hello("example.org"))
            .await,
        Some("a")
    );
    // Unknown protocol: only the IP target is known.
    assert_eq!(
        core.which("127.0.0.1", p, b"\x00\x01binary").await,
        Some("a")
    );
    core.engine.stop().await;
}

#[tokio::test]
async fn sniffing_can_be_disabled() {
    let echo = spawn_echo().await;
    let core = start(
        json!({"final": "a", "rules": [{"domain_suffix": "to-b.test", "outbound": "b"}]}),
        json!({"enabled": false}),
    )
    .await;
    assert_eq!(
        core.which("127.0.0.1", echo.port(), &http_request("www.to-b.test"))
            .await,
        Some("a")
    );
    core.engine.stop().await;
}

#[tokio::test]
async fn ip_port_protocol_logical_and_reject() {
    let echo = spawn_echo().await;
    let p = echo.port();
    let core = start(
        json!({"final": "a", "rules": [
            {"protocol": "bittorrent", "action": "reject"},
            {"type": "logical", "mode": "and", "rules": [{"protocol": "http"}, {"port": p}], "outbound": "b"},
            {"ip_cidr": "127.0.0.0/8", "port_range": format!("{}:{}", p, p), "network": "udp", "outbound": "b"},
        ]}),
        json!({}),
    )
    .await;
    assert_eq!(
        core.which("127.0.0.1", p, &http_request("x.test")).await,
        Some("b")
    );
    assert_eq!(
        core.which("127.0.0.1", p, b"plain text\r\n").await,
        Some("a"),
        "tcp is not udp"
    );
    let mut bt = b"\x13BitTorrent protocol".to_vec();
    bt.extend_from_slice(&[0u8; 48]);
    assert_eq!(core.which("127.0.0.1", p, &bt).await, None, "rejected");
    core.engine.stop().await;
}

#[tokio::test]
async fn geosite_geoip_and_rule_sets_from_files() {
    let echo = spawn_echo().await;
    let p = echo.port();
    let core = start(
        json!({
            "final": "a",
            "geosite": fixture("geosite.dat"),
            "geoip": fixture("geoip.dat"),
            "rule_set": [
                {"tag": "srs", "type": "local", "path": fixture("rs-v3-0.srs")},
                {"tag": "inline", "type": "inline", "rules": [{"domain_keyword": "inline-hit"}]},
            ],
            "rules": [
                {"geosite": "test@ads", "outbound": "b"},
                {"rule_set": ["srs", "inline"], "outbound": "b"},
                {"geoip": "test", "port": 1, "outbound": "b"},
            ]
        }),
        json!({}),
    )
    .await;
    assert_eq!(
        core.which("127.0.0.1", p, &http_request("x.ads.example.net"))
            .await,
        Some("b")
    );
    assert_eq!(
        core.which("127.0.0.1", p, &http_request("my-keyword-hit.io"))
            .await,
        Some("a"),
        "not tagged ads"
    );
    assert_eq!(
        core.which("127.0.0.1", p, &http_request("a.b.suffix.example.org"))
            .await,
        Some("b"),
        "from .srs"
    );
    assert_eq!(
        core.which("127.0.0.1", p, &http_request("my-inline-hit.io"))
            .await,
        Some("b"),
        "inline set"
    );
    assert_eq!(
        core.which("127.0.0.1", p, &http_request("nothing.example"))
            .await,
        Some("a")
    );
    core.engine.stop().await;

    // A missing geo file is a configuration error, not a silent miss.
    let engine = Engine::new(EngineOptions::default());
    let bad = json!({"route": {"geosite": "/nonexistent/geosite.dat", "rules": [{"geosite": "cn", "outbound": "direct"}]}});
    assert!(engine
        .start(serde_json::from_value(bad).unwrap())
        .await
        .is_err());
}

#[tokio::test]
async fn process_rules_see_the_local_application() {
    let echo = spawn_echo().await;
    let exe = std::env::current_exe().unwrap();
    let name = exe.file_name().unwrap().to_string_lossy().into_owned();
    let core = start(
        json!({"final": "a", "rules": [{"process_name": name, "outbound": "b"}]}),
        json!({}),
    )
    .await;
    assert_eq!(
        core.which("127.0.0.1", echo.port(), b"from this process")
            .await,
        Some("b")
    );
    core.engine.stop().await;

    let core = start(
        json!({"final": "a", "rules": [{"process_name": "someone-else.exe", "outbound": "b"}]}),
        json!({}),
    )
    .await;
    assert_eq!(
        core.which("127.0.0.1", echo.port(), b"from this process")
            .await,
        Some("a")
    );
    core.engine.stop().await;
}

#[tokio::test]
async fn override_destination_replaces_ip_with_sniffed_domain() {
    let echo = spawn_echo().await;
    let core = start(json!({"final": "a"}), json!({"override_destination": true})).await;
    let mut s = core.connect("127.0.0.1", echo.port()).await;
    s.write_all(&http_request("localhost")).await.unwrap();
    let mut got = [0u8; 10];
    s.read_exact(&mut got).await.unwrap();
    let conns = core
        .engine
        .call("connections.list", &Value::Null)
        .await
        .unwrap();
    assert_eq!(conns[0]["target"], format!("localhost:{}", echo.port()));
    assert_eq!(conns[0]["host"], "localhost");
    drop(s);
    core.engine.stop().await;
}

#[tokio::test]
async fn domain_strategy_resolves_for_ip_rules() {
    let echo = spawn_echo().await;
    let p = echo.port();
    let rules = json!([{"ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "b"}]);
    for (strategy, expect) in [
        ("as_is", "a"),
        ("ip_if_non_match", "b"),
        ("ip_on_demand", "b"),
    ] {
        let core = start(
            json!({"final": "a", "domain_strategy": strategy, "rules": rules.clone()}),
            json!({"enabled": false}),
        )
        .await;
        assert_eq!(
            core.which("localhost", p, b"resolve me").await,
            Some(expect),
            "{strategy}"
        );
        core.engine.stop().await;
    }
}

#[tokio::test]
async fn udp_is_sniffed_and_routed() {
    let echo = spawn_udp_echo().await;
    let core = start(
        json!({"final": "a", "rules": [{"protocol": "dns", "network": "udp", "outbound": "b"}]}),
        json!({}),
    )
    .await;

    let mut ctrl = TcpStream::connect(("127.0.0.1", core.port)).await.unwrap();
    ctrl.write_all(&[5, 1, 0]).await.unwrap();
    let mut rep = [0u8; 2];
    ctrl.read_exact(&mut rep).await.unwrap();
    ctrl.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut rep = [0u8; 10];
    ctrl.read_exact(&mut rep).await.unwrap();
    let relay = SocketAddr::from((
        [rep[4], rep[5], rep[6], rep[7]],
        u16::from_be_bytes([rep[8], rep[9]]),
    ));

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    let mut pkt = vec![0, 0, 0, 1, 127, 0, 0, 1];
    pkt.extend_from_slice(&echo.port().to_be_bytes());
    pkt.extend_from_slice(&query);
    sock.send_to(&pkt, relay).await.unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[10..n], &query[..]);
    assert!(core.down("b").await > 0 && core.down("a").await == 0);
    let conns = core
        .engine
        .call("connections.list", &Value::Null)
        .await
        .unwrap();
    assert_eq!(conns[0]["outbound"], "b");
    drop(ctrl);
    core.engine.stop().await;
}
