//! End-to-end tests of the local proxy inbound, the dispatcher and the
//! control API, all inside one process and on loopback only.

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::{json, Value};
use sybau_core::{Engine, EngineOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Minimal HTTP origin: answers every request with its own request line.
async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    if s.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                        return;
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let body = head.lines().next().unwrap_or_default().to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    addr
}

async fn spawn_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            sock.send_to(&buf[..n], from).await.unwrap();
        }
    });
    addr
}

async fn start(config: Value) -> Engine {
    let engine = Engine::new(EngineOptions {
        profile: "test".into(),
        ..Default::default()
    });
    engine
        .start(serde_json::from_value(config).unwrap())
        .await
        .unwrap();
    engine
}

async fn read_response(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

/// A refused connection is closed without a response. Depending on the
/// platform the client sees a clean EOF or a reset (Windows resets when
/// the proxy closes a socket that still has unread request bytes).
async fn assert_refused(s: &mut TcpStream) {
    let mut out = Vec::new();
    match tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out))
        .await
        .unwrap()
    {
        Ok(_) => assert!(
            out.is_empty(),
            "unexpected data: {:?}",
            String::from_utf8_lossy(&out)
        ),
        Err(e) => assert!(
            matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ),
            "unexpected error: {e}"
        ),
    }
}

async fn socks5_connect(
    proxy: u16,
    target: SocketAddr,
    auth: Option<(&str, &str)>,
) -> Result<TcpStream, String> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    let method = if auth.is_some() { 2 } else { 0 };
    s.write_all(&[5, 1, method]).await.unwrap();
    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).await.map_err(|e| e.to_string())?;
    if rep != [5, method] {
        return Err(format!("method rejected: {rep:?}"));
    }
    if let Some((u, p)) = auth {
        let mut m = vec![1, u.len() as u8];
        m.extend_from_slice(u.as_bytes());
        m.push(p.len() as u8);
        m.extend_from_slice(p.as_bytes());
        s.write_all(&m).await.unwrap();
        s.read_exact(&mut rep).await.map_err(|e| e.to_string())?;
        if rep != [1, 0] {
            return Err("auth failed".into());
        }
    }
    let SocketAddr::V4(v4) = target else {
        panic!("ipv4 only")
    };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.map_err(|e| e.to_string())?;
    if rep[1] != 0 {
        return Err(format!("connect failed: {}", rep[1]));
    }
    Ok(s)
}

#[tokio::test]
async fn socks5_http_connect_and_plain_http() {
    let origin = spawn_origin().await;
    let port = free_port();
    let engine = start(json!({
        "inbounds": [{"type": "mixed", "tag": "in", "port": port}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }))
    .await;

    // SOCKS5 CONNECT
    let mut s = socks5_connect(port, origin, None).await.unwrap();
    s.write_all(b"GET /socks5 HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert!(read_response(&mut s)
        .await
        .ends_with("GET /socks5 HTTP/1.1"));
    drop(s);

    // SOCKS4
    let SocketAddr::V4(v4) = origin else {
        unreachable!()
    };
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut req = vec![4, 1];
    req.extend_from_slice(&v4.port().to_be_bytes());
    req.extend_from_slice(&v4.ip().octets());
    req.push(0);
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 8];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x5a);
    s.write_all(b"GET /socks4 HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert!(read_response(&mut s)
        .await
        .ends_with("GET /socks4 HTTP/1.1"));
    drop(s);

    // HTTP CONNECT
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut rep = [0u8; 39];
    s.read_exact(&mut rep).await.unwrap();
    assert!(rep.starts_with(b"HTTP/1.1 200"));
    s.write_all(b"GET /connect HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert!(read_response(&mut s)
        .await
        .ends_with("GET /connect HTTP/1.1"));
    drop(s);

    // Plain HTTP through the proxy: the absolute URI becomes origin form.
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(format!("GET http://{origin}/plain?q=1 HTTP/1.1\r\nHost: {origin}\r\nProxy-Connection: keep-alive\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(read_response(&mut s)
        .await
        .ends_with("GET /plain?q=1 HTTP/1.1"));
    drop(s);

    // Statistics saw the traffic and no connection is left behind.
    let stats = engine.call("stats.get", &Value::Null).await.unwrap();
    assert!(stats["up"].as_u64().unwrap() > 0 && stats["down"].as_u64().unwrap() > 0);
    assert!(stats["outbounds"]["direct"]["down"].as_u64().unwrap() > 0);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        engine.call("connections.list", &Value::Null).await.unwrap(),
        json!([])
    );
    engine.stop().await;
}

#[tokio::test]
async fn socks5_udp_associate() {
    let echo = spawn_udp_echo().await;
    let port = free_port();
    let engine = start(json!({ "inbounds": [{"type": "socks", "port": port}] })).await;

    let mut ctrl = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    ctrl.write_all(&[5, 1, 0]).await.unwrap();
    let mut rep = [0u8; 2];
    ctrl.read_exact(&mut rep).await.unwrap();
    ctrl.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut rep = [0u8; 10];
    ctrl.read_exact(&mut rep).await.unwrap();
    assert_eq!(&rep[..4], &[5, 0, 0, 1]);
    let relay = SocketAddr::from((
        [rep[4], rep[5], rep[6], rep[7]],
        u16::from_be_bytes([rep[8], rep[9]]),
    ));

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(v4) = echo else {
        unreachable!()
    };
    for payload in [&b"first"[..], &b"second datagram"[..]] {
        let mut pkt = vec![0, 0, 0, 1];
        pkt.extend_from_slice(&v4.ip().octets());
        pkt.extend_from_slice(&v4.port().to_be_bytes());
        pkt.extend_from_slice(payload);
        sock.send_to(&pkt, relay).await.unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        // RSV RSV FRAG ATYP(1) ip(4) port(2) payload
        assert_eq!(&buf[..4], &[0, 0, 0, 1]);
        assert_eq!(&buf[4..8], &v4.ip().octets());
        assert_eq!(&buf[10..n], payload);
    }
    let conns = engine.call("connections.list", &Value::Null).await.unwrap();
    assert_eq!(conns[0]["network"], "udp");

    // Closing the TCP control connection ends the association.
    drop(ctrl);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        engine.call("connections.list", &Value::Null).await.unwrap(),
        json!([])
    );
    engine.stop().await;
}

#[tokio::test]
async fn authentication_is_enforced() {
    let origin = spawn_origin().await;
    let port = free_port();
    let engine = start(json!({
        "inbounds": [{"type": "mixed", "port": port, "users": [{"username": "u", "password": "p"}]}],
    }))
    .await;

    assert!(socks5_connect(port, origin, None).await.is_err());
    assert!(socks5_connect(port, origin, Some(("u", "wrong")))
        .await
        .is_err());
    let mut s = socks5_connect(port, origin, Some(("u", "p")))
        .await
        .unwrap();
    s.write_all(b"GET /auth HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert!(read_response(&mut s).await.ends_with("GET /auth HTTP/1.1"));

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(format!("CONNECT {origin} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(read_response(&mut s).await.starts_with("HTTP/1.1 407"));

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // "u:p" in base64
    s.write_all(
        format!("GET http://{origin}/ok HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    assert!(read_response(&mut s).await.ends_with("GET /ok HTTP/1.1"));
    engine.stop().await;
}

#[tokio::test]
async fn block_outbound_and_reload() {
    let origin = spawn_origin().await;
    let port = free_port();
    let engine = start(json!({
        "inbounds": [{"type": "mixed", "port": port}],
        "outbounds": [{"type": "block", "tag": "block"}, {"type": "direct", "tag": "direct"}],
        "route": {"final": "block"},
    }))
    .await;

    let mut s = socks5_connect(port, origin, None).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    assert_refused(&mut s).await;

    // A broken config is rejected and the old one keeps running.
    let bad = json!({ "config": { "outbounds": [{"type": "direct", "tag": "a"}], "route": {"final": "missing"} } });
    assert!(engine.call("core.reload", &bad).await.is_err());
    assert!(engine.is_running().await);
    let mut s = socks5_connect(port, origin, None).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    assert_refused(&mut s).await;

    // A good config on the same port takes over.
    let good = json!({ "config": {
        "inbounds": [{"type": "mixed", "port": port}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }});
    engine.call("core.reload", &good).await.unwrap();
    let mut s = socks5_connect(port, origin, None).await.unwrap();
    s.write_all(b"GET /reloaded HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(read_response(&mut s)
        .await
        .ends_with("GET /reloaded HTTP/1.1"));

    let list = engine.call("outbounds.list", &Value::Null).await.unwrap();
    assert_eq!(list[0]["tag"], "direct");
    assert_eq!(list[0]["final"], true);
    engine.stop().await;
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn control_channel_over_unix_socket() {
    use sybau_core::control;
    let dir = std::env::temp_dir().join(format!("sybau-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let endpoint = dir.join("ctl.sock").to_string_lossy().into_owned();
    let engine = start(json!({})).await;
    let cancel = engine.stop_token().child_token();
    let task = control::serve(engine.clone(), &endpoint, cancel.clone()).unwrap();

    let v = control::request(&endpoint, "core.version", Value::Null)
        .await
        .unwrap();
    assert_eq!(v["name"], "SYBAU-CORE");
    assert!(control::request(&endpoint, "no.such.method", Value::Null)
        .await
        .is_err());

    // Subscription: the response comes first, then periodic notifications.
    let mut lines = Vec::new();
    let _ = tokio::time::timeout(
        Duration::from_millis(450),
        control::follow(
            &endpoint,
            "stats.subscribe",
            json!({"interval_ms": 100}),
            |l| lines.push(l.to_string()),
        ),
    )
    .await;
    assert!(lines[0].contains("\"subscribed\":true"));
    assert!(lines.len() >= 3 && lines[1].contains("\"method\":\"stats\""));

    control::request(&endpoint, "core.stop", Value::Null)
        .await
        .unwrap();
    assert!(engine.stop_token().is_cancelled());
    cancel.cancel();
    task.await.unwrap();
    assert!(!std::path::Path::new(&endpoint).exists());
    engine.stop().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn detour_chain_and_cycle_detection() {
    let origin = spawn_origin().await;
    let port = free_port();
    let engine = start(json!({
        "inbounds": [{"type": "mixed", "port": port}],
        "outbounds": [
            {"type": "direct", "tag": "first", "detour": "second"},
            {"type": "direct", "tag": "second"},
        ],
        "route": {"final": "first"},
    }))
    .await;
    let mut s = socks5_connect(port, origin, None).await.unwrap();
    s.write_all(b"GET /chain HTTP/1.1\r\n\r\n").await.unwrap();
    assert!(read_response(&mut s).await.ends_with("GET /chain HTTP/1.1"));
    engine.stop().await;

    let looped = Engine::new(EngineOptions::default());
    let cfg = serde_json::from_value(json!({
        "outbounds": [
            {"type": "direct", "tag": "a", "detour": "b"},
            {"type": "direct", "tag": "b", "detour": "a"},
        ],
    }))
    .unwrap();
    let err = looped.start(cfg).await.unwrap_err();
    assert!(format!("{err:#}").contains("outbound cycle"), "{err:#}");
}

#[tokio::test]
async fn control_api_converts_configs_and_subscriptions() {
    let engine = start(json!({})).await;
    let sub = "vless://id@1.2.3.4:443?security=tls&sni=a.example#A\ntrojan://pw@b.example:443#B";
    let r = engine
        .call("subscriptions.parse", &json!({"content": sub}))
        .await
        .unwrap();
    assert_eq!(r["outbounds"].as_array().unwrap().len(), 2);
    assert_eq!(r["outbounds"][1]["tag"], "B");

    let xray =
        r#"{"outbounds": [{"protocol": "freedom", "tag": "direct"}], "routing": {"rules": []}}"#;
    let r = engine
        .call("config.convert", &json!({"text": xray}))
        .await
        .unwrap();
    assert_eq!(r["config"]["outbounds"][0]["type"], "direct");
    assert!(engine
        .call("config.convert", &json!({"text": "{", "from": "xray"}))
        .await
        .is_err());
    engine.stop().await;
}
