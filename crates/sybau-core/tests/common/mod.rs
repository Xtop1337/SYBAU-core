//! Helpers shared by the integration tests.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};
use sybau_core::{Engine, EngineOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../sybau-route/tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// Accepts connections, keeps them open and echoes what arrives.
pub async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

pub async fn spawn_udp_echo() -> SocketAddr {
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

pub struct Core {
    pub engine: Engine,
    pub port: u16,
}

/// Starts a core with a mixed inbound `in` on a free port; `config` is
/// completed with that inbound unless it defines its own.
pub async fn start_config(mut config: Value) -> Core {
    let port = free_port();
    if config.get("inbounds").is_none() {
        config["inbounds"] = json!([{"type": "mixed", "tag": "in", "port": port}]);
    } else {
        config["inbounds"][0]["port"] = json!(port);
    }
    let engine = Engine::new(EngineOptions::default());
    engine
        .start(serde_json::from_value(config).unwrap())
        .await
        .unwrap();
    Core { engine, port }
}

/// Core with two direct outbounds `a` (first, so the default final) and `b`.
pub async fn start(route: Value, sniff: Value) -> Core {
    start_config(json!({
        "inbounds": [{"type": "mixed", "tag": "in", "port": 0, "sniff": sniff}],
        "outbounds": [{"type": "direct", "tag": "a"}, {"type": "direct", "tag": "b"}],
        "route": route,
    }))
    .await
}

impl Core {
    pub async fn down(&self, tag: &str) -> u64 {
        let stats = self.engine.call("stats.get", &Value::Null).await.unwrap();
        stats["outbounds"][tag]["down"].as_u64().unwrap_or(0)
    }

    /// SOCKS5 CONNECT to `host:port` (domain or IP literal).
    pub async fn connect(&self, host: &str, port: u16) -> TcpStream {
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut rep = [0u8; 2];
        s.read_exact(&mut rep).await.unwrap();
        let mut req = vec![5, 1, 0];
        match host.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => {
                req.push(1);
                req.extend_from_slice(&ip.octets());
            }
            Err(_) => {
                req.extend_from_slice(&[3, host.len() as u8]);
                req.extend_from_slice(host.as_bytes());
            }
        }
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        s
    }

    /// Sends `payload` through the proxy to the echo server and returns
    /// the tag (`a` or `b`) whose counters grew, or `None` if refused.
    pub async fn which(&self, host: &str, port: u16, payload: &[u8]) -> Option<&'static str> {
        let (a0, b0) = (self.down("a").await, self.down("b").await);
        let mut s = self.connect(host, port).await;
        s.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        let ok = tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got))
            .await
            .is_ok_and(|r| r.is_ok());
        drop(s);
        tokio::time::sleep(Duration::from_millis(50)).await;
        if !ok {
            return None;
        }
        assert_eq!(got, payload);
        let (a1, b1) = (self.down("a").await, self.down("b").await);
        match (a1 > a0, b1 > b0) {
            (true, false) => Some("a"),
            (false, true) => Some("b"),
            other => panic!("unexpected counters {other:?}"),
        }
    }
}

pub fn http_request(host: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n\r\n").into_bytes()
}
