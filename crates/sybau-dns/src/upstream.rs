//! DNS upstreams. Network upstreams reach the server through an outbound,
//! so DNS can follow the same path as the traffic it resolves for.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use sybau_common::{io_err, proto_err, BoxStream, Network, Outbound, Session, Target};
use sybau_config::TlsConfig;
use sybau_transport::h2::{Framing, H2Pool};
use sybau_transport::tls::TlsClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::message::{
    Message, Record, RecordData, CLASS_IN, RCODE_NOTIMP, RCODE_SERVFAIL, TYPE_A, TYPE_AAAA,
};

const TIMEOUT: Duration = Duration::from_secs(5);
const UDP_ATTEMPTS: usize = 2;
const MAX_MESSAGE: usize = 65535;

#[async_trait]
pub trait Upstream: Send + Sync {
    /// Server description for logs, e.g. `udp://1.1.1.1:53`.
    fn name(&self) -> &str;
    async fn exchange(&self, query: &Message) -> io::Result<Message>;
}

/// Where a server lives, parsed from its `address`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    Udp(Target),
    Tcp(Target),
    Tls(Target),
    Https {
        target: Target,
        path: String,
    },
    /// The operating system resolver.
    Local,
    FakeIp,
    /// Answers every query with this response code.
    Rcode(u8),
}

fn host_port(text: &str, default_port: u16) -> Result<Target> {
    let t = text.trim().trim_end_matches('/');
    if let Some(v6) = t.strip_prefix('[') {
        let (host, rest) = v6
            .split_once(']')
            .ok_or_else(|| anyhow!("bad address `{text}`"))?;
        let port = match rest.strip_prefix(':') {
            Some(p) => p.parse()?,
            None => default_port,
        };
        return Ok(Target::from_host(host, port));
    }
    if t.matches(':').count() > 1 {
        // Bare IPv6 address without a port.
        return Ok(Target::from_host(t, default_port));
    }
    match t.rsplit_once(':') {
        Some((h, p)) => Ok(Target::from_host(
            h,
            p.parse().map_err(|_| anyhow!("bad port in `{text}`"))?,
        )),
        None => Ok(Target::from_host(t, default_port)),
    }
}

impl Address {
    pub fn parse(text: &str) -> Result<Self> {
        let t = text.trim();
        Ok(if let Some(r) = t.strip_prefix("udp://") {
            Address::Udp(host_port(r, 53)?)
        } else if let Some(r) = t.strip_prefix("tcp://") {
            Address::Tcp(host_port(r, 53)?)
        } else if let Some(r) = t.strip_prefix("tls://") {
            Address::Tls(host_port(r, 853)?)
        } else if let Some(r) = t.strip_prefix("https://") {
            let (authority, path) = match r.find('/') {
                Some(i) => (&r[..i], r[i..].to_string()),
                None => (r, "/dns-query".to_string()),
            };
            Address::Https {
                target: host_port(authority, 443)?,
                path,
            }
        } else if let Some(r) = t.strip_prefix("rcode://") {
            Address::Rcode(match r {
                "success" | "noerror" => 0,
                "format_error" | "formerr" => 1,
                "server_failure" | "servfail" => 2,
                "name_error" | "nxdomain" => 3,
                "not_implemented" | "notimp" => 4,
                "refused" => 5,
                other => bail!("unknown rcode `{other}`"),
            })
        } else if t == "local" {
            Address::Local
        } else if t == "fakeip" {
            Address::FakeIp
        } else if t.contains("://") {
            bail!("unsupported DNS server `{t}` (udp://, tcp://, tls://, https://, local, fakeip, rcode://)");
        } else {
            Address::Udp(host_port(t, 53)?)
        })
    }
}

fn check_reply(query: &Message, reply: &Message) -> io::Result<()> {
    if !reply.response
        || reply.id != query.id
        || reply.questions.first().map(|q| (&q.name, q.qtype))
            != query.questions.first().map(|q| (&q.name, q.qtype))
    {
        return Err(proto_err("DNS reply does not match the query"));
    }
    Ok(())
}

fn session(network: Network, target: &Target) -> Session {
    Session::new(network, Arc::from("dns"), None, target.clone())
}

fn encode(query: &Message) -> io::Result<Vec<u8>> {
    query
        .encode()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

fn decode(data: &[u8]) -> io::Result<Message> {
    Message::parse(data).map_err(|e| proto_err(format!("bad DNS reply: {e}")))
}

pub struct Udp {
    name: String,
    server: Target,
    outbound: Arc<dyn Outbound>,
    /// Truncated replies are retried over TCP.
    tcp: Tcp,
}

impl Udp {
    pub fn new(server: Target, outbound: Arc<dyn Outbound>) -> Self {
        Self {
            name: format!("udp://{server}"),
            tcp: Tcp::new(server.clone(), outbound.clone(), None),
            server,
            outbound,
        }
    }
}

#[async_trait]
impl Upstream for Udp {
    fn name(&self) -> &str {
        &self.name
    }

    async fn exchange(&self, query: &Message) -> io::Result<Message> {
        let wire = encode(query)?;
        let conn = self
            .outbound
            .bind(&session(Network::Udp, &self.server))
            .await?;
        let mut buf = vec![0u8; MAX_MESSAGE];
        for _ in 0..UDP_ATTEMPTS {
            conn.send_to(&wire, &self.server).await?;
            let deadline = tokio::time::Instant::now() + TIMEOUT / UDP_ATTEMPTS as u32;
            loop {
                let (n, _) = match tokio::time::timeout_at(deadline, conn.recv_from(&mut buf)).await
                {
                    Ok(r) => r?,
                    Err(_) => break,
                };
                // Stray or spoofed packets are ignored.
                let Ok(reply) = decode(&buf[..n]) else {
                    continue;
                };
                if check_reply(query, &reply).is_err() {
                    continue;
                }
                if reply.truncated {
                    return self.tcp.exchange(query).await;
                }
                return Ok(reply);
            }
        }
        Err(io_err(
            io::ErrorKind::TimedOut,
            format!("{} did not answer", self.name),
        ))
    }
}

/// DNS over TCP, optionally inside TLS (DoT). One connection per query.
pub struct Tcp {
    name: String,
    server: Target,
    outbound: Arc<dyn Outbound>,
    tls: Option<TlsClient>,
}

impl Tcp {
    pub fn new(server: Target, outbound: Arc<dyn Outbound>, tls: Option<TlsClient>) -> Self {
        let scheme = if tls.is_some() { "tls" } else { "tcp" };
        Self {
            name: format!("{scheme}://{server}"),
            server,
            outbound,
            tls,
        }
    }

    async fn open(&self) -> io::Result<BoxStream> {
        let stream = self
            .outbound
            .connect(&session(Network::Tcp, &self.server))
            .await?;
        match &self.tls {
            Some(tls) => tls.connect(stream).await,
            None => Ok(stream),
        }
    }
}

#[async_trait]
impl Upstream for Tcp {
    fn name(&self) -> &str {
        &self.name
    }

    async fn exchange(&self, query: &Message) -> io::Result<Message> {
        let wire = encode(query)?;
        let run = async {
            let mut s = self.open().await?;
            let mut framed = Vec::with_capacity(wire.len() + 2);
            framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
            framed.extend_from_slice(&wire);
            s.write_all(&framed).await?;
            s.flush().await?;
            let len = s.read_u16().await? as usize;
            let mut buf = vec![0u8; len];
            s.read_exact(&mut buf).await?;
            let reply = decode(&buf)?;
            check_reply(query, &reply)?;
            Ok(reply)
        };
        tokio::time::timeout(TIMEOUT, run).await.map_err(|_| {
            io_err(
                io::ErrorKind::TimedOut,
                format!("{} did not answer", self.name),
            )
        })?
    }
}

/// DNS over HTTPS (RFC 8484) using POST on a shared HTTP/2 connection.
pub struct Https {
    name: String,
    authority: String,
    path: String,
    pool: H2Pool,
}

impl Https {
    pub fn new(server: Target, path: String, outbound: Arc<dyn Outbound>, tls: TlsClient) -> Self {
        let authority = match (&server.host, server.port) {
            (_, 443) => tls.server_name(),
            _ => format!("{}:{}", tls.server_name(), server.port),
        };
        let name = format!("https://{authority}{path}");
        let tls = Arc::new(tls);
        let pool = H2Pool::new(Arc::new(move || {
            let (outbound, server, tls) = (outbound.clone(), server.clone(), tls.clone());
            Box::pin(async move {
                let stream = outbound.connect(&session(Network::Tcp, &server)).await?;
                tls.connect(stream).await
            })
        }));
        Self {
            name,
            authority,
            path,
            pool,
        }
    }
}

#[async_trait]
impl Upstream for Https {
    fn name(&self) -> &str {
        &self.name
    }

    async fn exchange(&self, query: &Message) -> io::Result<Message> {
        // RFC 8484 recommends ID 0 for cache friendliness.
        let mut q = query.clone();
        q.id = 0;
        let wire = encode(&q)?;
        let run = async {
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri(format!("https://{}{}", self.authority, self.path))
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let mut stream = self.pool.open(request, Framing::Raw).await?;
            stream.write_all(&wire).await?;
            stream.shutdown().await?;
            let mut body = Vec::with_capacity(512);
            (&mut stream)
                .take(MAX_MESSAGE as u64)
                .read_to_end(&mut body)
                .await?;
            let mut reply = decode(&body)?;
            reply.id = query.id;
            check_reply(query, &reply)?;
            Ok(reply)
        };
        tokio::time::timeout(TIMEOUT, run).await.map_err(|_| {
            io_err(
                io::ErrorKind::TimedOut,
                format!("{} did not answer", self.name),
            )
        })?
    }
}

/// The operating system resolver; only A and AAAA are supported.
pub struct Local;

#[async_trait]
impl Upstream for Local {
    fn name(&self) -> &str {
        "local"
    }

    async fn exchange(&self, query: &Message) -> io::Result<Message> {
        let q = query
            .questions
            .first()
            .ok_or_else(|| proto_err("query without question"))?;
        if q.qtype != TYPE_A && q.qtype != TYPE_AAAA {
            return Ok(query.reply(RCODE_NOTIMP));
        }
        let mut reply = query.reply(0);
        let addrs = match tokio::net::lookup_host((q.name.as_str(), 0)).await {
            Ok(a) => a,
            Err(_) => return Ok(query.reply(crate::message::RCODE_NXDOMAIN)),
        };
        for addr in addrs {
            let data = match (addr.ip().to_canonical(), q.qtype) {
                (std::net::IpAddr::V4(v4), TYPE_A) => RecordData::A(v4),
                (std::net::IpAddr::V6(v6), TYPE_AAAA) => RecordData::Aaaa(v6),
                _ => continue,
            };
            if !reply.answers.iter().any(|r| r.data == data) {
                reply.answers.push(Record {
                    name: q.name.clone(),
                    rtype: q.qtype,
                    class: CLASS_IN,
                    ttl: 60,
                    data,
                });
            }
        }
        Ok(reply)
    }
}

/// Answers every query with a fixed response code.
pub struct Rcode(pub u8);

#[async_trait]
impl Upstream for Rcode {
    fn name(&self) -> &str {
        "rcode"
    }

    async fn exchange(&self, query: &Message) -> io::Result<Message> {
        Ok(query.reply(self.0))
    }
}

/// Builds the upstream for an address. `Address::FakeIp` is handled by
/// the caller.
pub fn build(
    address: &Address,
    outbound: Arc<dyn Outbound>,
    tls: Option<&TlsConfig>,
) -> Result<Arc<dyn Upstream>> {
    let tls_for = |target: &Target, alpn: &[&str]| -> Result<TlsClient> {
        let mut cfg = tls.cloned().unwrap_or_default();
        cfg.enabled = true;
        if !cfg.alpn.is_empty() && alpn == ["h2"] && !cfg.alpn.iter().any(|a| a == "h2") {
            bail!("DNS over HTTPS needs ALPN h2");
        }
        TlsClient::new(&cfg, target, alpn, false)
    };
    Ok(match address {
        Address::Udp(t) => Arc::new(Udp::new(t.clone(), outbound)),
        Address::Tcp(t) => Arc::new(Tcp::new(t.clone(), outbound, None)),
        Address::Tls(t) => Arc::new(Tcp::new(t.clone(), outbound, Some(tls_for(t, &[])?))),
        Address::Https { target, path } => Arc::new(Https::new(
            target.clone(),
            path.clone(),
            outbound,
            tls_for(target, &["h2"])?,
        )),
        Address::Local => Arc::new(Local),
        Address::Rcode(code) => Arc::new(Rcode(*code)),
        Address::FakeIp => bail!("fakeip is not a network upstream"),
    })
}

/// SERVFAIL reply for a query that could not be answered.
pub fn servfail(query: &Message) -> Message {
    query.reply(RCODE_SERVFAIL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(
            Address::parse("1.1.1.1").unwrap(),
            Address::Udp(Target::parse("1.1.1.1:53").unwrap())
        );
        assert_eq!(
            Address::parse("udp://[2606:4700::1111]:5353").unwrap(),
            Address::Udp(Target::parse("[2606:4700::1111]:5353").unwrap())
        );
        assert_eq!(
            Address::parse("2606:4700::1111").unwrap(),
            Address::Udp(Target::parse("[2606:4700::1111]:53").unwrap())
        );
        assert_eq!(
            Address::parse("tcp://8.8.8.8").unwrap(),
            Address::Tcp(Target::parse("8.8.8.8:53").unwrap())
        );
        assert_eq!(
            Address::parse("tls://dns.google").unwrap(),
            Address::Tls(Target::parse("dns.google:853").unwrap())
        );
        assert_eq!(
            Address::parse("https://1.1.1.1/dns-query").unwrap(),
            Address::Https {
                target: Target::parse("1.1.1.1:443").unwrap(),
                path: "/dns-query".into()
            }
        );
        assert_eq!(
            Address::parse("https://dns.example:8443").unwrap(),
            Address::Https {
                target: Target::parse("dns.example:8443").unwrap(),
                path: "/dns-query".into()
            }
        );
        assert_eq!(
            Address::parse("rcode://refused").unwrap(),
            Address::Rcode(5)
        );
        assert_eq!(Address::parse("local").unwrap(), Address::Local);
        assert_eq!(Address::parse("fakeip").unwrap(), Address::FakeIp);
        assert!(Address::parse("quic://x").is_err());
        assert!(Address::parse("rcode://what").is_err());
    }
}
