//! DNS upstreams. Network upstreams reach the server through an outbound,
//! so DNS can follow the same path as the traffic it resolves for.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use bytes::Bytes;
use sybau_common::{io_err, proto_err, BoxStream, Network, Outbound, Session, Target};
use sybau_config::TlsConfig;
use sybau_transport::h2::{Framing, H2Pool};
use sybau_transport::tls::TlsClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::message::{
    Message, Record, RecordData, CLASS_IN, RCODE_NOTIMP, RCODE_SERVFAIL, TYPE_A, TYPE_AAAA,
};
use crate::quic::{quic_err, QuicConnector};

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
    /// DNS over QUIC (RFC 9250).
    Quic(Target),
    /// DNS over HTTPS on HTTP/3.
    H3 {
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

/// `host[:port][/path]` of an https:// or h3:// server.
fn url_parts(r: &str) -> Result<(Target, String)> {
    let (authority, path) = match r.find('/') {
        Some(i) => (&r[..i], r[i..].to_string()),
        None => (r, "/dns-query".to_string()),
    };
    Ok((host_port(authority, 443)?, path))
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
            let (target, path) = url_parts(r)?;
            Address::Https { target, path }
        } else if let Some(r) = t.strip_prefix("quic://") {
            Address::Quic(host_port(r, 853)?)
        } else if let Some(r) = t.strip_prefix("h3://") {
            let (target, path) = url_parts(r)?;
            Address::H3 { target, path }
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
            bail!("unsupported DNS server `{t}` (udp://, tcp://, tls://, https://, quic://, h3://, local, fakeip, rcode://)");
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

fn timed_out(name: &str) -> io::Error {
    io_err(io::ErrorKind::TimedOut, format!("{name} did not answer"))
}

/// DNS over QUIC (RFC 9250): one stream per query on a shared
/// connection, message ID 0, length-prefixed like DNS over TCP.
pub struct Quic {
    name: String,
    connector: QuicConnector,
}

impl Quic {
    pub fn new(
        server: Target,
        outbound: Arc<dyn Outbound>,
        tls: Option<&TlsConfig>,
    ) -> Result<Self> {
        Ok(Self {
            name: format!("quic://{server}"),
            connector: QuicConnector::new(server, outbound, tls, "doq")?,
        })
    }

    async fn ask(&self, conn: &quinn::Connection, wire: &[u8]) -> io::Result<Vec<u8>> {
        let (mut send, mut recv) = conn.open_bi().await.map_err(quic_err)?;
        let mut framed = Vec::with_capacity(wire.len() + 2);
        framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        framed.extend_from_slice(wire);
        send.write_all(&framed).await.map_err(quic_err)?;
        // The query is complete: the server answers after FIN.
        send.finish().map_err(quic_err)?;
        let mut len = [0u8; 2];
        recv.read_exact(&mut len).await.map_err(quic_err)?;
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
        recv.read_exact(&mut buf).await.map_err(quic_err)?;
        Ok(buf)
    }
}

#[async_trait]
impl Upstream for Quic {
    fn name(&self) -> &str {
        &self.name
    }

    async fn exchange(&self, query: &Message) -> io::Result<Message> {
        let mut q = query.clone();
        q.id = 0;
        let wire = encode(&q)?;
        let run = async {
            // A connection the server closed while idle fails the first
            // stream; one retry on a fresh connection covers that.
            let mut last = None;
            for fresh in [false, true] {
                let conn = self.connector.connection(fresh).await?;
                match self.ask(&conn, &wire).await {
                    Ok(body) => {
                        let mut reply = decode(&body)?;
                        reply.id = query.id;
                        check_reply(query, &reply)?;
                        return Ok(reply);
                    }
                    Err(e) => last = Some(e),
                }
            }
            Err(last.expect("two attempts"))
        };
        tokio::time::timeout(TIMEOUT, run)
            .await
            .map_err(|_| timed_out(&self.name))?
    }
}

type H3Requests = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// DNS over HTTPS (RFC 8484) on HTTP/3.
pub struct H3 {
    name: String,
    uri: String,
    connector: QuicConnector,
    session: tokio::sync::Mutex<Option<(quinn::Connection, H3Requests)>>,
}

impl H3 {
    pub fn new(
        server: Target,
        path: String,
        outbound: Arc<dyn Outbound>,
        tls: Option<&TlsConfig>,
    ) -> Result<Self> {
        let connector = QuicConnector::new(server.clone(), outbound, tls, "h3")?;
        let host = tls
            .and_then(|t| t.server_name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| server.host_string());
        let authority = if server.port == 443 {
            host
        } else {
            format!("{host}:{}", server.port)
        };
        Ok(Self {
            name: format!("h3://{authority}{path}"),
            uri: format!("https://{authority}{path}"),
            connector,
            session: tokio::sync::Mutex::new(None),
        })
    }

    /// HTTP/3 request sender on the current connection.
    async fn requests(&self, fresh: bool) -> io::Result<H3Requests> {
        let mut session = self.session.lock().await;
        if let Some((conn, send)) = session.as_ref() {
            if !fresh && conn.close_reason().is_none() {
                return Ok(send.clone());
            }
        }
        let conn = self.connector.connection(fresh).await?;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(quic_err)?;
        // Serves the connection's control streams until it closes.
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        *session = Some((conn, send.clone()));
        Ok(send)
    }

    async fn ask(&self, mut send: H3Requests, wire: &[u8]) -> io::Result<Vec<u8>> {
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(&self.uri)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut stream = send.send_request(request).await.map_err(quic_err)?;
        stream
            .send_data(Bytes::copy_from_slice(wire))
            .await
            .map_err(quic_err)?;
        stream.finish().await.map_err(quic_err)?;
        let response = stream.recv_response().await.map_err(quic_err)?;
        if response.status() != http::StatusCode::OK {
            return Err(proto_err(format!(
                "{}: HTTP {}",
                self.name,
                response.status()
            )));
        }
        let mut body = Vec::with_capacity(512);
        while let Some(mut chunk) = stream.recv_data().await.map_err(quic_err)? {
            use bytes::Buf;
            while chunk.has_remaining() {
                let part = chunk.chunk();
                if body.len() + part.len() > MAX_MESSAGE {
                    return Err(proto_err("DNS reply too large"));
                }
                body.extend_from_slice(part);
                let n = part.len();
                chunk.advance(n);
            }
        }
        Ok(body)
    }
}

#[async_trait]
impl Upstream for H3 {
    fn name(&self) -> &str {
        &self.name
    }

    async fn exchange(&self, query: &Message) -> io::Result<Message> {
        let mut q = query.clone();
        q.id = 0;
        let wire = encode(&q)?;
        let run = async {
            let mut last = None;
            for fresh in [false, true] {
                let send = self.requests(fresh).await?;
                match self.ask(send, &wire).await {
                    Ok(body) => {
                        let mut reply = decode(&body)?;
                        reply.id = query.id;
                        check_reply(query, &reply)?;
                        return Ok(reply);
                    }
                    Err(e) => last = Some(e),
                }
            }
            Err(last.expect("two attempts"))
        };
        tokio::time::timeout(TIMEOUT, run)
            .await
            .map_err(|_| timed_out(&self.name))?
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

/// Asks several upstreams in turn until one answers.
pub struct Fallback {
    name: String,
    upstreams: Vec<Arc<dyn Upstream>>,
}

impl Fallback {
    pub fn new(name: impl Into<String>, upstreams: Vec<Arc<dyn Upstream>>) -> Self {
        Self {
            name: name.into(),
            upstreams,
        }
    }
}

#[async_trait]
impl Upstream for Fallback {
    fn name(&self) -> &str {
        &self.name
    }

    async fn exchange(&self, query: &Message) -> io::Result<Message> {
        let mut last = io_err(io::ErrorKind::NotFound, "no DNS servers");
        for up in &self.upstreams {
            match up.exchange(query).await {
                Ok(reply) => return Ok(reply),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

/// DNS servers the system is configured with. Used instead of the system
/// resolver while a TUN captures traffic: the resolver's own queries would
/// otherwise come back through the TUN.
pub fn system_nameservers() -> Vec<std::net::SocketAddr> {
    #[cfg(unix)]
    {
        // systemd-resolved's stub (127.0.0.53) forwards from its own,
        // unmarked sockets; its upstream list avoids that loop.
        for path in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
            if let Ok(text) = std::fs::read_to_string(path) {
                let servers = parse_resolv_conf(&text);
                if !servers.is_empty() {
                    return servers;
                }
            }
        }
        Vec::new()
    }
    #[cfg(windows)]
    {
        windows_nameservers()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

/// DNS servers of the adapters that have a default gateway (the uplinks;
/// the TUN itself has none).
#[cfg(windows)]
fn windows_nameservers() -> Vec<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..4 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buf` is `size` bytes, aligned for the adapter records.
        let code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        match code {
            NO_ERROR => break,
            ERROR_BUFFER_OVERFLOW => continue,
            _ => return Vec::new(),
        }
    }
    let mut out = Vec::new();
    let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: the API filled `buf` with a linked list of adapter records
    // whose pointers stay inside it.
    unsafe {
        while !adapter.is_null() {
            let a = &*adapter;
            if a.OperStatus == IfOperStatusUp && !a.FirstGatewayAddress.is_null() {
                let mut dns = a.FirstDnsServerAddress;
                while !dns.is_null() {
                    let sa = (*dns).Address.lpSockaddr;
                    let ip = match (*sa).sa_family {
                        AF_INET => {
                            let v4 = &*(sa as *const SOCKADDR_IN);
                            Some(IpAddr::V4(Ipv4Addr::from(
                                v4.sin_addr.S_un.S_addr.to_ne_bytes(),
                            )))
                        }
                        AF_INET6 => {
                            let v6 = &*(sa as *const SOCKADDR_IN6);
                            Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)))
                        }
                        _ => None,
                    };
                    // fec0:0:0:ffff::1-3 are Windows placeholders, not servers.
                    if let Some(ip) = ip.filter(|ip| match ip {
                        IpAddr::V6(v6) => v6.segments()[..4] != [0xfec0, 0, 0, 0xffff],
                        IpAddr::V4(_) => true,
                    }) {
                        let addr = SocketAddr::new(ip, 53);
                        if !out.contains(&addr) {
                            out.push(addr);
                        }
                    }
                    dns = (*dns).Next;
                }
            }
            adapter = a.Next;
        }
    }
    out
}

/// `nameserver` lines of a resolv.conf.
pub fn parse_resolv_conf(text: &str) -> Vec<std::net::SocketAddr> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            (parts.next()? == "nameserver").then_some(())?;
            // A scoped IPv6 address (`fe80::1%eth0`) keeps only the address.
            let addr = parts.next()?.split('%').next()?;
            let ip: std::net::IpAddr = addr.parse().ok()?;
            Some(std::net::SocketAddr::new(ip, 53))
        })
        .collect()
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
        Address::Quic(t) => Arc::new(Quic::new(t.clone(), outbound, tls)?),
        Address::H3 { target, path } => {
            Arc::new(H3::new(target.clone(), path.clone(), outbound, tls)?)
        }
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
    #[test]
    fn resolv_conf() {
        let text = "# comment\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\noptions edns0\nnameserver bogus\n";
        let servers = super::parse_resolv_conf(text);
        assert_eq!(
            servers,
            vec![
                "192.168.1.1:53".parse().unwrap(),
                "[fe80::1]:53".parse().unwrap()
            ]
        );
    }

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
        assert_eq!(
            Address::parse("quic://dns.adguard-dns.com").unwrap(),
            Address::Quic(Target::parse("dns.adguard-dns.com:853").unwrap())
        );
        assert_eq!(
            Address::parse("h3://1.1.1.1:8443/q").unwrap(),
            Address::H3 {
                target: Target::parse("1.1.1.1:8443").unwrap(),
                path: "/q".into()
            }
        );
        assert!(Address::parse("dhcp://auto").is_err());
        assert!(Address::parse("rcode://what").is_err());
    }
}
