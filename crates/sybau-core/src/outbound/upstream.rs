//! Upstream proxies: SOCKS5 (TCP and UDP) and HTTP CONNECT.

use std::io;
use std::sync::Arc;

use anyhow::{bail, Result};
use async_trait::async_trait;
use base64::Engine as _;
use bytes::BytesMut;
use sybau_common::addr::{parse_socks_addr, put_socks_addr, read_socks_addr};
use sybau_common::{
    io_err, proto_err, ArcPacketConn, BoxStream, Dialer, Host, Outbound, PacketConn,
    PrefixedStream, Session, Target,
};
use sybau_config::UpstreamProxy;
use sybau_transport::Connector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn check(cfg: &UpstreamProxy) -> Result<Target> {
    if cfg.server.is_empty() || cfg.port == 0 {
        bail!("`server` and `port` are required");
    }
    Ok(Target::from_host(&cfg.server, cfg.port))
}

pub struct Socks5 {
    tag: Arc<str>,
    dialer: Arc<dyn Dialer>,
    connector: Connector,
    server: Target,
    auth: Option<(String, String)>,
}

impl Socks5 {
    pub fn new(tag: Arc<str>, cfg: &UpstreamProxy, dialer: Arc<dyn Dialer>) -> Result<Self> {
        let server = check(cfg)?;
        let auth = match (&cfg.username, &cfg.password) {
            (Some(u), p) if !u.is_empty() => {
                let p = p.clone().unwrap_or_default();
                if u.len() > 255 || p.len() > 255 {
                    bail!("SOCKS5 username and password are limited to 255 bytes");
                }
                Some((u.clone(), p))
            }
            _ => None,
        };
        let connector = Connector::new(dialer.clone(), server.clone(), cfg.tls.as_ref(), None)?;
        Ok(Self {
            tag,
            dialer,
            connector,
            server,
            auth,
        })
    }

    /// Negotiates the method, authenticates and sends `command` for `target`.
    /// Returns the stream and the address from the server's reply.
    async fn handshake(&self, command: u8, target: &Target) -> io::Result<(BoxStream, Target)> {
        let mut io = self.connector.connect().await?;
        match &self.auth {
            Some(_) => io.write_all(&[5, 2, 0, 2]).await?,
            None => io.write_all(&[5, 1, 0]).await?,
        }
        let mut rep = [0u8; 2];
        io.read_exact(&mut rep).await?;
        match (rep[0], rep[1], &self.auth) {
            (5, 0, _) => {}
            (5, 2, Some((user, pass))) => {
                let mut msg = vec![1, user.len() as u8];
                msg.extend_from_slice(user.as_bytes());
                msg.push(pass.len() as u8);
                msg.extend_from_slice(pass.as_bytes());
                io.write_all(&msg).await?;
                io.read_exact(&mut rep).await?;
                if rep[1] != 0 {
                    return Err(io_err(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS5 proxy rejected the credentials",
                    ));
                }
            }
            (5, 0xff, _) => {
                return Err(io_err(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 proxy accepts none of our auth methods",
                ))
            }
            _ => return Err(proto_err("unexpected SOCKS5 method reply")),
        }
        let mut req = BytesMut::from(&[5u8, command, 0][..]);
        put_socks_addr(&mut req, target);
        io.write_all(&req).await?;
        let mut head = [0u8; 3];
        io.read_exact(&mut head).await?;
        if head[0] != 5 {
            return Err(proto_err("unexpected SOCKS5 reply version"));
        }
        if head[1] != 0 {
            let reason = match head[1] {
                1 => "general failure",
                2 => "connection not allowed",
                3 => "network unreachable",
                4 => "host unreachable",
                5 => "connection refused",
                6 => "TTL expired",
                7 => "command not supported",
                8 => "address type not supported",
                _ => "unknown error",
            };
            return Err(io_err(
                io::ErrorKind::ConnectionRefused,
                format!("SOCKS5 proxy: {reason}"),
            ));
        }
        let bound = read_socks_addr(&mut io).await?;
        Ok((io, bound))
    }
}

#[async_trait]
impl Outbound for Socks5 {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "socks"
    }

    async fn connect(&self, sess: &Session) -> io::Result<BoxStream> {
        Ok(self.handshake(1, &sess.target).await?.0)
    }

    async fn bind(&self, _sess: &Session) -> io::Result<ArcPacketConn> {
        let any = Target::from_host("0.0.0.0", 0);
        let (control, mut relay) = self.handshake(3, &any).await?;
        // Servers commonly answer with an unspecified address, meaning
        // "the address you reached me at".
        if matches!(&relay.host, Host::Ip(ip) if ip.is_unspecified()) {
            relay.host = self.server.host.clone();
        }
        let udp = self.dialer.dial_udp(&relay).await?;
        Ok(Arc::new(Socks5Udp {
            udp,
            relay,
            _control: tokio::sync::Mutex::new(control),
        }))
    }
}

struct Socks5Udp {
    udp: ArcPacketConn,
    relay: Target,
    /// The association lives as long as this TCP connection.
    _control: tokio::sync::Mutex<BoxStream>,
}

#[async_trait]
impl PacketConn for Socks5Udp {
    async fn send_to(&self, buf: &[u8], dst: &Target) -> io::Result<usize> {
        let mut packet = BytesMut::with_capacity(buf.len() + 32);
        packet.extend_from_slice(&[0, 0, 0]);
        put_socks_addr(&mut packet, dst);
        packet.extend_from_slice(buf);
        self.udp.send_to(&packet, &self.relay).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let mut scratch = vec![0u8; 65535];
        loop {
            let (n, _) = self.udp.recv_from(&mut scratch).await?;
            if n < 4 || scratch[2] != 0 {
                continue;
            }
            let Ok(Some((from, used))) = parse_socks_addr(&scratch[3..n]) else {
                continue;
            };
            let start = 3 + used;
            let len = (n - start).min(buf.len());
            buf[..len].copy_from_slice(&scratch[start..start + len]);
            return Ok((len, from));
        }
    }
}

pub struct HttpConnect {
    tag: Arc<str>,
    connector: Connector,
    authorization: Option<String>,
}

impl HttpConnect {
    pub fn new(tag: Arc<str>, cfg: &UpstreamProxy, dialer: Arc<dyn Dialer>) -> Result<Self> {
        let server = check(cfg)?;
        let authorization = cfg.username.as_ref().filter(|u| !u.is_empty()).map(|u| {
            let raw = format!("{u}:{}", cfg.password.clone().unwrap_or_default());
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(raw)
            )
        });
        Ok(Self {
            tag,
            connector: Connector::new(dialer, server, cfg.tls.as_ref(), None)?,
            authorization,
        })
    }
}

#[async_trait]
impl Outbound for HttpConnect {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "http"
    }

    async fn connect(&self, sess: &Session) -> io::Result<BoxStream> {
        let mut io = self.connector.connect().await?;
        let authority = sess.target.to_string();
        let mut req = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
        );
        if let Some(auth) = &self.authorization {
            req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
        }
        req.push_str("\r\n");
        io.write_all(req.as_bytes()).await?;
        io.flush().await?;

        let mut buf = BytesMut::with_capacity(512);
        let head_len = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if buf.len() > 16 * 1024 {
                return Err(proto_err("HTTP proxy response head too large"));
            }
            if io.read_buf(&mut buf).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        };
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);
        if !matches!(
            resp.parse(&buf[..head_len]),
            Ok(httparse::Status::Complete(_))
        ) {
            return Err(proto_err("malformed response from HTTP proxy"));
        }
        match resp.code {
            Some(code) if (200..300).contains(&code) => {}
            Some(407) => {
                return Err(io_err(
                    io::ErrorKind::PermissionDenied,
                    "HTTP proxy requires authentication",
                ))
            }
            code => {
                return Err(io_err(
                    io::ErrorKind::ConnectionRefused,
                    format!(
                        "HTTP proxy answered {} {}",
                        code.unwrap_or(0),
                        resp.reason.unwrap_or("")
                    ),
                ))
            }
        }
        let rest = buf.split_off(head_len);
        Ok(Box::new(PrefixedStream::new(rest.freeze(), io)))
    }

    async fn bind(&self, _sess: &Session) -> io::Result<ArcPacketConn> {
        Err(io_err(
            io::ErrorKind::Unsupported,
            "HTTP proxies cannot carry UDP",
        ))
    }
}
