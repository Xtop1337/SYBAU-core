//! SOCKS5 (RFC 1928, RFC 1929) with UDP ASSOCIATE, and SOCKS4/4a.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use sybau_common::addr::{domain_host, parse_socks_addr, put_socks_addr, read_socks_addr};
use sybau_common::{proto_err, Host, Network, PacketConn, Session, Target};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

use super::local::LocalProxy;
use crate::dispatch::Dispatcher;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;
const REP_OK: u8 = 0;
const REP_CMD_NOT_SUPPORTED: u8 = 7;

fn reply(rep: u8) -> [u8; 10] {
    [5, rep, 0, 1, 0, 0, 0, 0, 0, 0]
}

async fn read_len_prefixed<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Vec<u8>> {
    let len = s.read_u8().await? as usize;
    let mut v = vec![0u8; len];
    s.read_exact(&mut v).await?;
    Ok(v)
}

pub async fn handle_v5<S>(
    proxy: &LocalProxy,
    mut s: S,
    peer: SocketAddr,
    local: SocketAddr,
    dispatcher: &Dispatcher,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake = async {
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await?;
        let mut methods = vec![0u8; head[1] as usize];
        s.read_exact(&mut methods).await?;
        let mut user = None;
        if proxy.auth_required() {
            if !methods.contains(&2) {
                s.write_all(&[5, 0xff]).await?;
                return Err(proto_err(
                    "client does not offer username/password authentication",
                ));
            }
            s.write_all(&[5, 2]).await?;
            if s.read_u8().await? != 1 {
                return Err(proto_err("bad auth sub-negotiation version"));
            }
            let name = String::from_utf8_lossy(&read_len_prefixed(&mut s).await?).into_owned();
            let pass = String::from_utf8_lossy(&read_len_prefixed(&mut s).await?).into_owned();
            if !proxy.check_user(&name, &pass) {
                s.write_all(&[1, 1]).await?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "wrong username or password",
                ));
            }
            s.write_all(&[1, 0]).await?;
            user = Some(name);
        } else {
            if !methods.contains(&0) {
                s.write_all(&[5, 0xff]).await?;
                return Err(proto_err(
                    "client requires authentication but none is configured",
                ));
            }
            s.write_all(&[5, 0]).await?;
        }
        let mut req = [0u8; 3];
        s.read_exact(&mut req).await?;
        if req[0] != 5 {
            return Err(proto_err("bad SOCKS5 request version"));
        }
        let target = read_socks_addr(&mut s).await?;
        Ok((req[1], target, user))
    };
    let (cmd, target, user) = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| proto_err("SOCKS5 handshake timed out"))??;
    let user: Option<Arc<str>> = user.map(Arc::from);

    match cmd {
        CMD_CONNECT => {
            s.write_all(&reply(REP_OK)).await?;
            let mut sess = Session::new(Network::Tcp, proxy.tag.clone(), Some(peer), target);
            sess.sniff = proxy.sniff();
            sess.user = user;
            dispatcher.dispatch_stream(sess, Box::new(s)).await;
            Ok(())
        }
        CMD_UDP_ASSOCIATE if proxy.cfg.udp => {
            let sock = UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await?;
            let bound = Target::from(sock.local_addr()?);
            let mut rep = vec![5, REP_OK, 0];
            put_socks_addr(&mut rep, &bound);
            s.write_all(&rep).await?;
            let conn = Arc::new(SocksUdp {
                sock,
                client_ip: peer.ip().to_canonical(),
                client: Mutex::new(None),
                scratch: tokio::sync::Mutex::new(vec![0u8; 65535]),
            });
            let mut sess = Session::new(Network::Udp, proxy.tag.clone(), Some(peer), bound);
            sess.sniff = proxy.sniff();
            sess.user = user;
            // The association lives exactly as long as the TCP connection.
            tokio::select! {
                _ = dispatcher.dispatch_packet(sess, conn) => {}
                _ = wait_closed(&mut s) => {}
            }
            Ok(())
        }
        other => {
            s.write_all(&reply(REP_CMD_NOT_SUPPORTED)).await?;
            Err(proto_err(format!("unsupported SOCKS5 command {other}")))
        }
    }
}

async fn wait_closed<S: AsyncRead + Unpin>(s: &mut S) {
    let mut buf = [0u8; 64];
    while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
}

/// Client-facing side of a SOCKS5 UDP association.
struct SocksUdp {
    sock: UdpSocket,
    client_ip: std::net::IpAddr,
    /// Learned from the first datagram; replies go there.
    client: Mutex<Option<SocketAddr>>,
    scratch: tokio::sync::Mutex<Vec<u8>>,
}

#[async_trait]
impl PacketConn for SocksUdp {
    async fn send_to(&self, buf: &[u8], from: &Target) -> io::Result<usize> {
        let Some(client) = *self.client.lock() else {
            return Ok(0);
        };
        let mut pkt = Vec::with_capacity(3 + 19 + buf.len());
        pkt.extend_from_slice(&[0, 0, 0]);
        put_socks_addr(&mut pkt, from);
        pkt.extend_from_slice(buf);
        self.sock.send_to(&pkt, client).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let mut scratch = self.scratch.lock().await;
        loop {
            let (n, from) = self.sock.recv_from(&mut scratch).await?;
            // Only the host that opened the association may use it, and
            // fragmented datagrams (FRAG != 0) are not supported.
            if from.ip().to_canonical() != self.client_ip || n < 4 || scratch[2] != 0 {
                continue;
            }
            let Ok(Some((target, used))) = parse_socks_addr(&scratch[3..n]) else {
                continue;
            };
            let payload = &scratch[3 + used..n];
            if payload.len() > buf.len() {
                continue;
            }
            buf[..payload.len()].copy_from_slice(payload);
            *self.client.lock() = Some(from);
            return Ok((payload.len(), target));
        }
    }
}

async fn read_cstring<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let b = s.read_u8().await?;
        if b == 0 {
            return Ok(out);
        }
        if out.len() >= 255 {
            return Err(proto_err("SOCKS4 string too long"));
        }
        out.push(b);
    }
}

pub async fn handle_v4<S>(
    proxy: &LocalProxy,
    mut s: S,
    peer: SocketAddr,
    dispatcher: &Dispatcher,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake = async {
        let mut head = [0u8; 8];
        s.read_exact(&mut head).await?;
        let port = u16::from_be_bytes([head[2], head[3]]);
        let ip = Ipv4Addr::new(head[4], head[5], head[6], head[7]);
        let _user_id = read_cstring(&mut s).await?;
        let o = ip.octets();
        // SOCKS4a: 0.0.0.x (x != 0) means "a domain name follows".
        let host = if o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] != 0 {
            domain_host(&read_cstring(&mut s).await?)?
        } else {
            Host::Ip(ip.into())
        };
        Ok::<_, io::Error>((head[1], Target::new(host, port)))
    };
    let (cmd, target) = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| proto_err("SOCKS4 handshake timed out"))??;
    // SOCKS4 cannot authenticate, so it is refused when accounts are set.
    if cmd != CMD_CONNECT || proxy.auth_required() {
        s.write_all(&[0, 0x5b, 0, 0, 0, 0, 0, 0]).await?;
        return Err(proto_err("SOCKS4 request rejected"));
    }
    s.write_all(&[0, 0x5a, 0, 0, 0, 0, 0, 0]).await?;
    let mut sess = Session::new(Network::Tcp, proxy.tag.clone(), Some(peer), target);
    sess.sniff = proxy.sniff();
    dispatcher.dispatch_stream(sess, Box::new(s)).await;
    Ok(())
}
