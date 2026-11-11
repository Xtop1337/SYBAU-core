//! TUN inbound: packets captured by a virtual interface become TCP
//! streams and UDP flows that go through the router like any other
//! session.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use sybau_common::{io_err, Network, PacketConn, Session, SniffOptions, Target};
use sybau_config::TunInbound as TunConfig;
use sybau_dns::message::Message;
use sybau_tun::routes::{RouteOptions, Routes};
use sybau_tun::{IpStackStream, IpStackTcpStream, IpStackUdpStream, Tun, TunOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::dispatch::Dispatcher;
use crate::dns::DnsResolver;

const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(300);
const DNS_TCP_IDLE: Duration = Duration::from_secs(30);

/// An opened TUN interface with its routes, ready to serve.
pub struct TunInbound {
    tag: Arc<str>,
    cfg: TunConfig,
    tun: Tun,
    routes: Option<Routes>,
    /// Interface networks; flows towards them would loop.
    own_nets: Vec<(IpAddr, u8)>,
}

impl TunInbound {
    pub fn open(tag: Arc<str>, cfg: &TunConfig) -> Result<Self> {
        if matches!(cfg.stack.as_str(), "system" | "mixed") {
            warn!(target: "sybau::inbound", "inbound `{tag}`: stack `{}` is not available yet, using `userspace`", cfg.stack);
        }
        let mut opts = TunOptions {
            name: cfg.interface_name.clone(),
            mtu: cfg.mtu,
            fd: cfg.file_descriptor,
            wintun_file: cfg.wintun_file.clone(),
            ..Default::default()
        };
        let mut cfg = cfg.clone();
        if cfg.address.iter().any(|a| a.contains(':')) && !sybau_tun::ipv6_available() {
            warn!(target: "sybau::inbound", "inbound `{tag}`: IPv6 is not available on this system; the TUN gets IPv4 only");
            cfg.address.retain(|a| !a.contains(':'));
            cfg.route_address.retain(|a| !a.contains(':'));
            cfg.route_exclude_address.retain(|a| !a.contains(':'));
        }
        let cfg = &cfg;
        let mut own_nets = Vec::new();
        for a in &cfg.address {
            let (ip, prefix) = sybau_config::parse_cidr(a)?;
            own_nets.push((ip, prefix));
            match ip {
                IpAddr::V4(v4) => opts.ipv4 = Some((v4, prefix)),
                IpAddr::V6(v6) => opts.ipv6 = Some((v6, prefix)),
            }
        }
        let tun = Tun::open(&opts).with_context(|| format!("inbound `{tag}`"))?;
        let routes = if cfg.auto_route && cfg.file_descriptor.is_none() {
            let ro = RouteOptions {
                interface: tun.name().to_string(),
                addresses: cfg.address.clone(),
                route_address: cfg.route_address.clone(),
                route_exclude_address: cfg.route_exclude_address.clone(),
                strict_route: cfg.strict_route,
                include_uid: cfg.include_uid.clone(),
                exclude_uid: cfg.exclude_uid.clone(),
                fwmark: cfg.fwmark,
                table: cfg.table,
                kill_switch: cfg.kill_switch,
            };
            Some(Routes::install(&ro).with_context(|| format!("inbound `{tag}`: auto_route"))?)
        } else {
            if cfg.kill_switch {
                warn!(target: "sybau::inbound", "inbound `{tag}`: kill_switch needs auto_route (on Android use the VpnService \"Block connections without VPN\" setting)");
            }
            None
        };
        Ok(Self {
            tag,
            cfg: cfg.clone(),
            tun,
            routes,
            own_nets,
        })
    }

    pub async fn serve(
        self,
        dispatcher: Arc<Dispatcher>,
        cancel: CancellationToken,
        keep_kill_switch: Arc<AtomicBool>,
    ) {
        let Self {
            tag,
            cfg,
            tun,
            routes,
            own_nets,
        } = self;
        info!(target: "sybau::inbound", "inbound `{tag}`: TUN `{}` up ({}, mtu {}{})", tun.name(), cfg.address.join(", "), cfg.mtu, if routes.is_some() { ", auto_route" } else { "" });
        let udp_timeout = cfg
            .udp_timeout
            .as_deref()
            .and_then(|d| sybau_config::route::parse_duration(d).ok())
            .unwrap_or(DEFAULT_UDP_TIMEOUT);
        let mut stack = tun.into_stack(udp_timeout);
        let ctx = Arc::new(Ctx {
            sniff: SniffOptions {
                enabled: cfg.sniff.enabled,
                override_destination: cfg.sniff.override_destination,
                timeout: Duration::from_millis(cfg.sniff.timeout_ms.clamp(10, 10_000)),
            },
            dns: if cfg.dns_hijack {
                dispatcher.dns.clone()
            } else {
                None
            },
            tag,
            cfg,
            own_nets,
            dispatcher,
        });
        loop {
            let stream = tokio::select! {
                r = stack.accept() => match r {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(target: "sybau::inbound", "inbound `{}`: TUN stack stopped: {e}", ctx.tag);
                        break;
                    }
                },
                _ = cancel.cancelled() => break,
            };
            let (ctx, cancel) = (ctx.clone(), cancel.clone());
            tokio::spawn(async move {
                tokio::select! {
                    _ = ctx.handle(stream) => {}
                    _ = cancel.cancelled() => {}
                }
            });
        }
        drop(stack);
        if let Some(routes) = routes {
            routes.shutdown(keep_kill_switch.load(Ordering::SeqCst));
        }
        info!(target: "sybau::inbound", "inbound `{}`: TUN closed", ctx.tag);
    }
}

struct Ctx {
    tag: Arc<str>,
    cfg: TunConfig,
    own_nets: Vec<(IpAddr, u8)>,
    sniff: SniffOptions,
    dispatcher: Arc<Dispatcher>,
    /// Set when DNS hijacking is on.
    dns: Option<Arc<DnsResolver>>,
}

fn in_net(ip: IpAddr, (net, prefix): (IpAddr, u8)) -> bool {
    match (ip.to_canonical(), net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// Destinations that are never proxied.
fn unroutable(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
    }
}

/// `true` if the process is named in `list` (by file name or full path).
fn process_listed(list: &[String], name: &str, path: &str) -> bool {
    list.iter().any(|entry| {
        let by_path = entry.contains(['/', '\\']);
        let have = if by_path { path } else { name };
        if cfg!(windows) {
            have.eq_ignore_ascii_case(entry)
                || (!by_path && have.eq_ignore_ascii_case(&format!("{entry}.exe")))
        } else {
            have == entry
        }
    })
}

impl Ctx {
    async fn handle(&self, stream: IpStackStream) {
        match stream {
            IpStackStream::Tcp(tcp) => {
                let (src, dst) = (tcp.local_addr(), tcp.peer_addr());
                if let Some(dns) = self.hijacked(dst) {
                    debug!(target: "sybau::dns", "hijacked DNS over TCP {src} -> {dst}");
                    serve_dns_tcp(dns, tcp).await;
                    return;
                }
                if !self.allowed(dst) {
                    return;
                }
                let sess = self.session(Network::Tcp, src, dst).await;
                self.dispatcher.dispatch_stream(sess, Box::new(tcp)).await;
            }
            IpStackStream::Udp(udp) => {
                let (src, dst) = (udp.local_addr(), udp.peer_addr());
                if let Some(dns) = self.hijacked(dst) {
                    debug!(target: "sybau::dns", "hijacked DNS {src} -> {dst}");
                    serve_dns_udp(dns, udp).await;
                    return;
                }
                if !self.allowed(dst) {
                    return;
                }
                let sess = self.session(Network::Udp, src, dst).await;
                let conn = Arc::new(FlowConn::new(udp, Target::from(dst)));
                self.dispatcher.dispatch_packet(sess, conn).await;
            }
            // ICMP and other protocols are not forwarded.
            IpStackStream::UnknownTransport(_) | IpStackStream::UnknownNetwork(_) => {}
        }
    }

    fn hijacked(&self, dst: SocketAddr) -> Option<Arc<DnsResolver>> {
        (dst.port() == 53).then(|| self.dns.clone()).flatten()
    }

    fn allowed(&self, dst: SocketAddr) -> bool {
        let ip = dst.ip();
        if unroutable(ip) {
            return false;
        }
        // Addresses of the TUN network itself: going out "directly" would
        // send the flow straight back into the interface.
        if self.own_nets.iter().any(|n| in_net(ip, *n)) {
            debug!(target: "sybau::inbound", "inbound `{}`: {dst} is on the TUN network; dropped", self.tag);
            return false;
        }
        true
    }

    async fn session(&self, network: Network, src: SocketAddr, dst: SocketAddr) -> Session {
        let mut sess = Session::new(network, self.tag.clone(), Some(src), Target::from(dst));
        sess.sniff = self.sniff;
        let (include, exclude) = (&self.cfg.include_process, &self.cfg.exclude_process);
        if include.is_empty() && exclude.is_empty() {
            return sess;
        }
        let found = tokio::task::spawn_blocking(move || crate::process::find(network, src, None))
            .await
            .ok()
            .flatten();
        let (name, path) = match &found {
            Some(info) if !info.path.is_empty() => {
                sess.process_path = Some(Arc::from(info.path.as_str()));
                sess.process_name = Some(Arc::from(info.name.as_str()));
                (info.name.as_str(), info.path.as_str())
            }
            _ => ("", ""),
        };
        sess.bypass = (!include.is_empty() && !process_listed(include, name, path))
            || process_listed(exclude, name, path);
        sess
    }
}

/// One UDP flow of the stack as a packet connection: datagrams from the
/// application all go to `dst`, replies appear to come from `dst`.
struct FlowConn {
    dst: Target,
    reader: tokio::sync::Mutex<ReadHalf<IpStackUdpStream>>,
    writer: tokio::sync::Mutex<WriteHalf<IpStackUdpStream>>,
}

impl FlowConn {
    fn new(udp: IpStackUdpStream, dst: Target) -> Self {
        let (r, w) = tokio::io::split(udp);
        Self {
            dst,
            reader: tokio::sync::Mutex::new(r),
            writer: tokio::sync::Mutex::new(w),
        }
    }
}

#[async_trait]
impl PacketConn for FlowConn {
    async fn send_to(&self, buf: &[u8], _from: &Target) -> io::Result<usize> {
        self.writer.lock().await.write(buf).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let n = self.reader.lock().await.read(buf).await?;
        if n == 0 {
            return Err(io_err(io::ErrorKind::UnexpectedEof, "UDP flow closed"));
        }
        Ok((n, self.dst.clone()))
    }
}

async fn answer(dns: &DnsResolver, packet: &[u8]) -> Option<Vec<u8>> {
    let query = Message::parse(packet).ok()?;
    if query.response {
        return None;
    }
    dns.exchange(&query).await.encode().ok()
}

/// Answers DNS datagrams of one flow; queries are answered concurrently
/// (resolvers send A and AAAA from the same socket at once).
async fn serve_dns_udp(dns: Arc<DnsResolver>, udp: IpStackUdpStream) {
    let (mut reader, writer) = tokio::io::split(udp);
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let mut buf = vec![0u8; 65535];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            _ => return,
        };
        let packet = buf[..n].to_vec();
        let (dns, writer) = (dns.clone(), writer.clone());
        tokio::spawn(async move {
            if let Some(reply) = answer(&dns, &packet).await {
                let _ = writer.lock().await.write(&reply).await;
            }
        });
    }
}

/// DNS over TCP: length-prefixed messages, answered in order.
async fn serve_dns_tcp(dns: Arc<DnsResolver>, mut tcp: IpStackTcpStream) {
    let mut buf = vec![0u8; 65535];
    loop {
        let len = match tokio::time::timeout(DNS_TCP_IDLE, tcp.read_u16()).await {
            Ok(Ok(len)) => usize::from(len),
            _ => return,
        };
        if tcp.read_exact(&mut buf[..len]).await.is_err() {
            return;
        }
        let Some(reply) = answer(&dns, &buf[..len]).await else {
            return;
        };
        let Ok(rlen) = u16::try_from(reply.len()) else {
            return;
        };
        let mut out = Vec::with_capacity(reply.len() + 2);
        out.extend_from_slice(&rlen.to_be_bytes());
        out.extend_from_slice(&reply);
        if tcp.write_all(&out).await.is_err() || tcp.flush().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks() {
        let net = sybau_config::parse_cidr("172.19.0.1/30").unwrap();
        assert!(in_net("172.19.0.2".parse().unwrap(), net));
        assert!(!in_net("172.19.0.4".parse().unwrap(), net));
        let v6 = sybau_config::parse_cidr("fdfe:dcba:9876::1/126").unwrap();
        assert!(in_net("fdfe:dcba:9876::2".parse().unwrap(), v6));
        assert!(!in_net("fdfe:dcba:9876::4".parse().unwrap(), v6));
        assert!(in_net(
            "1.2.3.4".parse().unwrap(),
            sybau_config::parse_cidr("0.0.0.0/0").unwrap()
        ));
        assert!(unroutable("224.0.0.251".parse().unwrap()));
        assert!(unroutable("255.255.255.255".parse().unwrap()));
        assert!(!unroutable("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn process_lists() {
        let list = vec!["firefox".to_string(), "/usr/bin/curl".to_string()];
        assert!(process_listed(&list, "firefox", "/usr/lib/firefox/firefox"));
        assert!(process_listed(&list, "curl", "/usr/bin/curl"));
        assert!(!process_listed(&list, "curl", "/opt/curl"));
        assert!(!process_listed(&list, "", ""));
    }
}
