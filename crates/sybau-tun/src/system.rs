//! The `system` stack: TCP is handled by the operating system's own TCP
//! stack through address translation inside the TUN.
//!
//! The interface address is A (`172.19.0.1`), the next address of its
//! network is B. A SYN from an application, `S:sp -> D:dp`, is rewritten
//! to `B:np -> A:lp` and written back into the TUN; the kernel delivers
//! it to a listener of the core on `A:lp`, which looks up `np` to learn
//! the original endpoints. Replies of that socket, `A:lp -> B:np`, leave
//! through the TUN and are rewritten back to `D:dp -> S:sp`. The kernel
//! does retransmission, congestion control and segmentation, which is
//! much faster than a userspace TCP stack.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};

/// What to do with a packet read from the TUN.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// TCP, rewritten in place: write it back into the TUN.
    Rewritten,
    /// TCP that cannot be translated.
    Drop,
    /// Not TCP: for the userspace stack.
    Pass,
}

/// One side of the translation for an address family.
#[derive(Clone, Copy, Debug)]
pub struct Family {
    /// Interface address (A), where the listener is.
    pub server: IpAddr,
    /// Next address of the interface network (B), the translated source.
    pub client: IpAddr,
    /// Port of the listener on A.
    pub port: u16,
}

struct Entry {
    src: SocketAddr,
    dst: SocketAddr,
    last: Instant,
    /// A stream of the core holds the entry.
    held: bool,
}

#[derive(Default)]
struct Table {
    by_port: HashMap<u16, Entry>,
    by_flow: HashMap<(SocketAddr, SocketAddr), u16>,
    next: u16,
}

const FIRST_PORT: u16 = 10_000;
const LAST_PORT: u16 = 65_000;
/// Entries not held by a stream are kept this long after their last
/// packet (covers retransmitted SYNs and the closing handshake).
const IDLE: Duration = Duration::from_secs(120);

/// The translation table.
pub struct Nat {
    v4: Option<Family>,
    v6: Option<Family>,
    table: Mutex<Table>,
}

impl Nat {
    pub fn new(v4: Option<Family>, v6: Option<Family>) -> Arc<Self> {
        Arc::new(Self {
            v4,
            v6,
            table: Mutex::new(Table {
                next: FIRST_PORT,
                ..Default::default()
            }),
        })
    }

    fn family(&self, v6: bool) -> Option<Family> {
        if v6 {
            self.v6
        } else {
            self.v4
        }
    }

    /// Port for a new flow, or the one it already has.
    fn port_for(&self, src: SocketAddr, dst: SocketAddr, create: bool) -> Option<u16> {
        let mut t = self.table.lock();
        if let Some(&port) = t.by_flow.get(&(src, dst)) {
            if let Some(e) = t.by_port.get_mut(&port) {
                e.last = Instant::now();
            }
            return Some(port);
        }
        if !create {
            return None;
        }
        let span = usize::from(LAST_PORT - FIRST_PORT) + 1;
        for _ in 0..span {
            let port = t.next;
            t.next = if port >= LAST_PORT {
                FIRST_PORT
            } else {
                port + 1
            };
            if let std::collections::hash_map::Entry::Vacant(slot) = t.by_port.entry(port) {
                slot.insert(Entry {
                    src,
                    dst,
                    last: Instant::now(),
                    held: false,
                });
                t.by_flow.insert((src, dst), port);
                return Some(port);
            }
        }
        None
    }

    fn reverse(&self, port: u16) -> Option<(SocketAddr, SocketAddr)> {
        let mut t = self.table.lock();
        let e = t.by_port.get_mut(&port)?;
        e.last = Instant::now();
        Some((e.src, e.dst))
    }

    /// Marks the flow behind `port` as served by a stream; `None` if the
    /// port is not a known flow.
    fn take(self: &Arc<Self>, port: u16) -> Option<(SocketAddr, SocketAddr, Held)> {
        let mut t = self.table.lock();
        let e = t.by_port.get_mut(&port)?;
        e.held = true;
        Some((
            e.src,
            e.dst,
            Held {
                nat: self.clone(),
                port,
            },
        ))
    }

    /// Drops idle entries; returns how many are left.
    pub fn expire(&self) -> usize {
        let mut t = self.table.lock();
        let now = Instant::now();
        let gone: Vec<(u16, SocketAddr, SocketAddr)> = t
            .by_port
            .iter()
            .filter(|(_, e)| !e.held && now.duration_since(e.last) > IDLE)
            .map(|(p, e)| (*p, e.src, e.dst))
            .collect();
        for (port, src, dst) in gone {
            t.by_port.remove(&port);
            t.by_flow.remove(&(src, dst));
        }
        t.by_port.len()
    }

    /// Translates a TCP packet read from the TUN in place.
    pub fn rewrite(&self, packet: &mut [u8]) -> Verdict {
        match packet.first().map(|b| b >> 4) {
            Some(4) => self.rewrite_v4(packet),
            Some(6) => self.rewrite_v6(packet),
            _ => Verdict::Pass,
        }
    }

    fn rewrite_v4(&self, p: &mut [u8]) -> Verdict {
        if p.len() < 20 || p[9] != 6 {
            return Verdict::Pass;
        }
        let ihl = usize::from(p[0] & 0x0f) * 4;
        let frag = u16::from_be_bytes([p[6], p[7]]) & 0x3fff;
        if ihl < 20 || p.len() < ihl + 20 || frag != 0 {
            return Verdict::Drop;
        }
        let Some(fam) = self.v4 else {
            return Verdict::Drop;
        };
        let src = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15])),
            u16::from_be_bytes([p[ihl], p[ihl + 1]]),
        );
        let dst = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19])),
            u16::from_be_bytes([p[ihl + 2], p[ihl + 3]]),
        );
        let Some((new_src, new_dst)) = self.translate(fam, src, dst, p[ihl + 13]) else {
            return Verdict::Drop;
        };
        let old: [u8; 12] = p[12..20]
            .iter()
            .chain(&p[ihl..ihl + 4])
            .copied()
            .collect::<Vec<u8>>()
            .try_into()
            .expect("12 bytes");
        set_ip(&mut p[12..16], new_src.ip());
        set_ip(&mut p[16..20], new_dst.ip());
        p[ihl..ihl + 2].copy_from_slice(&new_src.port().to_be_bytes());
        p[ihl + 2..ihl + 4].copy_from_slice(&new_dst.port().to_be_bytes());
        // IP header checksum covers the addresses; TCP's covers addresses
        // (pseudo header) and ports.
        let ip_sum = u16::from_be_bytes([p[10], p[11]]);
        let ip_sum = adjust(ip_sum, &old[..8], &p[12..20]);
        p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        let mut new = [0u8; 12];
        new[..8].copy_from_slice(&p[12..20]);
        new[8..].copy_from_slice(&p[ihl..ihl + 4]);
        let tcp_sum = u16::from_be_bytes([p[ihl + 16], p[ihl + 17]]);
        let tcp_sum = adjust(tcp_sum, &old, &new);
        p[ihl + 16..ihl + 18].copy_from_slice(&tcp_sum.to_be_bytes());
        Verdict::Rewritten
    }

    fn rewrite_v6(&self, p: &mut [u8]) -> Verdict {
        // Extension headers before TCP are left to the userspace stack.
        if p.len() < 40 || p[6] != 6 {
            return Verdict::Pass;
        }
        if p.len() < 60 {
            return Verdict::Drop;
        }
        let Some(fam) = self.v6 else {
            return Verdict::Drop;
        };
        let addr = |b: &[u8]| IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b).expect("16")));
        let src = SocketAddr::new(addr(&p[8..24]), u16::from_be_bytes([p[40], p[41]]));
        let dst = SocketAddr::new(addr(&p[24..40]), u16::from_be_bytes([p[42], p[43]]));
        let Some((new_src, new_dst)) = self.translate(fam, src, dst, p[53]) else {
            return Verdict::Drop;
        };
        let mut old = [0u8; 36];
        old[..32].copy_from_slice(&p[8..40]);
        old[32..].copy_from_slice(&p[40..44]);
        set_ip(&mut p[8..24], new_src.ip());
        set_ip(&mut p[24..40], new_dst.ip());
        p[40..42].copy_from_slice(&new_src.port().to_be_bytes());
        p[42..44].copy_from_slice(&new_dst.port().to_be_bytes());
        let mut new = [0u8; 36];
        new[..32].copy_from_slice(&p[8..40]);
        new[32..].copy_from_slice(&p[40..44]);
        let sum = adjust(u16::from_be_bytes([p[56], p[57]]), &old, &new);
        p[56..58].copy_from_slice(&sum.to_be_bytes());
        Verdict::Rewritten
    }

    /// New endpoints of a packet, `None` to drop it.
    fn translate(
        &self,
        fam: Family,
        src: SocketAddr,
        dst: SocketAddr,
        flags: u8,
    ) -> Option<(SocketAddr, SocketAddr)> {
        if src.ip() == fam.server && src.port() == fam.port {
            // Reply of the core's socket towards B:np.
            if dst.ip() != fam.client {
                return None;
            }
            let (orig_src, orig_dst) = self.reverse(dst.port())?;
            return Some((orig_dst, orig_src));
        }
        if !usable(dst.ip()) {
            return None;
        }
        // Only a SYN without ACK opens a flow; anything else must belong
        // to one (the kernel would reset it anyway).
        let syn = flags & 0x12 == 0x02;
        let port = self.port_for(src, dst, syn)?;
        Some((
            SocketAddr::new(fam.client, port),
            SocketAddr::new(fam.server, fam.port),
        ))
    }
}

fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !(v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified()),
        IpAddr::V6(v6) => !(v6.is_multicast() || v6.is_unspecified()),
    }
}

fn set_ip(out: &mut [u8], ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => out.copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.copy_from_slice(&v6.octets()),
    }
}

/// Updates a ones' complement checksum for `old` bytes replaced by `new`
/// (RFC 1624: HC' = ~(~HC + ~m + m')). Both have the same even length.
fn adjust(sum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut acc = u32::from(!sum);
    for (o, n) in old.as_chunks::<2>().0.iter().zip(new.as_chunks::<2>().0) {
        acc += u32::from(!u16::from_be_bytes(*o));
        acc += u32::from(u16::from_be_bytes(*n));
    }
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Keeps a flow's translation while the core's stream lives.
pub struct Held {
    nat: Arc<Nat>,
    port: u16,
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut t = self.nat.table.lock();
        if let Some(e) = t.by_port.get_mut(&self.port) {
            e.held = false;
            e.last = Instant::now();
        }
    }
}

/// A TCP connection of an application, delivered by the kernel.
pub struct Accepted {
    pub stream: TcpStream,
    /// The application's address.
    pub source: SocketAddr,
    /// Where the application connected to.
    pub destination: SocketAddr,
    /// Keep alive as long as `stream`.
    pub held: Held,
}

/// Listeners on the interface addresses.
pub struct TcpAcceptor {
    v4: Option<TcpListener>,
    v6: Option<TcpListener>,
    nat: Arc<Nat>,
}

impl TcpAcceptor {
    /// Binds the listeners and builds the table.
    pub fn bind(v4: Option<(Ipv4Addr, u8)>, v6: Option<(Ipv6Addr, u8)>) -> io::Result<Self> {
        let listen = |ip: IpAddr| -> io::Result<(TcpListener, u16)> {
            let std = std::net::TcpListener::bind(SocketAddr::new(ip, 0))?;
            std.set_nonblocking(true)?;
            let port = std.local_addr()?.port();
            Ok((TcpListener::from_std(std)?, port))
        };
        let mut fam4 = None;
        let mut l4 = None;
        if let Some((a, prefix)) = v4 {
            let b = next_v4(a, prefix).ok_or_else(|| {
                io::Error::other(
                    "the TUN IPv4 network needs room for a second address (/30 or wider)",
                )
            })?;
            let (l, port) = listen(IpAddr::V4(a))?;
            l4 = Some(l);
            fam4 = Some(Family {
                server: IpAddr::V4(a),
                client: IpAddr::V4(b),
                port,
            });
        }
        let mut fam6 = None;
        let mut l6 = None;
        if let Some((a, prefix)) = v6 {
            if let Some(b) = next_v6(a, prefix) {
                // The IPv6 address may still be tentative (DAD): skip it
                // rather than fail.
                match listen(IpAddr::V6(a)) {
                    Ok((l, port)) => {
                        l6 = Some(l);
                        fam6 = Some(Family {
                            server: IpAddr::V6(a),
                            client: IpAddr::V6(b),
                            port,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(target: "sybau::tun", "system stack: no IPv6 listener ({e}); IPv6 TCP is dropped")
                    }
                }
            }
        }
        Ok(Self {
            v4: l4,
            v6: l6,
            nat: Nat::new(fam4, fam6),
        })
    }

    pub fn nat(&self) -> Arc<Nat> {
        self.nat.clone()
    }

    pub async fn accept(&self) -> io::Result<Accepted> {
        loop {
            let (stream, peer) = match (&self.v4, &self.v6) {
                (Some(a), Some(b)) => tokio::select! {
                    r = a.accept() => r?,
                    r = b.accept() => r?,
                },
                (Some(a), None) => a.accept().await?,
                (None, Some(b)) => b.accept().await?,
                (None, None) => std::future::pending().await,
            };
            let fam = self.nat.family(peer.is_ipv6());
            // Anything but a translated flow (a host on the TUN network
            // dialling the listener directly) is turned away.
            if fam.is_none_or(|f| f.client != peer.ip()) {
                continue;
            }
            let Some((source, destination, held)) = self.nat.take(peer.port()) else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            return Ok(Accepted {
                stream,
                source,
                destination,
                held,
            });
        }
    }
}

fn next_v4(a: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    if prefix > 30 {
        return None;
    }
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    let net = u32::from(a) & mask;
    let bcast = net | !mask;
    (net + 1..bcast).map(Ipv4Addr::from).find(|x| *x != a)
}

fn next_v6(a: Ipv6Addr, prefix: u8) -> Option<Ipv6Addr> {
    if prefix > 126 {
        return None;
    }
    let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
    let net = u128::from(a) & mask;
    (1..4).map(|i| Ipv6Addr::from(net + i)).find(|x| *x != a)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full checksum of `data` with an initial sum.
    fn csum(init: u32, data: &[u8]) -> u16 {
        let mut acc = init;
        for c in data.chunks(2) {
            acc += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
        }
        while acc > 0xffff {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        !(acc as u16)
    }

    fn tcp_v4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 44, 0, 1, 0x40, 0, 64, 6, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        tcp.extend_from_slice(b"data");
        p.extend_from_slice(&tcp);
        fix_v4(&mut p);
        p
    }

    fn fix_v4(p: &mut [u8]) {
        p[10..12].copy_from_slice(&[0, 0]);
        let s = csum(0, &p[..20]);
        p[10..12].copy_from_slice(&s.to_be_bytes());
        p[36..38].copy_from_slice(&[0, 0]);
        let len = (p.len() - 20) as u32;
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&p[12..20]);
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&(len as u16).to_be_bytes());
        pseudo.extend_from_slice(&p[20..]);
        let s = csum(0, &pseudo);
        p[36..38].copy_from_slice(&s.to_be_bytes());
    }

    fn checksums_valid(p: &[u8]) -> bool {
        let mut copy = p.to_vec();
        fix_v4(&mut copy);
        copy == p
    }

    #[test]
    fn syn_and_reply_round_trip() {
        let a = Ipv4Addr::new(172, 19, 0, 1);
        let b = Ipv4Addr::new(172, 19, 0, 2);
        let nat = Nat::new(
            Some(Family {
                server: a.into(),
                client: b.into(),
                port: 4000,
            }),
            None,
        );
        // Application SYN: 172.19.0.1:5555 -> 93.184.216.34:443.
        let mut syn = tcp_v4([172, 19, 0, 1], 5555, [93, 184, 216, 34], 443, 0x02);
        assert_eq!(nat.rewrite(&mut syn), Verdict::Rewritten);
        assert_eq!(&syn[12..16], &b.octets());
        assert_eq!(&syn[16..20], &a.octets());
        let np = u16::from_be_bytes([syn[20], syn[21]]);
        assert_eq!(u16::from_be_bytes([syn[22], syn[23]]), 4000);
        assert!(
            checksums_valid(&syn),
            "incremental checksums match full ones"
        );
        // The same SYN again (retransmission) keeps its port.
        let mut again = tcp_v4([172, 19, 0, 1], 5555, [93, 184, 216, 34], 443, 0x02);
        nat.rewrite(&mut again);
        assert_eq!(u16::from_be_bytes([again[20], again[21]]), np);
        // The core's SYN-ACK: 172.19.0.1:4000 -> 172.19.0.2:np.
        let mut reply = tcp_v4([172, 19, 0, 1], 4000, [172, 19, 0, 2], np, 0x12);
        assert_eq!(nat.rewrite(&mut reply), Verdict::Rewritten);
        assert_eq!(&reply[12..16], &[93, 184, 216, 34]);
        assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 443);
        assert_eq!(&reply[16..20], &a.octets());
        assert_eq!(u16::from_be_bytes([reply[22], reply[23]]), 5555);
        assert!(checksums_valid(&reply));
        // Accepting the flow reveals the original endpoints.
        let (src, dst, held) = nat.take(np).unwrap();
        assert_eq!(src, "172.19.0.1:5555".parse().unwrap());
        assert_eq!(dst, "93.184.216.34:443".parse().unwrap());
        drop(held);
        // A stray ACK of an unknown flow is dropped, UDP passes.
        let mut stray = tcp_v4([172, 19, 0, 1], 6000, [1, 1, 1, 1], 80, 0x10);
        assert_eq!(nat.rewrite(&mut stray), Verdict::Drop);
        let mut udp = tcp_v4([172, 19, 0, 1], 6000, [1, 1, 1, 1], 53, 0);
        udp[9] = 17;
        assert_eq!(nat.rewrite(&mut udp), Verdict::Pass);
        assert_eq!(nat.expire(), 1);
    }

    #[test]
    fn second_addresses() {
        assert_eq!(
            next_v4(Ipv4Addr::new(172, 19, 0, 1), 30),
            Some(Ipv4Addr::new(172, 19, 0, 2))
        );
        assert_eq!(
            next_v4(Ipv4Addr::new(10, 0, 0, 2), 24),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(next_v4(Ipv4Addr::new(10, 0, 0, 1), 32), None);
        assert_eq!(
            next_v6("fdfe:dcba:9876::1".parse().unwrap(), 126),
            Some("fdfe:dcba:9876::2".parse().unwrap())
        );
    }
}
