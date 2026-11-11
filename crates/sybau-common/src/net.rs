use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::{io_err, ArcPacketConn, BoxStream, Host, PacketConn, Target};

/// Resolves domain names to IP addresses.
#[async_trait]
pub trait Resolver: Send + Sync + 'static {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

/// Resolver backed by the operating system (`getaddrinfo`).
pub struct SystemResolver;

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, 0))
            .await?
            .map(|a| a.ip())
            .collect();
        if addrs.is_empty() {
            return Err(io_err(
                io::ErrorKind::NotFound,
                format!("no addresses for {host}"),
            ));
        }
        Ok(addrs)
    }
}

/// Callback that excludes a socket from the VPN (Android `VpnService.protect`).
/// Receives the raw fd / SOCKET and returns `false` on failure.
pub type ProtectFn = Arc<dyn Fn(i64) -> bool + Send + Sync>;

/// Options applied to every socket the core opens towards the outside world.
#[derive(Clone, Default)]
pub struct SocketOpts {
    /// Bind to a network interface by name (`SO_BINDTODEVICE`).
    pub bind_interface: Option<String>,
    /// Linux firewall mark (`SO_MARK`), used to keep core traffic out of TUN.
    pub fwmark: Option<u32>,
    pub protect: Option<ProtectFn>,
    pub connect_timeout: Option<Duration>,
}

impl SocketOpts {
    /// `self` with every option it leaves unset taken from `base`.
    pub fn or(self, base: &SocketOpts) -> SocketOpts {
        SocketOpts {
            bind_interface: self.bind_interface.or_else(|| base.bind_interface.clone()),
            fwmark: self.fwmark.or(base.fwmark),
            protect: self.protect.or_else(|| base.protect.clone()),
            connect_timeout: self.connect_timeout.or(base.connect_timeout),
        }
    }

    fn apply(&self, sock: SockRef<'_>) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Some(mark) = self.fwmark {
                sock.set_mark(mark)?;
            }
            if let Some(iface) = &self.bind_interface {
                sock.bind_device(Some(iface.as_bytes()))?;
            }
        }
        if let Some(protect) = &self.protect {
            #[cfg(unix)]
            let raw = {
                use std::os::fd::AsRawFd;
                sock.as_raw_fd() as i64
            };
            #[cfg(windows)]
            let raw = {
                use std::os::windows::io::AsRawSocket;
                sock.as_raw_socket() as i64
            };
            if !protect(raw) {
                return Err(io_err(
                    io::ErrorKind::PermissionDenied,
                    "socket protect callback failed",
                ));
            }
        }
        let _ = &sock;
        Ok(())
    }
}

/// Opens outgoing connections: either straight to the network
/// ([`SystemDialer`]) or through another outbound (proxy chains).
#[async_trait]
pub trait Dialer: Send + Sync + 'static {
    async fn dial_tcp(&self, target: &Target) -> io::Result<BoxStream>;
    /// Opens a datagram endpoint. `target` is the first destination and is
    /// only a hint for transports that are bound to a single peer.
    async fn dial_udp(&self, target: &Target) -> io::Result<ArcPacketConn>;
}

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Dials directly through the operating system network stack.
pub struct SystemDialer {
    pub resolver: Arc<dyn Resolver>,
    pub opts: SocketOpts,
}

impl SystemDialer {
    pub fn new(resolver: Arc<dyn Resolver>, opts: SocketOpts) -> Self {
        Self { resolver, opts }
    }

    pub async fn resolve(&self, target: &Target) -> io::Result<Vec<SocketAddr>> {
        match &target.host {
            Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, target.port)]),
            Host::Domain(d) => {
                let mut ips = self.resolver.resolve(d).await?;
                // IPv4 first: the most widely working default until the DNS
                // strategy from the config takes over.
                ips.sort_by_key(|ip| ip.is_ipv6());
                Ok(ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, target.port))
                    .collect())
            }
        }
    }

    async fn connect_addr(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let sock = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        self.opts.apply(SockRef::from(&sock))?;
        let timeout = self.opts.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT);
        let stream = tokio::time::timeout(timeout, sock.connect(addr))
            .await
            .map_err(|_| {
                io_err(
                    io::ErrorKind::TimedOut,
                    format!("connect to {addr} timed out"),
                )
            })??;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// Connects and returns the raw `TcpStream` (needed for socket-level tricks).
    pub async fn connect_tcp(&self, target: &Target) -> io::Result<TcpStream> {
        let addrs = self.resolve(target).await?;
        let mut last = io_err(
            io::ErrorKind::NotFound,
            format!("no addresses for {target}"),
        );
        for addr in addrs.into_iter().take(6) {
            match self.connect_addr(addr).await {
                Ok(s) => return Ok(s),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    pub fn bind_udp(&self) -> io::Result<UdpConn> {
        UdpConn::bind(self.resolver.clone(), &self.opts)
    }
}

#[async_trait]
impl Dialer for SystemDialer {
    async fn dial_tcp(&self, target: &Target) -> io::Result<BoxStream> {
        Ok(Box::new(self.connect_tcp(target).await?))
    }

    async fn dial_udp(&self, _target: &Target) -> io::Result<ArcPacketConn> {
        Ok(Arc::new(self.bind_udp()?))
    }
}

/// Unconnected UDP socket able to reach both IPv4 and IPv6 destinations.
pub struct UdpConn {
    sock: UdpSocket,
    dual_stack: bool,
    resolver: Arc<dyn Resolver>,
    resolved: Mutex<HashMap<String, IpAddr>>,
}

impl UdpConn {
    pub fn bind(resolver: Arc<dyn Resolver>, opts: &SocketOpts) -> io::Result<Self> {
        let (sock, dual_stack) = match Self::bind_v6_dual() {
            Ok(s) => (s, true),
            Err(_) => {
                let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
                s.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
                (s, false)
            }
        };
        opts.apply(SockRef::from(&sock))?;
        sock.set_nonblocking(true)?;
        Ok(Self {
            sock: UdpSocket::from_std(sock.into())?,
            dual_stack,
            resolver,
            resolved: Mutex::new(HashMap::new()),
        })
    }

    fn bind_v6_dual() -> io::Result<Socket> {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        s.set_only_v6(false)?;
        s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
        Ok(s)
    }

    async fn destination(&self, dst: &Target) -> io::Result<SocketAddr> {
        let ip = match &dst.host {
            Host::Ip(ip) => *ip,
            Host::Domain(d) => {
                let cached = self.resolved.lock().get(d).copied();
                match cached {
                    Some(ip) => ip,
                    None => {
                        let ips = self.resolver.resolve(d).await?;
                        let ip = ips
                            .iter()
                            .find(|ip| ip.is_ipv4())
                            .or_else(|| ips.iter().find(|_| self.dual_stack))
                            .copied()
                            .ok_or_else(|| {
                                io_err(
                                    io::ErrorKind::NotFound,
                                    format!("no usable address for {d}"),
                                )
                            })?;
                        self.resolved.lock().insert(d.clone(), ip);
                        ip
                    }
                }
            }
        };
        match (ip, self.dual_stack) {
            (IpAddr::V4(v4), true) => Ok(SocketAddr::new(v4.to_ipv6_mapped().into(), dst.port)),
            (IpAddr::V6(_), false) => Err(io_err(
                io::ErrorKind::Unsupported,
                "IPv6 is not available on this host",
            )),
            (ip, _) => Ok(SocketAddr::new(ip, dst.port)),
        }
    }
}

#[async_trait]
impl PacketConn for UdpConn {
    async fn send_to(&self, buf: &[u8], dst: &Target) -> io::Result<usize> {
        let addr = self.destination(dst).await?;
        self.sock.send_to(buf, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let (n, from) = self.sock.recv_from(buf).await?;
        Ok((n, Target::from(from)))
    }
}
