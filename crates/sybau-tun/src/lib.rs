//! TUN support of SYBAU-CORE: the virtual interface, a userspace TCP/IP
//! stack that turns its packets into streams, system routes and the
//! kill switch.

pub mod device;
pub mod routes;

pub use device::{Tun, TunOptions};
pub use ipstack::{IpStackStream, IpStackTcpStream, IpStackUdpStream};

/// Whether the system can use IPv6 at all (kernels can be built or
/// booted without it).
pub fn ipv6_available() -> bool {
    std::net::UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0)).is_ok()
        || std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).is_ok()
}
