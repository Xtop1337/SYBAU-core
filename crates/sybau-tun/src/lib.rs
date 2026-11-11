//! TUN support of SYBAU-CORE: the virtual interface, a userspace TCP/IP
//! stack that turns its packets into streams, system routes and the
//! kill switch.

pub mod device;
pub mod routes;
#[cfg(windows)]
mod wfp;
#[cfg(windows)]
pub mod windows;

pub use device::{Tun, TunOptions};
pub use ipstack::{IpStackStream, IpStackTcpStream, IpStackUdpStream};

/// Whether the system can use IPv6 at all (kernels can be built or
/// booted without it).
pub fn ipv6_available() -> bool {
    std::net::UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0)).is_ok()
        || std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).is_ok()
}

/// Interface indexes of the IPv4 and IPv6 uplinks, i.e. the interfaces of
/// the system's default routes outside the TUN (0 when unknown). Only
/// Windows needs them; elsewhere they are always 0.
pub fn uplink_interfaces(tun_index: u32) -> (u32, u32) {
    #[cfg(windows)]
    {
        windows::uplinks(tun_index)
    }
    #[cfg(not(windows))]
    {
        let _ = tun_index;
        (0, 0)
    }
}
