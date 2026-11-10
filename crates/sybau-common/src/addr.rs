use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::proto_err;

/// Destination host: a literal IP or a domain name still to be resolved.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

/// Destination of a proxied connection or datagram.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl Target {
    pub fn new(host: Host, port: u16) -> Self {
        Self { host, port }
    }

    /// Builds a target from a textual host; IP literals become `Host::Ip`.
    pub fn from_host(host: &str, port: u16) -> Self {
        let trimmed = host.trim_start_matches('[').trim_end_matches(']');
        match trimmed.parse::<IpAddr>() {
            Ok(ip) => Self::new(Host::Ip(ip), port),
            Err(_) => Self::new(Host::Domain(host.to_ascii_lowercase()), port),
        }
    }

    /// Parses `host:port`, `1.2.3.4:port` or `[v6]:port`.
    pub fn parse(s: &str) -> Option<Self> {
        if let Ok(sa) = s.parse::<SocketAddr>() {
            return Some(sa.into());
        }
        let (host, port) = s.rsplit_once(':')?;
        if host.is_empty() {
            return None;
        }
        Some(Self::from_host(host, port.parse().ok()?))
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match &self.host {
            Host::Ip(ip) => Some(SocketAddr::new(*ip, self.port)),
            Host::Domain(_) => None,
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match &self.host {
            Host::Domain(d) => Some(d),
            Host::Ip(_) => None,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match &self.host {
            Host::Ip(ip) => Some(*ip),
            Host::Domain(_) => None,
        }
    }

    /// Host without the port, IPv6 without brackets.
    pub fn host_string(&self) -> String {
        match &self.host {
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(d) => d.clone(),
        }
    }
}

impl From<SocketAddr> for Target {
    fn from(sa: SocketAddr) -> Self {
        let ip = match sa.ip() {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        Self::new(Host::Ip(ip), sa.port())
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{}]:{}", ip, self.port),
            Host::Ip(ip) => write!(f, "{}:{}", ip, self.port),
            Host::Domain(d) => write!(f, "{}:{}", d, self.port),
        }
    }
}

pub const ATYP_V4: u8 = 1;
pub const ATYP_DOMAIN: u8 = 3;
pub const ATYP_V6: u8 = 4;

/// Writes a SOCKS5-style address (`ATYP | ADDR | PORT`). The same layout is
/// used by SOCKS5, Trojan and Shadowsocks.
pub fn put_socks_addr(buf: &mut impl BufMut, t: &Target) {
    match &t.host {
        Host::Ip(IpAddr::V4(ip)) => {
            buf.put_u8(ATYP_V4);
            buf.put_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            buf.put_u8(ATYP_V6);
            buf.put_slice(&ip.octets());
        }
        Host::Domain(d) => {
            let bytes = &d.as_bytes()[..d.len().min(255)];
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(bytes.len() as u8);
            buf.put_slice(bytes);
        }
    }
    buf.put_u16(t.port);
}

pub fn socks_addr_len(t: &Target) -> usize {
    match &t.host {
        Host::Ip(IpAddr::V4(_)) => 1 + 4 + 2,
        Host::Ip(IpAddr::V6(_)) => 1 + 16 + 2,
        Host::Domain(d) => 1 + 1 + d.len().min(255) + 2,
    }
}

/// Parses a SOCKS5-style address from the start of `buf`.
/// Returns `Ok(None)` when more bytes are needed.
pub fn parse_socks_addr(buf: &[u8]) -> io::Result<Option<(Target, usize)>> {
    let Some(&atyp) = buf.first() else {
        return Ok(None);
    };
    let (host, used) = match atyp {
        ATYP_V4 => {
            if buf.len() < 1 + 4 + 2 {
                return Ok(None);
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            (Host::Ip(ip.into()), 5)
        }
        ATYP_V6 => {
            if buf.len() < 1 + 16 + 2 {
                return Ok(None);
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[1..17]);
            (Host::Ip(Ipv6Addr::from(o).into()), 17)
        }
        ATYP_DOMAIN => {
            let Some(&len) = buf.get(1) else {
                return Ok(None);
            };
            let len = len as usize;
            if buf.len() < 2 + len + 2 {
                return Ok(None);
            }
            (domain_host(&buf[2..2 + len])?, 2 + len)
        }
        other => return Err(proto_err(format!("unknown address type {other:#x}"))),
    };
    let port = u16::from_be_bytes([buf[used], buf[used + 1]]);
    Ok(Some((Target::new(host, port), used + 2)))
}

/// Reads a SOCKS5-style address from a stream.
pub async fn read_socks_addr<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Target> {
    let atyp = r.read_u8().await?;
    let host = match atyp {
        ATYP_V4 => {
            let mut o = [0u8; 4];
            r.read_exact(&mut o).await?;
            Host::Ip(Ipv4Addr::from(o).into())
        }
        ATYP_V6 => {
            let mut o = [0u8; 16];
            r.read_exact(&mut o).await?;
            Host::Ip(Ipv6Addr::from(o).into())
        }
        ATYP_DOMAIN => {
            let len = r.read_u8().await? as usize;
            let mut d = vec![0u8; len];
            r.read_exact(&mut d).await?;
            domain_host(&d)?
        }
        other => return Err(proto_err(format!("unknown address type {other:#x}"))),
    };
    let port = r.read_u16().await?;
    Ok(Target::new(host, port))
}

/// Validates a domain received from the wire. Clients sometimes put an IP
/// literal into the domain field; that is normalised to `Host::Ip`.
pub fn domain_host(raw: &[u8]) -> io::Result<Host> {
    let s = std::str::from_utf8(raw).map_err(|_| proto_err("domain is not valid UTF-8"))?;
    if s.is_empty() || s.bytes().any(|b| b <= b' ' || b == b'/' || b == 0x7f) {
        return Err(proto_err("invalid domain name"));
    }
    Ok(match s.parse::<IpAddr>() {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(s.to_ascii_lowercase()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_targets() {
        assert_eq!(
            Target::parse("example.com:443").unwrap().to_string(),
            "example.com:443"
        );
        assert_eq!(
            Target::parse("1.2.3.4:80")
                .unwrap()
                .ip()
                .unwrap()
                .to_string(),
            "1.2.3.4"
        );
        assert_eq!(Target::parse("[::1]:53").unwrap().to_string(), "[::1]:53");
        assert!(Target::parse("nope").is_none());
        assert!(Target::parse(":80").is_none());
    }

    #[test]
    fn socks_addr_roundtrip() {
        for s in ["example.com:443", "1.2.3.4:80", "[2001:db8::1]:8443"] {
            let t = Target::parse(s).unwrap();
            let mut buf = Vec::new();
            put_socks_addr(&mut buf, &t);
            assert_eq!(buf.len(), socks_addr_len(&t));
            let (back, used) = parse_socks_addr(&buf).unwrap().unwrap();
            assert_eq!(back, t);
            assert_eq!(used, buf.len());
            for cut in 0..buf.len() {
                assert!(parse_socks_addr(&buf[..cut]).unwrap().is_none());
            }
        }
    }

    #[test]
    fn rejects_bad_atyp_and_domain() {
        assert!(parse_socks_addr(&[9, 0, 0]).is_err());
        assert!(parse_socks_addr(&[3, 2, b'a', b' ', 0, 80]).is_err());
    }
}
