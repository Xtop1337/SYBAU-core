//! Sets of IP prefixes with logarithmic lookup.

use std::net::IpAddr;

use anyhow::{anyhow, bail, Result};

/// Parses `1.2.3.0/24`, `2001:db8::/32` or a single address.
/// Returns the inclusive range it covers as IPv6-wide integers together
/// with the address family.
pub fn parse_cidr(text: &str) -> Result<(IpAddr, u8)> {
    let (addr, prefix) = match text.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (text, None),
    };
    let ip: IpAddr = addr
        .trim()
        .parse()
        .map_err(|_| anyhow!("`{text}` is not an IP address or CIDR"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(p) => p
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|p| *p <= max)
            .ok_or_else(|| anyhow!("bad prefix length in `{text}`"))?,
        None => max,
    };
    Ok((ip, prefix))
}

fn range_v4(ip: std::net::Ipv4Addr, prefix: u8) -> (u32, u32) {
    let value = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (value & mask, value | !mask)
}

fn range_v6(ip: std::net::Ipv6Addr, prefix: u8) -> (u128, u128) {
    let value = u128::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (value & mask, value | !mask)
}

#[derive(Default, Debug, Clone)]
pub struct IpSetBuilder {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpSetBuilder {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn add(&mut self, ip: IpAddr, prefix: u8) {
        match ip {
            IpAddr::V4(v4) => self.v4.push(range_v4(v4, prefix.min(32))),
            IpAddr::V6(v6) => self.v6.push(range_v6(v6, prefix.min(128))),
        }
    }

    pub fn add_cidr(&mut self, text: &str) -> Result<()> {
        let (ip, prefix) = parse_cidr(text)?;
        self.add(ip, prefix);
        Ok(())
    }

    /// Adds a prefix given as raw address bytes (4 or 16), as stored in
    /// `geoip.dat`.
    pub fn add_bytes(&mut self, ip: &[u8], prefix: u8) -> Result<()> {
        match ip.len() {
            4 => self.add(
                IpAddr::from(<[u8; 4]>::try_from(ip).expect("4 bytes")),
                prefix,
            ),
            16 => self.add(
                IpAddr::from(<[u8; 16]>::try_from(ip).expect("16 bytes")),
                prefix,
            ),
            n => bail!("IP address of {n} bytes"),
        }
        Ok(())
    }

    /// Adds an inclusive range of addresses of one family.
    pub fn add_range(&mut self, from: IpAddr, to: IpAddr) -> Result<()> {
        match (from, to) {
            (IpAddr::V4(a), IpAddr::V4(b)) if a <= b => self.v4.push((a.into(), b.into())),
            (IpAddr::V6(a), IpAddr::V6(b)) if a <= b => self.v6.push((a.into(), b.into())),
            _ => bail!("invalid IP range {from} - {to}"),
        }
        Ok(())
    }

    pub fn extend(&mut self, other: &IpSetBuilder) {
        self.v4.extend_from_slice(&other.v4);
        self.v6.extend_from_slice(&other.v6);
    }

    pub fn build(self) -> IpSet {
        IpSet {
            v4: merge(self.v4),
            v6: merge(self.v6),
        }
    }
}

/// Sorts ranges and merges overlapping or adjacent ones.
fn merge<T: Ord + Copy + Successor>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if last.1.successor().is_none_or(|next| start <= next) => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => out.push((start, end)),
        }
    }
    out
}

trait Successor: Sized {
    fn successor(self) -> Option<Self>;
}
impl Successor for u32 {
    fn successor(self) -> Option<Self> {
        self.checked_add(1)
    }
}
impl Successor for u128 {
    fn successor(self) -> Option<Self> {
        self.checked_add(1)
    }
}

/// Immutable set of IP ranges.
#[derive(Debug, Default)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn contains<T: Ord + Copy>(ranges: &[(T, T)], value: T) -> bool {
    let idx = ranges.partition_point(|(start, _)| *start <= value);
    idx > 0 && ranges[idx - 1].1 >= value
}

impl IpSet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => contains(&self.v4, v4.into()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => contains(&self.v4, v4.into()),
                None => contains(&self.v6, v6.into()),
            },
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Number of disjoint ranges, for diagnostics.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

/// Private, loopback, link-local and other non-public ranges
/// (`geoip:private`).
pub fn private_ranges() -> IpSetBuilder {
    let mut b = IpSetBuilder::default();
    for cidr in [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3",
        "::/127",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ] {
        b.add_cidr(cidr).expect("built-in CIDR is valid");
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn membership_and_merging() {
        let mut b = IpSetBuilder::default();
        for c in [
            "10.0.0.0/8",
            "10.1.0.0/16",
            "192.168.1.0/24",
            "192.168.2.0/24",
            "8.8.8.8",
            "2001:db8::/32",
            "::1",
        ] {
            b.add_cidr(c).unwrap();
        }
        let set = b.build();
        // 10/8 swallows 10.1/16; the two /24 are adjacent and merge.
        assert_eq!(set.len(), 3 + 2);
        for yes in [
            "10.0.0.0",
            "10.255.255.255",
            "192.168.1.0",
            "192.168.2.255",
            "8.8.8.8",
            "2001:db8::1",
            "::1",
            "::ffff:10.2.3.4",
        ] {
            assert!(set.contains(ip(yes)), "{yes}");
        }
        for no in [
            "9.255.255.255",
            "11.0.0.0",
            "192.168.0.255",
            "192.168.3.0",
            "8.8.8.9",
            "2001:db9::",
            "::2",
        ] {
            assert!(!set.contains(ip(no)), "{no}");
        }
    }

    #[test]
    fn edge_prefixes_and_errors() {
        let mut b = IpSetBuilder::default();
        b.add_cidr("0.0.0.0/0").unwrap();
        b.add_cidr("::/0").unwrap();
        let all = b.build();
        assert!(all.contains(ip("255.255.255.255")) && all.contains(ip("ffff::")));
        assert_eq!(all.len(), 2);

        let mut b = IpSetBuilder::default();
        assert!(b.add_cidr("1.2.3.4/33").is_err());
        assert!(b.add_cidr("example.com").is_err());
        assert!(b.add_cidr("::/129").is_err());
        assert!(b.add_bytes(&[1, 2, 3], 8).is_err());
        b.add_bytes(&[1, 2, 3, 4], 24).unwrap();
        b.add_range(ip("5.5.5.5"), ip("5.5.5.9")).unwrap();
        assert!(b.add_range(ip("5.5.5.9"), ip("5.5.5.5")).is_err());
        let set = b.build();
        assert!(
            set.contains(ip("1.2.3.200"))
                && set.contains(ip("5.5.5.7"))
                && !set.contains(ip("5.5.5.10"))
        );
    }

    #[test]
    fn private_set() {
        let set = private_ranges().build();
        for yes in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "172.31.255.255",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "fd00::1",
        ] {
            assert!(set.contains(ip(yes)), "{yes}");
        }
        for no in ["8.8.8.8", "172.32.0.1", "1.1.1.1", "2606:4700::1111"] {
            assert!(!set.contains(ip(no)), "{no}");
        }
    }
}
