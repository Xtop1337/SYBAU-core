//! Fake-IP pool: hands out addresses from reserved ranges for domains, so
//! that applications connect to an IP the core can map back to the domain.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};
use parking_lot::Mutex;

struct Pool<T> {
    base: u128,
    size: u128,
    next: u128,
    by_domain: HashMap<String, T>,
    by_ip: HashMap<T, String>,
    order: VecDeque<T>,
}

impl<T: Copy + Eq + std::hash::Hash> Pool<T> {
    fn new(base: u128, size: u128) -> Self {
        Self {
            base,
            size,
            next: 0,
            by_domain: HashMap::new(),
            by_ip: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn allocate(&mut self, domain: &str, make: impl Fn(u128) -> T, capacity: usize) -> T {
        if let Some(ip) = self.by_domain.get(domain) {
            return *ip;
        }
        // Recycle the oldest mapping when the pool or the table is full.
        if self.order.len() as u128 >= self.size || self.order.len() >= capacity {
            if let Some(old) = self.order.pop_front() {
                if let Some(d) = self.by_ip.remove(&old) {
                    self.by_domain.remove(&d);
                }
            }
        }
        let ip = loop {
            let candidate = make(self.base + self.next);
            self.next = (self.next + 1) % self.size;
            if !self.by_ip.contains_key(&candidate) {
                break candidate;
            }
        };
        self.by_domain.insert(domain.to_string(), ip);
        self.by_ip.insert(ip, domain.to_string());
        self.order.push_back(ip);
        ip
    }
}

pub struct FakeIp {
    v4: Option<Mutex<Pool<Ipv4Addr>>>,
    v6: Option<Mutex<Pool<Ipv6Addr>>>,
    v4_range: Option<(u32, u32)>,
    v6_range: Option<(u128, u128)>,
    capacity: usize,
}

fn parse_range(text: &str) -> Result<(IpAddr, u8)> {
    let (a, p) = text
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("`{text}` is not a CIDR range"))?;
    let ip: IpAddr = a.trim().parse()?;
    let p: u8 = p.trim().parse()?;
    Ok((ip, p))
}

impl FakeIp {
    /// `inet4` like `198.18.0.0/15`, `inet6` like `fc00::/18`.
    pub fn new(inet4: Option<&str>, inet6: Option<&str>, capacity: usize) -> Result<Self> {
        let mut pool = Self {
            v4: None,
            v6: None,
            v4_range: None,
            v6_range: None,
            capacity: capacity.max(16),
        };
        if let Some(r) = inet4 {
            let (IpAddr::V4(ip), prefix @ 0..=30) = parse_range(r)? else {
                bail!("bad fake-ip IPv4 range `{r}`")
            };
            let size = 1u32 << (32 - prefix);
            let base = u32::from(ip) & !(size - 1);
            // Skip the network address.
            pool.v4 = Some(Mutex::new(Pool::new(base as u128 + 1, size as u128 - 2)));
            pool.v4_range = Some((base, base + (size - 1)));
        }
        if let Some(r) = inet6 {
            let (IpAddr::V6(ip), prefix @ 0..=126) = parse_range(r)? else {
                bail!("bad fake-ip IPv6 range `{r}`")
            };
            let size = 1u128 << (128 - prefix);
            let base = u128::from(ip) & !(size - 1);
            pool.v6 = Some(Mutex::new(Pool::new(
                base + 1,
                (size - 2).min(u64::MAX as u128),
            )));
            pool.v6_range = Some((base, base + (size - 1)));
        }
        if pool.v4.is_none() && pool.v6.is_none() {
            bail!("fake-ip needs an IPv4 or IPv6 range");
        }
        Ok(pool)
    }

    pub fn has_v4(&self) -> bool {
        self.v4.is_some()
    }

    pub fn has_v6(&self) -> bool {
        self.v6.is_some()
    }

    pub fn v4(&self, domain: &str) -> Option<Ipv4Addr> {
        let cap = self.capacity;
        self.v4
            .as_ref()
            .map(|p| p.lock().allocate(domain, |v| Ipv4Addr::from(v as u32), cap))
    }

    pub fn v6(&self, domain: &str) -> Option<Ipv6Addr> {
        let cap = self.capacity;
        self.v6
            .as_ref()
            .map(|p| p.lock().allocate(domain, Ipv6Addr::from, cap))
    }

    /// Whether `ip` belongs to a fake range (mapped or not).
    pub fn is_fake(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v4) => self
                .v4_range
                .is_some_and(|(a, b)| (a..=b).contains(&u32::from(v4))),
            IpAddr::V6(v6) => self
                .v6_range
                .is_some_and(|(a, b)| (a..=b).contains(&u128::from(v6))),
        }
    }

    /// Domain behind a fake address.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        match ip.to_canonical() {
            IpAddr::V4(v4) => self.v4.as_ref()?.lock().by_ip.get(&v4).cloned(),
            IpAddr::V6(v6) => self.v6.as_ref()?.lock().by_ip.get(&v6).cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_stable_reversible_addresses() {
        let pool = FakeIp::new(Some("198.18.0.0/15"), Some("fc00::/18"), 1000).unwrap();
        let a = pool.v4("a.example").unwrap();
        assert_eq!(a, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(pool.v4("a.example").unwrap(), a, "stable");
        let b = pool.v4("b.example").unwrap();
        assert_ne!(a, b);
        assert_eq!(pool.lookup(a.into()).as_deref(), Some("a.example"));
        assert_eq!(
            pool.lookup(IpAddr::V6(a.to_ipv6_mapped())).as_deref(),
            Some("a.example")
        );
        let v6 = pool.v6("a.example").unwrap();
        assert!(
            pool.is_fake(v6.into()) && pool.is_fake(IpAddr::V4(Ipv4Addr::new(198, 19, 255, 254)))
        );
        assert!(!pool.is_fake("8.8.8.8".parse().unwrap()));
        assert_eq!(pool.lookup("198.18.9.9".parse().unwrap()), None);
    }

    #[test]
    fn recycles_oldest_when_full() {
        let pool = FakeIp::new(Some("10.0.0.0/30"), None, 1000).unwrap();
        let a = pool.v4("a").unwrap();
        let b = pool.v4("b").unwrap();
        assert_eq!(
            (a, b),
            (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
        );
        let c = pool.v4("c").unwrap();
        assert_eq!(c, a, "the oldest address is reused");
        assert_eq!(pool.lookup(a.into()).as_deref(), Some("c"));
        assert!(FakeIp::new(None, None, 10).is_err());
        assert!(FakeIp::new(Some("10.0.0.0/31"), None, 10).is_err());
    }
}
