//! sing-box binary rule-sets (`.srs`, versions 1 to 5).
//!
//! Layout: `"SRS" | version(1) | zlib(uvarint(count) rule*)`; see
//! sing-box `common/srs/binary.go`. Domains are stored in a LOUDS
//! encoded trie of reversed names (sing `common/domain`).

use std::io::Read;

use anyhow::{anyhow, bail, Context, Result};

use crate::domain::DomainSetBuilder;
use crate::ipset::IpSetBuilder;
use crate::rule::{parse_port_range, IpItem, LogicalMode, Network, RuleSpec};

const MAGIC: &[u8; 3] = b"SRS";
const MAX_VERSION: u8 = 5;
const MAX_DEPTH: usize = 100;
/// Decompressed size limit; real rule-sets are a few MiB at most.
const MAX_SIZE: u64 = 256 << 20;

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD_DOMAIN: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;
const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
const ITEM_FINAL: u8 = 0xff;

/// Labels of the domain trie with special meaning.
const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Result<u8> {
        let (&b, rest) = self
            .buf
            .split_first()
            .ok_or_else(|| anyhow!("truncated rule-set"))?;
        self.buf = rest;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            bail!("truncated rule-set");
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }

    fn uvarint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        bail!("bad varint in rule-set")
    }

    /// A count that must fit in the remaining bytes (`min_item` each).
    fn count(&mut self, min_item: usize) -> Result<usize> {
        let n = self.uvarint()? as usize;
        if n.saturating_mul(min_item.max(1)) > self.buf.len() {
            bail!("rule-set declares more items than it contains");
        }
        Ok(n)
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.count(1)?;
        self.take(n)
    }

    fn strings(&mut self) -> Result<Vec<String>> {
        let n = self.count(1)?;
        (0..n)
            .map(|_| Ok(String::from_utf8(self.bytes()?.to_vec())?))
            .collect()
    }

    fn u16s(&mut self) -> Result<Vec<u16>> {
        let n = self.count(2)?;
        (0..n)
            .map(|_| {
                Ok(u16::from_be_bytes(
                    self.take(2)?.try_into().expect("2 bytes"),
                ))
            })
            .collect()
    }

    fn u64s(&mut self) -> Result<Vec<u64>> {
        let n = self.count(8)?;
        (0..n)
            .map(|_| {
                Ok(u64::from_be_bytes(
                    self.take(8)?.try_into().expect("8 bytes"),
                ))
            })
            .collect()
    }
}

fn bit(words: &[u64], i: usize) -> bool {
    words.get(i >> 6).is_some_and(|w| w & (1 << (i & 63)) != 0)
}

/// Decodes the succinct trie into the keys it stores.
fn read_domain_trie(c: &mut Cursor<'_>) -> Result<Vec<Vec<u8>>> {
    let _version = c.u8()?;
    let leaves = c.u64s()?;
    let bitmap = c.u64s()?;
    let labels = c.bytes()?;
    let total_bits = bitmap.len() * 64;
    let ones: usize = bitmap.iter().map(|w| w.count_ones() as usize).sum();
    if ones != labels.len() + 1 && !(ones == 0 && labels.is_empty()) {
        bail!("malformed domain trie in rule-set");
    }
    // LOUDS: per node in BFS order, one 0 per child, then a 1.
    // The k-th 0 is the edge to node k+1 and carries labels[k].
    let mut parent = Vec::with_capacity(labels.len() + 1);
    let mut node = 0usize;
    let mut edge = 0usize;
    parent.push(usize::MAX);
    for i in 0..total_bits {
        if node > labels.len() {
            break;
        }
        if bit(&bitmap, i) {
            node += 1;
        } else {
            if edge >= labels.len() {
                break;
            }
            parent.push(node);
            edge += 1;
        }
    }
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(parent.len());
    keys.push(Vec::new());
    for id in 1..parent.len() {
        let mut key = keys[parent[id]].clone();
        key.push(labels[id - 1]);
        keys.push(key);
    }
    Ok((0..keys.len())
        .filter(|id| bit(&leaves, *id))
        .map(|id| std::mem::take(&mut keys[id]))
        .collect())
}

/// Converts reversed trie keys into domain patterns, as sing-box's
/// `Matcher.Dump` does.
fn add_domains(keys: Vec<Vec<u8>>, out: &mut DomainSetBuilder) -> Result<()> {
    for mut key in keys {
        key.reverse();
        let text = String::from_utf8(key).context("domain in rule-set is not UTF-8")?;
        match text.as_bytes().first() {
            // `\r.example.com`: subdomains only.
            Some(&PREFIX_LABEL) => out.suffix_raw(&text[1..]),
            // `\nexample.com`: the domain and its subdomains.
            Some(&ROOT_LABEL) => out.suffix_raw(&text[1..]),
            _ => out.full_raw(&text),
        }
    }
    Ok(())
}

fn read_ip_set(c: &mut Cursor<'_>) -> Result<IpItem> {
    if c.u8()? != 1 {
        bail!("unsupported IP set version in rule-set");
    }
    let n = u64::from_be_bytes(c.take(8)?.try_into().expect("8 bytes")) as usize;
    if n.saturating_mul(10) > c.buf.len() {
        bail!("rule-set declares more IP ranges than it contains");
    }
    let mut set = IpSetBuilder::default();
    let addr = |c: &mut Cursor<'_>| -> Result<std::net::IpAddr> {
        let len = c.uvarint()? as usize;
        let raw = c.take(len)?;
        Ok(match len {
            4 => std::net::IpAddr::from(<[u8; 4]>::try_from(raw).expect("4 bytes")),
            16 => std::net::IpAddr::from(<[u8; 16]>::try_from(raw).expect("16 bytes")),
            _ => bail!("bad address length in rule-set"),
        })
    };
    for _ in 0..n {
        let from = addr(c)?;
        let to = addr(c)?;
        set.add_range(from, to)?;
    }
    Ok(IpItem { set, negate: false })
}

fn read_rule(c: &mut Cursor<'_>, depth: usize) -> Result<RuleSpec> {
    if depth > MAX_DEPTH {
        bail!("logical rules nested too deep");
    }
    match c.u8()? {
        0 => read_default_rule(c),
        1 => {
            let mode = match c.u8()? {
                0 => LogicalMode::And,
                1 => LogicalMode::Or,
                m => bail!("unknown logical mode {m}"),
            };
            let n = c.count(1)?;
            let rules = (0..n)
                .map(|_| read_rule(c, depth + 1))
                .collect::<Result<Vec<_>>>()?;
            let invert = c.u8()? != 0;
            Ok(RuleSpec {
                logical: Some((mode, rules)),
                invert,
                ..Default::default()
            })
        }
        t => bail!("unknown rule type {t}"),
    }
}

fn ports(list: Vec<u16>) -> Vec<(u16, u16)> {
    list.into_iter().map(|p| (p, p)).collect()
}

fn read_default_rule(c: &mut Cursor<'_>) -> Result<RuleSpec> {
    let mut r = RuleSpec::default();
    loop {
        let item = c.u8()?;
        match item {
            ITEM_QUERY_TYPE => r.query_type = c.u16s()?,
            ITEM_NETWORK => {
                for n in c.strings()? {
                    match n.as_str() {
                        "tcp" => r.network.push(Network::Tcp),
                        "udp" => r.network.push(Network::Udp),
                        // e.g. "icmp": nothing routed here is ICMP.
                        _ => {}
                    }
                }
                if r.network.is_empty() {
                    r.unsupported = true;
                }
            }
            ITEM_DOMAIN => {
                r.has_domain = true;
                add_domains(read_domain_trie(c)?, &mut r.domain)?;
            }
            ITEM_DOMAIN_KEYWORD => {
                r.has_domain = true;
                c.strings()?.iter().for_each(|k| r.domain.keyword(k));
            }
            ITEM_DOMAIN_REGEX => {
                r.has_domain = true;
                c.strings()?.iter().for_each(|k| r.domain.regex(k));
            }
            ITEM_SOURCE_IP_CIDR => r.source_ip.push(read_ip_set(c)?),
            ITEM_IP_CIDR => r.dest_ip.push(read_ip_set(c)?),
            ITEM_SOURCE_PORT => r.source_port.extend(ports(c.u16s()?)),
            ITEM_SOURCE_PORT_RANGE => {
                for p in c.strings()? {
                    r.source_port.push(parse_port_range(&p)?);
                }
            }
            ITEM_PORT => r.dest_port.extend(ports(c.u16s()?)),
            ITEM_PORT_RANGE => {
                for p in c.strings()? {
                    r.dest_port.push(parse_port_range(&p)?);
                }
            }
            ITEM_PROCESS_NAME => r.process_name = c.strings()?,
            ITEM_PROCESS_PATH => r.process_path = c.strings()?,
            ITEM_PROCESS_PATH_REGEX => r.process_path_regex = c.strings()?,
            ITEM_PACKAGE_NAME => r.package_name = c.strings()?,
            ITEM_PACKAGE_NAME_REGEX => {
                c.strings()?;
                r.unsupported = true;
            }
            ITEM_WIFI_SSID | ITEM_WIFI_BSSID => {
                c.strings()?;
                r.unsupported = true;
            }
            ITEM_NETWORK_TYPE => {
                let n = c.count(1)?;
                c.take(n)?;
                r.unsupported = true;
            }
            ITEM_NETWORK_IS_EXPENSIVE | ITEM_NETWORK_IS_CONSTRAINED => r.unsupported = true,
            ITEM_NETWORK_INTERFACE_ADDRESS => {
                for _ in 0..c.count(2)? {
                    c.u8()?;
                    for _ in 0..c.count(1)? {
                        skip_prefix(c)?;
                    }
                }
                r.unsupported = true;
            }
            ITEM_DEFAULT_INTERFACE_ADDRESS => {
                for _ in 0..c.count(1)? {
                    skip_prefix(c)?;
                }
                r.unsupported = true;
            }
            ITEM_ADGUARD_DOMAIN => bail!("AdGuard domain rules in rule-sets are not supported yet"),
            ITEM_FINAL => {
                r.invert = c.u8()? != 0;
                return Ok(r);
            }
            other => bail!("unknown rule-set item {other}"),
        }
    }
}

/// `netip.Prefix` as written by sing-box: address bytes then prefix bits.
fn skip_prefix(c: &mut Cursor<'_>) -> Result<()> {
    let len = c.uvarint()? as usize;
    c.take(len)?;
    c.u8()?;
    Ok(())
}

/// Parses a binary rule-set into rule specifications.
pub fn read(data: &[u8]) -> Result<Vec<RuleSpec>> {
    if data.len() < 4 || &data[..3] != MAGIC {
        bail!("not a sing-box rule-set (missing SRS header)");
    }
    let version = data[3];
    if version == 0 || version > MAX_VERSION {
        bail!("unsupported rule-set version {version}");
    }
    let mut raw = Vec::new();
    flate2::read::ZlibDecoder::new(&data[4..])
        .take(MAX_SIZE)
        .read_to_end(&mut raw)
        .context("rule-set is not valid zlib data")?;
    let mut c = Cursor { buf: &raw };
    let n = c.count(2)?;
    (0..n)
        .map(|i| read_rule(&mut c, 0).with_context(|| format!("rule {i}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(read(b"").is_err());
        assert!(read(b"XYZ\x01").is_err());
        assert!(read(b"SRS\x09xx").is_err());
        assert!(read(b"SRS\x01not zlib").is_err());
        // A valid zlib stream that claims a billion rules.
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut z, &[0x80, 0x94, 0xeb, 0xdc, 0x03]).unwrap();
        let mut data = b"SRS\x03".to_vec();
        data.extend(z.finish().unwrap());
        assert!(read(&data).is_err());
    }
}
