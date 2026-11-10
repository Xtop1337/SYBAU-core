//! DNS messages (RFC 1035), with EDNS(0) and Client Subnet (RFC 7871).
//!
//! Parsing is strict about bounds and compression loops: messages come
//! from the network and from local applications.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

const OPTION_CLIENT_SUBNET: u16 = 8;
const MAX_POINTERS: usize = 64;

/// `A`, `AAAA`, `HTTPS`, ... or a number.
pub fn parse_type(name: &str) -> Option<u16> {
    Some(match name.to_ascii_uppercase().as_str() {
        "A" => TYPE_A,
        "NS" => TYPE_NS,
        "CNAME" => TYPE_CNAME,
        "SOA" => TYPE_SOA,
        "PTR" => TYPE_PTR,
        "MX" => TYPE_MX,
        "TXT" => TYPE_TXT,
        "AAAA" => TYPE_AAAA,
        "SRV" => TYPE_SRV,
        "SVCB" => TYPE_SVCB,
        "HTTPS" => TYPE_HTTPS,
        other => return other.parse().ok(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// Lower case, without the trailing dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    /// Anything else, kept as raw RDATA. Names inside it may use
    /// compression pointers into the original message, so such records
    /// are only re-sent inside that message.
    Other(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RecordData,
}

/// EDNS Client Subnet option.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSubnet {
    pub addr: IpAddr,
    pub source_prefix: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    /// EDNS UDP payload size, if an OPT record was present.
    pub edns_udp_size: Option<u16>,
    pub client_subnet: Option<ClientSubnet>,
}

struct Reader<'a> {
    msg: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.msg.len() - self.pos < n {
            bail!("truncated DNS message");
        }
        let out = &self.msg[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a possibly compressed name starting at the current position.
    fn name(&mut self) -> Result<String> {
        let (name, end) = read_name(self.msg, self.pos)?;
        self.pos = end;
        Ok(name)
    }
}

/// Reads a name at `pos`; returns it and the position after it.
fn read_name(msg: &[u8], mut pos: usize) -> Result<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut pointers = 0;
    loop {
        let Some(&len) = msg.get(pos) else {
            bail!("truncated DNS name")
        };
        match len & 0xc0 {
            0x00 => {
                pos += 1;
                if len == 0 {
                    break;
                }
                let label = msg
                    .get(pos..pos + len as usize)
                    .ok_or_else(|| anyhow::anyhow!("truncated DNS label"))?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &b in label {
                    if b == b'.' || b.is_ascii_whitespace() || !b.is_ascii_graphic() {
                        // Escape the few bytes that would change the name's meaning.
                        name.push_str(&format!("\\{b:03}"));
                    } else {
                        name.push(b.to_ascii_lowercase() as char);
                    }
                }
                if name.len() > 1024 {
                    bail!("DNS name too long");
                }
                pos += len as usize;
            }
            0xc0 => {
                let Some(&low) = msg.get(pos + 1) else {
                    bail!("truncated DNS pointer")
                };
                if end.is_none() {
                    end = Some(pos + 2);
                }
                pointers += 1;
                if pointers > MAX_POINTERS {
                    bail!("DNS name compression loop");
                }
                pos = (((len & 0x3f) as usize) << 8) | low as usize;
            }
            _ => bail!("unsupported DNS label type"),
        }
    }
    Ok((name, end.unwrap_or(pos)))
}

fn put_name(out: &mut Vec<u8>, name: &str) -> Result<()> {
    let name = name.trim_end_matches('.');
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                bail!("invalid DNS name `{name}`");
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    Ok(())
}

fn parse_record(r: &mut Reader<'_>) -> Result<Record> {
    let name = r.name()?;
    let rtype = r.u16()?;
    let class = r.u16()?;
    let ttl = r.u32()?;
    let len = r.u16()? as usize;
    let start = r.pos;
    let rdata = r.take(len)?;
    let data = match (rtype, len) {
        (TYPE_A, 4) => RecordData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
        (TYPE_AAAA, 16) => RecordData::Aaaa(Ipv6Addr::from(
            <[u8; 16]>::try_from(rdata).expect("16 bytes"),
        )),
        (TYPE_CNAME, _) => RecordData::Cname(read_name(r.msg, start)?.0),
        (TYPE_A | TYPE_AAAA, _) => bail!("bad address record length"),
        _ => RecordData::Other(rdata.to_vec()),
    };
    Ok(Record {
        name,
        rtype,
        class,
        ttl,
        data,
    })
}

impl Message {
    pub fn parse(msg: &[u8]) -> Result<Self> {
        let mut r = Reader { msg, pos: 0 };
        let id = r.u16()?;
        let flags = r.u16()?;
        let counts = [r.u16()?, r.u16()?, r.u16()?, r.u16()?];
        // Every entry takes at least 5 bytes; reject absurd counts early.
        if counts.iter().map(|c| *c as usize).sum::<usize>() * 5 > msg.len() {
            bail!("DNS message declares more records than it contains");
        }
        let mut m = Message {
            id,
            response: flags & 0x8000 != 0,
            opcode: ((flags >> 11) & 0xf) as u8,
            authoritative: flags & 0x0400 != 0,
            truncated: flags & 0x0200 != 0,
            recursion_desired: flags & 0x0100 != 0,
            recursion_available: flags & 0x0080 != 0,
            rcode: (flags & 0xf) as u8,
            ..Default::default()
        };
        for _ in 0..counts[0] {
            let name = r.name()?;
            m.questions.push(Question {
                name,
                qtype: r.u16()?,
                qclass: r.u16()?,
            });
        }
        for _ in 0..counts[1] {
            m.answers.push(parse_record(&mut r)?);
        }
        for _ in 0..counts[2] {
            m.authority.push(parse_record(&mut r)?);
        }
        for _ in 0..counts[3] {
            let rec = parse_record(&mut r)?;
            if rec.rtype == TYPE_OPT {
                m.edns_udp_size = Some(rec.class);
                m.rcode |= ((rec.ttl >> 24) as u8) << 4;
                if let RecordData::Other(options) = &rec.data {
                    m.client_subnet = parse_client_subnet(options);
                }
                continue;
            }
            m.additional.push(rec);
        }
        Ok(m)
    }

    /// A recursive query for `name`.
    pub fn query(id: u16, name: &str, qtype: u16) -> Self {
        Message {
            id,
            recursion_desired: true,
            questions: vec![Question {
                name: name.trim_end_matches('.').to_ascii_lowercase(),
                qtype,
                qclass: CLASS_IN,
            }],
            edns_udp_size: Some(1232),
            ..Default::default()
        }
    }

    /// An empty response to `self` with `rcode`.
    pub fn reply(&self, rcode: u8) -> Self {
        Message {
            id: self.id,
            response: true,
            opcode: self.opcode,
            recursion_desired: self.recursion_desired,
            recursion_available: true,
            rcode,
            questions: self.questions.clone(),
            edns_udp_size: self.edns_udp_size.map(|_| 1232),
            ..Default::default()
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&self.id.to_be_bytes());
        let mut flags = ((self.opcode as u16 & 0xf) << 11) | (self.rcode as u16 & 0xf);
        for (bit, set) in [
            (0x8000, self.response),
            (0x0400, self.authoritative),
            (0x0200, self.truncated),
            (0x0100, self.recursion_desired),
            (0x0080, self.recursion_available),
        ] {
            if set {
                flags |= bit;
            }
        }
        out.extend_from_slice(&flags.to_be_bytes());
        let additional = self.additional.len() + usize::from(self.edns_udp_size.is_some());
        for count in [
            self.questions.len(),
            self.answers.len(),
            self.authority.len(),
            additional,
        ] {
            out.extend_from_slice(&(count as u16).to_be_bytes());
        }
        for q in &self.questions {
            put_name(&mut out, &q.name)?;
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for rec in self
            .answers
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
        {
            put_record(&mut out, rec)?;
        }
        if let Some(size) = self.edns_udp_size {
            out.push(0);
            out.extend_from_slice(&TYPE_OPT.to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&(((self.rcode >> 4) as u32) << 24).to_be_bytes());
            let options = self
                .client_subnet
                .as_ref()
                .map(encode_client_subnet)
                .unwrap_or_default();
            out.extend_from_slice(&(options.len() as u16).to_be_bytes());
            out.extend_from_slice(&options);
        }
        Ok(out)
    }

    /// Addresses in the answer section.
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.answers
            .iter()
            .filter_map(|r| match r.data {
                RecordData::A(ip) => Some(IpAddr::V4(ip)),
                RecordData::Aaaa(ip) => Some(IpAddr::V6(ip)),
                _ => None,
            })
            .collect()
    }

    /// Smallest TTL of the answers (or of the SOA for negative answers).
    pub fn min_ttl(&self) -> Option<u32> {
        let ttls = self.answers.iter().map(|r| r.ttl);
        let ttl = ttls.min();
        ttl.or_else(|| {
            self.authority
                .iter()
                .find(|r| r.rtype == TYPE_SOA)
                .map(|r| r.ttl)
        })
    }
}

fn put_record(out: &mut Vec<u8>, rec: &Record) -> Result<()> {
    put_name(out, &rec.name)?;
    out.extend_from_slice(&rec.rtype.to_be_bytes());
    out.extend_from_slice(&rec.class.to_be_bytes());
    out.extend_from_slice(&rec.ttl.to_be_bytes());
    let mut rdata = Vec::new();
    match &rec.data {
        RecordData::A(ip) => rdata.extend_from_slice(&ip.octets()),
        RecordData::Aaaa(ip) => rdata.extend_from_slice(&ip.octets()),
        RecordData::Cname(name) => put_name(&mut rdata, name)?,
        RecordData::Other(raw) => rdata.extend_from_slice(raw),
    }
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    Ok(())
}

fn parse_client_subnet(mut options: &[u8]) -> Option<ClientSubnet> {
    while options.len() >= 4 {
        let code = u16::from_be_bytes([options[0], options[1]]);
        let len = u16::from_be_bytes([options[2], options[3]]) as usize;
        let data = options.get(4..4 + len)?;
        options = &options[4 + len..];
        if code != OPTION_CLIENT_SUBNET || data.len() < 4 {
            continue;
        }
        let family = u16::from_be_bytes([data[0], data[1]]);
        let prefix = data[2];
        let addr = &data[4..];
        return match family {
            1 => {
                let mut b = [0u8; 4];
                b[..addr.len().min(4)].copy_from_slice(&addr[..addr.len().min(4)]);
                Some(ClientSubnet {
                    addr: Ipv4Addr::from(b).into(),
                    source_prefix: prefix.min(32),
                })
            }
            2 => {
                let mut b = [0u8; 16];
                b[..addr.len().min(16)].copy_from_slice(&addr[..addr.len().min(16)]);
                Some(ClientSubnet {
                    addr: Ipv6Addr::from(b).into(),
                    source_prefix: prefix.min(128),
                })
            }
            _ => None,
        };
    }
    None
}

fn encode_client_subnet(ecs: &ClientSubnet) -> Vec<u8> {
    let (family, bytes): (u16, Vec<u8>) = match ecs.addr {
        IpAddr::V4(ip) => (1, ip.octets().to_vec()),
        IpAddr::V6(ip) => (2, ip.octets().to_vec()),
    };
    let prefix = ecs.source_prefix.min(bytes.len() as u8 * 8);
    let used = (prefix as usize).div_ceil(8);
    let mut addr = bytes[..used].to_vec();
    if !prefix.is_multiple_of(8) {
        if let Some(last) = addr.last_mut() {
            *last &= 0xffu8 << (8 - prefix % 8);
        }
    }
    let mut out = Vec::with_capacity(8 + used);
    out.extend_from_slice(&OPTION_CLIENT_SUBNET.to_be_bytes());
    out.extend_from_slice(&((4 + used) as u16).to_be_bytes());
    out.extend_from_slice(&family.to_be_bytes());
    out.push(prefix);
    out.push(0);
    out.extend_from_slice(&addr);
    out
}

/// Parses `1.2.3.0/24` or `2001:db8::/56` for the ECS option.
pub fn parse_client_subnet_option(text: &str) -> Result<ClientSubnet> {
    let (addr, prefix) = match text.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (text, None),
    };
    let addr: IpAddr = addr
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("bad client_subnet `{text}`"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let source_prefix = match prefix {
        Some(p) => p
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|p| *p <= max)
            .ok_or_else(|| anyhow::anyhow!("bad prefix in `{text}`"))?,
        None => {
            if addr.is_ipv4() {
                24
            } else {
                56
            }
        }
    };
    Ok(ClientSubnet {
        addr,
        source_prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real response captured from a public resolver for
    /// `example.com A`, using name compression.
    const RESPONSE: &[u8] = &[
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, //
        0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
        b'm', 0x00, 0x00, 0x01, 0x00, 0x01, //
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x02, 0xc0, 0x10, //
        0xc0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 215, 14,
    ];

    #[test]
    fn parses_compressed_response() {
        let m = Message::parse(RESPONSE).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(m.response && m.recursion_desired && m.recursion_available);
        assert_eq!(
            m.questions[0],
            Question {
                name: "www.example.com".into(),
                qtype: TYPE_A,
                qclass: CLASS_IN
            }
        );
        assert_eq!(m.answers[0].data, RecordData::Cname("example.com".into()));
        assert_eq!(m.answers[1].name, "example.com");
        assert_eq!(m.addresses(), vec![IpAddr::from([93, 184, 215, 14])]);
        assert_eq!(m.min_ttl(), Some(60));
    }

    #[test]
    fn encode_parse_roundtrip_with_edns_and_ecs() {
        let mut q = Message::query(7, "Example.COM.", TYPE_AAAA);
        q.client_subnet = Some(parse_client_subnet_option("203.0.113.77/24").unwrap());
        let wire = q.encode().unwrap();
        let back = Message::parse(&wire).unwrap();
        assert_eq!(back.questions[0].name, "example.com");
        assert_eq!(back.edns_udp_size, Some(1232));
        assert_eq!(
            back.client_subnet,
            Some(ClientSubnet {
                addr: "203.0.113.0".parse().unwrap(),
                source_prefix: 24
            })
        );

        let mut reply = back.reply(RCODE_NOERROR);
        reply.answers.push(Record {
            name: "example.com".into(),
            rtype: TYPE_AAAA,
            class: CLASS_IN,
            ttl: 300,
            data: RecordData::Aaaa("2001:db8::1".parse().unwrap()),
        });
        let back = Message::parse(&reply.encode().unwrap()).unwrap();
        assert_eq!(
            back.addresses(),
            vec!["2001:db8::1".parse::<IpAddr>().unwrap()]
        );
        assert!(back.response);
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(Message::parse(&[]).is_err());
        assert!(Message::parse(&RESPONSE[..RESPONSE.len() - 1]).is_err());
        // Pointer to itself.
        let mut looped = RESPONSE[..12].to_vec();
        looped[5] = 1;
        looped[7] = 0;
        looped.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert!(Message::parse(&looped).is_err());
        // Huge counts.
        let mut counts = RESPONSE[..12].to_vec();
        counts[6] = 0xff;
        assert!(Message::parse(&counts).is_err());
        assert!(Message::query(1, "a..b", TYPE_A).encode().is_err());
        assert!(Message::query(1, &"x".repeat(64), TYPE_A).encode().is_err());
    }

    #[test]
    fn types_and_ecs_options() {
        assert_eq!(parse_type("aaaa"), Some(TYPE_AAAA));
        assert_eq!(parse_type("65"), Some(TYPE_HTTPS));
        assert_eq!(parse_type("bogus"), None);
        assert_eq!(
            parse_client_subnet_option("2001:db8::1")
                .unwrap()
                .source_prefix,
            56
        );
        assert!(parse_client_subnet_option("1.2.3.4/33").is_err());
        let ecs = encode_client_subnet(&parse_client_subnet_option("10.20.30.40/20").unwrap());
        // code(2) len(2) family(2) prefix scope addr(3)
        assert_eq!(ecs, vec![0, 8, 0, 7, 0, 1, 20, 0, 10, 20, 16]);
    }
}
