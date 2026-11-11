//! Sniffers for datagrams: QUIC (SNI of the ClientHello inside Initial
//! packets), BitTorrent (uTP, DHT, UDP trackers) and DNS.

use std::collections::BTreeMap;

use aes::cipher::{BlockEncrypt, KeyInit};
use sybau_proto::crypto::{Aead, AeadKind};
use sybau_tls::keys::HashAlg;

use super::{client_hello_sni, SniffResult, Sniffed};

const VERSION_1: u32 = 0x0000_0001;
const VERSION_2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Upper bound of reassembled CRYPTO data; a ClientHello with post-quantum
/// key shares is about 1.8 KiB.
const MAX_CRYPTO: usize = 16 * 1024;

fn varint(b: &mut &[u8]) -> Option<u64> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for byte in &b[1..len] {
        v = (v << 8) | *byte as u64;
    }
    *b = &b[len..];
    Some(v)
}

/// Removes header and packet protection of a client Initial packet.
/// Returns the decrypted frames.
pub(crate) fn decrypt_initial(packet: &[u8]) -> Option<Vec<u8>> {
    let first = *packet.first()?;
    // Long header with the fixed bit.
    if first & 0xc0 != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes(packet.get(1..5)?.try_into().ok()?);
    let (salt, initial_type, labels) = match version {
        VERSION_1 => (&SALT_V1, 0, ["quic key", "quic iv", "quic hp"]),
        VERSION_2 => (&SALT_V2, 1, ["quicv2 key", "quicv2 iv", "quicv2 hp"]),
        _ => return None,
    };
    if (first >> 4) & 3 != initial_type {
        return None;
    }
    let mut rest = &packet[5..];
    let dcid_len = *rest.first()? as usize;
    let dcid = rest.get(1..1 + dcid_len)?;
    rest = &rest[1 + dcid_len..];
    let scid_len = *rest.first()? as usize;
    rest = rest.get(1 + scid_len..)?;
    let token_len = varint(&mut rest)? as usize;
    rest = rest.get(token_len..)?;
    let length = varint(&mut rest)? as usize;
    let pn_offset = packet.len() - rest.len();
    if rest.len() < length || length < 4 + 16 {
        return None;
    }

    let h = HashAlg::Sha256;
    let initial = h.extract(salt, dcid);
    let client = h.expand_label(&initial, "client in", &[], 32);
    let key = h.expand_label(&client, labels[0], &[], 16);
    let iv = h.expand_label(&client, labels[1], &[], 12);
    let hp = h.expand_label(&client, labels[2], &[], 16);

    let sample = packet.get(pn_offset + 4..pn_offset + 20)?;
    let mut mask = aes::Block::clone_from_slice(sample);
    aes::Aes128::new_from_slice(&hp)
        .ok()?
        .encrypt_block(&mut mask);
    let first = first ^ (mask[0] & 0x0f);
    let pn_len = (first & 3) as usize + 1;
    let mut header = packet[..pn_offset + pn_len].to_vec();
    header[0] = first;
    let mut pn = 0u64;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | header[pn_offset + i] as u64;
    }
    let mut nonce: [u8; 12] = iv.try_into().ok()?;
    for (n, p) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
        *n ^= p;
    }
    let mut payload = packet.get(pn_offset + pn_len..pn_offset + length)?.to_vec();
    let n = Aead::new(AeadKind::Aes128Gcm, &key)
        .open(&nonce, &header, &mut payload)
        .ok()?;
    payload.truncate(n);
    Some(payload)
}

/// Collects CRYPTO frames of Initial packets until the SNI is known.
///
/// Browsers spread the ClientHello over several packets and send its
/// pieces out of order, so one packet is often not enough.
#[derive(Default)]
pub struct QuicSniffer {
    /// CRYPTO data by stream offset.
    chunks: BTreeMap<u64, Vec<u8>>,
    saw_quic: bool,
}

impl QuicSniffer {
    pub fn new() -> Self {
        Self::default()
    }

    fn add_frames(&mut self, mut frames: &[u8]) -> Option<()> {
        while let Some(&kind) = frames.first() {
            frames = &frames[1..];
            match kind {
                // PADDING, PING
                0x00 | 0x01 => {}
                // ACK
                0x02 | 0x03 => {
                    varint(&mut frames)?;
                    varint(&mut frames)?;
                    let ranges = varint(&mut frames)?;
                    varint(&mut frames)?;
                    for _ in 0..ranges {
                        varint(&mut frames)?;
                        varint(&mut frames)?;
                    }
                    if kind == 0x03 {
                        for _ in 0..3 {
                            varint(&mut frames)?;
                        }
                    }
                }
                // CRYPTO
                0x06 => {
                    let offset = varint(&mut frames)?;
                    let len = varint(&mut frames)? as usize;
                    let data = frames.get(..len)?;
                    frames = &frames[len..];
                    if offset as usize + len <= MAX_CRYPTO {
                        self.chunks.insert(offset, data.to_vec());
                    }
                }
                // CONNECTION_CLOSE and anything else: nothing more to learn.
                _ => return None,
            }
        }
        Some(())
    }

    /// Contiguous CRYPTO data from offset 0.
    fn assembled(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (offset, data) in &self.chunks {
            let offset = *offset as usize;
            if offset > out.len() {
                break;
            }
            if offset + data.len() > out.len() {
                out.extend_from_slice(&data[out.len() - offset..]);
            }
        }
        out
    }

    /// Feeds one datagram sent by the client.
    pub fn feed(&mut self, datagram: &[u8]) -> SniffResult {
        match decrypt_initial(datagram) {
            Some(frames) => {
                self.saw_quic = true;
                let _ = self.add_frames(&frames);
            }
            None if !self.saw_quic => return sniff_other_datagram(datagram),
            // A later packet that is not an Initial (0-RTT, Handshake).
            None => {}
        }
        match client_hello_sni(&self.assembled()) {
            Ok(Some(host)) => SniffResult::Found(Sniffed {
                protocol: "quic",
                host,
            }),
            Ok(None) => SniffResult::NeedMore,
            Err(()) => SniffResult::Found(Sniffed {
                protocol: "quic",
                host: None,
            }),
        }
    }

    /// Result to use when the client sent nothing more.
    pub fn finish(&self) -> SniffResult {
        if self.saw_quic {
            SniffResult::Found(Sniffed {
                protocol: "quic",
                host: None,
            })
        } else {
            SniffResult::Unknown
        }
    }
}

/// BitTorrent over UDP (uTP, DHT, tracker protocol) and DNS.
fn sniff_other_datagram(d: &[u8]) -> SniffResult {
    let bittorrent = SniffResult::Found(Sniffed {
        protocol: "bittorrent",
        host: None,
    });
    // DHT: bencoded dictionary with a query, response or error.
    if d.len() > 12
        && d[0] == b'd'
        && (d.windows(4).any(|w| w == b"1:y1")
            || d.starts_with(b"d1:ad2:id20:")
            || d.starts_with(b"d1:rd2:id20:"))
    {
        return bittorrent;
    }
    // UDP tracker connect request: protocol magic + action 0.
    if d.len() >= 16 && d[..8] == 0x0417_2710_1980u64.to_be_bytes() && d[8..12] == [0, 0, 0, 0] {
        return bittorrent;
    }
    // uTP SYN: type 4, version 1, no extension or a known one, seq 1.
    if d.len() == 20 && d[0] == 0x41 && d[1] <= 2 && d[16..18] == [0, 1] {
        return bittorrent;
    }
    if d.len() >= 17 && is_dns_query(d) {
        return SniffResult::Found(Sniffed {
            protocol: "dns",
            host: None,
        });
    }
    SniffResult::Unknown
}

/// A DNS query header: QR clear, standard query, one question, no
/// answers or authority records, at most one additional (EDNS OPT).
pub(crate) fn is_dns_query(d: &[u8]) -> bool {
    d.len() >= 12
        && d[2] & 0x80 == 0
        && (d[2] >> 3) & 0x0f == 0
        && d[4..6] == [0, 1]
        && d[6..10] == [0, 0, 0, 0]
        && d[10] == 0
        && d[11] <= 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sniff::stream::tests::client_hello;

    fn put_varint(out: &mut Vec<u8>, v: u64) {
        if v < 64 {
            out.push(v as u8);
        } else if v < 16384 {
            out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes());
        } else {
            out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes());
        }
    }

    fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06];
        put_varint(&mut f, offset);
        put_varint(&mut f, data.len() as u64);
        f.extend_from_slice(data);
        f
    }

    /// Builds a protected client Initial packet (the inverse of
    /// `decrypt_initial`), padded to 1200 bytes like real clients do.
    fn initial_packet(version: u32, dcid: &[u8], pn: u32, frames: &[u8]) -> Vec<u8> {
        let (salt, type_bits, labels) = match version {
            VERSION_1 => (&SALT_V1, 0u8, ["quic key", "quic iv", "quic hp"]),
            _ => (&SALT_V2, 1u8, ["quicv2 key", "quicv2 iv", "quicv2 hp"]),
        };
        let h = HashAlg::Sha256;
        let client = h.expand_label(&h.extract(salt, dcid), "client in", &[], 32);
        let key = h.expand_label(&client, labels[0], &[], 16);
        let iv = h.expand_label(&client, labels[1], &[], 12);
        let hp = h.expand_label(&client, labels[2], &[], 16);

        let mut header = vec![0xc0 | (type_bits << 4) | 3];
        header.extend_from_slice(&version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0);
        header.push(0); // token length
        let mut payload = frames.to_vec();
        let target = 1200usize.saturating_sub(header.len() + 2 + 4 + 16);
        if payload.len() < target {
            payload.resize(target, 0);
        }
        put_varint(&mut header, (4 + payload.len() + 16) as u64);
        let pn_offset = header.len();
        header.extend_from_slice(&pn.to_be_bytes());

        let mut nonce: [u8; 12] = iv.try_into().unwrap();
        for (n, p) in nonce[4..].iter_mut().zip((pn as u64).to_be_bytes()) {
            *n ^= p;
        }
        let tag = Aead::new(AeadKind::Aes128Gcm, &key).seal(&nonce, &header, &mut payload);
        payload.extend_from_slice(&tag);

        let mut packet = header;
        packet.extend_from_slice(&payload);
        let mut mask = aes::Block::clone_from_slice(&packet[pn_offset + 4..pn_offset + 20]);
        aes::Aes128::new_from_slice(&hp)
            .unwrap()
            .encrypt_block(&mut mask);
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..4 {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        packet
    }

    fn found(host: Option<&str>) -> SniffResult {
        SniffResult::Found(Sniffed {
            protocol: "quic",
            host: host.map(str::to_string),
        })
    }

    /// RFC 9001, Appendix A.1: keys derived for DCID 8394c8f03e515708.
    #[test]
    fn rfc9001_initial_keys() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let h = HashAlg::Sha256;
        let client = h.expand_label(&h.extract(&SALT_V1, &dcid), "client in", &[], 32);
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&client),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );
        assert_eq!(
            hex(&h.expand_label(&client, "quic key", &[], 16)),
            "1f369613dd76d5467730efcbe3b1a22d"
        );
        assert_eq!(
            hex(&h.expand_label(&client, "quic iv", &[], 12)),
            "fa044b2f42a3fd3b46fb255c"
        );
        assert_eq!(
            hex(&h.expand_label(&client, "quic hp", &[], 16)),
            "9f50449e04a0e810283a1e9933adedd2"
        );
    }

    #[test]
    fn single_packet_v1_and_v2() {
        let hello = client_hello(Some("quic.example.com"), 0);
        for version in [VERSION_1, VERSION_2] {
            let packet = initial_packet(
                version,
                &[1, 2, 3, 4, 5, 6, 7, 8],
                0,
                &crypto_frame(0, &hello),
            );
            assert_eq!(packet.len(), 1200);
            assert_eq!(
                QuicSniffer::new().feed(&packet),
                found(Some("quic.example.com")),
                "version {version:#x}"
            );
        }
    }

    #[test]
    fn hello_spread_over_packets_and_out_of_order() {
        // A hello larger than one packet, as with post-quantum key shares.
        let hello = client_hello(Some("big.example.org"), 1500);
        let dcid = [9u8; 12];
        let (a, rest) = hello.split_at(400);
        let (b, c) = rest.split_at(700);
        // Second packet carries the tail and the head, with PING/padding between.
        let mut frames2 = crypto_frame(1100, c);
        frames2.push(0x01);
        frames2.extend_from_slice(&[0, 0, 0]);
        frames2.extend(crypto_frame(0, a));
        let p1 = initial_packet(VERSION_1, &dcid, 0, &crypto_frame(400, b));
        let p2 = initial_packet(VERSION_1, &dcid, 1, &frames2);

        let mut s = QuicSniffer::new();
        assert_eq!(s.feed(&p1), SniffResult::NeedMore);
        assert_eq!(s.feed(&p2), found(Some("big.example.org")));

        // If the rest never comes, it is still known to be QUIC.
        let mut s = QuicSniffer::new();
        assert_eq!(s.feed(&p1), SniffResult::NeedMore);
        assert_eq!(s.finish(), found(None));
    }

    #[test]
    fn tampered_and_foreign_packets() {
        let hello = client_hello(Some("x.y"), 0);
        let mut packet = initial_packet(VERSION_1, &[1; 8], 0, &crypto_frame(0, &hello));
        packet[600] ^= 1;
        assert_eq!(QuicSniffer::new().feed(&packet), SniffResult::Unknown);
        // Unknown QUIC version and short header.
        let mut v = initial_packet(VERSION_1, &[1; 8], 0, &crypto_frame(0, &hello));
        v[4] = 0x77;
        assert_eq!(QuicSniffer::new().feed(&v), SniffResult::Unknown);
        assert_eq!(
            QuicSniffer::new().feed(&[0x40, 1, 2, 3]),
            SniffResult::Unknown
        );
        assert_eq!(QuicSniffer::new().finish(), SniffResult::Unknown);
    }

    #[test]
    fn bittorrent_and_dns_datagrams() {
        let bt = SniffResult::Found(Sniffed {
            protocol: "bittorrent",
            host: None,
        });
        assert_eq!(
            QuicSniffer::new().feed(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"),
            bt
        );
        let mut tracker = 0x0417_2710_1980u64.to_be_bytes().to_vec();
        tracker.extend_from_slice(&[0, 0, 0, 0, 1, 2, 3, 4]);
        assert_eq!(QuicSniffer::new().feed(&tracker), bt);
        let mut utp = vec![0x41, 0, 0x12, 0x34];
        utp.extend_from_slice(&[0u8; 12]);
        utp.extend_from_slice(&[0, 1, 0, 0]);
        assert_eq!(QuicSniffer::new().feed(&utp), bt);

        let mut dns = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        dns.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        assert_eq!(
            QuicSniffer::new().feed(&dns),
            SniffResult::Found(Sniffed {
                protocol: "dns",
                host: None
            })
        );
        assert_eq!(
            QuicSniffer::new().feed(b"random payload bytes"),
            SniffResult::Unknown
        );
    }
}
