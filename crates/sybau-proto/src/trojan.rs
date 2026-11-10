//! Trojan client side.
//!
//! Request: `hex(SHA224(password)) CRLF cmd(1) atyp addr port CRLF payload`
//! UDP packet inside the stream: `atyp addr port | len(2) | CRLF | payload`

use std::io;

use bytes::{BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha224};
use sybau_common::addr::{parse_socks_addr, put_socks_addr};
use sybau_common::{proto_err, Target};

use crate::packet::PacketCodec;

pub const CMD_CONNECT: u8 = 1;
pub const CMD_UDP_ASSOCIATE: u8 = 3;

/// The 56 hex characters that authenticate a Trojan client.
pub fn password_hash(password: &str) -> [u8; 56] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha224::digest(password.as_bytes());
    let mut out = [0u8; 56];
    for (i, b) in digest.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
    out
}

pub fn encode_request(hash: &[u8; 56], command: u8, target: &Target) -> BytesMut {
    let mut out = BytesMut::with_capacity(56 + 2 + 1 + 260 + 2);
    out.put_slice(hash);
    out.put_slice(b"\r\n");
    out.put_u8(command);
    put_socks_addr(&mut out, target);
    out.put_slice(b"\r\n");
    out
}

/// Datagram framing of Trojan UDP ASSOCIATE.
pub struct TrojanPacketCodec;

impl PacketCodec for TrojanPacketCodec {
    fn encode(&self, payload: &[u8], dst: &Target, out: &mut BytesMut) -> io::Result<()> {
        let len = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"))?;
        put_socks_addr(out, dst);
        out.put_u16(len);
        out.put_slice(b"\r\n");
        out.put_slice(payload);
        Ok(())
    }

    fn decode(&self, buf: &mut BytesMut) -> io::Result<Option<(Bytes, Target)>> {
        let Some((from, used)) = parse_socks_addr(buf)? else {
            return Ok(None);
        };
        if buf.len() < used + 4 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([buf[used], buf[used + 1]]) as usize;
        if &buf[used + 2..used + 4] != b"\r\n" {
            return Err(proto_err("malformed Trojan UDP packet"));
        }
        if buf.len() < used + 4 + len {
            return Ok(None);
        }
        let _ = buf.split_to(used + 4);
        Ok(Some((buf.split_to(len).freeze(), from)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_sha224() {
        // SHA-224("password") from the FIPS test tooling.
        assert_eq!(
            std::str::from_utf8(&password_hash("password")).unwrap(),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn request_layout() {
        let h = encode_request(
            &password_hash("p"),
            CMD_CONNECT,
            &Target::parse("example.com:443").unwrap(),
        );
        assert_eq!(&h[56..58], b"\r\n");
        assert_eq!(h[58], CMD_CONNECT);
        assert_eq!(&h[59..61], &[3, 11]);
        assert!(h.ends_with(b"\x01\xbb\r\n"));
    }

    #[test]
    fn udp_codec_roundtrip_and_partial_input() {
        let codec = TrojanPacketCodec;
        let dst = Target::parse("[2001:db8::1]:53").unwrap();
        let mut buf = BytesMut::new();
        codec.encode(b"query", &dst, &mut buf).unwrap();
        codec.encode(b"", &dst, &mut buf).unwrap();
        let full = buf.clone();
        for cut in 0..full.len() - 1 - (1 + 16 + 2 + 2 + 2) {
            let mut partial = BytesMut::from(&full[..cut]);
            if cut < 1 + 16 + 2 + 2 + 2 + 5 {
                assert!(codec.decode(&mut partial).unwrap().is_none(), "cut {cut}");
            }
        }
        let (p, from) = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!((&p[..], &from), (&b"query"[..], &dst));
        let (p, _) = codec.decode(&mut buf).unwrap().unwrap();
        assert!(p.is_empty() && buf.is_empty());
    }

    #[test]
    fn udp_codec_rejects_missing_crlf() {
        let mut buf = BytesMut::from(&[1u8, 1, 2, 3, 4, 0, 53, 0, 1, b'x', b'y', b'z'][..]);
        assert!(TrojanPacketCodec.decode(&mut buf).is_err());
    }
}
