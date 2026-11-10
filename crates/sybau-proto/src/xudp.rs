//! XUDP: UDP over one Mux.Cool stream with a destination per packet
//! (full cone NAT). Carried by VLESS with the `mux` command.
//!
//! Frame: `meta_len(2) | session(2)=0 | status(1) | option(1)=1 [| net(1)=2 | port(2) | atyp addr [| global_id(8)]] | len(2) | payload`
//! with status 1 (New, first packet), 2 (Keep) or 4 (KeepAlive).

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use sybau_common::{proto_err, Host, Target};

use crate::packet::PacketCodec;
use crate::vless::{put_addr, ATYP_DOMAIN, ATYP_V4, ATYP_V6};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const NETWORK_UDP: u8 = 2;

/// Xray drops datagrams that do not fit its buffer with the frame header.
pub const MAX_PAYLOAD: usize = 8192 - 666;

/// Identifier that lets the server keep one NAT mapping per client
/// socket across reconnects: a keyed hash of the client's source address.
/// All zeros means "no identifier".
pub fn global_id(source: Option<SocketAddr>) -> [u8; 8] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    let Some(source) = source else {
        return [0u8; 8];
    };
    let key = KEY.get_or_init(crate::crypto::random_bytes);
    let hash = blake3::keyed_hash(key, source.to_string().as_bytes());
    hash.as_bytes()[..8].try_into().expect("8 bytes")
}

/// Parses `port | atyp | addr` from the front of `b`.
fn read_addr(b: &mut &[u8]) -> io::Result<Target> {
    let short = || proto_err("truncated XUDP address");
    if b.len() < 3 {
        return Err(short());
    }
    let port = u16::from_be_bytes([b[0], b[1]]);
    let atyp = b[2];
    b.advance(3);
    let host = match atyp {
        ATYP_V4 => {
            let raw: [u8; 4] = b.get(..4).ok_or_else(short)?.try_into().expect("4 bytes");
            b.advance(4);
            Host::Ip(std::net::Ipv4Addr::from(raw).into())
        }
        ATYP_V6 => {
            let raw: [u8; 16] = b.get(..16).ok_or_else(short)?.try_into().expect("16 bytes");
            b.advance(16);
            Host::Ip(std::net::Ipv6Addr::from(raw).into())
        }
        ATYP_DOMAIN => {
            let len = *b.first().ok_or_else(short)? as usize;
            let name = b.get(1..1 + len).ok_or_else(short)?;
            let host = sybau_common::addr::domain_host(name)?;
            b.advance(1 + len);
            host
        }
        other => return Err(proto_err(format!("unknown XUDP address type {other}"))),
    };
    Ok(Target::new(host, port))
}

pub struct XudpCodec {
    global_id: [u8; 8],
    started: AtomicBool,
    /// Sender assumed for frames that carry no address.
    default_peer: Target,
}

impl XudpCodec {
    pub fn new(global_id: [u8; 8], first_destination: Target) -> Self {
        Self {
            global_id,
            started: AtomicBool::new(false),
            default_peer: first_destination,
        }
    }
}

impl PacketCodec for XudpCodec {
    fn encode(&self, payload: &[u8], dst: &Target, out: &mut BytesMut) -> io::Result<()> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD {
            // Same limit as Xray: such datagrams are silently dropped.
            return Ok(());
        }
        let start = out.len();
        out.put_slice(&[0, 0, 0, 0]);
        let first = !self.started.swap(true, Ordering::Relaxed);
        out.put_u8(if first { STATUS_NEW } else { STATUS_KEEP });
        out.put_u8(OPTION_DATA);
        out.put_u8(NETWORK_UDP);
        put_addr(out, dst);
        if first {
            out.put_slice(&self.global_id);
        }
        let meta_len = (out.len() - start - 2) as u16;
        out[start..start + 2].copy_from_slice(&meta_len.to_be_bytes());
        out.put_u16(payload.len() as u16);
        out.put_slice(payload);
        Ok(())
    }

    fn decode(&self, buf: &mut BytesMut) -> io::Result<Option<(Bytes, Target)>> {
        loop {
            if buf.len() < 2 {
                return Ok(None);
            }
            let meta_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if !(4..=512).contains(&meta_len) {
                return Err(proto_err("invalid XUDP frame"));
            }
            if buf.len() < 2 + meta_len {
                return Ok(None);
            }
            let meta = &buf[2..2 + meta_len];
            let (status, option) = (meta[2], meta[3]);
            let has_data = option & OPTION_DATA != 0;
            let data_len = if has_data {
                if buf.len() < 2 + meta_len + 2 {
                    return Ok(None);
                }
                u16::from_be_bytes([buf[2 + meta_len], buf[3 + meta_len]]) as usize
            } else {
                0
            };
            let total = 2 + meta_len + if has_data { 2 + data_len } else { 0 };
            if buf.len() < total {
                return Ok(None);
            }
            let from = match status {
                STATUS_KEEP if meta_len > 4 && meta[4] == NETWORK_UDP => {
                    Some(read_addr(&mut &meta[5..])?)
                }
                STATUS_KEEP => Some(self.default_peer.clone()),
                STATUS_KEEP_ALIVE => None,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "XUDP session closed by the server",
                    ))
                }
            };
            let mut frame = buf.split_to(total);
            match from {
                Some(from) if has_data && data_len > 0 => {
                    return Ok(Some((frame.split_off(total - data_len).freeze(), from)));
                }
                _ => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_frame_is_new_with_global_id_then_keep() {
        let dst = Target::parse("8.8.8.8:53").unwrap();
        let codec = XudpCodec::new([9; 8], dst.clone());
        let mut out = BytesMut::new();
        codec.encode(b"query", &dst, &mut out).unwrap();
        // meta: session(2) status opt net port(2) atyp ip(4) global_id(8) = 20
        assert_eq!(&out[..2], &[0, 20]);
        assert_eq!(&out[2..7], &[0, 0, STATUS_NEW, OPTION_DATA, NETWORK_UDP]);
        assert_eq!(&out[7..14], &[0, 53, ATYP_V4, 8, 8, 8, 8]);
        assert_eq!(&out[14..22], &[9; 8]);
        assert_eq!(&out[22..], b"\x00\x05query");

        let mut out = BytesMut::new();
        codec
            .encode(
                b"again",
                &Target::parse("example.com:443").unwrap(),
                &mut out,
            )
            .unwrap();
        assert_eq!(&out[2..7], &[0, 0, STATUS_KEEP, OPTION_DATA, NETWORK_UDP]);
        assert_eq!(&out[7..10], &[0x01, 0xbb, ATYP_DOMAIN]);
        assert_eq!(out[1] as usize, 4 + 1 + 2 + 1 + 1 + 11);

        // Oversized and empty datagrams are dropped, as Xray does.
        let mut out = BytesMut::new();
        codec
            .encode(&vec![0u8; MAX_PAYLOAD + 1], &dst, &mut out)
            .unwrap();
        codec.encode(b"", &dst, &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn decodes_server_frames_including_keepalive_and_partial_input() {
        let codec = XudpCodec::new([0; 8], Target::parse("1.1.1.1:53").unwrap());
        let mut wire = BytesMut::new();
        // Keep with address
        wire.put_slice(&[
            0,
            12,
            0,
            0,
            STATUS_KEEP,
            OPTION_DATA,
            NETWORK_UDP,
            0,
            53,
            ATYP_V4,
            9,
            9,
            9,
            9,
            0,
            3,
        ]);
        wire.put_slice(b"abc");
        // KeepAlive carrying data that must be ignored
        wire.put_slice(&[0, 4, 0, 0, STATUS_KEEP_ALIVE, OPTION_DATA, 0, 2, b'x', b'y']);
        // KeepAlive without data
        wire.put_slice(&[0, 4, 0, 0, STATUS_KEEP_ALIVE, 0]);
        // Keep without address: attributed to the first destination
        wire.put_slice(&[0, 4, 0, 0, STATUS_KEEP, OPTION_DATA, 0, 2, b'o', b'k']);
        let full = wire.clone();

        for cut in 0..full.len() {
            let mut partial = BytesMut::from(&full[..cut]);
            let mut seen = 0;
            while codec.decode(&mut partial).unwrap().is_some() {
                seen += 1;
            }
            assert!(seen <= 2, "cut {cut}");
        }
        let (data, from) = codec.decode(&mut wire).unwrap().unwrap();
        assert_eq!(
            (&data[..], from.to_string().as_str()),
            (&b"abc"[..], "9.9.9.9:53")
        );
        let (data, from) = codec.decode(&mut wire).unwrap().unwrap();
        assert_eq!(
            (&data[..], from.to_string().as_str()),
            (&b"ok"[..], "1.1.1.1:53")
        );
        assert!(codec.decode(&mut wire).unwrap().is_none() && wire.is_empty());

        // End of session and garbage.
        assert!(codec
            .decode(&mut BytesMut::from(&[0u8, 4, 0, 0, 3, 0][..]))
            .is_err());
        assert!(codec
            .decode(&mut BytesMut::from(&[0xffu8, 0xff, 0, 0][..]))
            .is_err());
    }

    #[test]
    fn global_id_is_stable_per_source() {
        let a: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        assert_eq!(global_id(Some(a)), global_id(Some(a)));
        assert_ne!(global_id(Some(a)), global_id(Some(b)));
        assert_eq!(global_id(None), [0u8; 8]);
    }
}
