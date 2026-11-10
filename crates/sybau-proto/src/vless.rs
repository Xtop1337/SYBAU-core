//! VLESS (version 0) client side.
//!
//! Request:  `ver(1)=0 | uuid(16) | addons_len(1) addons | cmd(1) | port(2) | atyp(1) addr | payload`
//! Response: `ver(1)=0 | addons_len(1) addons | payload`

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use sybau_common::{proto_err, HeaderStream, Host, Target};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const VERSION: u8 = 0;
pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 2;
pub const CMD_MUX: u8 = 3;

pub const ATYP_V4: u8 = 1;
pub const ATYP_DOMAIN: u8 = 2;
pub const ATYP_V6: u8 = 3;

pub const FLOW_VISION: &str = "xtls-rprx-vision";

/// VLESS address: `port | atyp | addr` (the port comes first).
pub fn put_addr(out: &mut impl BufMut, target: &Target) {
    out.put_u16(target.port);
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            out.put_u8(ATYP_V4);
            out.put_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            out.put_u8(ATYP_V6);
            out.put_slice(&ip.octets());
        }
        Host::Domain(d) => {
            let bytes = &d.as_bytes()[..d.len().min(255)];
            out.put_u8(ATYP_DOMAIN);
            out.put_u8(bytes.len() as u8);
            out.put_slice(bytes);
        }
    }
}

/// Builds the request header. `flow` is written as the protobuf addon
/// `Addons { string Flow = 1; }`. `target` is ignored for `CMD_MUX`.
pub fn encode_request(
    uuid: &[u8; 16],
    flow: Option<&str>,
    command: u8,
    target: &Target,
) -> BytesMut {
    let mut out = BytesMut::with_capacity(64 + target.host_string().len());
    out.put_u8(VERSION);
    out.put_slice(uuid);
    match flow.filter(|f| !f.is_empty()) {
        Some(flow) => {
            let flow = &flow.as_bytes()[..flow.len().min(120)];
            out.put_u8(2 + flow.len() as u8);
            out.put_u8(0x0a);
            out.put_u8(flow.len() as u8);
            out.put_slice(flow);
        }
        None => out.put_u8(0),
    }
    out.put_u8(command);
    if command != CMD_MUX {
        put_addr(&mut out, target);
    }
    out
}

#[derive(Clone, Copy)]
enum ResponseState {
    Version,
    AddonsLen,
    Addons(u8),
    Done,
}

/// Client stream: sends the request header with the first payload and
/// strips the response header from the first bytes received.
pub struct VlessStream<S> {
    inner: HeaderStream<S>,
    response: ResponseState,
}

impl<S> VlessStream<S> {
    pub fn new(
        inner: S,
        uuid: &[u8; 16],
        flow: Option<&str>,
        command: u8,
        target: &Target,
    ) -> Self {
        Self {
            inner: HeaderStream::new(encode_request(uuid, flow, command, target).freeze(), inner),
            response: ResponseState::Version,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if matches!(this.response, ResponseState::Done) {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let before = buf.filled().len();
            match Pin::new(&mut this.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
            let got = buf.filled().len() - before;
            if got == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut skip = 0;
            while skip < got {
                let byte = buf.filled()[before + skip];
                match this.response {
                    ResponseState::Version => {
                        if byte != VERSION {
                            return Poll::Ready(Err(proto_err(format!(
                                "unexpected VLESS response version {byte}"
                            ))));
                        }
                        this.response = ResponseState::AddonsLen;
                    }
                    ResponseState::AddonsLen => {
                        this.response = if byte == 0 {
                            ResponseState::Done
                        } else {
                            ResponseState::Addons(byte)
                        };
                    }
                    ResponseState::Addons(left) => {
                        this.response = if left == 1 {
                            ResponseState::Done
                        } else {
                            ResponseState::Addons(left - 1)
                        };
                    }
                    ResponseState::Done => break,
                }
                skip += 1;
            }
            let rest = got - skip;
            let filled = buf.filled_mut();
            filled.copy_within(before + skip..before + got, before);
            buf.set_filled(before + rest);
            if rest > 0 {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const UUID: [u8; 16] = [0x11; 16];

    #[test]
    fn request_layout() {
        let t = Target::parse("example.com:443").unwrap();
        let h = encode_request(&UUID, None, CMD_TCP, &t);
        let mut expect = vec![0u8];
        expect.extend_from_slice(&UUID);
        expect.extend_from_slice(&[0, CMD_TCP, 0x01, 0xbb, ATYP_DOMAIN, 11]);
        expect.extend_from_slice(b"example.com");
        assert_eq!(&h[..], &expect[..]);

        let h = encode_request(
            &UUID,
            Some(FLOW_VISION),
            CMD_TCP,
            &Target::parse("1.2.3.4:80").unwrap(),
        );
        assert_eq!(h[17], 18);
        assert_eq!(&h[18..20], &[0x0a, 16]);
        assert_eq!(&h[20..36], FLOW_VISION.as_bytes());
        assert_eq!(&h[36..], &[CMD_TCP, 0, 80, ATYP_V4, 1, 2, 3, 4]);

        let h = encode_request(&UUID, None, CMD_MUX, &t);
        assert_eq!(h.len(), 1 + 16 + 1 + 1);
    }

    #[tokio::test]
    async fn header_goes_with_first_payload_and_response_is_stripped() {
        let (client, mut server) = tokio::io::duplex(1024);
        let t = Target::parse("example.com:443").unwrap();
        let mut s = VlessStream::new(client, &UUID, None, CMD_TCP, &t);
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let expect_len = encode_request(&UUID, None, CMD_TCP, &t).len() + 5;
        let mut got = vec![0u8; expect_len];
        server.read_exact(&mut got).await.unwrap();
        assert!(got.ends_with(b"hello"));

        // Response header with addons, delivered byte by byte.
        for b in [0u8, 2, 0xaa, 0xbb, b'o', b'k'] {
            server.write_all(&[b]).await.unwrap();
        }
        let mut buf = [0u8; 2];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");
        server.write_all(b"more").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"more");
    }

    #[tokio::test]
    async fn flush_sends_header_alone_and_bad_version_fails() {
        let (client, mut server) = tokio::io::duplex(1024);
        let t = Target::parse("1.2.3.4:80").unwrap();
        let mut s = VlessStream::new(client, &UUID, None, CMD_TCP, &t);
        s.flush().await.unwrap();
        let mut got = vec![0u8; encode_request(&UUID, None, CMD_TCP, &t).len()];
        server.read_exact(&mut got).await.unwrap();
        server.write_all(&[9, 0]).await.unwrap();
        assert!(s.read_u8().await.is_err());
    }
}
