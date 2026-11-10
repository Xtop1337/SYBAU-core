//! Classic Shadowsocks AEAD (SIP004).
//!
//! TCP: `salt | [len(2)+tag][payload+tag] ...`, chunk payload <= 0x3FFF,
//!      the first plaintext bytes are the target address.
//! UDP: `salt | AEAD(addr | payload)` with an all-zero nonce.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use sybau_common::addr::{parse_socks_addr, put_socks_addr};
use sybau_common::{poll_drain, proto_err, ArcPacketConn, PacketConn, Target};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_read_buf;

use super::session_subkey;
use crate::crypto::{fill_random, Aead, AeadKind, CounterNonce, TAG_LEN};

pub const MAX_CHUNK: usize = 0x3fff;

enum ReadState {
    Salt,
    Length,
    Payload(usize),
}

/// Client stream. `key` is the master key (see `evp_bytes_to_key`).
pub struct SsAeadStream<S> {
    inner: S,
    kind: AeadKind,
    key: Vec<u8>,
    /// Target address, sent inside the first chunk.
    first: Option<BytesMut>,
    enc: Option<(Aead, CounterNonce)>,
    wbuf: BytesMut,
    dec: Option<(Aead, CounterNonce)>,
    state: ReadState,
    rbuf: BytesMut,
    plain: BytesMut,
}

impl<S> SsAeadStream<S> {
    pub fn new(inner: S, kind: AeadKind, key: Vec<u8>, target: &Target) -> Self {
        let mut first = BytesMut::new();
        put_socks_addr(&mut first, target);
        Self {
            inner,
            kind,
            key,
            first: Some(first),
            enc: None,
            wbuf: BytesMut::new(),
            dec: None,
            state: ReadState::Salt,
            rbuf: BytesMut::with_capacity(8192),
            plain: BytesMut::new(),
        }
    }

    fn encode_chunk(&mut self, plain: &[u8]) {
        if self.enc.is_none() {
            let mut salt = vec![0u8; self.kind.key_len()];
            fill_random(&mut salt);
            let subkey = session_subkey(&self.key, &salt);
            self.wbuf.put_slice(&salt);
            self.enc = Some((
                Aead::new(self.kind, &subkey),
                CounterNonce::new(self.kind.nonce_len()),
            ));
        }
        let (aead, nonce) = self.enc.as_mut().expect("initialised above");
        aead.seal_append(
            &nonce.advance(),
            &[],
            &(plain.len() as u16).to_be_bytes(),
            &mut self.wbuf,
        );
        aead.seal_append(&nonce.advance(), &[], plain, &mut self.wbuf);
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SsAeadStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(poll_drain(&mut this.inner, cx, &mut this.wbuf))?;
        let n = match this.first.take() {
            Some(mut first) => {
                let n = buf.len().min(MAX_CHUNK - first.len());
                first.extend_from_slice(&buf[..n]);
                this.encode_chunk(&first);
                n
            }
            None => {
                let n = buf.len().min(MAX_CHUNK);
                this.encode_chunk(&buf[..n]);
                n
            }
        };
        let _ = poll_drain(&mut this.inner, cx, &mut this.wbuf)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(first) = this.first.take() {
            this.encode_chunk(&first);
        }
        ready!(poll_drain(&mut this.inner, cx, &mut this.wbuf))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SsAeadStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if !this.plain.is_empty() {
                let n = this.plain.len().min(buf.remaining());
                buf.put_slice(&this.plain[..n]);
                this.plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            match this.state {
                ReadState::Salt if this.rbuf.len() >= this.kind.key_len() => {
                    let salt = this.rbuf.split_to(this.kind.key_len());
                    let subkey = session_subkey(&this.key, &salt);
                    this.dec = Some((
                        Aead::new(this.kind, &subkey),
                        CounterNonce::new(this.kind.nonce_len()),
                    ));
                    this.state = ReadState::Length;
                    continue;
                }
                ReadState::Length if this.rbuf.len() >= 2 + TAG_LEN => {
                    let (aead, nonce) = this.dec.as_mut().expect("salt was read");
                    let mut head = this.rbuf.split_to(2 + TAG_LEN);
                    aead.open(&nonce.advance(), &[], &mut head)?;
                    let len = u16::from_be_bytes([head[0], head[1]]) as usize;
                    if len > MAX_CHUNK {
                        return Poll::Ready(Err(proto_err("Shadowsocks chunk too large")));
                    }
                    this.state = ReadState::Payload(len);
                    continue;
                }
                ReadState::Payload(len) if this.rbuf.len() >= len + TAG_LEN => {
                    let (aead, nonce) = this.dec.as_mut().expect("salt was read");
                    let mut chunk = this.rbuf.split_to(len + TAG_LEN);
                    aead.open(&nonce.advance(), &[], &mut chunk)?;
                    chunk.truncate(len);
                    this.plain = chunk;
                    this.state = ReadState::Length;
                    continue;
                }
                _ => {}
            }
            this.rbuf.reserve(4096);
            if ready!(poll_read_buf(Pin::new(&mut this.inner), cx, &mut this.rbuf))? == 0 {
                return Poll::Ready(if this.rbuf.is_empty() {
                    Ok(())
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                });
            }
        }
    }
}

/// Encrypts one UDP packet: `salt | AEAD(addr | payload)`.
pub fn encode_packet(kind: AeadKind, key: &[u8], dst: &Target, payload: &[u8]) -> BytesMut {
    let salt_len = kind.key_len();
    let mut out = BytesMut::with_capacity(salt_len + 300 + payload.len() + TAG_LEN);
    out.resize(salt_len, 0);
    fill_random(&mut out);
    let aead = Aead::new(kind, &session_subkey(key, &out));
    put_socks_addr(&mut out, dst);
    out.put_slice(payload);
    let nonce = [0u8; 24];
    let tag = aead.seal(&nonce[..kind.nonce_len()], &[], &mut out[salt_len..]);
    out.put_slice(&tag);
    out
}

/// Decrypts one UDP packet in place; returns the sender address and the
/// range of the payload inside `packet`.
pub fn decode_packet(
    kind: AeadKind,
    key: &[u8],
    packet: &mut [u8],
) -> io::Result<(Target, std::ops::Range<usize>)> {
    let salt_len = kind.key_len();
    if packet.len() < salt_len + TAG_LEN {
        return Err(proto_err("Shadowsocks UDP packet too short"));
    }
    let (salt, body) = packet.split_at_mut(salt_len);
    let aead = Aead::new(kind, &session_subkey(key, salt));
    let nonce = [0u8; 24];
    let n = aead.open(&nonce[..kind.nonce_len()], &[], body)?;
    let (from, used) = parse_socks_addr(&body[..n])?
        .ok_or_else(|| proto_err("truncated address in UDP packet"))?;
    Ok((from, salt_len + used..salt_len + n))
}

/// Shadowsocks UDP relay over a datagram socket to the server.
pub struct SsAeadPacketConn {
    inner: ArcPacketConn,
    server: Target,
    kind: AeadKind,
    key: Vec<u8>,
}

impl SsAeadPacketConn {
    pub fn new(inner: ArcPacketConn, server: Target, kind: AeadKind, key: Vec<u8>) -> Self {
        Self {
            inner,
            server,
            kind,
            key,
        }
    }
}

#[async_trait]
impl PacketConn for SsAeadPacketConn {
    async fn send_to(&self, buf: &[u8], dst: &Target) -> io::Result<usize> {
        let packet = encode_packet(self.kind, &self.key, dst, buf);
        self.inner.send_to(&packet, &self.server).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let mut scratch = vec![0u8; 65535];
        loop {
            let (n, _) = self.inner.recv_from(&mut scratch).await?;
            // Garbage and forged packets are dropped, not fatal.
            let Ok((from, range)) = decode_packet(self.kind, &self.key, &mut scratch[..n]) else {
                continue;
            };
            let len = range.len().min(buf.len());
            buf[..len].copy_from_slice(&scratch[range.start..range.start + len]);
            return Ok((len, from));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowsocks::evp_bytes_to_key;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Server-side decoding written independently of the stream, straight
    /// from the SIP004 description.
    async fn server_read_chunk<S: AsyncRead + Unpin>(
        s: &mut S,
        aead: &Aead,
        nonce: &mut CounterNonce,
    ) -> Vec<u8> {
        let mut head = [0u8; 2 + TAG_LEN];
        s.read_exact(&mut head).await.unwrap();
        aead.open(&nonce.advance(), &[], &mut head).unwrap();
        let len = u16::from_be_bytes([head[0], head[1]]) as usize;
        let mut body = vec![0u8; len + TAG_LEN];
        s.read_exact(&mut body).await.unwrap();
        aead.open(&nonce.advance(), &[], &mut body).unwrap();
        body.truncate(len);
        body
    }

    #[tokio::test]
    async fn stream_matches_sip004_layout() {
        for kind in [
            AeadKind::Aes128Gcm,
            AeadKind::Aes256Gcm,
            AeadKind::ChaCha20Poly1305,
            AeadKind::XChaCha20Poly1305,
        ] {
            let key = evp_bytes_to_key(b"secret", kind.key_len());
            let target = Target::parse("example.com:80").unwrap();
            let (client, mut server) = tokio::io::duplex(1 << 20);
            let mut c = SsAeadStream::new(client, kind, key.clone(), &target);
            let big = vec![0x5au8; 40_000];
            c.write_all(b"GET /").await.unwrap();
            c.write_all(&big).await.unwrap();
            c.flush().await.unwrap();

            let mut salt = vec![0u8; kind.key_len()];
            server.read_exact(&mut salt).await.unwrap();
            let aead = Aead::new(kind, &session_subkey(&key, &salt));
            let mut nonce = CounterNonce::new(kind.nonce_len());
            let first = server_read_chunk(&mut server, &aead, &mut nonce).await;
            let (t, used) = parse_socks_addr(&first).unwrap().unwrap();
            assert_eq!(t, target);
            assert_eq!(&first[used..], b"GET /");
            let mut rest = Vec::new();
            while rest.len() < big.len() {
                rest.extend(server_read_chunk(&mut server, &aead, &mut nonce).await);
            }
            assert_eq!(rest, big);

            // Server reply: its own salt, then chunks.
            let mut reply = BytesMut::new();
            let rsalt = vec![9u8; kind.key_len()];
            reply.put_slice(&rsalt);
            let raead = Aead::new(kind, &session_subkey(&key, &rsalt));
            let mut rnonce = CounterNonce::new(kind.nonce_len());
            for part in [&b"HTTP/1.1 "[..], &b"200 OK"[..]] {
                raead.seal_append(
                    &rnonce.advance(),
                    &[],
                    &(part.len() as u16).to_be_bytes(),
                    &mut reply,
                );
                raead.seal_append(&rnonce.advance(), &[], part, &mut reply);
            }
            server.write_all(&reply).await.unwrap();
            let mut got = [0u8; 15];
            c.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"HTTP/1.1 200 OK");
            drop(server);
            assert_eq!(c.read(&mut got).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn flush_sends_address_alone_and_tampering_is_detected() {
        let kind = AeadKind::Aes128Gcm;
        let key = evp_bytes_to_key(b"k", 16);
        let (client, mut server) = tokio::io::duplex(4096);
        let mut c = SsAeadStream::new(
            client,
            kind,
            key.clone(),
            &Target::parse("1.2.3.4:5").unwrap(),
        );
        c.flush().await.unwrap();
        let mut buf = vec![0u8; 16 + 2 + 16 + 7 + 16];
        server.read_exact(&mut buf).await.unwrap();
        server.write_all(&[0u8; 16 + 2 + 16]).await.unwrap();
        let mut one = [0u8; 1];
        assert!(c.read(&mut one).await.is_err());
    }

    #[test]
    fn udp_packet_roundtrip() {
        let kind = AeadKind::ChaCha20Poly1305;
        let key = evp_bytes_to_key(b"pw", 32);
        let dst = Target::parse("8.8.8.8:53").unwrap();
        let mut pkt = encode_packet(kind, &key, &dst, b"dns query");
        let (from, range) = decode_packet(kind, &key, &mut pkt).unwrap();
        assert_eq!(from, dst);
        assert_eq!(&pkt[range], b"dns query");
        let mut bad = encode_packet(kind, &key, &dst, b"x");
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decode_packet(kind, &key, &mut bad).is_err());
        assert!(decode_packet(kind, &key, &mut [0u8; 10]).is_err());
    }
}
