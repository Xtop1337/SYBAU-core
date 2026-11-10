//! Shadowsocks 2022 (SIP022, `2022-blake3-*`) client side, including
//! identity headers for multi-user servers (SIP023).
//!
//! TCP request:  `salt | [identity headers] | AEAD(type ts varlen) | AEAD(addr padlen padding payload) | chunks`
//! TCP response: `salt | AEAD(type ts request_salt len) | AEAD(payload) | chunks`
//! Chunk:        `AEAD(len u16) | AEAD(payload)`

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{ready, Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use parking_lot::Mutex;
use rand::Rng;
use sybau_common::addr::{parse_socks_addr, put_socks_addr, socks_addr_len};
use sybau_common::{poll_drain, proto_err, ArcPacketConn, PacketConn, Target};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_read_buf;

use crate::crypto::{fill_random, Aead, AeadKind, CounterNonce, TAG_LEN};

const TYPE_CLIENT: u8 = 0;
const TYPE_SERVER: u8 = 1;
const MAX_TIME_DIFF: u64 = 30;
const MAX_PADDING: usize = 900;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn check_timestamp(ts: u64) -> io::Result<()> {
    if now().abs_diff(ts) > MAX_TIME_DIFF {
        return Err(proto_err(
            "Shadowsocks 2022 timestamp out of range (check the system clock)",
        ));
    }
    Ok(())
}

pub fn session_subkey(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(key.len() + salt.len());
    material.extend_from_slice(key);
    material.extend_from_slice(salt);
    blake3::derive_key("shadowsocks 2022 session subkey", &material)[..key.len()].to_vec()
}

fn identity_subkey(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(key.len() + salt.len());
    material.extend_from_slice(key);
    material.extend_from_slice(salt);
    blake3::derive_key("shadowsocks 2022 identity subkey", &material)[..key.len()].to_vec()
}

fn aes_block(key: &[u8], block: &mut [u8; 16], encrypt: bool) {
    let b = aes::Block::from_mut_slice(block);
    match key.len() {
        16 => {
            let c = aes::Aes128::new_from_slice(key).expect("key length checked");
            if encrypt {
                c.encrypt_block(b)
            } else {
                c.decrypt_block(b)
            }
        }
        _ => {
            let c = aes::Aes256::new_from_slice(key).expect("key length checked");
            if encrypt {
                c.encrypt_block(b)
            } else {
                c.decrypt_block(b)
            }
        }
    }
}

fn psk_hash(psk: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&blake3::hash(psk).as_bytes()[..16]);
    out
}

enum ReadState {
    Salt,
    FixedHeader,
    Length,
    Payload(usize),
}

/// Client stream. `keys` are the PSKs; the last one is the user key and
/// the preceding ones are identity keys.
pub struct Ss2022Stream<S> {
    inner: S,
    kind: AeadKind,
    keys: Vec<Vec<u8>>,
    /// Target address, sent in the request header.
    first: Option<BytesMut>,
    request_salt: Vec<u8>,
    enc: Option<(Aead, CounterNonce)>,
    wbuf: BytesMut,
    dec: Option<(Aead, CounterNonce)>,
    state: ReadState,
    rbuf: BytesMut,
    plain: BytesMut,
}

impl<S> Ss2022Stream<S> {
    pub fn new(inner: S, kind: AeadKind, keys: Vec<Vec<u8>>, target: &Target) -> Self {
        assert!(!keys.is_empty(), "at least one key");
        let mut first = BytesMut::with_capacity(socks_addr_len(target));
        put_socks_addr(&mut first, target);
        Self {
            inner,
            kind,
            keys,
            first: Some(first),
            request_salt: Vec::new(),
            enc: None,
            wbuf: BytesMut::new(),
            dec: None,
            state: ReadState::Salt,
            rbuf: BytesMut::with_capacity(8192),
            plain: BytesMut::new(),
        }
    }

    fn user_key(&self) -> &[u8] {
        self.keys.last().expect("at least one key")
    }

    /// Writes salt, identity headers and both request headers.
    /// Returns how many bytes of `payload` were included.
    fn encode_request(&mut self, addr: BytesMut, payload: &[u8]) -> usize {
        let key_len = self.kind.key_len();
        let mut salt = vec![0u8; key_len];
        fill_random(&mut salt);
        self.wbuf.put_slice(&salt);
        for i in 0..self.keys.len() - 1 {
            let mut block = psk_hash(&self.keys[i + 1]);
            aes_block(&identity_subkey(&self.keys[i], &salt), &mut block, true);
            self.wbuf.put_slice(&block);
        }
        let aead = Aead::new(self.kind, &session_subkey(self.user_key(), &salt));
        let mut nonce = CounterNonce::new(12);

        let n = payload.len().min(0xffff - addr.len() - 2);
        // Without payload the header must carry padding, so that the
        // request length does not reveal the address length.
        let padding = if n == 0 {
            rand::thread_rng().gen_range(1..=MAX_PADDING)
        } else {
            0
        };
        let mut variable = BytesMut::with_capacity(addr.len() + 2 + padding + n);
        variable.put_slice(&addr);
        variable.put_u16(padding as u16);
        variable.put_bytes(0, padding);
        variable.put_slice(&payload[..n]);

        let mut fixed = [0u8; 11];
        fixed[0] = TYPE_CLIENT;
        fixed[1..9].copy_from_slice(&now().to_be_bytes());
        fixed[9..11].copy_from_slice(&(variable.len() as u16).to_be_bytes());
        aead.seal_append(&nonce.advance(), &[], &fixed, &mut self.wbuf);
        aead.seal_append(&nonce.advance(), &[], &variable, &mut self.wbuf);
        self.request_salt = salt;
        self.enc = Some((aead, nonce));
        n
    }

    fn encode_chunk(&mut self, plain: &[u8]) {
        let (aead, nonce) = self.enc.as_mut().expect("request header was sent");
        aead.seal_append(
            &nonce.advance(),
            &[],
            &(plain.len() as u16).to_be_bytes(),
            &mut self.wbuf,
        );
        aead.seal_append(&nonce.advance(), &[], plain, &mut self.wbuf);
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Ss2022Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(poll_drain(&mut this.inner, cx, &mut this.wbuf))?;
        let n = match this.first.take() {
            Some(addr) => this.encode_request(addr, buf),
            None => {
                let n = buf.len().min(0xffff);
                this.encode_chunk(&buf[..n]);
                n
            }
        };
        let _ = poll_drain(&mut this.inner, cx, &mut this.wbuf)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(addr) = this.first.take() {
            this.encode_request(addr, &[]);
        }
        ready!(poll_drain(&mut this.inner, cx, &mut this.wbuf))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Ss2022Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let key_len = this.kind.key_len();
        loop {
            if !this.plain.is_empty() {
                let n = this.plain.len().min(buf.remaining());
                buf.put_slice(&this.plain[..n]);
                this.plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            match this.state {
                ReadState::Salt if this.rbuf.len() >= key_len => {
                    let salt = this.rbuf.split_to(key_len);
                    let subkey = session_subkey(this.keys.last().expect("at least one key"), &salt);
                    this.dec = Some((Aead::new(this.kind, &subkey), CounterNonce::new(12)));
                    this.state = ReadState::FixedHeader;
                    continue;
                }
                ReadState::FixedHeader if this.rbuf.len() >= 1 + 8 + key_len + 2 + TAG_LEN => {
                    let (aead, nonce) = this.dec.as_mut().expect("salt was read");
                    let mut head = this.rbuf.split_to(1 + 8 + key_len + 2 + TAG_LEN);
                    aead.open(&nonce.advance(), &[], &mut head)?;
                    if head[0] != TYPE_SERVER {
                        return Poll::Ready(Err(proto_err(
                            "unexpected Shadowsocks 2022 header type",
                        )));
                    }
                    check_timestamp(u64::from_be_bytes(head[1..9].try_into().expect("8 bytes")))?;
                    if head[9..9 + key_len] != this.request_salt[..] {
                        return Poll::Ready(Err(proto_err(
                            "Shadowsocks 2022 response does not match the request",
                        )));
                    }
                    let len = u16::from_be_bytes([head[9 + key_len], head[10 + key_len]]) as usize;
                    this.state = ReadState::Payload(len);
                    continue;
                }
                ReadState::Length if this.rbuf.len() >= 2 + TAG_LEN => {
                    let (aead, nonce) = this.dec.as_mut().expect("salt was read");
                    let mut head = this.rbuf.split_to(2 + TAG_LEN);
                    aead.open(&nonce.advance(), &[], &mut head)?;
                    this.state =
                        ReadState::Payload(u16::from_be_bytes([head[0], head[1]]) as usize);
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

/// Shadowsocks 2022 UDP relay over a datagram socket to the server.
///
/// AES methods:  `AES-ECB(session_id packet_id) | [identity headers] | AEAD(body)`
/// ChaCha20:     `nonce(24) | XChaCha20-Poly1305(session_id packet_id body)`
/// Client body:  `type(0) ts padlen padding addr payload`
/// Server body:  `type(1) ts client_session_id padlen padding addr payload`
pub struct Ss2022PacketConn {
    inner: ArcPacketConn,
    server: Target,
    kind: AeadKind,
    keys: Vec<Vec<u8>>,
    session_id: [u8; 8],
    packet_id: AtomicU64,
    /// Client session cipher (AES methods).
    send_aead: Option<Aead>,
    /// Cipher of the server session seen last (AES methods).
    recv_session: Mutex<Option<([u8; 8], std::sync::Arc<Aead>)>>,
}

impl Ss2022PacketConn {
    pub fn new(inner: ArcPacketConn, server: Target, kind: AeadKind, keys: Vec<Vec<u8>>) -> Self {
        assert!(!keys.is_empty(), "at least one key");
        let session_id: [u8; 8] = crate::crypto::random_bytes();
        let send_aead = (kind != AeadKind::ChaCha20Poly1305).then(|| {
            Aead::new(
                kind,
                &session_subkey(keys.last().expect("non-empty"), &session_id),
            )
        });
        Self {
            inner,
            server,
            kind,
            keys,
            session_id,
            packet_id: AtomicU64::new(0),
            send_aead,
            recv_session: Mutex::new(None),
        }
    }

    fn user_key(&self) -> &[u8] {
        self.keys.last().expect("non-empty")
    }

    pub fn encode(&self, payload: &[u8], dst: &Target) -> BytesMut {
        let packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed);
        let mut header = [0u8; 16];
        header[..8].copy_from_slice(&self.session_id);
        header[8..].copy_from_slice(&packet_id.to_be_bytes());

        let mut body = BytesMut::with_capacity(11 + socks_addr_len(dst) + payload.len());
        body.put_u8(TYPE_CLIENT);
        body.put_u64(now());
        body.put_u16(0);
        put_socks_addr(&mut body, dst);
        body.put_slice(payload);

        let mut out = BytesMut::with_capacity(24 + 16 * self.keys.len() + body.len() + TAG_LEN);
        match &self.send_aead {
            Some(aead) => {
                let mut sealed_header = header;
                aes_block(&self.keys[0], &mut sealed_header, true);
                out.put_slice(&sealed_header);
                for i in 0..self.keys.len() - 1 {
                    let mut block = psk_hash(&self.keys[i + 1]);
                    block.iter_mut().zip(header).for_each(|(b, h)| *b ^= h);
                    aes_block(&self.keys[i], &mut block, true);
                    out.put_slice(&block);
                }
                aead.seal_append(&header[4..16], &[], &body, &mut out);
            }
            None => {
                let nonce: [u8; 24] = crate::crypto::random_bytes();
                out.put_slice(&nonce);
                let start = out.len();
                out.put_slice(&header);
                out.put_slice(&body);
                let aead = Aead::new(AeadKind::XChaCha20Poly1305, self.user_key());
                let tag = aead.seal(&nonce, &[], &mut out[start..]);
                out.put_slice(&tag);
            }
        }
        out
    }

    /// Decrypts a packet from the server in place; returns the sender
    /// address and the payload range inside `packet`.
    pub fn decode(&self, packet: &mut [u8]) -> io::Result<(Target, std::ops::Range<usize>)> {
        let (body_start, body_len) = match self.kind {
            AeadKind::ChaCha20Poly1305 => {
                if packet.len() < 24 + 16 + TAG_LEN {
                    return Err(proto_err("Shadowsocks 2022 UDP packet too short"));
                }
                let (nonce, rest) = packet.split_at_mut(24);
                let aead = Aead::new(AeadKind::XChaCha20Poly1305, self.user_key());
                let n = aead.open(nonce, &[], rest)?;
                (24 + 16, n - 16)
            }
            _ => {
                if packet.len() < 16 + TAG_LEN {
                    return Err(proto_err("Shadowsocks 2022 UDP packet too short"));
                }
                let (head, rest) = packet.split_at_mut(16);
                let header: &mut [u8; 16] = head.try_into().expect("16 bytes");
                aes_block(self.user_key(), header, false);
                let server_session: [u8; 8] = header[..8].try_into().expect("8 bytes");
                let cached = self
                    .recv_session
                    .lock()
                    .as_ref()
                    .filter(|(id, _)| *id == server_session)
                    .map(|(_, a)| a.clone());
                let aead = match cached {
                    Some(a) => a,
                    None => {
                        let a = std::sync::Arc::new(Aead::new(
                            self.kind,
                            &session_subkey(self.user_key(), &server_session),
                        ));
                        *self.recv_session.lock() = Some((server_session, a.clone()));
                        a
                    }
                };
                let n = aead.open(&header[4..16], &[], rest)?;
                (16, n)
            }
        };
        let body = &packet[body_start..body_start + body_len];
        if body.len() < 1 + 8 + 8 + 2 || body[0] != TYPE_SERVER {
            return Err(proto_err("malformed Shadowsocks 2022 UDP body"));
        }
        check_timestamp(u64::from_be_bytes(body[1..9].try_into().expect("8 bytes")))?;
        if body[9..17] != self.session_id {
            return Err(proto_err("Shadowsocks 2022 UDP packet for another session"));
        }
        let padding = u16::from_be_bytes([body[17], body[18]]) as usize;
        let addr_start = 19 + padding;
        if body.len() < addr_start {
            return Err(proto_err("malformed Shadowsocks 2022 UDP padding"));
        }
        let (from, used) = parse_socks_addr(&body[addr_start..])?
            .ok_or_else(|| proto_err("truncated address in UDP packet"))?;
        let start = body_start + addr_start + used;
        Ok((from, start..body_start + body_len))
    }
}

#[async_trait]
impl PacketConn for Ss2022PacketConn {
    async fn send_to(&self, buf: &[u8], dst: &Target) -> io::Result<usize> {
        let packet = self.encode(buf, dst);
        self.inner.send_to(&packet, &self.server).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let mut scratch = vec![0u8; 65535];
        loop {
            let (n, _) = self.inner.recv_from(&mut scratch).await?;
            let Ok((from, range)) = self.decode(&mut scratch[..n]) else {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn request_layout_and_response_validation() {
        for (kind, nkeys) in [
            (AeadKind::Aes128Gcm, 1),
            (AeadKind::Aes256Gcm, 2),
            (AeadKind::ChaCha20Poly1305, 1),
        ] {
            let klen = kind.key_len();
            let keys: Vec<Vec<u8>> = (0..nkeys).map(|i| vec![i as u8 + 1; klen]).collect();
            let target = Target::parse("example.com:443").unwrap();
            let (client, mut server) = tokio::io::duplex(1 << 20);
            let mut c = Ss2022Stream::new(client, kind, keys.clone(), &target);
            c.write_all(b"hello").await.unwrap();
            c.flush().await.unwrap();

            // Decode the request the way a server would.
            let mut salt = vec![0u8; klen];
            server.read_exact(&mut salt).await.unwrap();
            if nkeys == 2 {
                let mut eih = [0u8; 16];
                server.read_exact(&mut eih).await.unwrap();
                aes_block(&identity_subkey(&keys[0], &salt), &mut eih, false);
                assert_eq!(eih, psk_hash(&keys[1]));
            }
            let aead = Aead::new(kind, &session_subkey(keys.last().unwrap(), &salt));
            let mut nonce = CounterNonce::new(12);
            let mut fixed = [0u8; 11 + TAG_LEN];
            server.read_exact(&mut fixed).await.unwrap();
            aead.open(&nonce.advance(), &[], &mut fixed).unwrap();
            assert_eq!(fixed[0], TYPE_CLIENT);
            let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
            let mut var = vec![0u8; var_len + TAG_LEN];
            server.read_exact(&mut var).await.unwrap();
            aead.open(&nonce.advance(), &[], &mut var).unwrap();
            let (t, used) = parse_socks_addr(&var[..var_len]).unwrap().unwrap();
            assert_eq!(t, target);
            assert_eq!(&var[used..used + 2], &[0, 0]);
            assert_eq!(&var[used + 2..var_len], b"hello");

            // Server response bound to the request salt.
            let rsalt = vec![0x42u8; klen];
            let raead = Aead::new(kind, &session_subkey(keys.last().unwrap(), &rsalt));
            let mut rnonce = CounterNonce::new(12);
            let mut resp = BytesMut::from(&rsalt[..]);
            let mut head = vec![TYPE_SERVER];
            head.extend_from_slice(&now().to_be_bytes());
            head.extend_from_slice(&salt);
            head.extend_from_slice(&2u16.to_be_bytes());
            raead.seal_append(&rnonce.advance(), &[], &head, &mut resp);
            raead.seal_append(&rnonce.advance(), &[], b"ok", &mut resp);
            raead.seal_append(&rnonce.advance(), &[], &3u16.to_be_bytes(), &mut resp);
            raead.seal_append(&rnonce.advance(), &[], b"abc", &mut resp);
            server.write_all(&resp).await.unwrap();
            let mut got = [0u8; 5];
            c.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"okabc");
        }
    }

    #[tokio::test]
    async fn header_without_payload_is_padded_and_wrong_salt_is_rejected() {
        let kind = AeadKind::Aes128Gcm;
        let key = vec![3u8; 16];
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let mut c = Ss2022Stream::new(
            client,
            kind,
            vec![key.clone()],
            &Target::parse("1.2.3.4:80").unwrap(),
        );
        c.flush().await.unwrap();
        let mut salt = [0u8; 16];
        server.read_exact(&mut salt).await.unwrap();
        let aead = Aead::new(kind, &session_subkey(&key, &salt));
        let mut nonce = CounterNonce::new(12);
        let mut fixed = [0u8; 11 + TAG_LEN];
        server.read_exact(&mut fixed).await.unwrap();
        aead.open(&nonce.advance(), &[], &mut fixed).unwrap();
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        assert!(var_len > 7 + 2, "padding expected, got {var_len}");

        let rsalt = [0x11u8; 16];
        let raead = Aead::new(kind, &session_subkey(&key, &rsalt));
        let mut resp = BytesMut::from(&rsalt[..]);
        let mut head = vec![TYPE_SERVER];
        head.extend_from_slice(&now().to_be_bytes());
        head.extend_from_slice(&[0u8; 16]); // not our salt
        head.extend_from_slice(&0u16.to_be_bytes());
        raead.seal_append(&CounterNonce::new(12).advance(), &[], &head, &mut resp);
        server.write_all(&resp).await.unwrap();
        assert!(c.read_u8().await.is_err());
    }

    struct Loopback;
    #[async_trait]
    impl PacketConn for Loopback {
        async fn send_to(&self, buf: &[u8], _dst: &Target) -> io::Result<usize> {
            Ok(buf.len())
        }
        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, Target)> {
            std::future::pending().await
        }
    }

    /// Builds a server packet independently and checks the client decodes it.
    #[test]
    fn udp_packets_both_ciphers() {
        let server = Target::parse("9.9.9.9:8388").unwrap();
        let dst = Target::parse("1.1.1.1:53").unwrap();
        for kind in [
            AeadKind::Aes128Gcm,
            AeadKind::Aes256Gcm,
            AeadKind::ChaCha20Poly1305,
        ] {
            let key = vec![5u8; kind.key_len()];
            let conn = Ss2022PacketConn::new(
                std::sync::Arc::new(Loopback),
                server.clone(),
                kind,
                vec![key.clone()],
            );

            // Client packet, decoded like a server.
            let mut pkt = conn.encode(b"query", &dst);
            let body: Vec<u8> = if kind == AeadKind::ChaCha20Poly1305 {
                let (nonce, rest) = pkt.split_at_mut(24);
                let n = Aead::new(AeadKind::XChaCha20Poly1305, &key)
                    .open(nonce, &[], rest)
                    .unwrap();
                assert_eq!(&rest[..8], &conn.session_id);
                rest[16..n].to_vec()
            } else {
                let (head, rest) = pkt.split_at_mut(16);
                let header: &mut [u8; 16] = head.try_into().unwrap();
                aes_block(&key, header, false);
                assert_eq!(&header[..8], &conn.session_id);
                assert_eq!(&header[8..], &0u64.to_be_bytes());
                let aead = Aead::new(kind, &session_subkey(&key, &header[..8]));
                let n = aead.open(&header[4..16], &[], rest).unwrap();
                rest[..n].to_vec()
            };
            assert_eq!(body[0], TYPE_CLIENT);
            let (t, used) = parse_socks_addr(&body[11..]).unwrap().unwrap();
            assert_eq!(t, dst);
            assert_eq!(&body[11 + used..], b"query");

            // Server packet with padding.
            let ssid = [7u8; 8];
            let mut sbody = vec![TYPE_SERVER];
            sbody.extend_from_slice(&now().to_be_bytes());
            sbody.extend_from_slice(&conn.session_id);
            sbody.extend_from_slice(&3u16.to_be_bytes());
            sbody.extend_from_slice(&[0, 0, 0]);
            put_socks_addr(&mut sbody, &dst);
            sbody.extend_from_slice(b"answer");
            let mut header = [0u8; 16];
            header[..8].copy_from_slice(&ssid);
            header[8..].copy_from_slice(&1u64.to_be_bytes());
            let mut spkt = BytesMut::new();
            if kind == AeadKind::ChaCha20Poly1305 {
                let nonce = [9u8; 24];
                spkt.put_slice(&nonce);
                let mut plain = header.to_vec();
                plain.extend_from_slice(&sbody);
                Aead::new(AeadKind::XChaCha20Poly1305, &key).seal_append(
                    &nonce,
                    &[],
                    &plain,
                    &mut spkt,
                );
            } else {
                let mut sealed = header;
                aes_block(&key, &mut sealed, true);
                spkt.put_slice(&sealed);
                Aead::new(kind, &session_subkey(&key, &ssid)).seal_append(
                    &header[4..16],
                    &[],
                    &sbody,
                    &mut spkt,
                );
            }
            let (from, range) = conn.decode(&mut spkt).unwrap();
            assert_eq!(from, dst);
            assert_eq!(&spkt[range], b"answer");
        }
    }
}
