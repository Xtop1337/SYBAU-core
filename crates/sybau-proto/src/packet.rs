//! Datagrams carried inside a byte stream (UDP over VLESS, Trojan, ...).

use std::io;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use sybau_common::{BoxStream, PacketConn, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

/// How one protocol frames datagrams inside its stream.
pub trait PacketCodec: Send + Sync + 'static {
    /// Appends one framed datagram for `dst` to `out`.
    fn encode(&self, payload: &[u8], dst: &Target, out: &mut BytesMut) -> io::Result<()>;
    /// Extracts one datagram from the front of `buf`;
    /// `Ok(None)` when more bytes are needed.
    fn decode(&self, buf: &mut BytesMut) -> io::Result<Option<(Bytes, Target)>>;
}

/// [`PacketConn`] over a stream using a [`PacketCodec`].
pub struct FramedPacketConn<C> {
    codec: C,
    reader: Mutex<(ReadHalf<BoxStream>, BytesMut)>,
    writer: Mutex<(WriteHalf<BoxStream>, BytesMut)>,
}

impl<C: PacketCodec> FramedPacketConn<C> {
    pub fn new(stream: BoxStream, codec: C) -> Self {
        let (r, w) = tokio::io::split(stream);
        Self {
            codec,
            reader: Mutex::new((r, BytesMut::with_capacity(4096))),
            writer: Mutex::new((w, BytesMut::with_capacity(2048))),
        }
    }
}

#[async_trait]
impl<C: PacketCodec> PacketConn for FramedPacketConn<C> {
    async fn send_to(&self, buf: &[u8], dst: &Target) -> io::Result<usize> {
        let mut guard = self.writer.lock().await;
        let (writer, scratch) = &mut *guard;
        scratch.clear();
        self.codec.encode(buf, dst, scratch)?;
        writer.write_all(scratch).await?;
        writer.flush().await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let mut guard = self.reader.lock().await;
        let (reader, pending) = &mut *guard;
        loop {
            if let Some((payload, from)) = self.codec.decode(pending)? {
                let n = payload.len().min(buf.len());
                buf[..n].copy_from_slice(&payload[..n]);
                return Ok((n, from));
            }
            if reader.read_buf(pending).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }
}

/// `u16 length | payload`, every datagram for one fixed destination.
/// Used by VLESS UDP.
pub struct LengthPrefixed {
    pub peer: Target,
}

impl PacketCodec for LengthPrefixed {
    fn encode(&self, payload: &[u8], _dst: &Target, out: &mut BytesMut) -> io::Result<()> {
        let len = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
        Ok(())
    }

    fn decode(&self, buf: &mut BytesMut) -> io::Result<Option<(Bytes, Target)>> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if buf.len() < 2 + len {
            return Ok(None);
        }
        let _ = buf.split_to(2);
        Ok(Some((buf.split_to(len).freeze(), self.peer.clone())))
    }
}

/// Datagrams over a stream that preserves message boundaries by itself
/// (one write = one message, one read = one message), e.g. VMess chunks.
/// Every datagram belongs to the single peer the stream was opened for.
pub struct MessagePacketConn {
    reader: Mutex<ReadHalf<BoxStream>>,
    writer: Mutex<WriteHalf<BoxStream>>,
    peer: Target,
}

impl MessagePacketConn {
    pub fn new(stream: BoxStream, peer: Target) -> Self {
        let (r, w) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(r),
            writer: Mutex::new(w),
            peer,
        }
    }
}

#[async_trait]
impl PacketConn for MessagePacketConn {
    async fn send_to(&self, buf: &[u8], _dst: &Target) -> io::Result<usize> {
        let mut writer = self.writer.lock().await;
        writer.write_all(buf).await?;
        writer.flush().await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let n = self.reader.lock().await.read(buf).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok((n, self.peer.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn length_prefixed_roundtrip_over_stream() {
        let (a, b) = tokio::io::duplex(64);
        let peer = Target::parse("1.1.1.1:53").unwrap();
        let left = FramedPacketConn::new(Box::new(a), LengthPrefixed { peer: peer.clone() });
        let right = FramedPacketConn::new(Box::new(b), LengthPrefixed { peer: peer.clone() });
        let big = vec![7u8; 500];
        let send = async {
            left.send_to(b"one", &peer).await.unwrap();
            left.send_to(&big, &peer).await.unwrap();
            left.send_to(b"", &peer).await.unwrap();
        };
        let recv = async {
            let mut buf = [0u8; 1024];
            let (n, from) = right.recv_from(&mut buf).await.unwrap();
            assert_eq!((&buf[..n], &from), (&b"one"[..], &peer));
            let (n, _) = right.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &big[..]);
            let (n, _) = right.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 0);
        };
        tokio::join!(send, recv);
    }
}
