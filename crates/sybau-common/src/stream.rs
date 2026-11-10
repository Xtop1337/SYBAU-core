use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::Target;

/// Any bidirectional byte stream the core can relay.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncStream for T {}

pub type BoxStream = Box<dyn AsyncStream>;

/// Datagram endpoint that can talk to arbitrary destinations.
///
/// On the outbound side `send_to` sends towards the remote `dst` and
/// `recv_from` yields the remote peer. On the inbound side `recv_from`
/// yields the destination requested by the client and `send_to` delivers a
/// reply that appears to come from `dst`.
#[async_trait]
pub trait PacketConn: Send + Sync + 'static {
    async fn send_to(&self, buf: &[u8], dst: &Target) -> io::Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)>;
}

pub type ArcPacketConn = Arc<dyn PacketConn>;

/// Stream that first replays bytes already consumed from `inner`
/// (protocol detection, sniffing) and then continues with `inner`.
pub struct PrefixedStream<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: impl Into<Bytes>, inner: S) -> Self {
        Self {
            prefix: prefix.into(),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
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

/// Writes as much of `buf` as `inner` accepts; `Ready(Ok(()))` once `buf`
/// is empty. The building block of every framing stream in the core.
pub fn poll_drain<S: AsyncWrite + Unpin>(
    inner: &mut S,
    cx: &mut Context<'_>,
    buf: &mut bytes::BytesMut,
) -> Poll<io::Result<()>> {
    while !buf.is_empty() {
        let n = match Pin::new(&mut *inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        if n == 0 {
            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
        }
        buf.advance(n);
    }
    Poll::Ready(Ok(()))
}

/// Stream that sends `header` in front of the first payload, in the same
/// write, so that the handshake and the first data share one packet.
/// If the application flushes before writing, the header goes out alone.
///
/// All outbound protocol streams follow this convention: nothing is sent
/// until the first write or flush.
pub struct HeaderStream<S> {
    inner: S,
    header: Option<Bytes>,
    wbuf: bytes::BytesMut,
}

impl<S> HeaderStream<S> {
    pub fn new(header: impl Into<Bytes>, inner: S) -> Self {
        Self {
            inner,
            header: Some(header.into()),
            wbuf: bytes::BytesMut::new(),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HeaderStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HeaderStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if let Some(header) = this.header.take() {
            this.wbuf.extend_from_slice(&header);
            this.wbuf.extend_from_slice(buf);
            // The payload is now owned by `wbuf`; report it as written and
            // let later calls finish the drain.
            let _ = poll_drain(&mut this.inner, cx, &mut this.wbuf)?;
            return Poll::Ready(Ok(buf.len()));
        }
        if !this.wbuf.is_empty() {
            match poll_drain(&mut this.inner, cx, &mut this.wbuf) {
                Poll::Ready(r) => r?,
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(header) = this.header.take() {
            this.wbuf.extend_from_slice(&header);
        }
        match poll_drain(&mut this.inner, cx, &mut this.wbuf) {
            Poll::Ready(r) => r?,
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(r) => r?,
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Streams that can stop encrypting in one or both directions.
///
/// XTLS Vision uses this once it has seen that the proxied traffic is
/// itself TLS 1.3: from then on the inner records travel on the bare TCP
/// connection instead of being encrypted a second time.
pub trait RawSwitch {
    /// Everything read from now on, including bytes already received but
    /// not yet decrypted, is delivered as it arrived.
    fn switch_read_to_raw(&mut self);
    /// Everything written from now on goes to the transport unchanged,
    /// after the data already encrypted has been sent.
    fn switch_write_to_raw(&mut self);
}
