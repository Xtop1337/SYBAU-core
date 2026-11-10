//! HTTP/2 based transports: gRPC ("gun") and plain HTTP/2 streams.
//! Many proxy streams share one HTTP/2 connection.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::client::{ResponseFuture, SendRequest};
use h2::{RecvStream, SendStream};
use sybau_common::{io_err, proto_err, BoxStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

pub type DialFuture = Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send>>;
pub type DialFn = Arc<dyn Fn() -> DialFuture + Send + Sync>;

const STREAM_WINDOW: u32 = 4 * 1024 * 1024;
const CONNECTION_WINDOW: u32 = 16 * 1024 * 1024;
/// Largest payload placed into one DATA frame / gRPC message.
const MAX_WRITE: usize = 16 * 1024;
/// gRPC prefix (5) + protobuf tag (1) + length varint (up to 5).
const GRPC_OVERHEAD: usize = 11;

fn h2_err(e: h2::Error) -> io::Error {
    if e.is_io() {
        e.into_io().expect("checked is_io")
    } else {
        io_err(io::ErrorKind::Other, format!("HTTP/2: {e}"))
    }
}

/// How payload is placed into DATA frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// Bytes as they are (HTTP/2 transport).
    Raw,
    /// `0x00 | u32 len | protobuf { bytes data = 1; }` (gRPC transport).
    Grpc,
}

/// One HTTP/2 connection shared by the streams of an outbound; replaced
/// transparently when it breaks.
pub struct H2Pool {
    dial: DialFn,
    conn: tokio::sync::Mutex<Option<SendRequest<Bytes>>>,
}

impl H2Pool {
    pub fn new(dial: DialFn) -> Self {
        Self {
            dial,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    async fn handshake(&self) -> io::Result<SendRequest<Bytes>> {
        let io = (self.dial)().await?;
        let (send_request, connection) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .enable_push(false)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(h2_err)?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!(target: "sybau::transport", "HTTP/2 connection closed: {e}");
            }
        });
        Ok(send_request)
    }

    /// Opens a new stream, reconnecting once if the cached connection is dead.
    pub async fn open(&self, request: http::Request<()>, framing: Framing) -> io::Result<H2Stream> {
        let mut guard = self.conn.lock().await;
        for attempt in 0..2 {
            let sender = match guard.take() {
                Some(s) => s,
                None => self.handshake().await?,
            };
            let fresh = attempt == 1;
            let mut sender = match sender.ready().await {
                Ok(s) => s,
                Err(e) if fresh => return Err(h2_err(e)),
                Err(_) => continue,
            };
            match sender.send_request(request.clone(), false) {
                Ok((response, send)) => {
                    *guard = Some(sender);
                    return Ok(H2Stream::new(response, send, framing));
                }
                Err(e) if fresh => return Err(h2_err(e)),
                Err(_) => continue,
            }
        }
        Err(io_err(
            io::ErrorKind::ConnectionAborted,
            "cannot open an HTTP/2 stream",
        ))
    }
}

enum Recv {
    Response(ResponseFuture),
    Body(RecvStream),
    Done,
}

/// One proxied stream inside an HTTP/2 connection.
pub struct H2Stream {
    send: SendStream<Bytes>,
    recv: Recv,
    framing: Framing,
    /// Undecoded gRPC bytes.
    pending: BytesMut,
    plain: BytesMut,
}

fn put_varint(out: &mut BytesMut, mut v: usize) {
    while v >= 0x80 {
        out.put_u8((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.put_u8(v as u8);
}

fn varint_len(mut v: usize) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Encodes one gRPC message holding `data`.
pub fn encode_grpc(data: &[u8]) -> Bytes {
    let message_len = 1 + varint_len(data.len()) + data.len();
    let mut out = BytesMut::with_capacity(5 + message_len);
    out.put_u8(0);
    out.put_u32(message_len as u32);
    out.put_u8(0x0a);
    put_varint(&mut out, data.len());
    out.put_slice(data);
    out.freeze()
}

/// Moves complete gRPC messages from `pending` into `plain`.
/// Accepts both `Hunk` and `MultiHunk` (repeated field 1).
pub fn decode_grpc(pending: &mut BytesMut, plain: &mut BytesMut) -> io::Result<()> {
    loop {
        if pending.len() < 5 {
            return Ok(());
        }
        if pending[0] != 0 {
            return Err(proto_err("compressed gRPC messages are not supported"));
        }
        let len = u32::from_be_bytes([pending[1], pending[2], pending[3], pending[4]]) as usize;
        if len > 64 * 1024 * 1024 {
            return Err(proto_err("gRPC message too large"));
        }
        if pending.len() < 5 + len {
            return Ok(());
        }
        pending.advance(5);
        let mut message = pending.split_to(len);
        while !message.is_empty() {
            if message.get_u8() != 0x0a {
                return Err(proto_err("unexpected field in gRPC message"));
            }
            let mut size = 0usize;
            let mut shift = 0;
            loop {
                if message.is_empty() || shift > 28 {
                    return Err(proto_err("malformed gRPC message"));
                }
                let b = message.get_u8();
                size |= ((b & 0x7f) as usize) << shift;
                if b & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            if size > message.len() {
                return Err(proto_err("malformed gRPC message"));
            }
            plain.extend_from_slice(&message.split_to(size));
        }
    }
}

impl H2Stream {
    fn new(response: ResponseFuture, send: SendStream<Bytes>, framing: Framing) -> Self {
        Self {
            send,
            recv: Recv::Response(response),
            framing,
            pending: BytesMut::new(),
            plain: BytesMut::new(),
        }
    }

    fn overhead(&self) -> usize {
        match self.framing {
            Framing::Raw => 0,
            Framing::Grpc => GRPC_OVERHEAD,
        }
    }
}

impl AsyncRead for H2Stream {
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
            match &mut this.recv {
                Recv::Done => return Poll::Ready(Ok(())),
                Recv::Response(fut) => {
                    let response = ready!(Pin::new(fut).poll(cx)).map_err(h2_err)?;
                    if response.status() != http::StatusCode::OK {
                        return Poll::Ready(Err(proto_err(format!(
                            "server answered HTTP {}",
                            response.status()
                        ))));
                    }
                    this.recv = Recv::Body(response.into_body());
                }
                Recv::Body(body) => match ready!(body.poll_data(cx)) {
                    Some(Ok(data)) => {
                        // Flow control credit is returned as soon as the
                        // data is ours; the relay applies back-pressure.
                        let _ = body.flow_control().release_capacity(data.len());
                        match this.framing {
                            Framing::Raw => this.plain.extend_from_slice(&data),
                            Framing::Grpc => {
                                this.pending.extend_from_slice(&data);
                                decode_grpc(&mut this.pending, &mut this.plain)?;
                            }
                        }
                    }
                    Some(Err(e)) => return Poll::Ready(Err(h2_err(e))),
                    None => this.recv = Recv::Done,
                },
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let overhead = this.overhead();
        let want = buf.len().min(MAX_WRITE);
        loop {
            let capacity = this.send.capacity();
            if capacity > overhead {
                let n = want.min(capacity - overhead);
                let frame = match this.framing {
                    Framing::Raw => Bytes::copy_from_slice(&buf[..n]),
                    Framing::Grpc => encode_grpc(&buf[..n]),
                };
                this.send.send_data(frame, false).map_err(h2_err)?;
                return Poll::Ready(Ok(n));
            }
            this.send.reserve_capacity(want + overhead);
            match ready!(this.send.poll_capacity(cx)) {
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Poll::Ready(Err(h2_err(e))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // DATA frames are flushed by the connection task.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Ending an already closed stream is not an error for the caller.
        let _ = self.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

/// Request path of the gRPC tunnel, following Xray's service name rules:
/// a plain name gives `/<name>/Tun` (or `TunMulti`), a name starting with
/// `/` is a custom path `/<service>/<tun>|<tun-multi>`.
pub fn grpc_path(service_name: &str, multi: bool) -> String {
    if !service_name.starts_with('/') {
        return format!(
            "/{}/{}",
            service_name,
            if multi { "TunMulti" } else { "Tun" }
        );
    }
    let last = service_name.rfind('/').unwrap_or(0).max(1);
    let service = &service_name[1..last];
    let ending = service_name.get(last + 1..).unwrap_or("");
    let mut names = ending.split('|');
    let tun = names.next().unwrap_or("");
    let stream = if multi {
        names.next().unwrap_or(tun)
    } else {
        tun
    };
    format!("/{service}/{stream}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn grpc_paths_follow_xray_rules() {
        assert_eq!(grpc_path("GunService", false), "/GunService/Tun");
        assert_eq!(grpc_path("GunService", true), "/GunService/TunMulti");
        assert_eq!(
            grpc_path("/my/sample/path1|path2", false),
            "/my/sample/path1"
        );
        assert_eq!(
            grpc_path("/my/sample/path1|path2", true),
            "/my/sample/path2"
        );
        assert_eq!(grpc_path("/my/sample/path", true), "/my/sample/path");
    }

    #[test]
    fn grpc_codec_roundtrip_and_multi_hunk() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_grpc(b"hello"));
        wire.extend_from_slice(&encode_grpc(&vec![7u8; 300]));
        // MultiHunk: two `data` entries in one message.
        wire.extend_from_slice(&[0, 0, 0, 0, 6, 0x0a, 1, b'a', 0x0a, 1, b'b']);
        let mut plain = BytesMut::new();
        let mut partial = BytesMut::new();
        for byte in wire.iter() {
            partial.put_u8(*byte);
            decode_grpc(&mut partial, &mut plain).unwrap();
        }
        assert!(partial.is_empty());
        assert_eq!(&plain[..5], b"hello");
        assert_eq!(plain.len(), 5 + 300 + 2);
        assert_eq!(&plain[305..], b"ab");
        assert!(decode_grpc(&mut BytesMut::from(&[1u8, 0, 0, 0, 0][..]), &mut plain).is_err());
        assert!(decode_grpc(
            &mut BytesMut::from(&[0u8, 0, 0, 0, 2, 0x12, 0][..]),
            &mut plain
        )
        .is_err());
    }

    /// Real HTTP/2 server (h2 crate) echoing gRPC messages; two streams
    /// share one connection and the pool reconnects after the server dies.
    #[tokio::test]
    async fn streams_share_a_connection_and_pool_reconnects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted2 = accepted.clone();
        // Wakes only the connections alive at the time of the call.
        let kill = Arc::new(tokio::sync::Notify::new());
        let kill_server = kill.clone();
        tokio::spawn(async move {
            loop {
                let (sock, _) = listener.accept().await.unwrap();
                accepted2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let kill = kill_server.clone();
                tokio::spawn(async move {
                    let mut conn = h2::server::handshake(sock).await.unwrap();
                    loop {
                        let next = tokio::select! {
                            n = conn.accept() => n,
                            _ = kill.notified() => return,
                        };
                        let Some(Ok((req, mut respond))) = next else {
                            return;
                        };
                        assert_eq!(req.uri().path(), "/Svc/Tun");
                        assert_eq!(req.headers()["content-type"], "application/grpc");
                        tokio::spawn(async move {
                            let Ok(mut send) =
                                respond.send_response(http::Response::new(()), false)
                            else {
                                return;
                            };
                            let mut body = req.into_body();
                            while let Some(Ok(chunk)) = body.data().await {
                                let _ = body.flow_control().release_capacity(chunk.len());
                                if send.send_data(chunk, false).is_err() {
                                    return;
                                }
                            }
                            let _ = send.send_data(Bytes::new(), true);
                        });
                    }
                });
            }
        });

        let dial: DialFn = Arc::new(move || {
            Box::pin(async move {
                Ok(Box::new(tokio::net::TcpStream::connect(addr).await?) as BoxStream)
            })
        });
        let pool = H2Pool::new(dial);
        let request = || {
            http::Request::builder()
                .method("POST")
                .uri("http://example.com/Svc/Tun")
                .header("content-type", "application/grpc")
                .body(())
                .unwrap()
        };
        let mut a = pool.open(request(), Framing::Grpc).await.unwrap();
        let mut b = pool.open(request(), Framing::Grpc).await.unwrap();
        let big = vec![0x61u8; 100_000];
        a.write_all(&big).await.unwrap();
        b.write_all(b"second stream").await.unwrap();
        let mut got = vec![0u8; big.len()];
        a.read_exact(&mut got).await.unwrap();
        assert_eq!(got, big);
        let mut got = [0u8; 13];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"second stream");
        a.shutdown().await.unwrap();
        assert_eq!(a.read(&mut got).await.unwrap(), 0);
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);

        kill.notify_waiters();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut c = pool.open(request(), Framing::Grpc).await.unwrap();
        c.write_all(b"again").await.unwrap();
        let mut got = [0u8; 5];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"again");
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
