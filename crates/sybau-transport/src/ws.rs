//! WebSocket client transport (RFC 6455) with early data.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use base64::Engine as _;
use bytes::{Buf, BufMut, BytesMut};
use sha1::{Digest, Sha1};
use sybau_common::{poll_drain, proto_err};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::io::poll_read_buf;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HEAD: usize = 16 * 1024;
const MAX_FRAME: usize = 16 * 1024 * 1024;

const OP_CONTINUATION: u8 = 0;
const OP_TEXT: u8 = 1;
const OP_BINARY: u8 = 2;
const OP_CLOSE: u8 = 8;
const OP_PING: u8 = 9;
const OP_PONG: u8 = 10;

#[derive(Clone, Debug)]
pub struct WsOptions {
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    /// Header that carries early data; `None` appends it to the path.
    pub early_data_header: Option<String>,
}

pub fn accept_key(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// Builds the upgrade request. Early data is base64url-encoded without padding.
pub fn build_request(opts: &WsOptions, key: &str, early: &[u8]) -> String {
    let early_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(early);
    let mut path = if opts.path.starts_with('/') {
        opts.path.clone()
    } else {
        format!("/{}", opts.path)
    };
    if !early.is_empty() && opts.early_data_header.is_none() {
        path.push_str(&early_b64);
    }
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n",
        opts.host
    );
    let mut has_ua = false;
    for (name, value) in &opts.headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        has_ua |= name.eq_ignore_ascii_case("user-agent");
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    if !has_ua {
        req.push_str("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n");
    }
    if let (false, Some(header)) = (early.is_empty(), &opts.early_data_header) {
        req.push_str(&format!("{header}: {early_b64}\r\n"));
    }
    req.push_str("\r\n");
    req
}

/// Reads an HTTP response head; returns it and any bytes that followed.
pub(crate) async fn read_response_head<S: AsyncRead + Unpin>(
    io: &mut S,
) -> io::Result<(Vec<u8>, BytesMut)> {
    let mut buf = BytesMut::with_capacity(1024);
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(pos + 4);
            return Ok((buf.to_vec(), rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(proto_err("HTTP response head too large"));
        }
        if io.read_buf(&mut buf).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed during the HTTP handshake",
            ));
        }
    }
}

/// Checks that `head` is `101 Switching Protocols`; returns its headers.
pub(crate) fn check_switching(head: &[u8]) -> io::Result<Vec<(String, String)>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(proto_err("malformed HTTP response from server")),
    }
    if resp.code != Some(101) {
        return Err(proto_err(format!(
            "server refused the upgrade: HTTP {} {}",
            resp.code.unwrap_or(0),
            resp.reason.unwrap_or("")
        )));
    }
    Ok(resp
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                String::from_utf8_lossy(h.value).trim().to_string(),
            )
        })
        .collect())
}

/// Performs the client handshake, carrying `early` inside the request.
pub async fn connect<S>(mut io: S, opts: &WsOptions, early: &[u8]) -> io::Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 16]>());
    io.write_all(build_request(opts, &key, early).as_bytes())
        .await?;
    io.flush().await?;
    let (head, rest) = read_response_head(&mut io).await?;
    let headers = check_switching(&head)?;
    let accept = headers
        .iter()
        .find(|(n, _)| n == "sec-websocket-accept")
        .map(|(_, v)| v.as_str());
    if accept != Some(accept_key(&key).as_str()) {
        return Err(proto_err("server sent a wrong Sec-WebSocket-Accept"));
    }
    Ok(WsStream::new(io, rest, true))
}

enum ReadState {
    Header,
    Payload {
        opcode: u8,
        len: usize,
        mask: Option<[u8; 4]>,
    },
    Closed,
}

/// Byte stream over binary WebSocket frames.
pub struct WsStream<S> {
    inner: S,
    /// Clients mask their frames, servers do not.
    mask_outgoing: bool,
    state: ReadState,
    rbuf: BytesMut,
    plain: BytesMut,
    wbuf: BytesMut,
    close_sent: bool,
}

fn apply_mask(data: &mut [u8], key: [u8; 4]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i & 3];
    }
}

impl<S> WsStream<S> {
    pub fn new(inner: S, already_read: BytesMut, mask_outgoing: bool) -> Self {
        Self {
            inner,
            mask_outgoing,
            state: ReadState::Header,
            rbuf: already_read,
            plain: BytesMut::new(),
            wbuf: BytesMut::new(),
            close_sent: false,
        }
    }

    fn put_frame(&mut self, opcode: u8, payload: &[u8]) {
        let out = &mut self.wbuf;
        out.put_u8(0x80 | opcode);
        let mask_bit = if self.mask_outgoing { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => out.put_u8(mask_bit | n as u8),
            n if n <= 0xffff => {
                out.put_u8(mask_bit | 126);
                out.put_u16(n as u16);
            }
            n => {
                out.put_u8(mask_bit | 127);
                out.put_u64(n as u64);
            }
        }
        if self.mask_outgoing {
            let key: [u8; 4] = rand::random();
            out.put_slice(&key);
            let start = out.len();
            out.put_slice(payload);
            apply_mask(&mut out[start..], key);
        } else {
            out.put_slice(payload);
        }
    }

    /// Parses a frame header from `rbuf` if it is complete.
    fn parse_header(&mut self) -> io::Result<bool> {
        let b = &self.rbuf;
        if b.len() < 2 {
            return Ok(false);
        }
        let opcode = b[0] & 0x0f;
        let masked = b[1] & 0x80 != 0;
        let (len, mut used) = match b[1] & 0x7f {
            126 => {
                if b.len() < 4 {
                    return Ok(false);
                }
                (u16::from_be_bytes([b[2], b[3]]) as u64, 4)
            }
            127 => {
                if b.len() < 10 {
                    return Ok(false);
                }
                (
                    u64::from_be_bytes(b[2..10].try_into().expect("8 bytes")),
                    10,
                )
            }
            n => (n as u64, 2),
        };
        if len > MAX_FRAME as u64 {
            return Err(proto_err("WebSocket frame too large"));
        }
        let mask = if masked {
            if b.len() < used + 4 {
                return Ok(false);
            }
            let key = [b[used], b[used + 1], b[used + 2], b[used + 3]];
            used += 4;
            Some(key)
        } else {
            None
        };
        self.rbuf.advance(used);
        self.state = ReadState::Payload {
            opcode,
            len: len as usize,
            mask,
        };
        Ok(true)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
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
                ReadState::Closed => return Poll::Ready(Ok(())),
                ReadState::Header => {
                    if this.parse_header()? {
                        continue;
                    }
                }
                ReadState::Payload { opcode, len, mask } if this.rbuf.len() >= len => {
                    let mut payload = this.rbuf.split_to(len);
                    if let Some(key) = mask {
                        apply_mask(&mut payload, key);
                    }
                    this.state = ReadState::Header;
                    match opcode {
                        OP_CONTINUATION | OP_TEXT | OP_BINARY => this.plain = payload,
                        OP_PING => {
                            this.put_frame(OP_PONG, &payload);
                            // Best effort now; the next write or flush finishes it.
                            let _ = poll_drain(&mut this.inner, cx, &mut this.wbuf)?;
                        }
                        OP_PONG => {}
                        OP_CLOSE => this.state = ReadState::Closed,
                        other => {
                            return Poll::Ready(Err(proto_err(format!(
                                "unknown WebSocket opcode {other}"
                            ))))
                        }
                    }
                    continue;
                }
                ReadState::Payload { .. } => {}
            }
            this.rbuf.reserve(4096);
            if ready!(poll_read_buf(Pin::new(&mut this.inner), cx, &mut this.rbuf))? == 0 {
                this.state = ReadState::Closed;
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(poll_drain(&mut this.inner, cx, &mut this.wbuf))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.put_frame(OP_BINARY, buf);
        let _ = poll_drain(&mut this.inner, cx, &mut this.wbuf)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(poll_drain(&mut this.inner, cx, &mut this.wbuf))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.close_sent {
            this.close_sent = true;
            this.put_frame(OP_CLOSE, &1000u16.to_be_bytes());
        }
        ready!(poll_drain(&mut this.inner, cx, &mut this.wbuf))?;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(header: Option<&str>) -> WsOptions {
        WsOptions {
            path: "/ws".into(),
            host: "example.com".into(),
            headers: vec![("X-Test".into(), "1".into())],
            early_data_header: header.map(str::to_string),
        }
    }

    #[test]
    fn rfc6455_accept_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn request_carries_early_data() {
        let r = build_request(&opts(Some("Sec-WebSocket-Protocol")), "KEY", &[0xfb, 0xff]);
        assert!(r.starts_with("GET /ws HTTP/1.1\r\nHost: example.com\r\n"));
        assert!(r.contains("Sec-WebSocket-Protocol: -_8\r\n"));
        assert!(r.contains("X-Test: 1\r\n") && r.ends_with("\r\n\r\n"));
        let r = build_request(&opts(None), "KEY", &[0xfb, 0xff]);
        assert!(r.starts_with("GET /ws-_8 HTTP/1.1\r\n"));
        let r = build_request(&opts(Some("Sec-WebSocket-Protocol")), "KEY", &[]);
        assert!(!r.contains("Sec-WebSocket-Protocol"));
    }

    /// Client and server ends of the framing talk to each other, with a
    /// ping in the middle and frames of all three length encodings.
    #[tokio::test]
    async fn frames_roundtrip_with_ping_and_close() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let mut client = WsStream::new(a, BytesMut::new(), true);
        let mut server = WsStream::new(b, BytesMut::new(), false);
        for size in [0usize, 5, 125, 126, 65535, 65536, 200_000] {
            let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
            client.write_all(&data).await.unwrap();
            client.flush().await.unwrap();
            let mut got = vec![0u8; size];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got, data, "size {size}");
        }
        server.put_frame(OP_PING, b"p");
        server.write_all(b"after ping").await.unwrap();
        server.flush().await.unwrap();
        let mut got = [0u8; 10];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"after ping");
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();
        // The pong is consumed silently, then the close frame ends the stream.
        assert_eq!(server.read(&mut got).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn handshake_validates_status_and_accept() {
        async fn run(response: &'static str) -> io::Result<()> {
            let (a, mut b) = tokio::io::duplex(4096);
            let server = tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = b.read(&mut buf).await;
                let _ = b.write_all(response.as_bytes()).await;
                b
            });
            let r = connect(a, &opts(None), &[]).await.map(|_| ());
            drop(server.await);
            r
        }
        assert!(run("HTTP/1.1 403 Forbidden\r\n\r\n")
            .await
            .unwrap_err()
            .to_string()
            .contains("403"));
        assert!(
            run("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: bogus\r\n\r\n")
                .await
                .is_err()
        );
    }
}
