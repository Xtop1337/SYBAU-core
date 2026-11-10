//! Xray "TCP with HTTP header" disguise: the client sends a fake HTTP
//! request head before its data and discards the fake response head.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use sybau_common::{proto_err, HeaderStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_RESPONSE_HEAD: usize = 8 * 1024;
const END: &[u8; 4] = b"\r\n\r\n";

#[derive(Clone, Debug)]
pub struct HttpObfsOptions {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
}

pub fn build_request(opts: &HttpObfsOptions) -> String {
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        opts.method, opts.path, opts.host
    );
    let mut seen = std::collections::HashSet::new();
    for (name, value) in &opts.headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        seen.insert(name.to_ascii_lowercase());
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    for (name, value) in [
        ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Connection", "keep-alive"),
        ("Pragma", "no-cache"),
    ] {
        if !seen.contains(&name.to_ascii_lowercase()) {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    req.push_str("\r\n");
    req
}

pub struct HttpObfsStream<S> {
    inner: HeaderStream<S>,
    /// How many bytes of `\r\n\r\n` have been matched; 4 = head stripped.
    matched: usize,
    skipped: usize,
}

impl<S> HttpObfsStream<S> {
    pub fn new(inner: S, opts: &HttpObfsOptions) -> Self {
        Self {
            inner: HeaderStream::new(build_request(opts).into_bytes(), inner),
            matched: 0,
            skipped: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HttpObfsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.matched == END.len() {
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
            while skip < got && this.matched < END.len() {
                let byte = buf.filled()[before + skip];
                this.matched = if byte == END[this.matched] {
                    this.matched + 1
                } else if byte == b'\r' {
                    1
                } else {
                    0
                };
                skip += 1;
            }
            this.skipped += skip;
            if this.matched < END.len() && this.skipped > MAX_RESPONSE_HEAD {
                return Poll::Ready(Err(proto_err("HTTP disguise: response head too large")));
            }
            let rest = got - skip;
            buf.filled_mut()
                .copy_within(before + skip..before + got, before);
            buf.set_filled(before + rest);
            if rest > 0 {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpObfsStream<S> {
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

    #[tokio::test]
    async fn request_head_is_prepended_and_response_head_stripped() {
        let (a, mut b) = tokio::io::duplex(4096);
        let opts = HttpObfsOptions {
            method: "GET".into(),
            path: "/".into(),
            host: "www.example.com".into(),
            headers: vec![],
        };
        let mut s = HttpObfsStream::new(a, &opts);
        s.write_all(b"DATA").await.unwrap();
        s.flush().await.unwrap();
        let expect = build_request(&opts);
        let mut got = vec![0u8; expect.len() + 4];
        b.read_exact(&mut got).await.unwrap();
        assert!(got.starts_with(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n"));
        assert!(got.ends_with(b"\r\n\r\nDATA"));

        // Response head arrives in awkward pieces, including a split terminator.
        for piece in [
            &b"HTTP/1.1 200 OK\r\nA: b\r"[..],
            &b"\nC: d\r\n\r"[..],
            &b"\nPAY"[..],
            &b"LOAD"[..],
        ] {
            b.write_all(piece).await.unwrap();
            b.flush().await.unwrap();
            tokio::task::yield_now().await;
        }
        let mut got = [0u8; 7];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"PAYLOAD");
    }
}
