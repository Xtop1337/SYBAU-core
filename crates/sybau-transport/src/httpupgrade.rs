//! HTTPUpgrade transport: an HTTP/1.1 `Upgrade: websocket` exchange and
//! then the raw stream, without WebSocket framing.

use std::io;

use sybau_common::{proto_err, PrefixedStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::ws::{check_switching, read_response_head};

#[derive(Clone, Debug)]
pub struct HttpUpgradeOptions {
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
}

pub fn build_request(opts: &HttpUpgradeOptions) -> String {
    let path = if opts.path.starts_with('/') {
        opts.path.clone()
    } else {
        format!("/{}", opts.path)
    };
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
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
    req.push_str("\r\n");
    req
}

pub async fn connect<S>(mut io: S, opts: &HttpUpgradeOptions) -> io::Result<PrefixedStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    io.write_all(build_request(opts).as_bytes()).await?;
    io.flush().await?;
    let (head, rest) = read_response_head(&mut io).await?;
    let headers = check_switching(&head)?;
    let upgraded = headers
        .iter()
        .any(|(n, v)| n == "upgrade" && v.eq_ignore_ascii_case("websocket"));
    if !upgraded {
        return Err(proto_err("server did not confirm the websocket upgrade"));
    }
    Ok(PrefixedStream::new(rest.freeze(), io))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn upgrade_then_raw_bytes() {
        let (a, mut b) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = b.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            b.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nearly")
                .await
                .unwrap();
            (req, b)
        });
        let opts = HttpUpgradeOptions {
            path: "up".into(),
            host: "h.example".into(),
            headers: vec![],
        };
        let mut s = connect(a, &opts).await.unwrap();
        let (req, _b) = server.await.unwrap();
        assert!(req.starts_with(
            "GET /up HTTP/1.1\r\nHost: h.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        ));
        let mut got = [0u8; 5];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"early");
    }
}
