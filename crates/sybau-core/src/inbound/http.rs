//! HTTP proxy: `CONNECT` tunnels and plain-HTTP forwarding.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use sybau_common::{proto_err, Network, PrefixedStream, Session, Target};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::local::LocalProxy;
use crate::dispatch::Dispatcher;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEAD: usize = 64 * 1024;

/// What to do with a parsed proxy request.
#[derive(Debug, PartialEq)]
pub enum Action {
    /// `CONNECT`: answer 200 and tunnel.
    Tunnel { target: Target },
    /// Plain HTTP: forward `head` (rewritten to origin form) to `target`.
    Forward { target: Target, head: Vec<u8> },
}

/// Credentials from `Proxy-Authorization: Basic ...`, if present and well-formed.
pub fn basic_credentials(value: &[u8]) -> Option<(String, String)> {
    let value = std::str::from_utf8(value).ok()?.trim();
    let (scheme, b64) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (u, p) = text.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

/// Parses a complete request head (ending in `\r\n\r\n`).
/// Returns the action and the proxy credentials the client sent.
pub fn parse_request(head: &[u8]) -> io::Result<(Action, Option<(String, String)>)> {
    let mut headers = [httparse::EMPTY_HEADER; 96];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err(proto_err("incomplete HTTP request head")),
        Err(e) => return Err(proto_err(format!("bad HTTP request: {e}"))),
    }
    let method = req.method.unwrap_or_default();
    let path = req.path.unwrap_or_default();
    let version = req.version.unwrap_or(1);
    let creds = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("proxy-authorization"))
        .and_then(|h| basic_credentials(h.value));

    if method.eq_ignore_ascii_case("CONNECT") {
        let target = Target::parse(path)
            .or_else(|| {
                (!path.is_empty() && !path.contains('/')).then(|| Target::from_host(path, 443))
            })
            .ok_or_else(|| proto_err("bad CONNECT authority"))?;
        return Ok((Action::Tunnel { target }, creds));
    }

    let rest = path
        .get(..7)
        .filter(|p| p.eq_ignore_ascii_case("http://"))
        .map(|_| &path[7..])
        .ok_or_else(|| proto_err("not a proxy request (absolute http:// URI expected)"))?;
    let (authority, origin_path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let target = Target::parse(authority)
        .or_else(|| (!authority.is_empty()).then(|| Target::from_host(authority, 80)))
        .ok_or_else(|| proto_err("bad request host"))?;

    let is_upgrade = req
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("upgrade"));
    let mut out = Vec::with_capacity(head.len());
    out.extend_from_slice(format!("{method} {origin_path} HTTP/1.{version}\r\n").as_bytes());
    let mut has_host = false;
    for h in req.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        if name.starts_with("proxy-")
            || (name == "connection" && !is_upgrade)
            || name == "keep-alive"
        {
            continue;
        }
        has_host |= name == "host";
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(h.value);
        out.extend_from_slice(b"\r\n");
    }
    if !has_host {
        out.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
    }
    if !is_upgrade {
        // One request per upstream connection: the next request on this
        // client connection may be for a different host.
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok((Action::Forward { target, head: out }, creds))
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

async fn respond<S: AsyncWrite + Unpin>(s: &mut S, status: &str, extra: &str) -> io::Result<()> {
    let msg = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n");
    s.write_all(msg.as_bytes()).await?;
    s.flush().await
}

pub async fn handle<S>(
    proxy: &LocalProxy,
    mut s: S,
    peer: SocketAddr,
    dispatcher: &Dispatcher,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = Vec::with_capacity(2048);
    let read_head = async {
        loop {
            if let Some(end) = find_head_end(&buf) {
                return Ok::<usize, io::Error>(end);
            }
            if buf.len() > MAX_HEAD {
                return Err(proto_err("HTTP request head too large"));
            }
            if s.read_buf(&mut buf).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    };
    let head_len = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_head)
        .await
        .map_err(|_| proto_err("HTTP request timed out"))??;

    let (action, creds) = match parse_request(&buf[..head_len]) {
        Ok(v) => v,
        Err(e) => {
            respond(&mut s, "400 Bad Request", "").await?;
            return Err(e);
        }
    };
    let mut user = None;
    if proxy.auth_required() {
        match creds {
            Some((u, p)) if proxy.check_user(&u, &p) => user = Some(Arc::<str>::from(u)),
            _ => {
                respond(
                    &mut s,
                    "407 Proxy Authentication Required",
                    "Proxy-Authenticate: Basic realm=\"SYBAU\"\r\n",
                )
                .await?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "proxy authentication failed",
                ));
            }
        }
    }
    let leftover = buf.split_off(head_len);
    match action {
        Action::Tunnel { target } => {
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            let mut sess = Session::new(Network::Tcp, proxy.tag.clone(), Some(peer), target);
            sess.sniff = proxy.sniff();
            sess.user = user;
            dispatcher
                .dispatch_stream(sess, Box::new(PrefixedStream::new(leftover, s)))
                .await;
        }
        Action::Forward { target, mut head } => {
            head.extend_from_slice(&leftover);
            let mut sess = Session::new(Network::Tcp, proxy.tag.clone(), Some(peer), target);
            sess.sniff = proxy.sniff();
            sess.user = user;
            dispatcher
                .dispatch_stream(sess, Box::new(PrefixedStream::new(head, s)))
                .await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request() {
        let (a, c) =
            parse_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                .unwrap();
        assert_eq!(
            a,
            Action::Tunnel {
                target: Target::parse("example.com:443").unwrap()
            }
        );
        assert!(c.is_none());
    }

    #[test]
    fn plain_request_is_rewritten() {
        let (a, c) = parse_request(
            b"GET http://user@Example.com:8080/a?b=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic dTpw\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert_eq!(c, Some(("u".into(), "p".into())));
        let Action::Forward { target, head } = a else {
            panic!("expected forward")
        };
        assert_eq!(target.to_string(), "example.com:8080");
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("GET /a?b=1 HTTP/1.1\r\n"));
        assert!(!head.to_ascii_lowercase().contains("proxy-"));
        assert!(head.contains("Connection: close\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn query_without_path_and_default_port() {
        let (a, _) = parse_request(b"GET http://example.com?x=1 HTTP/1.0\r\n\r\n").unwrap();
        let Action::Forward { target, head } = a else {
            panic!("expected forward")
        };
        assert_eq!(target.to_string(), "example.com:80");
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("GET /?x=1 HTTP/1.0\r\n"));
        assert!(head.contains("Host: example.com\r\n"));
    }

    #[test]
    fn upgrade_keeps_connection_header() {
        let (a, _) = parse_request(
            b"GET http://h/ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .unwrap();
        let Action::Forward { head, .. } = a else {
            panic!("expected forward")
        };
        let head = String::from_utf8(head).unwrap();
        assert!(head.contains("Connection: Upgrade\r\n"));
        assert!(!head.contains("Connection: close"));
    }

    #[test]
    fn origin_form_is_not_a_proxy_request() {
        assert!(parse_request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_err());
    }
}
