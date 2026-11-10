//! Sniffers for TCP-like streams: TLS, HTTP and BitTorrent.

use super::{client_hello_sni, SniffResult, Sniffed};

const BITTORRENT_HANDSHAKE: &[u8] = b"\x13BitTorrent protocol";
const HTTP_METHODS: [&str; 9] = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH", "TRACE",
];

/// Looks at the first bytes a client sent.
pub fn sniff_stream(data: &[u8]) -> SniffResult {
    if data.is_empty() {
        return SniffResult::NeedMore;
    }
    match sniff_tls(data) {
        SniffResult::Unknown => {}
        other => return other,
    }
    match sniff_bittorrent(data) {
        SniffResult::Unknown => {}
        other => return other,
    }
    sniff_http(data)
}

/// TLS ClientHello, possibly split over several handshake records.
fn sniff_tls(data: &[u8]) -> SniffResult {
    let mut handshake = Vec::new();
    let mut rest = data;
    let mut records = 0;
    loop {
        if rest.len() < 5 {
            if records == 0 {
                // Decide on the bytes we do have.
                let plausible = rest[0] == 22
                    && rest.get(1).is_none_or(|v| *v == 3)
                    && rest.get(2).is_none_or(|v| *v <= 4);
                return if plausible {
                    SniffResult::NeedMore
                } else {
                    SniffResult::Unknown
                };
            }
            break;
        }
        if rest[0] != 22 || rest[1] != 3 || rest[2] > 4 {
            if records == 0 {
                return SniffResult::Unknown;
            }
            break;
        }
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if len == 0 || len > 16384 + 256 {
            return SniffResult::Unknown;
        }
        let end = (5 + len).min(rest.len());
        handshake.extend_from_slice(&rest[5..end]);
        records += 1;
        if end < 5 + len {
            break;
        }
        rest = &rest[end..];
        if rest.is_empty() {
            break;
        }
    }
    match client_hello_sni(&handshake) {
        Ok(Some(host)) => SniffResult::Found(Sniffed {
            protocol: "tls",
            host,
        }),
        Ok(None) => SniffResult::NeedMore,
        Err(()) => SniffResult::Unknown,
    }
}

fn sniff_bittorrent(data: &[u8]) -> SniffResult {
    let n = data.len().min(BITTORRENT_HANDSHAKE.len());
    if data[..n] != BITTORRENT_HANDSHAKE[..n] {
        return SniffResult::Unknown;
    }
    if n < BITTORRENT_HANDSHAKE.len() {
        return SniffResult::NeedMore;
    }
    SniffResult::Found(Sniffed {
        protocol: "bittorrent",
        host: None,
    })
}

fn sniff_http(data: &[u8]) -> SniffResult {
    let head_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 2);
    let head = &data[..head_end.unwrap_or(data.len())];
    let Ok(text) = std::str::from_utf8(head) else {
        // Binary data before the end of the head: not HTTP.
        return SniffResult::Unknown;
    };
    let first_line = text.split("\r\n").next().unwrap_or("");
    let method_ok = match first_line.split_once(' ') {
        Some((method, _)) => HTTP_METHODS.contains(&method),
        // The method itself may still be arriving.
        None => HTTP_METHODS.iter().any(|m| m.starts_with(first_line)) && !text.contains("\r\n"),
    };
    if !method_ok {
        return SniffResult::Unknown;
    }
    if text.contains("\r\n") && !first_line.contains(" HTTP/1.") {
        return SniffResult::Unknown;
    }
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("host") {
            continue;
        }
        let value = value.trim();
        // Strip the port, keeping bracketed IPv6 literals intact.
        let host = match value.rfind(':') {
            Some(i)
                if !value.ends_with(']') && value[i + 1..].bytes().all(|b| b.is_ascii_digit()) =>
            {
                &value[..i]
            }
            _ => value,
        };
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if host.is_empty() || host.bytes().any(|b| b <= b' ' || b == b'/') {
            return SniffResult::Unknown;
        }
        return SniffResult::Found(Sniffed {
            protocol: "http",
            host: Some(host),
        });
    }
    if head_end.is_some() {
        return SniffResult::Found(Sniffed {
            protocol: "http",
            host: None,
        });
    }
    if data.len() > 8192 {
        return SniffResult::Unknown;
    }
    SniffResult::NeedMore
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A ClientHello handshake message with the given SNI.
    pub(crate) fn client_hello(sni: Option<&str>, padding: usize) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7u8; 32]);
        body.push(32);
        body.extend_from_slice(&[9u8; 32]);
        body.extend_from_slice(&[0, 4, 0x13, 0x01, 0x13, 0x02, 1, 0]);
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0, 10, 0, 4, 0, 2, 0, 29]);
        if let Some(name) = sni {
            let n = name.len() as u16;
            ext.extend_from_slice(&[0, 0]);
            ext.extend_from_slice(&(n + 5).to_be_bytes());
            ext.extend_from_slice(&(n + 3).to_be_bytes());
            ext.push(0);
            ext.extend_from_slice(&n.to_be_bytes());
            ext.extend_from_slice(name.as_bytes());
        }
        if padding > 0 {
            ext.extend_from_slice(&[0, 21]);
            ext.extend_from_slice(&(padding as u16).to_be_bytes());
            ext.resize(ext.len() + padding, 0);
        }
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut msg = vec![1];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    fn records(msg: &[u8], size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in msg.chunks(size) {
            out.extend_from_slice(&[22, 3, 1]);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    fn found(protocol: &'static str, host: Option<&str>) -> SniffResult {
        SniffResult::Found(Sniffed {
            protocol,
            host: host.map(str::to_string),
        })
    }

    #[test]
    fn tls_sni_whole_fragmented_and_truncated() {
        let hello = client_hello(Some("Example.COM"), 0);
        let wire = records(&hello, 16384);
        assert_eq!(sniff_stream(&wire), found("tls", Some("example.com")));
        // Split into many small TLS records (ClientHello fragmentation).
        assert_eq!(
            sniff_stream(&records(&hello, 17)),
            found("tls", Some("example.com"))
        );
        // Every proper prefix either needs more data or already has the SNI.
        for cut in 1..wire.len() {
            match sniff_stream(&wire[..cut]) {
                SniffResult::NeedMore => {}
                r if r == found("tls", Some("example.com")) => {}
                other => panic!("cut {cut}: {other:?}"),
            }
        }
        assert_eq!(
            sniff_stream(&records(&client_hello(None, 0), 16384)),
            found("tls", None)
        );
        // SNI after a large extension is still found.
        assert_eq!(
            sniff_stream(&records(&client_hello(Some("a.b"), 0), 4096)),
            found("tls", Some("a.b"))
        );
    }

    #[test]
    fn not_tls() {
        assert_eq!(
            sniff_stream(&[22, 3, 9, 0, 5, 1, 2, 3, 4, 5]),
            SniffResult::Unknown
        );
        assert_eq!(
            sniff_stream(&[23, 3, 3, 0, 5, 1, 2, 3, 4, 5]),
            SniffResult::Unknown
        );
        // A ServerHello is not a ClientHello.
        assert_eq!(
            sniff_stream(&records(&[2, 0, 0, 40, 3, 3], 100)),
            SniffResult::Unknown
        );
        assert_eq!(sniff_stream(&[0x05, 0x01, 0x00]), SniffResult::Unknown);
        assert_eq!(
            sniff_stream(b"SSH-2.0-OpenSSH_9.6\r\n"),
            SniffResult::Unknown
        );
    }

    #[test]
    fn http_host() {
        assert_eq!(
            sniff_stream(b"GET / HTTP/1.1\r\nHost: Example.com:8080\r\nAccept: */*\r\n\r\n"),
            found("http", Some("example.com"))
        );
        assert_eq!(
            sniff_stream(b"POST /x HTTP/1.1\r\nUser-Agent: a\r\nhost:  [2001:db8::1]:80\r\n\r\n"),
            found("http", Some("2001:db8::1"))
        );
        assert_eq!(sniff_stream(b"GET / HTTP/1.0\r\n\r\n"), found("http", None));
        assert_eq!(sniff_stream(b"GE"), SniffResult::NeedMore);
        assert_eq!(
            sniff_stream(b"GET /index.html HTTP/1.1\r\nUser-Agent: curl\r\n"),
            SniffResult::NeedMore
        );
        assert_eq!(sniff_stream(b"GETX / HTTP/1.1\r\n"), SniffResult::Unknown);
        assert_eq!(
            sniff_stream(b"HELO mail.example.com\r\n"),
            SniffResult::Unknown
        );
        assert_eq!(
            sniff_stream(b"GET /a b c\r\nHost: x\r\n\r\n"),
            SniffResult::Unknown
        );
    }

    #[test]
    fn bittorrent_handshake() {
        let mut hs = BITTORRENT_HANDSHAKE.to_vec();
        hs.extend_from_slice(&[0u8; 48]);
        assert_eq!(sniff_stream(&hs), found("bittorrent", None));
        assert_eq!(sniff_stream(&hs[..10]), SniffResult::NeedMore);
        assert_eq!(
            sniff_stream(b"\x13BitTorrent protocoX"),
            SniffResult::Unknown
        );
    }
}
