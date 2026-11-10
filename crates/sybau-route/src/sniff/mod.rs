//! Protocol detection from the first bytes of a flow.
//!
//! Sniffing gives the router a domain for connections made to bare IP
//! addresses (TLS SNI, HTTP Host, QUIC SNI) and lets rules single out
//! BitTorrent.

pub mod quic;
pub mod stream;

pub use quic::QuicSniffer;
pub use stream::sniff_stream;

/// What a sniffer learned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sniffed {
    /// `tls`, `http`, `quic`, `bittorrent` or `dns`.
    pub protocol: &'static str,
    /// Domain the client asked for, lower case.
    pub host: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffResult {
    Found(Sniffed),
    /// Looks like a known protocol but the data is incomplete.
    NeedMore,
    /// Nothing recognised.
    Unknown,
}

/// Extracts the SNI from a TLS ClientHello handshake message
/// (`type(1) len(3) body`), without the record layer.
/// `Err(())` = not a ClientHello, `Ok(None)` = incomplete or no SNI yet.
pub(crate) fn client_hello_sni(msg: &[u8]) -> Result<Option<Option<String>>, ()> {
    // Returns Ok(Some(sni)) when the hello is complete enough to answer.
    struct Cur<'a>(&'a [u8]);
    impl<'a> Cur<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.0.len() < n {
                return None;
            }
            let (a, b) = self.0.split_at(n);
            self.0 = b;
            Some(a)
        }
        fn u8(&mut self) -> Option<usize> {
            self.take(1).map(|b| b[0] as usize)
        }
        fn u16(&mut self) -> Option<usize> {
            self.take(2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        }
    }
    if msg.is_empty() {
        return Ok(None);
    }
    if msg[0] != 1 {
        return Err(());
    }
    if msg.len() < 4 {
        return Ok(None);
    }
    let declared = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
    if !(38..=65536).contains(&declared) {
        return Err(());
    }
    let complete = msg.len() >= 4 + declared;
    let mut c = Cur(&msg[4..(4 + declared).min(msg.len())]);
    // Everything before the extensions; running out of bytes here just
    // means the hello is not complete yet.
    macro_rules! need {
        ($e:expr) => {
            match $e {
                Some(v) => v,
                None => return if complete { Err(()) } else { Ok(None) },
            }
        };
    }
    let version = need!(c.take(2));
    if version[0] != 3 {
        return Err(());
    }
    need!(c.take(32));
    let n = need!(c.u8());
    need!(c.take(n));
    let n = need!(c.u16());
    need!(c.take(n));
    let n = need!(c.u8());
    need!(c.take(n));
    if c.0.is_empty() && complete {
        return Ok(Some(None));
    }
    let ext_len = need!(c.u16());
    let mut ext = Cur(&c.0[..ext_len.min(c.0.len())]);
    while let Some(id) = ext.u16() {
        let Some(len) = ext.u16() else { break };
        let Some(data) = ext.take(len) else { break };
        if id != 0 {
            continue;
        }
        let mut d = Cur(data);
        let list_len = d.u16().ok_or(())?;
        let mut list = Cur(d.take(list_len).ok_or(())?);
        while let Some(kind) = list.u8() {
            let len = list.u16().ok_or(())?;
            let name = list.take(len).ok_or(())?;
            if kind == 0 {
                let name = std::str::from_utf8(name).map_err(|_| ())?;
                if name.is_empty() || name.bytes().any(|b| b <= b' ' || b == 0x7f) {
                    return Err(());
                }
                return Ok(Some(Some(name.to_ascii_lowercase())));
            }
        }
        return Ok(Some(None));
    }
    if complete {
        Ok(Some(None))
    } else {
        Ok(None)
    }
}
