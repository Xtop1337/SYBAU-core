//! XTLS Vision (`flow: xtls-rprx-vision`), client side.
//!
//! Vision hides the length pattern of the first packets of a connection
//! behind padding and, once it has seen that the proxied traffic is TLS
//! 1.3, stops encrypting it a second time: the inner TLS records then
//! travel directly on the TCP connection ("direct copy").
//!
//! Padded block: `[uuid(16), first block only] cmd(1) content_len(2) padding_len(2) content padding`
//! with `cmd`: 0 = more padded blocks follow, 1 = padding ends,
//! 2 = padding ends and the sender switches to direct copy.
//!
//! The logic follows `proxy/proxy.go` of Xray-core so that both ends make
//! the same decisions about the same bytes.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::Rng;
use sybau_common::{poll_drain, proto_err, RawSwitch, Target};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::vless;

const CMD_CONTINUE: u8 = 0;
const CMD_END: u8 = 1;
const CMD_DIRECT: u8 = 2;

/// Xray's buffer size; a padded block never exceeds it.
const BUF_SIZE: usize = 8192;
/// uuid (16) + command header (5).
const BLOCK_OVERHEAD: usize = 21;
const MAX_CONTENT: usize = BUF_SIZE - BLOCK_OVERHEAD;
/// How many packets of each connection are inspected for TLS.
const PACKETS_TO_FILTER: i32 = 8;

const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// What both directions learn about the proxied traffic.
struct TrafficState {
    packets_to_filter: i32,
    enable_xtls: bool,
    is_tls12_or_above: bool,
    is_tls: bool,
    cipher: u16,
    remaining_server_hello: i32,
}

impl TrafficState {
    fn new() -> Self {
        Self {
            packets_to_filter: PACKETS_TO_FILTER,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
        }
    }

    /// `XtlsFilterTls`: looks at one buffer of proxied data.
    fn filter(&mut self, b: &[u8]) {
        if self.packets_to_filter <= 0 {
            return;
        }
        self.packets_to_filter -= 1;
        if b.len() >= 6 {
            if b[..3] == TLS_SERVER_HANDSHAKE_START && b[5] == 0x02 {
                self.remaining_server_hello = ((b[3] as i32) << 8 | b[4] as i32) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if b.len() >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = b[43] as usize;
                    if let Some(suite) = b.get(43 + session_id_len + 1..43 + session_id_len + 3) {
                        self.cipher = u16::from_be_bytes([suite[0], suite[1]]);
                    }
                }
            } else if b[..2] == TLS_CLIENT_HANDSHAKE_START && b[5] == 0x01 {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(b.len());
            self.remaining_server_hello -= b.len() as i32;
            if b[..end].windows(6).any(|w| w == TLS13_SUPPORTED_VERSIONS) {
                // TLS 1.3 inside: direct copy is safe for every AEAD
                // suite except the truncated-tag CCM one.
                let known = (0x1301..=0x1305).contains(&self.cipher);
                if known && self.cipher != TLS_AES_128_CCM_8_SHA256 {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                // TLS 1.2: keep the outer encryption.
                self.packets_to_filter = 0;
            }
        }
    }
}

/// `IsCompleteRecord`: is `b` a whole number of TLS application data records?
fn is_complete_record(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        if b.len() - i < 5 || b[i..i + 3] != TLS_APPLICATION_DATA_START {
            return false;
        }
        let len = u16::from_be_bytes([b[i + 3], b[i + 4]]) as usize;
        if len == 0 || b.len() - i - 5 < len {
            return false;
        }
        i += 5 + len;
    }
    !b.is_empty()
}

/// `XtlsPadding`: appends one padded block to `out`.
fn put_block(
    out: &mut BytesMut,
    uuid: &mut Option<[u8; 16]>,
    command: u8,
    content: &[u8],
    long_padding: bool,
) {
    let content_len = content.len();
    let mut rng = rand::thread_rng();
    let mut padding_len = if content_len < 900 && long_padding {
        rng.gen_range(0..500) + 900 - content_len
    } else {
        rng.gen_range(0..256)
    };
    padding_len = padding_len.min(BUF_SIZE - BLOCK_OVERHEAD - content_len);
    if let Some(id) = uuid.take() {
        out.put_slice(&id);
    }
    out.put_u8(command);
    out.put_u16(content_len as u16);
    out.put_u16(padding_len as u16);
    out.put_slice(content);
    let start = out.len();
    out.resize(start + padding_len, 0);
    rng.fill(&mut out[start..]);
}

/// Reader side of the padding (`XtlsUnpadding`).
struct Unpadder {
    uuid: [u8; 16],
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
}

impl Unpadder {
    fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
        }
    }

    /// Extracts the content of `data`. Data that does not start a padded
    /// block while none is in progress passes through unchanged.
    fn unpad(&mut self, mut data: BytesMut) -> BytesMut {
        if self.remaining_command == -1
            && self.remaining_content == -1
            && self.remaining_padding == -1
        {
            if data.len() >= BLOCK_OVERHEAD && data[..16] == self.uuid {
                data.advance(16);
                self.remaining_command = 5;
            } else {
                return data;
            }
        }
        let mut out = BytesMut::with_capacity(data.len());
        while !data.is_empty() {
            if self.remaining_command > 0 {
                let byte = data.get_u8();
                match self.remaining_command {
                    5 => self.current_command = byte,
                    4 => self.remaining_content = (byte as i32) << 8,
                    3 => self.remaining_content |= byte as i32,
                    2 => self.remaining_padding = (byte as i32) << 8,
                    _ => self.remaining_padding |= byte as i32,
                }
                self.remaining_command -= 1;
            } else if self.remaining_content > 0 {
                let n = (self.remaining_content as usize).min(data.len());
                out.put_slice(&data.split_to(n));
                self.remaining_content -= n as i32;
            } else {
                let n = (self.remaining_padding as usize).min(data.len());
                data.advance(n);
                self.remaining_padding -= n as i32;
            }
            if self.remaining_command <= 0
                && self.remaining_content <= 0
                && self.remaining_padding <= 0
            {
                if self.current_command == CMD_CONTINUE {
                    self.remaining_command = 5;
                } else {
                    self.remaining_command = -1;
                    self.remaining_content = -1;
                    self.remaining_padding = -1;
                    // Whatever follows the last block is already plain.
                    out.put_slice(&data);
                    break;
                }
            }
        }
        out
    }
}

#[derive(Clone, Copy)]
enum ResponseHeader {
    Version,
    AddonsLen,
    Addons(u8),
    Done,
}

/// VLESS client stream with the Vision flow. `S` is the outer TLS (or
/// REALITY) stream; it must be able to switch to raw mode.
pub struct VisionStream<S> {
    inner: S,
    state: TrafficState,
    /// VLESS request header, sent with the first block.
    header: Option<Bytes>,
    write_uuid: Option<[u8; 16]>,
    /// Outgoing data is still wrapped in padded blocks.
    is_padding: bool,
    /// Switch the outer stream to raw writes once `wbuf` is flushed.
    direct_write_pending: bool,
    wbuf: BytesMut,
    response: ResponseHeader,
    unpadder: Unpadder,
    within_padding: bool,
    direct_read: bool,
    plain: BytesMut,
    scratch: Vec<u8>,
}

impl<S> VisionStream<S> {
    /// `command` is `vless::CMD_TCP` or `vless::CMD_MUX` (XUDP).
    pub fn new(inner: S, uuid: &[u8; 16], command: u8, target: &Target) -> Self {
        Self {
            inner,
            state: TrafficState::new(),
            header: Some(
                vless::encode_request(uuid, Some(vless::FLOW_VISION), command, target).freeze(),
            ),
            write_uuid: Some(*uuid),
            is_padding: true,
            direct_write_pending: false,
            wbuf: BytesMut::new(),
            response: ResponseHeader::Version,
            unpadder: Unpadder::new(*uuid),
            within_padding: true,
            direct_read: false,
            plain: BytesMut::new(),
            scratch: vec![0u8; 16 * 1024],
        }
    }

    fn put_header(&mut self) -> bool {
        match self.header.take() {
            Some(header) => {
                self.wbuf.put_slice(&header);
                true
            }
            None => false,
        }
    }

    /// `VisionWriter.WriteMultiBuffer` for one write of the application.
    fn encode_padded(&mut self, buf: &[u8]) {
        for packet in buf.chunks(BUF_SIZE) {
            self.state.filter(packet);
        }
        let complete = is_complete_record(buf);
        let chunks: Vec<&[u8]> = buf.chunks(MAX_CONTENT).collect();
        let last = chunks.len() - 1;
        let mut long_padding = self.state.is_tls;
        let mut index = 0;
        while index < chunks.len() {
            let chunk = chunks[index];
            index += 1;
            if self.state.is_tls
                && chunk.len() >= 6
                && chunk[..3] == TLS_APPLICATION_DATA_START
                && complete
            {
                if self.state.enable_xtls {
                    self.direct_write_pending = true;
                }
                let command = match (index - 1 == last, self.state.enable_xtls) {
                    (false, _) => CMD_CONTINUE,
                    (true, false) => CMD_END,
                    (true, true) => CMD_DIRECT,
                };
                put_block(&mut self.wbuf, &mut self.write_uuid, command, chunk, true);
                self.is_padding = false;
                long_padding = false;
                continue;
            }
            if !self.state.is_tls12_or_above && self.state.packets_to_filter <= 1 {
                // Not TLS: padding ends here and the rest goes unframed.
                self.is_padding = false;
                put_block(
                    &mut self.wbuf,
                    &mut self.write_uuid,
                    CMD_END,
                    chunk,
                    long_padding,
                );
                break;
            }
            let command = match (
                index - 1 == last && !self.is_padding,
                self.state.enable_xtls,
            ) {
                (false, _) => CMD_CONTINUE,
                (true, false) => CMD_END,
                (true, true) => CMD_DIRECT,
            };
            put_block(
                &mut self.wbuf,
                &mut self.write_uuid,
                command,
                chunk,
                long_padding,
            );
        }
        for chunk in &chunks[index..] {
            self.wbuf.put_slice(chunk);
        }
    }

    /// `VisionReader.ReadMultiBuffer` for one buffer from the outer stream.
    /// Returns `true` when the reader must switch to direct copy.
    fn decode(&mut self, data: BytesMut) -> bool {
        let mut data = data;
        let mut switch = false;
        if self.within_padding || self.state.packets_to_filter > 0 {
            data = self.unpadder.unpad(data);
            let u = &self.unpadder;
            if u.remaining_content > 0
                || u.remaining_padding > 0
                || u.current_command == CMD_CONTINUE
            {
                self.within_padding = true;
            } else if u.current_command == CMD_END {
                self.within_padding = false;
            } else if u.current_command == CMD_DIRECT {
                self.within_padding = false;
                switch = true;
            }
        }
        if self.state.packets_to_filter > 0 && !data.is_empty() {
            self.state.filter(&data);
        }
        if self.plain.is_empty() {
            self.plain = data;
        } else {
            self.plain.unsplit(data);
        }
        switch
    }
}

impl<S: AsyncRead + AsyncWrite + RawSwitch + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(poll_drain(&mut this.inner, cx, &mut this.wbuf))?;
        if this.direct_write_pending {
            this.direct_write_pending = false;
            this.inner.switch_write_to_raw();
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.is_padding {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        let n = buf.len().min(4 * BUF_SIZE);
        this.put_header();
        this.encode_padded(&buf[..n]);
        let _ = poll_drain(&mut this.inner, cx, &mut this.wbuf)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.put_header() {
            // Nothing to send yet: an empty block with long padding hides
            // the length of the VLESS header.
            put_block(
                &mut this.wbuf,
                &mut this.write_uuid,
                CMD_CONTINUE,
                &[],
                true,
            );
        }
        ready!(poll_drain(&mut this.inner, cx, &mut this.wbuf))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + RawSwitch + Unpin> AsyncRead for VisionStream<S> {
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
            if this.direct_read || (!this.within_padding && this.state.packets_to_filter <= 0) {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let mut scratch = ReadBuf::new(&mut this.scratch);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut scratch))?;
            let mut data = scratch.filled();
            if data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            // VLESS response header: version, addons length, addons.
            while !data.is_empty() && !matches!(this.response, ResponseHeader::Done) {
                let byte = data[0];
                data = &data[1..];
                this.response = match this.response {
                    ResponseHeader::Version if byte != vless::VERSION => {
                        return Poll::Ready(Err(proto_err(format!(
                            "unexpected VLESS response version {byte}"
                        ))));
                    }
                    ResponseHeader::Version => ResponseHeader::AddonsLen,
                    ResponseHeader::AddonsLen if byte == 0 => ResponseHeader::Done,
                    ResponseHeader::AddonsLen => ResponseHeader::Addons(byte),
                    ResponseHeader::Addons(1) => ResponseHeader::Done,
                    ResponseHeader::Addons(left) => ResponseHeader::Addons(left - 1),
                    ResponseHeader::Done => ResponseHeader::Done,
                };
            }
            if data.is_empty() {
                continue;
            }
            let data = BytesMut::from(data);
            if this.decode(data) {
                // The server writes raw from now on; what the outer stream
                // has buffered beyond this point is already inner data.
                this.direct_read = true;
                this.inner.switch_read_to_raw();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    const UUID: [u8; 16] = [0x42; 16];

    /// Outer stream stand-in: records every switch and tags raw writes.
    struct Outer {
        io: DuplexStream,
        raw_read: bool,
        raw_write: bool,
    }

    impl RawSwitch for Outer {
        fn switch_read_to_raw(&mut self) {
            self.raw_read = true;
        }
        fn switch_write_to_raw(&mut self) {
            self.raw_write = true;
        }
    }

    impl AsyncRead for Outer {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Outer {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.io).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    fn pair() -> (VisionStream<Outer>, DuplexStream) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let target = Target::parse("example.com:443").unwrap();
        (
            VisionStream::new(
                Outer {
                    io: a,
                    raw_read: false,
                    raw_write: false,
                },
                &UUID,
                vless::CMD_TCP,
                &target,
            ),
            b,
        )
    }

    /// Reads one padded block the way the server would.
    async fn read_block(peer: &mut DuplexStream, expect_uuid: bool) -> (u8, Vec<u8>, usize) {
        if expect_uuid {
            let mut id = [0u8; 16];
            peer.read_exact(&mut id).await.unwrap();
            assert_eq!(id, UUID);
        }
        let mut head = [0u8; 5];
        peer.read_exact(&mut head).await.unwrap();
        let content_len = u16::from_be_bytes([head[1], head[2]]) as usize;
        let padding_len = u16::from_be_bytes([head[3], head[4]]) as usize;
        let mut content = vec![0u8; content_len];
        peer.read_exact(&mut content).await.unwrap();
        let mut padding = vec![0u8; padding_len];
        peer.read_exact(&mut padding).await.unwrap();
        (head[0], content, padding_len)
    }

    fn header_len() -> usize {
        vless::encode_request(
            &UUID,
            Some(vless::FLOW_VISION),
            vless::CMD_TCP,
            &Target::parse("example.com:443").unwrap(),
        )
        .len()
    }

    fn client_hello() -> Vec<u8> {
        let mut v = vec![0x16, 0x03, 0x01, 0x00, 0xc8, 0x01];
        v.resize(205, 0xaa);
        v
    }

    /// TLS 1.3 ServerHello record with `cipher`, as the filter expects it.
    fn server_hello(cipher: u16, tls13: bool) -> Vec<u8> {
        let mut body = vec![0x02, 0, 0, 0, 0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.push(32);
        body.extend_from_slice(&[0x22; 32]);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        let extensions: &[u8] = if tls13 {
            &[
                0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x02, 0x00, 0x1d,
            ]
        } else {
            &[0xff, 0x01, 0x00, 0x01, 0x00]
        };
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        let len = body.len() - 4;
        body[1..4].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    fn app_data(len: usize) -> Vec<u8> {
        let mut v = vec![0x17, 0x03, 0x03];
        v.extend_from_slice(&(len as u16).to_be_bytes());
        v.resize(5 + len, 0x5a);
        v
    }

    /// Server side framing of one block.
    fn server_block(first: bool, command: u8, content: &[u8], padding: usize) -> Vec<u8> {
        let mut out = Vec::new();
        if first {
            out.extend_from_slice(&UUID);
        }
        out.push(command);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&(padding as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding, 0);
        out
    }

    #[test]
    fn complete_record_detection() {
        assert!(is_complete_record(&app_data(10)));
        assert!(is_complete_record(&[app_data(10), app_data(300)].concat()));
        assert!(!is_complete_record(&app_data(10)[..12]));
        assert!(!is_complete_record(
            &[app_data(10), vec![0x17, 0x03]].concat()
        ));
        assert!(!is_complete_record(&client_hello()));
        assert!(!is_complete_record(&[]));
    }

    #[test]
    fn filter_recognises_tls13_and_tls12() {
        let mut s = TrafficState::new();
        s.filter(&client_hello());
        assert!(s.is_tls && !s.is_tls12_or_above && !s.enable_xtls);
        s.filter(&server_hello(0x1301, true));
        assert!(s.is_tls12_or_above && s.enable_xtls && s.packets_to_filter == 0);

        let mut s = TrafficState::new();
        s.filter(&server_hello(0xc02f, false));
        assert!(s.is_tls12_or_above && !s.enable_xtls && s.packets_to_filter == 0);

        // TLS 1.3 with the CCM-8 suite keeps the outer encryption.
        let mut s = TrafficState::new();
        s.filter(&server_hello(0x1305, true));
        assert!(!s.enable_xtls);

        let mut s = TrafficState::new();
        for _ in 0..8 {
            s.filter(b"GET / HTTP/1.1\r\n\r\n");
        }
        assert!(!s.is_tls && s.packets_to_filter == 0);
    }

    #[test]
    fn unpadder_handles_split_blocks_and_trailing_plain_data() {
        let mut wire = server_block(true, CMD_CONTINUE, b"hello ", 30);
        wire.extend(server_block(false, CMD_END, b"world", 7));
        wire.extend_from_slice(b"!plain");
        // First piece must contain the uuid and the command header.
        for cut in [21, 30, 60, wire.len() - 3, wire.len()] {
            let mut u = Unpadder::new(UUID);
            let mut out = u.unpad(BytesMut::from(&wire[..cut]));
            if cut < wire.len() {
                out.unsplit(u.unpad(BytesMut::from(&wire[cut..])));
            }
            assert_eq!(&out[..], b"hello world!plain", "cut {cut}");
            assert_eq!(u.current_command, CMD_END);
        }
        // Data that is not a padded block passes through.
        let mut u = Unpadder::new(UUID);
        assert_eq!(
            &u.unpad(BytesMut::from(&b"just bytes, longer than 21 of them"[..]))[..],
            b"just bytes, longer than 21 of them"
        );
    }

    #[tokio::test]
    async fn tls13_traffic_switches_both_directions_to_direct_copy() {
        let (mut client, mut server) = pair();

        // Uplink: ClientHello goes out padded, with the VLESS header.
        client.write_all(&client_hello()).await.unwrap();
        client.flush().await.unwrap();
        let mut header = vec![0u8; header_len()];
        server.read_exact(&mut header).await.unwrap();
        assert_eq!(header[17], 18, "flow addon length");
        let (cmd, content, padding) = read_block(&mut server, true).await;
        assert_eq!((cmd, content), (CMD_CONTINUE, client_hello()));
        assert!(
            205 + padding >= 900,
            "TLS packets get long padding, got {padding}"
        );

        // Downlink: response header, ServerHello (padded), then a Direct block.
        let mut down = vec![0u8, 0];
        down.extend(server_block(
            true,
            CMD_CONTINUE,
            &server_hello(0x1302, true),
            100,
        ));
        down.extend(server_block(false, CMD_DIRECT, &app_data(50), 20));
        down.extend_from_slice(b"RAW AFTER DIRECT");
        server.write_all(&down).await.unwrap();
        let expect = [
            server_hello(0x1302, true),
            app_data(50),
            b"RAW AFTER DIRECT".to_vec(),
        ]
        .concat();
        let mut got = vec![0u8; expect.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expect);
        assert!(client.inner.raw_read, "reader switched to direct copy");
        assert!(!client.inner.raw_write, "writer has not switched yet");

        // Uplink application data: last padded block says Direct, the
        // write after it goes out raw.
        client.write_all(&app_data(100)).await.unwrap();
        client.flush().await.unwrap();
        let (cmd, content, _) = read_block(&mut server, false).await;
        assert_eq!((cmd, content), (CMD_DIRECT, app_data(100)));
        assert!(!client.inner.raw_write);
        client.write_all(&app_data(64)).await.unwrap();
        client.flush().await.unwrap();
        assert!(client.inner.raw_write);
        let mut raw = vec![0u8; 69];
        server.read_exact(&mut raw).await.unwrap();
        assert_eq!(raw, app_data(64));
    }

    #[tokio::test]
    async fn tls12_traffic_ends_padding_without_direct_copy() {
        let (mut client, mut server) = pair();
        client.write_all(&client_hello()).await.unwrap();
        client.flush().await.unwrap();
        let mut header = vec![0u8; header_len()];
        server.read_exact(&mut header).await.unwrap();
        read_block(&mut server, true).await;

        let mut down = vec![0u8, 0];
        down.extend(server_block(
            true,
            CMD_CONTINUE,
            &server_hello(0xc02f, false),
            10,
        ));
        server.write_all(&down).await.unwrap();
        let mut got = vec![0u8; server_hello(0xc02f, false).len()];
        client.read_exact(&mut got).await.unwrap();

        client.write_all(&app_data(40)).await.unwrap();
        client.flush().await.unwrap();
        let (cmd, content, _) = read_block(&mut server, false).await;
        assert_eq!((cmd, content), (CMD_END, app_data(40)));
        client.write_all(b"unframed").await.unwrap();
        client.flush().await.unwrap();
        let mut plain = [0u8; 8];
        server.read_exact(&mut plain).await.unwrap();
        assert_eq!(&plain, b"unframed");
        assert!(!client.inner.raw_write && !client.inner.raw_read);
    }

    #[tokio::test]
    async fn non_tls_traffic_stops_padding_after_the_filter_window() {
        let (mut client, mut server) = pair();
        let mut commands = Vec::new();
        for i in 0..8 {
            client
                .write_all(format!("packet-{i}").as_bytes())
                .await
                .unwrap();
            client.flush().await.unwrap();
            if i == 0 {
                let mut header = vec![0u8; header_len()];
                server.read_exact(&mut header).await.unwrap();
            }
            if commands.last() == Some(&CMD_END) {
                let mut plain = [0u8; 8];
                server.read_exact(&mut plain).await.unwrap();
                assert_eq!(plain, format!("packet-{i}").as_bytes());
            } else {
                let (cmd, content, padding) = read_block(&mut server, i == 0).await;
                assert_eq!(content, format!("packet-{i}").as_bytes());
                assert!(padding < 256, "non-TLS packets get short padding");
                commands.push(cmd);
            }
        }
        // Seven padded packets, the seventh ends the padding.
        assert_eq!(commands, vec![0, 0, 0, 0, 0, 0, 1]);
    }

    #[tokio::test]
    async fn flush_without_data_sends_header_and_empty_long_block() {
        let (mut client, mut server) = pair();
        client.flush().await.unwrap();
        let mut header = vec![0u8; header_len()];
        server.read_exact(&mut header).await.unwrap();
        let (cmd, content, padding) = read_block(&mut server, true).await;
        assert_eq!((cmd, content.len()), (CMD_CONTINUE, 0));
        assert!(padding >= 900);

        // A large write is split into blocks that fit Xray's buffers.
        let big = vec![7u8; 20_000];
        client.write_all(&big).await.unwrap();
        client.flush().await.unwrap();
        let mut got = Vec::new();
        while got.len() < big.len() {
            let (_, content, padding) = read_block(&mut server, false).await;
            assert!(content.len() + padding + BLOCK_OVERHEAD <= BUF_SIZE);
            got.extend(content);
        }
        assert_eq!(got, big);
    }

    #[tokio::test]
    async fn bad_response_version_is_an_error() {
        let (mut client, mut server) = pair();
        server.write_all(&[7, 0, 1, 2, 3]).await.unwrap();
        assert!(client.read_u8().await.is_err());
    }
}
