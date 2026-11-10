//! TLS 1.3 record layer after the handshake.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, BytesMut};
use sybau_common::{poll_drain, proto_err, RawSwitch};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_read_buf;

use crate::keys::RecordKeys;

pub(crate) const TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const TYPE_ALERT: u8 = 21;
pub(crate) const TYPE_HANDSHAKE: u8 = 22;
pub(crate) const TYPE_APPLICATION_DATA: u8 = 23;

/// Largest plaintext of one record.
const MAX_PLAINTEXT: usize = 16384;
/// Largest protected record body a peer may send.
pub(crate) const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;

const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_KEY_UPDATE: u8 = 24;

pub(crate) fn alert_error(payload: &[u8]) -> io::Error {
    let description = payload.get(1).copied().unwrap_or(0);
    let name = match description {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        109 => "missing_extension",
        112 => "unrecognized_name",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown",
    };
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        format!("TLS alert from server: {name} ({description})"),
    )
}

/// An established TLS 1.3 connection.
pub struct TlsStream<S> {
    inner: S,
    read_keys: RecordKeys,
    write_keys: RecordKeys,
    /// Bytes received from the transport, not yet decrypted.
    rbuf: BytesMut,
    /// Decrypted application data not yet handed to the reader.
    plain: BytesMut,
    /// Post-handshake messages being reassembled.
    handshake: BytesMut,
    wbuf: BytesMut,
    eof: bool,
    raw_read: bool,
    raw_write: bool,
    close_sent: bool,
    alpn: Option<Vec<u8>>,
}

impl<S> TlsStream<S> {
    pub(crate) fn new(
        inner: S,
        read_keys: RecordKeys,
        write_keys: RecordKeys,
        rbuf: BytesMut,
        alpn: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner,
            read_keys,
            write_keys,
            rbuf,
            plain: BytesMut::new(),
            handshake: BytesMut::new(),
            wbuf: BytesMut::new(),
            eof: false,
            raw_read: false,
            raw_write: false,
            close_sent: false,
            alpn,
        }
    }

    /// Protocol selected by the server through ALPN.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Handles post-handshake messages collected in `self.handshake`.
    fn process_handshake(&mut self) -> io::Result<()> {
        while self.handshake.len() >= 4 {
            let len =
                u32::from_be_bytes([0, self.handshake[1], self.handshake[2], self.handshake[3]])
                    as usize;
            if len > 1 << 16 {
                return Err(proto_err("oversized post-handshake message"));
            }
            if self.handshake.len() < 4 + len {
                break;
            }
            let message = self.handshake.split_to(4 + len);
            match message[0] {
                // Session resumption is not used; tickets are dropped.
                HS_NEW_SESSION_TICKET => {}
                HS_KEY_UPDATE => {
                    if len != 1 || message[4] > 1 {
                        return Err(proto_err("malformed KeyUpdate"));
                    }
                    self.read_keys.update();
                    if message[4] == 1 {
                        // The peer asked us to update too: announce it
                        // under the old key, then switch.
                        self.write_keys.seal_record(
                            TYPE_HANDSHAKE,
                            &[HS_KEY_UPDATE, 0, 0, 1, 0],
                            &mut self.wbuf,
                        );
                        self.write_keys.update();
                    }
                }
                other => {
                    return Err(proto_err(format!(
                        "unexpected post-handshake message {other}"
                    )))
                }
            }
        }
        Ok(())
    }

    /// Decrypts the next complete record in `rbuf`, if any.
    /// Returns `false` when more bytes are needed.
    fn process_record(&mut self) -> io::Result<bool> {
        if self.rbuf.len() < 5 {
            return Ok(false);
        }
        let header: [u8; 5] = self.rbuf[..5].try_into().expect("5 bytes");
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len > MAX_CIPHERTEXT {
            return Err(proto_err("TLS record too large"));
        }
        if self.rbuf.len() < 5 + len {
            return Ok(false);
        }
        self.rbuf.advance(5);
        let mut body = self.rbuf.split_to(len);
        match header[0] {
            // Middlebox compatibility: meaningless in TLS 1.3.
            TYPE_CHANGE_CIPHER_SPEC => Ok(true),
            TYPE_APPLICATION_DATA => {
                let (content_type, n) = self.read_keys.open_record(&header, &mut body)?;
                body.truncate(n);
                match content_type {
                    TYPE_APPLICATION_DATA => {
                        if self.plain.is_empty() {
                            self.plain = body;
                        } else {
                            self.plain.unsplit(body);
                        }
                    }
                    TYPE_HANDSHAKE => {
                        self.handshake.extend_from_slice(&body);
                        self.process_handshake()?;
                    }
                    TYPE_ALERT => {
                        if body.get(1) == Some(&0) {
                            self.eof = true;
                        } else {
                            return Err(alert_error(&body));
                        }
                    }
                    other => return Err(proto_err(format!("unexpected TLS content type {other}"))),
                }
                Ok(true)
            }
            other => Err(proto_err(format!(
                "unexpected unprotected TLS record of type {other}"
            ))),
        }
    }
}

impl<S> RawSwitch for TlsStream<S> {
    fn switch_read_to_raw(&mut self) {
        if !self.raw_read {
            self.raw_read = true;
            // What was received but not decrypted is already raw data.
            let pending = self.rbuf.split();
            self.plain.extend_from_slice(&pending);
        }
    }

    fn switch_write_to_raw(&mut self) {
        self.raw_write = true;
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
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
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.raw_read {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            if this.process_record()? {
                if !this.wbuf.is_empty() {
                    // A KeyUpdate reply; finished by the next write or flush.
                    let _ = poll_drain(&mut this.inner, cx, &mut this.wbuf)?;
                }
                continue;
            }
            this.rbuf.reserve(MAX_CIPHERTEXT + 5);
            if ready!(poll_read_buf(Pin::new(&mut this.inner), cx, &mut this.rbuf))? == 0 {
                this.eof = true;
                // Without close_notify the data may have been truncated,
                // but peers that just drop the connection are too common
                // to treat this as an error when nothing is pending.
                if !this.rbuf.is_empty() {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(poll_drain(&mut this.inner, cx, &mut this.wbuf))?;
        if this.raw_write {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_PLAINTEXT);
        this.write_keys
            .seal_record(TYPE_APPLICATION_DATA, &buf[..n], &mut this.wbuf);
        let _ = poll_drain(&mut this.inner, cx, &mut this.wbuf)?;
        Poll::Ready(Ok(n))
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
            if !this.raw_write {
                this.write_keys
                    .seal_record(TYPE_ALERT, &[1, 0], &mut this.wbuf);
            }
        }
        ready!(poll_drain(&mut this.inner, cx, &mut this.wbuf))?;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
