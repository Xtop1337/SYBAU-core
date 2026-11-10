//! TLS 1.3 client handshake (RFC 8446) with a fingerprinted ClientHello.

use std::io;
use std::io::Read as _;
use std::sync::Arc;

use bytes::{Buf, BufMut, BytesMut};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sybau_common::proto_err;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::fingerprint::{ClientHello, Fingerprint, HelloParams};
use crate::keys::{KeySchedule, RecordKeys, Suite, Transcript};
use crate::reality::{self, RealityParams};
use crate::stream::{
    alert_error, TlsStream, MAX_CIPHERTEXT, TYPE_ALERT, TYPE_APPLICATION_DATA,
    TYPE_CHANGE_CIPHER_SPEC, TYPE_HANDSHAKE,
};

const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_REQUEST: u8 = 13;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_COMPRESSED_CERTIFICATE: u8 = 25;
const HS_MESSAGE_HASH: u8 = 254;

const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_COOKIE: u16 = 44;
const EXT_KEY_SHARE: u16 = 51;

/// `SHA-256("HelloRetryRequest")`: the random of a HelloRetryRequest.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

const MAX_HANDSHAKE_MESSAGE: usize = 1 << 20;
const MAX_CERTIFICATE_CHAIN: usize = 1 << 22;

/// How the server proves its identity.
#[derive(Clone)]
pub enum Trust {
    /// X.509 chain validation (WebPKI roots, pins or `insecure`).
    Certificate {
        verifier: Arc<dyn ServerCertVerifier>,
        name: ServerName<'static>,
    },
    /// REALITY: the server knows the private key matching `public_key`.
    Reality(RealityParams),
}

#[derive(Clone)]
pub struct ClientConfig {
    pub fingerprint: Fingerprint,
    /// SNI. Empty for IP literal targets (no SNI extension is sent).
    pub server_name: String,
    /// Overrides the ALPN protocols of the fingerprint.
    pub alpn: Option<Vec<String>>,
    pub trust: Trust,
}

/// Reads records and reassembles handshake messages.
struct Reader {
    rbuf: BytesMut,
    messages: BytesMut,
    keys: Option<RecordKeys>,
}

impl Reader {
    async fn fill<S: AsyncRead + Unpin>(&mut self, io: &mut S, want: usize) -> io::Result<()> {
        while self.rbuf.len() < want {
            if io.read_buf(&mut self.rbuf).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed during the TLS handshake",
                ));
            }
        }
        Ok(())
    }

    /// Next record as `(content type, plaintext)`; ChangeCipherSpec is skipped.
    async fn record<S: AsyncRead + Unpin>(&mut self, io: &mut S) -> io::Result<(u8, BytesMut)> {
        loop {
            self.fill(io, 5).await?;
            let header: [u8; 5] = self.rbuf[..5].try_into().expect("5 bytes");
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            if len > MAX_CIPHERTEXT {
                return Err(proto_err("TLS record too large (is this a TLS server?)"));
            }
            self.fill(io, 5 + len).await?;
            self.rbuf.advance(5);
            let mut body = self.rbuf.split_to(len);
            match (header[0], &mut self.keys) {
                (TYPE_CHANGE_CIPHER_SPEC, _) => continue,
                (TYPE_APPLICATION_DATA, Some(keys)) => {
                    let (content_type, n) = keys.open_record(&header, &mut body)?;
                    body.truncate(n);
                    return Ok((content_type, body));
                }
                (TYPE_HANDSHAKE | TYPE_ALERT, None) => return Ok((header[0], body)),
                (other, _) => {
                    return Err(proto_err(format!(
                        "unexpected TLS record type {other} during the handshake"
                    )))
                }
            }
        }
    }

    /// Next handshake message including its 4-byte header.
    async fn message<S: AsyncRead + Unpin>(&mut self, io: &mut S) -> io::Result<BytesMut> {
        loop {
            if self.messages.len() >= 4 {
                let len =
                    u32::from_be_bytes([0, self.messages[1], self.messages[2], self.messages[3]])
                        as usize;
                if len > MAX_HANDSHAKE_MESSAGE {
                    return Err(proto_err("TLS handshake message too large"));
                }
                if self.messages.len() >= 4 + len {
                    return Ok(self.messages.split_to(4 + len));
                }
            }
            let (content_type, body) = self.record(io).await?;
            match content_type {
                TYPE_HANDSHAKE => self.messages.extend_from_slice(&body),
                TYPE_ALERT => return Err(alert_error(&body)),
                other => {
                    return Err(proto_err(format!(
                        "unexpected TLS content type {other} during the handshake"
                    )))
                }
            }
        }
    }
}

/// Cursor over a handshake message body.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(proto_err("truncated TLS handshake message"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> io::Result<usize> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize)
    }
    fn vec8(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn vec24(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u24()?;
        self.take(n)
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

struct ServerHello<'a> {
    random: [u8; 32],
    session_id: &'a [u8],
    cipher_suite: u16,
    tls13: bool,
    key_share: Option<(u16, &'a [u8])>,
    cookie: Option<&'a [u8]>,
}

fn parse_server_hello(message: &[u8]) -> io::Result<ServerHello<'_>> {
    if message[0] != HS_SERVER_HELLO {
        return Err(proto_err(format!(
            "expected ServerHello, got handshake message {}",
            message[0]
        )));
    }
    let mut c = Cursor(&message[4..]);
    let _legacy_version = c.u16()?;
    let random: [u8; 32] = c.take(32)?.try_into().expect("32 bytes");
    let session_id = c.vec8()?;
    let cipher_suite = c.u16()?;
    let _compression = c.u8()?;
    let mut hello = ServerHello {
        random,
        session_id,
        cipher_suite,
        tls13: false,
        key_share: None,
        cookie: None,
    };
    if c.is_empty() {
        return Ok(hello);
    }
    let is_retry = random == HRR_RANDOM;
    let mut extensions = Cursor(c.vec16()?);
    while !extensions.is_empty() {
        let id = extensions.u16()?;
        let mut data = Cursor(extensions.vec16()?);
        match id {
            EXT_SUPPORTED_VERSIONS => hello.tls13 = data.u16()? == 0x0304,
            EXT_KEY_SHARE => {
                let group = data.u16()?;
                let key = if is_retry { &[][..] } else { data.vec16()? };
                hello.key_share = Some((group, key));
            }
            EXT_COOKIE => hello.cookie = Some(data.vec16()?),
            _ => {}
        }
    }
    Ok(hello)
}

/// Parses a Certificate message body into DER certificates.
fn parse_certificate_chain(body: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut c = Cursor(body);
    let _request_context = c.vec8()?;
    let mut list = Cursor(c.vec24()?);
    let mut certs = Vec::new();
    while !list.is_empty() {
        certs.push(list.vec24()?.to_vec());
        let _extensions = list.vec16()?;
    }
    if certs.is_empty() {
        return Err(proto_err("server sent no certificate"));
    }
    Ok(certs)
}

/// Inflates a CompressedCertificate (RFC 8879) into a Certificate body.
fn decompress_certificate(body: &[u8], offered: &[u16]) -> io::Result<Vec<u8>> {
    let mut c = Cursor(body);
    let algorithm = c.u16()?;
    let uncompressed_len = c.u24()?;
    let compressed = c.vec24()?;
    if !offered.contains(&algorithm) {
        return Err(proto_err(
            "server used a certificate compression algorithm that was not offered",
        ));
    }
    if uncompressed_len > MAX_CERTIFICATE_CHAIN {
        return Err(proto_err("compressed certificate is too large"));
    }
    let mut out = Vec::with_capacity(uncompressed_len);
    let limit = uncompressed_len as u64 + 1;
    let result = match algorithm {
        1 => flate2::read::ZlibDecoder::new(compressed)
            .take(limit)
            .read_to_end(&mut out),
        2 => brotli_decompressor::Decompressor::new(compressed, 4096)
            .take(limit)
            .read_to_end(&mut out),
        3 => ruzstd::StreamingDecoder::new(compressed)
            .map_err(|e| proto_err(format!("zstd: {e}")))?
            .take(limit)
            .read_to_end(&mut out),
        other => {
            return Err(proto_err(format!(
                "unknown certificate compression algorithm {other}"
            )))
        }
    };
    result.map_err(|e| proto_err(format!("cannot decompress the server certificate: {e}")))?;
    if out.len() != uncompressed_len {
        return Err(proto_err(
            "compressed certificate has a wrong declared length",
        ));
    }
    Ok(out)
}

fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(kind);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

fn plaintext_record(out: &mut BytesMut, content_type: u8, version: u16, payload: &[u8]) {
    for chunk in payload.chunks(16384) {
        out.put_u8(content_type);
        out.put_u16(version);
        out.put_u16(chunk.len() as u16);
        out.put_slice(chunk);
    }
}

/// Performs the handshake over `io` and returns the encrypted stream.
pub async fn connect<S>(mut io: S, config: &ClientConfig) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    config
        .fingerprint
        .require_tls13()
        .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e.to_string()))?;
    let params = HelloParams {
        server_name: config.server_name.clone(),
        alpn: config.alpn.clone(),
    };
    let mut hello = ClientHello::build(&config.fingerprint, &params);
    let auth_key = match &config.trust {
        Trust::Reality(reality) => Some(reality::seal_hello(&mut hello, reality)?),
        Trust::Certificate { .. } => None,
    };

    // The first record carries version 0x0301, as browsers send it.
    let mut out = BytesMut::with_capacity(hello.raw.len() + 16);
    plaintext_record(&mut out, TYPE_HANDSHAKE, 0x0301, &hello.raw);
    io.write_all(&out).await?;
    io.flush().await?;

    let mut reader = Reader {
        rbuf: BytesMut::with_capacity(8192),
        messages: BytesMut::new(),
        keys: None,
    };
    let mut message = reader.message(&mut io).await?;
    let mut server_hello = parse_server_hello(&message)?;
    if !server_hello.tls13 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the server negotiated TLS 1.2; fingerprinted TLS 1.2 is not implemented yet (remove `fingerprint` to use the standard TLS client)",
        ));
    }
    let suite = Suite::from_id(server_hello.cipher_suite)
        .filter(|s| hello.cipher_suites.contains(&s.id))
        .ok_or_else(|| {
            proto_err(format!(
                "server chose cipher suite {:#06x} that was not offered",
                server_hello.cipher_suite
            ))
        })?;
    let mut transcript = Transcript::new(suite.hash);

    if server_hello.random == HRR_RANDOM {
        // HelloRetryRequest: the first hello is replaced by its hash.
        let (group, _) = server_hello
            .key_share
            .ok_or_else(|| proto_err("HelloRetryRequest without key_share"))?;
        if !hello.supported_groups.contains(&group) || hello.shared_groups.contains(&group) {
            return Err(proto_err("HelloRetryRequest asks for an invalid group"));
        }
        if !crate::keyshare::KeyShares::can_offer(group) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "server insists on key exchange group {group:#06x}, which is not implemented"
                ),
            ));
        }
        let first_hash = suite.hash.hash(&hello.raw);
        transcript.update(&[HS_MESSAGE_HASH, 0, 0, first_hash.len() as u8]);
        transcript.update(&first_hash);
        transcript.update(&message);
        let cookie = server_hello.cookie.map(<[u8]>::to_vec);
        hello.rebuild_for_retry(&config.fingerprint, &params, group, cookie.as_deref());

        let mut out = BytesMut::with_capacity(hello.raw.len() + 16);
        plaintext_record(&mut out, TYPE_CHANGE_CIPHER_SPEC, 0x0303, &[1]);
        plaintext_record(&mut out, TYPE_HANDSHAKE, 0x0303, &hello.raw);
        io.write_all(&out).await?;
        io.flush().await?;
        transcript.update(&hello.raw);

        message = reader.message(&mut io).await?;
        server_hello = parse_server_hello(&message)?;
        if server_hello.random == HRR_RANDOM
            || !server_hello.tls13
            || server_hello.cipher_suite != suite.id
        {
            return Err(proto_err("invalid ServerHello after HelloRetryRequest"));
        }
    } else {
        transcript.update(&hello.raw);
    }
    transcript.update(&message);

    if server_hello.session_id != hello.session_id.as_slice() {
        return Err(proto_err("server did not echo the session id"));
    }
    let (group, share) = server_hello
        .key_share
        .ok_or_else(|| proto_err("ServerHello without key_share"))?;
    if !hello.shared_groups.contains(&group) {
        return Err(proto_err(
            "server chose a key exchange group that was not offered",
        ));
    }
    let shared_secret = hello.key_shares.shared_secret(group, share)?;
    let schedule = KeySchedule::new(suite, &shared_secret);
    let (client_hs, server_hs) = schedule.handshake_secrets(&transcript.current());
    reader.keys = Some(RecordKeys::new(suite, &server_hs));
    if !reader.messages.is_empty() {
        return Err(proto_err("unencrypted data after ServerHello"));
    }

    // EncryptedExtensions
    let message = reader.message(&mut io).await?;
    if message[0] != HS_ENCRYPTED_EXTENSIONS {
        return Err(proto_err(format!(
            "expected EncryptedExtensions, got handshake message {}",
            message[0]
        )));
    }
    let mut alpn = None;
    {
        let mut c = Cursor(&message[4..]);
        let mut extensions = Cursor(c.vec16()?);
        while !extensions.is_empty() {
            let id = extensions.u16()?;
            let mut data = Cursor(extensions.vec16()?);
            if id == EXT_ALPN {
                let mut list = Cursor(data.vec16()?);
                alpn = Some(list.vec8()?.to_vec());
            }
        }
    }
    transcript.update(&message);

    // [CertificateRequest], Certificate | CompressedCertificate
    let mut message = reader.message(&mut io).await?;
    let mut certificate_request_context = None;
    if message[0] == HS_CERTIFICATE_REQUEST {
        certificate_request_context = Some(Cursor(&message[4..]).vec8()?.to_vec());
        transcript.update(&message);
        message = reader.message(&mut io).await?;
    }
    let certificates = match message[0] {
        HS_CERTIFICATE => parse_certificate_chain(&message[4..])?,
        HS_COMPRESSED_CERTIFICATE => parse_certificate_chain(&decompress_certificate(
            &message[4..],
            &hello.cert_compression,
        )?)?,
        other => {
            return Err(proto_err(format!(
                "expected Certificate, got handshake message {other}"
            )))
        }
    };
    transcript.update(&message);

    // CertificateVerify
    let message = reader.message(&mut io).await?;
    if message[0] != HS_CERTIFICATE_VERIFY {
        return Err(proto_err(format!(
            "expected CertificateVerify, got handshake message {}",
            message[0]
        )));
    }
    let (scheme, signature) = {
        let mut c = Cursor(&message[4..]);
        (c.u16()?, c.vec16()?)
    };
    let mut signed = Vec::with_capacity(64 + 34 + 48);
    signed.extend_from_slice(&[0x20; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    signed.extend_from_slice(&transcript.current());
    match (&config.trust, auth_key) {
        (Trust::Reality(_), Some(auth_key)) => {
            let public_key = reality::verify_certificate(&certificates[0], &auth_key)?;
            reality::verify_handshake_signature(&public_key, scheme, &signed, signature)?;
        }
        (Trust::Certificate { verifier, name }, _) => {
            let end_entity = CertificateDer::from(certificates[0].as_slice());
            let intermediates: Vec<CertificateDer<'_>> = certificates[1..]
                .iter()
                .map(|c| CertificateDer::from(c.as_slice()))
                .collect();
            verifier
                .verify_server_cert(&end_entity, &intermediates, name, &[], UnixTime::now())
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("certificate verification failed: {e}"),
                    )
                })?;
            crate::verify::verify_tls13_signature(scheme, &certificates[0], &signed, signature)?;
        }
        (Trust::Reality(_), None) => {
            unreachable!("the auth key is derived whenever REALITY is configured")
        }
    }
    transcript.update(&message);

    // Finished
    let message = reader.message(&mut io).await?;
    if message[0] != HS_FINISHED {
        return Err(proto_err(format!(
            "expected Finished, got handshake message {}",
            message[0]
        )));
    }
    let expected = schedule.finished(&server_hs, &transcript.current());
    // Constant-time comparison of the MAC.
    let equal = message.len() == 4 + expected.len()
        && message[4..]
            .iter()
            .zip(&expected)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    if !equal {
        return Err(proto_err("server Finished does not verify"));
    }
    transcript.update(&message);
    if !reader.messages.is_empty() {
        return Err(proto_err("unexpected handshake data after server Finished"));
    }
    let (client_app, server_app) = schedule.application_secrets(&transcript.current());

    // Client flight: dummy ChangeCipherSpec, [Certificate], Finished.
    let mut out = BytesMut::with_capacity(256);
    if !hello.session_id.is_empty() {
        plaintext_record(&mut out, TYPE_CHANGE_CIPHER_SPEC, 0x0303, &[1]);
    }
    let mut write_keys = RecordKeys::new(suite, &client_hs);
    if let Some(context) = certificate_request_context {
        // No client certificate is configured: send an empty list.
        let mut body = vec![context.len() as u8];
        body.extend_from_slice(&context);
        body.extend_from_slice(&[0, 0, 0]);
        let certificate = handshake_message(HS_CERTIFICATE, &body);
        transcript.update(&certificate);
        write_keys.seal_record(TYPE_HANDSHAKE, &certificate, &mut out);
    }
    let finished = handshake_message(
        HS_FINISHED,
        &schedule.finished(&client_hs, &transcript.current()),
    );
    write_keys.seal_record(TYPE_HANDSHAKE, &finished, &mut out);
    io.write_all(&out).await?;
    io.flush().await?;

    Ok(TlsStream::new(
        io,
        RecordKeys::new(suite, &server_app),
        RecordKeys::new(suite, &client_app),
        reader.rbuf,
        alpn,
    ))
}
