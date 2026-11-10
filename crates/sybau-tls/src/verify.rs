//! Server certificate verification: WebPKI roots, `insecure`, pinning.

use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

pub fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: std::sync::OnceLock<Arc<CryptoProvider>> = std::sync::OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

fn roots() -> Arc<RootCertStore> {
    static ROOTS: std::sync::OnceLock<Arc<RootCertStore>> = std::sync::OnceLock::new();
    ROOTS
        .get_or_init(|| {
            Arc::new(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
        })
        .clone()
}

/// Decodes a SHA-256 written as hex (with optional `:` separators) or base64.
pub fn parse_sha256(text: &str) -> Result<[u8; 32]> {
    let t = text.trim();
    let hex: String = t.chars().filter(|c| *c != ':').collect();
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16)
                .expect("hex digits");
        }
        return Ok(out);
    }
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(t) {
            if let Ok(out) = <[u8; 32]>::try_from(bytes) {
                return Ok(out);
            }
        }
    }
    bail!("`{text}` is not a SHA-256 in hex or base64")
}

/// Xray's chain hash: `h = sha256(cert0)`, then `h = sha256(h || sha256(cert_i))`.
pub fn chain_hash<'a>(certs: impl Iterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut acc: Option<[u8; 32]> = None;
    for cert in certs {
        let h: [u8; 32] = Sha256::digest(cert).into();
        acc = Some(match acc {
            None => h,
            Some(prev) => {
                let mut hasher = Sha256::new();
                hasher.update(prev);
                hasher.update(h);
                hasher.finalize().into()
            }
        });
    }
    acc.unwrap_or_default()
}

/// What to accept as a valid server certificate.
#[derive(Clone, Debug, Default)]
pub struct VerifyOptions {
    /// Accept any certificate.
    pub insecure: bool,
    /// SHA-256 of acceptable leaf certificates; a match is sufficient.
    pub leaf_pins: Vec<[u8; 32]>,
    /// Xray chain hashes, checked in addition to normal verification.
    pub chain_pins: Vec<[u8; 32]>,
}

impl VerifyOptions {
    pub fn from_strings(insecure: bool, leaf: &[String], chain: &[String]) -> Result<Self> {
        Ok(Self {
            insecure,
            leaf_pins: leaf
                .iter()
                .map(|p| parse_sha256(p))
                .collect::<Result<_>>()?,
            chain_pins: chain
                .iter()
                .map(|p| parse_sha256(p))
                .collect::<Result<_>>()?,
        })
    }
}

#[derive(Debug)]
struct Verifier {
    /// `None` when `insecure` is set.
    webpki: Option<Arc<WebPkiServerVerifier>>,
    algorithms: WebPkiSupportedAlgorithms,
    leaf_pins: Vec<[u8; 32]>,
    chain_pins: Vec<[u8; 32]>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !self.leaf_pins.is_empty() {
            let leaf: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
            if self.leaf_pins.contains(&leaf) {
                return Ok(ServerCertVerified::assertion());
            }
            if self.chain_pins.is_empty() {
                return Err(rustls::Error::General(
                    "server certificate does not match the pinned SHA-256".into(),
                ));
            }
        }
        if !self.chain_pins.is_empty() {
            let all = std::iter::once(end_entity.as_ref())
                .chain(intermediates.iter().map(|c| c.as_ref()));
            if !self.chain_pins.contains(&chain_hash(all)) {
                return Err(rustls::Error::General(
                    "server certificate chain does not match the pinned SHA-256".into(),
                ));
            }
        }
        if let Some(webpki) = &self.webpki {
            webpki.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Builds the certificate verifier shared by the rustls client and the
/// fingerprinted client.
pub fn build_verifier(opts: &VerifyOptions) -> Result<Arc<dyn ServerCertVerifier>> {
    let provider = provider();
    let webpki = if opts.insecure {
        None
    } else {
        Some(
            WebPkiServerVerifier::builder_with_provider(roots(), provider.clone())
                .build()
                .map_err(|e| anyhow!("cannot build certificate verifier: {e}"))?,
        )
    };
    Ok(Arc::new(Verifier {
        webpki,
        algorithms: provider.signature_verification_algorithms,
        leaf_pins: opts.leaf_pins.clone(),
        chain_pins: opts.chain_pins.clone(),
    }))
}

/// Verifies a TLS 1.3 handshake signature made with the key of `cert`.
pub fn verify_tls13_signature(
    scheme: u16,
    cert: &[u8],
    message: &[u8],
    signature: &[u8],
) -> std::io::Result<()> {
    use sybau_common::proto_err;
    // TLS 1.3 forbids PKCS#1 v1.5 and SHA-1 signatures in CertificateVerify.
    if !matches!(scheme, 0x0403 | 0x0503 | 0x0603 | 0x0804..=0x0806 | 0x0807 | 0x0809..=0x080b) {
        return Err(proto_err(format!(
            "signature scheme {scheme:#06x} is not allowed in TLS 1.3"
        )));
    }
    let provider = provider();
    let algs = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(s, _)| u16::from(*s) == scheme)
        .map(|(_, algs)| *algs)
        .ok_or_else(|| proto_err(format!("unsupported signature scheme {scheme:#06x}")))?;
    let der = CertificateDer::from(cert);
    let cert = webpki::EndEntityCert::try_from(&der)
        .map_err(|e| proto_err(format!("bad server certificate: {e}")))?;
    cert.verify_signature(algs[0], message, signature)
        .map_err(|_| proto_err("server's handshake signature is invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_formats() {
        let hex = "aa".repeat(32);
        assert_eq!(parse_sha256(&hex).unwrap(), [0xaa; 32]);
        let colon = ["AA"; 32].join(":");
        assert_eq!(parse_sha256(&colon).unwrap(), [0xaa; 32]);
        let b64 = base64::engine::general_purpose::STANDARD.encode([0xaa; 32]);
        assert_eq!(parse_sha256(&b64).unwrap(), [0xaa; 32]);
        assert!(parse_sha256("abcd").is_err());
    }

    #[test]
    fn chain_hash_matches_xray_definition() {
        let (a, b): (&[u8], &[u8]) = (b"cert-a", b"cert-b");
        let ha: [u8; 32] = Sha256::digest(a).into();
        let hb: [u8; 32] = Sha256::digest(b).into();
        assert_eq!(chain_hash([a].into_iter()), ha);
        let mut h = Sha256::new();
        h.update(ha);
        h.update(hb);
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(chain_hash([a, b].into_iter()), expect);
    }
}
