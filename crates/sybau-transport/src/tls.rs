//! Standard TLS client (rustls): SNI, ALPN, `insecure`, certificate pinning.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use sybau_common::{BoxStream, Target};
use sybau_config::TlsConfig;
use tokio_rustls::TlsConnector;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
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

/// A configured TLS client for one server.
#[derive(Clone)]
pub struct TlsClient {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl TlsClient {
    /// `server` supplies the default SNI; `default_alpn` is used when the
    /// config does not set ALPN (transports that require a protocol).
    pub fn new(cfg: &TlsConfig, server: &Target, default_alpn: &[&str]) -> Result<Self> {
        let provider = provider();
        let leaf_pins = cfg
            .pinned_cert_sha256
            .iter()
            .map(|p| parse_sha256(p))
            .collect::<Result<Vec<_>>>()?;
        let chain_pins = cfg
            .pinned_cert_chain_sha256
            .iter()
            .map(|p| parse_sha256(p))
            .collect::<Result<Vec<_>>>()?;
        let webpki = if cfg.insecure {
            None
        } else {
            Some(
                WebPkiServerVerifier::builder_with_provider(roots(), provider.clone())
                    .build()
                    .map_err(|e| anyhow!("cannot build certificate verifier: {e}"))?,
            )
        };
        let verifier = Verifier {
            webpki,
            algorithms: provider.signature_verification_algorithms,
            leaf_pins,
            chain_pins,
        };
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow!("TLS configuration: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        config.alpn_protocols = if cfg.alpn.is_empty() {
            default_alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
        } else {
            cfg.alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
        };

        let name = cfg
            .server_name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| server.host_string());
        let server_name = match name.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(name.clone())
                .map_err(|_| anyhow!("invalid TLS server name `{name}`"))?,
        };
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
        })
    }

    /// Name sent as SNI, used by transports as the default HTTP host.
    pub fn server_name(&self) -> String {
        match &self.server_name {
            ServerName::DnsName(d) => d.as_ref().to_string(),
            ServerName::IpAddress(ip) => IpAddr::from(*ip).to_string(),
            _ => String::new(),
        }
    }

    pub async fn connect(&self, io: BoxStream) -> io::Result<BoxStream> {
        Ok(Box::new(
            self.connector.connect(self.server_name.clone(), io).await?,
        ))
    }
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
