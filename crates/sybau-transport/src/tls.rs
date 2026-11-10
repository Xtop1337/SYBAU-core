//! TLS towards the proxy server.
//!
//! Two clients share one configuration block: rustls for standard TLS
//! (1.2 and 1.3) and `sybau-tls` when a browser fingerprint, REALITY or
//! XTLS Vision is requested.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use sybau_common::{BoxStream, Target};
use sybau_config::TlsConfig;
use sybau_tls::verify::{build_verifier, provider, VerifyOptions};
use sybau_tls::{Fingerprint, RealityParams, Trust};
use tokio_rustls::TlsConnector;

/// Fingerprint used when one is required but not configured.
const DEFAULT_FINGERPRINT: &str = "chrome";

#[derive(Clone)]
enum Inner {
    Standard {
        connector: TlsConnector,
        server_name: ServerName<'static>,
    },
    Fingerprinted(Arc<sybau_tls::ClientConfig>),
}

/// A configured TLS client for one server.
#[derive(Clone)]
pub struct TlsClient {
    inner: Inner,
    sni: String,
}

impl TlsClient {
    /// `server` supplies the default SNI; `default_alpn` is used when the
    /// config does not set ALPN (transports that require a protocol).
    /// `raw_switch` asks for a client whose streams can stop encrypting
    /// (XTLS Vision).
    pub fn new(
        cfg: &TlsConfig,
        server: &Target,
        default_alpn: &[&str],
        raw_switch: bool,
    ) -> Result<Self> {
        let name = cfg
            .server_name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| server.host_string());
        let is_ip = name.parse::<IpAddr>().is_ok();
        let server_name = match name.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(name.clone())
                .map_err(|_| anyhow!("invalid TLS server name `{name}`"))?,
        };
        let verify = VerifyOptions::from_strings(
            cfg.insecure,
            &cfg.pinned_cert_sha256,
            &cfg.pinned_cert_chain_sha256,
        )?;
        let verify = VerifyOptions {
            verify_names: cfg.verify_names.clone(),
            ..verify
        };

        if cfg.fingerprint.is_none() && cfg.reality.is_none() && !raw_switch {
            let mut config = ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .map_err(|e| anyhow!("TLS configuration: {e}"))?
                .dangerous()
                .with_custom_certificate_verifier(build_verifier(&verify)?)
                .with_no_client_auth();
            config.alpn_protocols = if cfg.alpn.is_empty() {
                default_alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
            } else {
                cfg.alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
            };
            let connector = TlsConnector::from(Arc::new(config));
            return Ok(Self {
                inner: Inner::Standard {
                    connector,
                    server_name,
                },
                sni: name,
            });
        }

        let fingerprint =
            Fingerprint::by_name(cfg.fingerprint.as_deref().unwrap_or(DEFAULT_FINGERPRINT))?;
        fingerprint.require_tls13()?;
        let trust = match &cfg.reality {
            Some(reality) => {
                if is_ip {
                    bail!("REALITY needs `tls.server_name`: the domain of the site the server imitates");
                }
                Trust::Reality(RealityParams::parse(
                    &reality.public_key,
                    &reality.short_id,
                )?)
            }
            None => Trust::Certificate {
                verifier: build_verifier(&verify)?,
                name: server_name,
            },
        };
        // The fingerprint defines ALPN. It is replaced only on request or
        // when the transport cannot work over HTTP/2 (WebSocket).
        let alpn = if !cfg.alpn.is_empty() {
            Some(cfg.alpn.clone())
        } else if default_alpn == ["http/1.1"] {
            Some(vec!["http/1.1".to_string()])
        } else {
            None
        };
        let config = sybau_tls::ClientConfig {
            fingerprint,
            // Browsers send no SNI for IP literals.
            server_name: if is_ip { String::new() } else { name.clone() },
            alpn,
            trust,
        };
        Ok(Self {
            inner: Inner::Fingerprinted(Arc::new(config)),
            sni: name,
        })
    }

    /// Name sent as SNI, used by transports as the default HTTP host.
    pub fn server_name(&self) -> String {
        self.sni.clone()
    }

    pub async fn connect(&self, io: BoxStream) -> io::Result<BoxStream> {
        match &self.inner {
            Inner::Standard {
                connector,
                server_name,
            } => Ok(Box::new(connector.connect(server_name.clone(), io).await?)),
            Inner::Fingerprinted(config) => Ok(Box::new(sybau_tls::connect(io, config).await?)),
        }
    }

    /// Like [`connect`](Self::connect) but keeps the concrete stream type,
    /// which can switch to raw mode. Only for clients created with
    /// `raw_switch`.
    pub async fn connect_switchable(
        &self,
        io: BoxStream,
    ) -> io::Result<sybau_tls::TlsStream<BoxStream>> {
        match &self.inner {
            Inner::Fingerprinted(config) => sybau_tls::connect(io, config).await,
            Inner::Standard { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this TLS client cannot switch to raw mode",
            )),
        }
    }
}
