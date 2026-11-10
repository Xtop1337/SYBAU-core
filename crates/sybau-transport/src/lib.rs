//! TLS and stream transports of SYBAU-CORE.
//!
//! A [`Connector`] turns "server address + TLS settings + transport
//! settings" into a ready byte stream for a proxy protocol.

pub mod fragment;
pub mod h2;
pub mod httpobfs;
pub mod httpupgrade;
pub mod lazy;
pub mod tls;
pub mod ws;

use std::io;
use std::sync::Arc;

use anyhow::{bail, Result};
use rand::seq::SliceRandom;
use sybau_common::{BoxStream, Dialer, Target};
use sybau_config::{Headers, TlsConfig, TransportConfig};

use crate::h2::{Framing, H2Pool};
use crate::tls::TlsClient;

struct Base {
    dialer: Arc<dyn Dialer>,
    server: Target,
    tls: Option<TlsClient>,
    fragment: Option<fragment::Fragment>,
}

impl Base {
    async fn dial_tcp(&self) -> io::Result<BoxStream> {
        let tcp = self.dialer.dial_tcp(&self.server).await?;
        Ok(match self.fragment {
            Some(fragment) => Box::new(fragment::FragmentStream::new(tcp, fragment)),
            None => tcp,
        })
    }

    async fn dial(&self) -> io::Result<BoxStream> {
        let tcp = self.dial_tcp().await?;
        match &self.tls {
            Some(tls) => tls.connect(tcp).await,
            None => Ok(tcp),
        }
    }

    /// Host used in HTTP requests when the transport does not set one.
    fn default_host(&self) -> String {
        match &self.tls {
            Some(tls) => tls.server_name(),
            None => self.server.host_string(),
        }
    }
}

enum Kind {
    Raw,
    HttpObfs {
        hosts: Vec<String>,
        opts: httpobfs::HttpObfsOptions,
    },
    Ws {
        opts: ws::WsOptions,
        max_early_data: usize,
    },
    HttpUpgrade(httpupgrade::HttpUpgradeOptions),
    H2 {
        pool: H2Pool,
        framing: Framing,
        method: http::Method,
        scheme: &'static str,
        hosts: Vec<String>,
        path: String,
        headers: Vec<(String, String)>,
    },
}

/// Opens streams to one proxy server.
pub struct Connector {
    base: Arc<Base>,
    kind: Kind,
}

fn header_list(headers: &Headers) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

impl Connector {
    pub fn new(
        dialer: Arc<dyn Dialer>,
        server: Target,
        tls: Option<&TlsConfig>,
        transport: Option<&TransportConfig>,
    ) -> Result<Self> {
        Self::build(dialer, server, tls, transport, false)
    }

    /// Connector for XTLS Vision: TLS (or REALITY) directly over TCP, with
    /// streams that can switch to raw mode.
    pub fn new_switchable(
        dialer: Arc<dyn Dialer>,
        server: Target,
        tls: Option<&TlsConfig>,
        transport: Option<&TransportConfig>,
    ) -> Result<Self> {
        let plain_tcp = match transport {
            None => true,
            Some(TransportConfig::Tcp(t)) => t.http_obfs.is_none(),
            Some(_) => false,
        };
        if !plain_tcp || !tls.is_some_and(|t| t.enabled) {
            bail!("xtls-rprx-vision works only over plain TCP with TLS or REALITY");
        }
        Self::build(dialer, server, tls, transport, true)
    }

    fn build(
        dialer: Arc<dyn Dialer>,
        server: Target,
        tls: Option<&TlsConfig>,
        transport: Option<&TransportConfig>,
        raw_switch: bool,
    ) -> Result<Self> {
        let default_alpn: &[&str] = match transport {
            Some(TransportConfig::Ws(_) | TransportConfig::HttpUpgrade(_)) => &["http/1.1"],
            Some(TransportConfig::Grpc(_) | TransportConfig::Http(_)) => &["h2"],
            _ => &[],
        };
        let fragment = match tls.and_then(|t| t.fragment.as_ref()) {
            Some(f) => Some(fragment::Fragment::from_config(f)?),
            None => None,
        };
        let tls = match tls.filter(|t| t.enabled) {
            Some(cfg) => Some(TlsClient::new(cfg, &server, default_alpn, raw_switch)?),
            None => None,
        };
        let base = Arc::new(Base {
            dialer,
            server,
            tls,
            fragment,
        });
        let default_host = base.default_host();
        let kind = match transport {
            None => Kind::Raw,
            Some(TransportConfig::Tcp(t)) => match &t.http_obfs {
                None => Kind::Raw,
                Some(o) => Kind::HttpObfs {
                    hosts: o.host.clone(),
                    opts: httpobfs::HttpObfsOptions {
                        method: o.method.clone().unwrap_or_else(|| "GET".into()),
                        path: o.path.clone(),
                        host: default_host,
                        headers: header_list(&o.headers),
                    },
                },
            },
            Some(TransportConfig::Ws(w)) => Kind::Ws {
                opts: ws::WsOptions {
                    path: w.path.clone(),
                    host: w
                        .host
                        .clone()
                        .filter(|h| !h.is_empty())
                        .unwrap_or(default_host),
                    headers: header_list(&w.headers),
                    early_data_header: w.early_data_header_name.clone().filter(|h| !h.is_empty()),
                },
                max_early_data: w.max_early_data,
            },
            Some(TransportConfig::HttpUpgrade(h)) => {
                Kind::HttpUpgrade(httpupgrade::HttpUpgradeOptions {
                    path: h.path.clone(),
                    host: h
                        .host
                        .clone()
                        .filter(|x| !x.is_empty())
                        .unwrap_or(default_host),
                    headers: header_list(&h.headers),
                })
            }
            Some(TransportConfig::Grpc(g)) => {
                let dial_base = base.clone();
                Kind::H2 {
                    pool: H2Pool::new(Arc::new(move || {
                        let b = dial_base.clone();
                        Box::pin(async move { b.dial().await })
                    })),
                    framing: Framing::Grpc,
                    method: http::Method::POST,
                    scheme: if base.tls.is_some() { "https" } else { "http" },
                    hosts: vec![g
                        .authority
                        .clone()
                        .filter(|a| !a.is_empty())
                        .unwrap_or(default_host)],
                    path: h2::grpc_path(&g.service_name, g.multi_mode),
                    headers: vec![
                        ("content-type".into(), "application/grpc".into()),
                        ("te".into(), "trailers".into()),
                        (
                            "user-agent".into(),
                            g.user_agent
                                .clone()
                                .unwrap_or_else(|| "grpc-go/1.71.0".into()),
                        ),
                    ],
                }
            }
            Some(TransportConfig::Http(h)) => {
                let method = match &h.method {
                    Some(m) => match http::Method::from_bytes(m.to_ascii_uppercase().as_bytes()) {
                        Ok(m) => m,
                        Err(_) => bail!("invalid HTTP method `{m}`"),
                    },
                    None => http::Method::PUT,
                };
                let dial_base = base.clone();
                Kind::H2 {
                    pool: H2Pool::new(Arc::new(move || {
                        let b = dial_base.clone();
                        Box::pin(async move { b.dial().await })
                    })),
                    framing: Framing::Raw,
                    method,
                    scheme: if base.tls.is_some() { "https" } else { "http" },
                    hosts: if h.host.is_empty() {
                        vec![default_host]
                    } else {
                        h.host.clone()
                    },
                    path: if h.path.starts_with('/') {
                        h.path.clone()
                    } else {
                        format!("/{}", h.path)
                    },
                    headers: header_list(&h.headers)
                        .into_iter()
                        .map(|(k, v)| (k.to_ascii_lowercase(), v))
                        .collect(),
                }
            }
        };
        if let Kind::H2 {
            hosts,
            path,
            scheme,
            ..
        } = &kind
        {
            for host in hosts {
                if format!("{scheme}://{host}{path}")
                    .parse::<http::Uri>()
                    .is_err()
                {
                    bail!("invalid HTTP/2 request target `{host}{path}`");
                }
            }
        }
        Ok(Self { base, kind })
    }

    /// Opens a TLS stream that can switch to raw mode. Only for
    /// connectors made with [`new_switchable`](Self::new_switchable).
    pub async fn connect_switchable(&self) -> io::Result<sybau_tls::TlsStream<BoxStream>> {
        let tcp = self.base.dial_tcp().await?;
        match &self.base.tls {
            Some(tls) => tls.connect_switchable(tcp).await,
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no TLS configured",
            )),
        }
    }

    /// Opens a new stream to the server. Depending on the transport the
    /// handshake may be deferred until the first write or flush.
    pub async fn connect(&self) -> io::Result<BoxStream> {
        match &self.kind {
            Kind::Raw => self.base.dial().await,
            Kind::HttpObfs { hosts, opts } => {
                let mut opts = opts.clone();
                if let Some(host) = hosts.choose(&mut rand::thread_rng()) {
                    opts.host = host.clone();
                }
                Ok(Box::new(httpobfs::HttpObfsStream::new(
                    self.base.dial().await?,
                    &opts,
                )))
            }
            Kind::Ws {
                opts,
                max_early_data,
            } => {
                if *max_early_data == 0 {
                    return Ok(Box::new(
                        ws::connect(self.base.dial().await?, opts, &[]).await?,
                    ));
                }
                let (base, opts) = (self.base.clone(), opts.clone());
                Ok(Box::new(lazy::LazyStream::new(
                    *max_early_data,
                    move |early| async move {
                        let io = base.dial().await?;
                        Ok(Box::new(ws::connect(io, &opts, &early).await?) as BoxStream)
                    },
                )))
            }
            Kind::HttpUpgrade(opts) => Ok(Box::new(
                httpupgrade::connect(self.base.dial().await?, opts).await?,
            )),
            Kind::H2 {
                pool,
                framing,
                method,
                scheme,
                hosts,
                path,
                headers,
            } => {
                let host = hosts
                    .choose(&mut rand::thread_rng())
                    .expect("at least one host");
                let mut request = http::Request::builder()
                    .method(method.clone())
                    .uri(format!("{scheme}://{host}{path}"));
                for (name, value) in headers {
                    request = request.header(name.as_str(), value.as_str());
                }
                let request = request
                    .body(())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                Ok(Box::new(pool.open(request, *framing).await?))
            }
        }
    }
}
