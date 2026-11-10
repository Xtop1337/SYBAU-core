//! Inbound listeners.

pub mod http;
pub mod local;
pub mod socks;

use std::sync::Arc;

use anyhow::{Context, Result};
use sybau_config::{InboundConfig, InboundKind};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::dispatch::Dispatcher;

/// An inbound whose sockets are already bound; `spawn` starts serving.
pub enum BoundInbound {
    Local(local::LocalProxy, TcpListener),
}

impl BoundInbound {
    /// Binds the listening sockets so that address conflicts are reported
    /// before the engine reports a successful start.
    pub async fn bind(index: usize, cfg: &InboundConfig) -> Result<Self> {
        let tag: Arc<str> = if cfg.tag.is_empty() {
            Arc::from(format!("{}-{}", cfg.kind.type_name(), index))
        } else {
            Arc::from(cfg.tag.as_str())
        };
        match &cfg.kind {
            InboundKind::Mixed(c) | InboundKind::Socks(c) | InboundKind::Http(c) => {
                let mode = match &cfg.kind {
                    InboundKind::Mixed(_) => local::Mode::Mixed,
                    InboundKind::Socks(_) => local::Mode::Socks,
                    InboundKind::Http(_) => local::Mode::Http,
                };
                let addr = format!("{}:{}", bracket_v6(&c.listen), c.port);
                let listener = TcpListener::bind(&addr)
                    .await
                    .with_context(|| format!("inbound `{tag}`: cannot listen on {addr}"))?;
                Ok(BoundInbound::Local(
                    local::LocalProxy::new(tag, mode, c.clone()),
                    listener,
                ))
            }
        }
    }

    pub fn spawn(self, dispatcher: Arc<Dispatcher>, cancel: CancellationToken) -> JoinHandle<()> {
        match self {
            BoundInbound::Local(proxy, listener) => {
                tokio::spawn(Arc::new(proxy).serve(listener, dispatcher, cancel))
            }
        }
    }
}

fn bracket_v6(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}
