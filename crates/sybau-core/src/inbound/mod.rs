//! Inbound listeners.

pub mod http;
pub mod local;
pub mod socks;
pub mod tun;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use sybau_common::net::InterfaceIndex;
use sybau_config::{InboundConfig, InboundKind};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::dispatch::Dispatcher;

/// An inbound whose sockets are already bound; `spawn` starts serving.
pub enum BoundInbound {
    Local(local::LocalProxy, TcpListener),
    Tun(Box<tun::TunInbound>),
}

impl BoundInbound {
    /// Binds the listening sockets so that address conflicts are reported
    /// before the engine reports a successful start.
    /// `uplink` is the interface pinning of the core's sockets, which a
    /// TUN inbound keeps pointing at the current uplink (Windows).
    pub async fn bind(
        index: usize,
        cfg: &InboundConfig,
        uplink: Option<Arc<InterfaceIndex>>,
    ) -> Result<Self> {
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
                    _ => local::Mode::Http,
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
            InboundKind::Tun(c) => {
                // Creating the interface and routes blocks on system calls
                // and `ip`/`nft` runs.
                let c = (**c).clone();
                let tun =
                    tokio::task::spawn_blocking(move || tun::TunInbound::open(tag, &c, uplink))
                        .await
                        .context("TUN setup panicked")??;
                Ok(BoundInbound::Tun(Box::new(tun)))
            }
        }
    }

    /// `keep_kill_switch` is read when the inbound stops: set during a
    /// reload so that a TUN kill switch stays in place.
    pub fn spawn(
        self,
        dispatcher: Arc<Dispatcher>,
        cancel: CancellationToken,
        keep_kill_switch: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        match self {
            BoundInbound::Local(proxy, listener) => {
                tokio::spawn(Arc::new(proxy).serve(listener, dispatcher, cancel))
            }
            BoundInbound::Tun(tun) => tokio::spawn(tun.serve(dispatcher, cancel, keep_kill_switch)),
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
