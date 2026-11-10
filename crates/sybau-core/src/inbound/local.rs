//! Local proxy listener: SOCKS4/4a/5 and HTTP on one port (`mixed`), or
//! each protocol alone.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sybau_common::{proto_err, PrefixedStream};
use sybau_config::LocalProxyInbound;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{http, socks};
use crate::dispatch::Dispatcher;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Mixed,
    Socks,
    Http,
}

pub struct LocalProxy {
    pub tag: Arc<str>,
    pub mode: Mode,
    pub cfg: LocalProxyInbound,
}

impl LocalProxy {
    pub fn new(tag: Arc<str>, mode: Mode, cfg: LocalProxyInbound) -> Self {
        Self { tag, mode, cfg }
    }

    pub fn check_user(&self, user: &str, pass: &str) -> bool {
        self.cfg
            .users
            .iter()
            .any(|u| u.username == user && u.password == pass)
    }

    pub fn auth_required(&self) -> bool {
        !self.cfg.users.is_empty()
    }

    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        dispatcher: Arc<Dispatcher>,
        cancel: CancellationToken,
    ) {
        if let Ok(addr) = listener.local_addr() {
            info!(target: "sybau::inbound", "inbound `{}` listening on {}", self.tag, addr);
        }
        loop {
            let (stream, peer) = tokio::select! {
                r = listener.accept() => match r {
                    Ok(v) => v,
                    Err(e) => {
                        // Typically fd exhaustion; back off instead of spinning.
                        warn!(target: "sybau::inbound", "inbound `{}` accept: {}", self.tag, e);
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                },
                _ = cancel.cancelled() => return,
            };
            let _ = stream.set_nodelay(true);
            let (this, dispatcher, cancel) = (self.clone(), dispatcher.clone(), cancel.clone());
            tokio::spawn(async move {
                tokio::select! {
                    r = this.handle(stream, peer, &dispatcher) => {
                        if let Err(e) = r {
                            debug!(target: "sybau::inbound", "inbound `{}` {}: {}", this.tag, peer, e);
                        }
                    }
                    _ = cancel.cancelled() => {}
                }
            });
        }
    }

    async fn handle(
        &self,
        mut stream: TcpStream,
        peer: SocketAddr,
        dispatcher: &Dispatcher,
    ) -> std::io::Result<()> {
        let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_u8())
            .await
            .map_err(|_| proto_err("handshake timed out"))??;
        let local = stream.local_addr()?;
        let stream = PrefixedStream::new(vec![first], stream);
        match (first, self.mode) {
            (5, Mode::Mixed | Mode::Socks) => {
                socks::handle_v5(self, stream, peer, local, dispatcher).await
            }
            (4, Mode::Mixed | Mode::Socks) => {
                socks::handle_v4(self, stream, peer, dispatcher).await
            }
            (_, Mode::Mixed | Mode::Http) => http::handle(self, stream, peer, dispatcher).await,
            (other, Mode::Socks) => Err(proto_err(format!(
                "not a SOCKS request (first byte {other:#x})"
            ))),
        }
    }
}
