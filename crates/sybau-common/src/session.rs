use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::Target;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        }
    }
}

/// Protocol sniffing requested by the inbound that accepted a flow.
#[derive(Clone, Copy, Debug, Default)]
pub struct SniffOptions {
    pub enabled: bool,
    /// Replace an IP target with the sniffed domain.
    pub override_destination: bool,
    /// How long to wait for the client's first bytes.
    pub timeout: std::time::Duration,
}

/// Everything known about one proxied flow; filled by the inbound, enriched
/// by sniffing and consumed by the router and the outbound.
#[derive(Clone, Debug)]
pub struct Session {
    pub id: u64,
    pub network: Network,
    pub inbound_tag: Arc<str>,
    pub source: Option<SocketAddr>,
    pub target: Target,
    /// Domain discovered by sniffing (TLS SNI, HTTP Host, QUIC SNI).
    pub sniffed_host: Option<String>,
    /// Application protocol discovered by sniffing: `tls`, `http`, `quic`, `bittorrent`.
    pub protocol: Option<&'static str>,
    /// Authenticated inbound user, if any.
    pub user: Option<Arc<str>>,
    /// Full path of the local process owning the flow, if resolved.
    pub process_path: Option<Arc<str>>,
    /// Executable name of that process.
    pub process_name: Option<Arc<str>>,
    pub sniff: SniffOptions,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl Session {
    pub fn new(
        network: Network,
        inbound_tag: Arc<str>,
        source: Option<SocketAddr>,
        target: Target,
    ) -> Self {
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            network,
            inbound_tag,
            source,
            target,
            sniffed_host: None,
            protocol: None,
            user: None,
            process_path: None,
            process_name: None,
            sniff: SniffOptions::default(),
        }
    }
}
