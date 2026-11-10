use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use crate::{ArcPacketConn, BoxStream, Dialer, Network, Session, Target};

/// A way to reach a destination: direct, blocked or through a proxy protocol.
#[async_trait]
pub trait Outbound: Send + Sync + 'static {
    fn tag(&self) -> &str;
    /// Protocol name as written in the config (`direct`, `vless`, ...).
    fn kind(&self) -> &'static str;
    /// Opens a TCP-like stream to `sess.target`.
    async fn connect(&self, sess: &Session) -> io::Result<BoxStream>;
    /// Opens a datagram endpoint; `sess.target` is the first destination.
    async fn bind(&self, sess: &Session) -> io::Result<ArcPacketConn>;
}

/// Adapter that lets an outbound serve as the dialer of another outbound,
/// which is how proxy chains (`detour`) are built.
pub struct OutboundDialer(pub Arc<dyn Outbound>);

impl OutboundDialer {
    fn session(&self, network: Network, target: &Target) -> Session {
        Session::new(network, Arc::from("detour"), None, target.clone())
    }
}

#[async_trait]
impl Dialer for OutboundDialer {
    async fn dial_tcp(&self, target: &Target) -> io::Result<BoxStream> {
        self.0.connect(&self.session(Network::Tcp, target)).await
    }

    async fn dial_udp(&self, target: &Target) -> io::Result<ArcPacketConn> {
        self.0.bind(&self.session(Network::Udp, target)).await
    }
}
