//! Glue between inbounds and outbounds: picks the outbound for a session,
//! connects it and relays traffic while keeping statistics.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use sybau_common::{ArcPacketConn, BoxStream, Outbound, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::outbound::OutboundManager;
use crate::relay::relay;
use crate::stats::{CountedStream, Stats};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long to wait for the client's first bytes once the outbound is up.
const FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(50);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const UDP_FIRST_PACKET_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Dispatcher {
    pub outbounds: OutboundManager,
    pub stats: Arc<Stats>,
    /// Outbound for traffic no rule matched.
    pub final_tag: Arc<str>,
}

impl Dispatcher {
    fn route(&self, _sess: &Session) -> (Arc<str>, Arc<dyn Outbound>) {
        let outbound = self
            .outbounds
            .get(&self.final_tag)
            .expect("final outbound exists (validated at build)");
        (self.final_tag.clone(), outbound.clone())
    }

    /// Relays one TCP-like stream accepted by an inbound.
    pub async fn dispatch_stream(&self, sess: Session, stream: BoxStream) {
        let (tag, outbound) = self.route(&sess);
        let source = sess
            .source
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".into());
        info!(target: "sybau::route", "[{}] tcp {} -> {} via {} ({})", sess.id, source, sess.target, tag, sess.inbound_tag);
        let guard = self.stats.track(&sess, &tag);
        let mut client = CountedStream::new(stream, guard.counters.clone());

        // While the outbound connects, collect the first bytes from the
        // client: protocol streams put their header and the first payload
        // into one packet.
        let mut first = BytesMut::with_capacity(16 * 1024);
        let mut have_first = false;
        let mut remote = {
            let connect = tokio::time::timeout(CONNECT_TIMEOUT, outbound.connect(&sess));
            tokio::pin!(connect);
            loop {
                tokio::select! {
                    r = &mut connect => match r {
                        Ok(Ok(s)) => break s,
                        Ok(Err(e)) => {
                            warn!(target: "sybau::route", "[{}] {} via {}: {}", sess.id, sess.target, tag, e);
                            return;
                        }
                        Err(_) => {
                            warn!(target: "sybau::route", "[{}] {} via {}: connect timed out", sess.id, sess.target, tag);
                            return;
                        }
                    },
                    r = client.read_buf(&mut first), if !have_first => match r {
                        Ok(n) if n > 0 => have_first = true,
                        // The client left before the connection was made.
                        _ => return,
                    },
                    _ = guard.cancel.cancelled() => return,
                }
            }
        };
        if !have_first {
            // Server-speaks-first protocols send nothing; do not wait long.
            let _ = tokio::time::timeout(FIRST_PAYLOAD_WAIT, client.read_buf(&mut first)).await;
        }
        let started = async {
            if !first.is_empty() {
                remote.write_all(&first).await?;
            }
            remote.flush().await
        };
        if let Err(e) = started.await {
            warn!(target: "sybau::route", "[{}] {} via {}: {}", sess.id, sess.target, tag, e);
            return;
        }
        drop(first);
        tokio::select! {
            r = relay(client, remote) => {
                if let Err(e) = r {
                    debug!(target: "sybau::route", "[{}] {} closed: {}", sess.id, sess.target, e);
                }
            }
            _ = guard.cancel.cancelled() => {
                debug!(target: "sybau::route", "[{}] closed by control API", sess.id);
            }
        }
    }

    /// Relays one UDP association. `inbound.recv_from` yields client
    /// datagrams with their destinations; replies go back via `send_to`.
    /// The outbound is chosen by the destination of the first datagram.
    pub async fn dispatch_packet(&self, mut sess: Session, inbound: ArcPacketConn) {
        let mut buf = vec![0u8; 65535];
        let (n, first_dst) =
            match tokio::time::timeout(UDP_FIRST_PACKET_TIMEOUT, inbound.recv_from(&mut buf)).await
            {
                Ok(Ok(v)) => v,
                _ => return,
            };
        sess.target = first_dst.clone();
        let (tag, outbound) = self.route(&sess);
        let source = sess
            .source
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".into());
        info!(target: "sybau::route", "[{}] udp {} -> {} via {} ({})", sess.id, source, sess.target, tag, sess.inbound_tag);
        let guard = self.stats.track(&sess, &tag);
        let remote = match tokio::time::timeout(CONNECT_TIMEOUT, outbound.bind(&sess)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                warn!(target: "sybau::route", "[{}] udp {} via {}: {}", sess.id, sess.target, tag, e);
                return;
            }
            Err(_) => {
                warn!(target: "sybau::route", "[{}] udp {} via {}: bind timed out", sess.id, sess.target, tag);
                return;
            }
        };
        if let Err(e) = remote.send_to(&buf[..n], &first_dst).await {
            debug!(target: "sybau::route", "[{}] udp send to {}: {}", sess.id, first_dst, e);
        }
        guard.counters.add_up(n);

        let counters = guard.counters.clone();
        let (inbound2, remote2) = (inbound.clone(), remote.clone());
        let up = async move {
            loop {
                let (n, dst) = inbound2.recv_from(&mut buf).await?;
                counters.add_up(n);
                // A single unreachable destination must not kill the association.
                let _ = remote2.send_to(&buf[..n], &dst).await;
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        };
        let counters = guard.counters.clone();
        let down =
            async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let (n, from) =
                        match tokio::time::timeout(UDP_IDLE_TIMEOUT, remote.recv_from(&mut buf))
                            .await
                        {
                            Ok(r) => r?,
                            Err(_) => return Ok::<(), std::io::Error>(()),
                        };
                    counters.add_down(n);
                    inbound.send_to(&buf[..n], &from).await?;
                }
            };
        tokio::select! {
            r = up => { if let Err(e) = r { debug!(target: "sybau::route", "[{}] udp closed: {}", sess.id, e); } }
            r = down => { if let Err(e) = r { debug!(target: "sybau::route", "[{}] udp closed: {}", sess.id, e); } }
            _ = guard.cancel.cancelled() => {}
        }
    }
}
