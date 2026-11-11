//! Glue between inbounds and outbounds: sniffs and routes each session,
//! connects the chosen outbound and relays traffic while keeping statistics.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use sybau_common::{ArcPacketConn, BoxStream, Host, Network, Outbound, Resolver, Session, Target};
use sybau_route::rule::{MatchContext, Network as RuleNetwork};
use sybau_route::sniff::{sniff_stream, QuicSniffer, SniffResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::outbound::OutboundManager;
use crate::relay::relay;
use crate::route::{Action, DomainStrategy, Router};
use crate::stats::{CountedStream, Stats};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long to wait for the client's first bytes once the outbound is up.
const FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(50);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const UDP_FIRST_PACKET_TIMEOUT: Duration = Duration::from_secs(60);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Bytes collected at most while sniffing a stream.
const SNIFF_LIMIT: usize = 16 * 1024;
/// Datagrams collected at most while sniffing QUIC.
const SNIFF_DATAGRAMS: usize = 4;

pub struct Dispatcher {
    pub outbounds: OutboundManager,
    pub stats: Arc<Stats>,
    pub router: Router,
    pub resolver: Arc<dyn Resolver>,
    pub dns: Option<Arc<crate::dns::DnsResolver>>,
    /// Direct path for sessions that skip the rules (`Session::bypass`).
    pub bypass: Arc<dyn Outbound>,
}

/// The outbound picked for a session.
enum Route {
    Outbound(Arc<str>, Arc<dyn Outbound>, String),
    Reject(String),
}

fn source_label(sess: &Session) -> String {
    sess.source
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".into())
}

/// A sniffed host is used only when it is a plausible domain name.
fn usable_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.parse::<IpAddr>().is_err()
        && !host.starts_with(['.', '-'])
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

impl Dispatcher {
    /// Maps a fake-ip target back to its domain. `false` if the target is
    /// a fake address nobody asked for (stale or forged).
    fn restore_fake_ip(&self, sess: &mut Session) -> bool {
        let (Some(dns), Some(ip)) = (&self.dns, sess.target.ip()) else {
            return true;
        };
        let Some(pool) = dns.fakeip() else {
            return true;
        };
        if !pool.is_fake(ip) {
            return true;
        }
        match pool.lookup(ip) {
            Some(domain) => {
                sess.target = Target::new(Host::Domain(domain), sess.target.port);
                true
            }
            None => {
                warn!(target: "sybau::route", "[{}] {} is a fake-ip address with no domain behind it", sess.id, sess.target);
                false
            }
        }
    }

    /// Process lookup for rules that ask for it.
    async fn resolve_process(&self, sess: &mut Session) {
        if !self.router.needs_process || sess.process_path.is_some() {
            return;
        }
        let Some(source) = sess.source else { return };
        let network = sess.network;
        let found =
            tokio::task::spawn_blocking(move || crate::process::find(network, source, None))
                .await
                .ok()
                .flatten();
        if let Some(info) = found {
            if !info.path.is_empty() {
                sess.process_path = Some(Arc::from(info.path.as_str()));
                sess.process_name = Some(Arc::from(info.name.as_str()));
            }
        }
    }

    async fn resolve_ips(&self, domain: &str) -> Vec<IpAddr> {
        match tokio::time::timeout(RESOLVE_TIMEOUT, self.resolver.resolve(domain)).await {
            Ok(Ok(ips)) => ips,
            _ => Vec::new(),
        }
    }

    async fn route(&self, sess: &Session) -> Route {
        if sess.bypass {
            return Route::Outbound(
                Arc::from("direct"),
                self.bypass.clone(),
                "bypass".to_string(),
            );
        }
        let target_domain = sess.target.domain().map(str::to_string);
        let domain = sess.sniffed_host.clone().or(target_domain.clone());
        let mut ips: Vec<IpAddr> = sess.target.ip().into_iter().collect();
        let strategy = self.router.domain_strategy;
        if strategy == DomainStrategy::IpOnDemand && self.router.needs_ip && ips.is_empty() {
            if let Some(d) = &target_domain {
                ips = self.resolve_ips(d).await;
            }
        }
        let network = match sess.network {
            Network::Tcp => RuleNetwork::Tcp,
            Network::Udp => RuleNetwork::Udp,
        };
        let decide = |ips: &[IpAddr]| {
            let ctx = MatchContext {
                network: Some(network),
                domain: domain.as_deref(),
                dest_ips: ips,
                dest_port: sess.target.port,
                source_ip: sess.source.map(|s| s.ip().to_canonical()),
                source_port: sess.source.map(|s| s.port()),
                inbound: &sess.inbound_tag,
                protocol: sess.protocol,
                user: sess.user.as_deref(),
                process_name: sess.process_name.as_deref(),
                process_path: sess.process_path.as_deref(),
                package_name: None,
                query_type: None,
            };
            self.router.decide(&ctx).map(|d| (d.action.clone(), d.rule))
        };
        let mut decision = decide(&ips);
        if decision.is_none()
            && strategy == DomainStrategy::IpIfNonMatch
            && self.router.needs_ip
            && ips.is_empty()
        {
            if let Some(d) = &target_domain {
                ips = self.resolve_ips(d).await;
                if !ips.is_empty() {
                    decision = decide(&ips);
                }
            }
        }
        let (action, why) = match decision {
            Some((action, Some(i))) => (action, format!("rule {i}")),
            _ => (
                Action::Route(self.router.final_tag.clone()),
                "final".to_string(),
            ),
        };
        match action {
            Action::Reject => Route::Reject(why),
            Action::Route(tag) => {
                let outbound = self
                    .outbounds
                    .get(&tag)
                    .expect("route targets are validated at build")
                    .clone();
                Route::Outbound(tag, outbound, why)
            }
        }
    }

    /// Reads the client's first bytes until the protocol is known.
    async fn sniff_stream(
        &self,
        sess: &mut Session,
        client: &mut CountedStream<BoxStream>,
        first: &mut BytesMut,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + sess.sniff.timeout;
        loop {
            match sniff_stream(first) {
                SniffResult::Found(found) => {
                    sess.protocol = Some(found.protocol);
                    sess.sniffed_host = found.host.filter(|h| usable_host(h));
                    return true;
                }
                SniffResult::Unknown => return true,
                SniffResult::NeedMore if first.len() >= SNIFF_LIMIT => return true,
                SniffResult::NeedMore => {}
            }
            match tokio::time::timeout_at(deadline, client.read_buf(first)).await {
                Ok(Ok(n)) if n > 0 => {}
                // The client closed the connection.
                Ok(_) => return false,
                // Nothing (more) within the timeout: server-speaks-first or slow client.
                Err(_) => return true,
            }
        }
    }

    fn apply_override(sess: &mut Session) {
        if !sess.sniff.override_destination {
            return;
        }
        if let (Host::Ip(_), Some(host)) = (&sess.target.host, &sess.sniffed_host) {
            sess.target = Target::new(Host::Domain(host.clone()), sess.target.port);
        }
    }

    /// Relays one TCP-like stream accepted by an inbound.
    pub async fn dispatch_stream(&self, mut sess: Session, stream: BoxStream) {
        if !self.restore_fake_ip(&mut sess) {
            return;
        }
        let tracker = crate::stats::Counters::detached();
        let mut client = CountedStream::new(stream, tracker);
        let mut first = BytesMut::with_capacity(4096);
        if sess.sniff.enabled && !self.sniff_stream(&mut sess, &mut client, &mut first).await {
            return;
        }
        Self::apply_override(&mut sess);
        self.resolve_process(&mut sess).await;

        let (tag, outbound, why) = match self.route(&sess).await {
            Route::Outbound(tag, outbound, why) => (tag, outbound, why),
            Route::Reject(why) => {
                info!(target: "sybau::route", "[{}] tcp {} -> {}{} rejected ({}, {})", sess.id, source_label(&sess), sess.target, host_note(&sess), why, sess.inbound_tag);
                return;
            }
        };
        info!(target: "sybau::route", "[{}] tcp {} -> {}{} via {} ({}, {})", sess.id, source_label(&sess), sess.target, host_note(&sess), tag, why, sess.inbound_tag);
        let guard = self.stats.track(&sess, &tag);
        // Bytes read while sniffing are counted now that the session exists.
        guard.counters.add_up(first.len());
        client.set_counters(guard.counters.clone());

        // While the outbound connects, collect the first bytes from the
        // client (if sniffing did not already): protocol streams put their
        // header and the first payload into one packet.
        let mut have_first = !first.is_empty();
        let mut remote = {
            let connect = tokio::time::timeout(CONNECT_TIMEOUT, outbound.connect(&sess));
            tokio::pin!(connect);
            loop {
                tokio::select! {
                    r = &mut connect => match r {
                        Ok(Ok(s)) => {
                            guard.set_chain(sess.chain.lock().clone());
                            break s;
                        }
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
        if !have_first && !sess.sniff.enabled {
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
    /// The outbound is chosen by the first datagram(s).
    pub async fn dispatch_packet(&self, mut sess: Session, inbound: ArcPacketConn) {
        let mut buf = vec![0u8; 65535];
        let (n, first_dst) =
            match tokio::time::timeout(UDP_FIRST_PACKET_TIMEOUT, inbound.recv_from(&mut buf)).await
            {
                Ok(Ok(v)) => v,
                _ => return,
            };
        let mut pending: Vec<(Vec<u8>, Target)> = vec![(buf[..n].to_vec(), first_dst.clone())];
        sess.target = first_dst.clone();
        if !self.restore_fake_ip(&mut sess) {
            return;
        }

        if sess.sniff.enabled {
            let mut sniffer = QuicSniffer::new();
            let deadline = tokio::time::Instant::now() + sess.sniff.timeout;
            let mut result = sniffer.feed(&pending[0].0);
            while result == SniffResult::NeedMore && pending.len() < SNIFF_DATAGRAMS {
                match tokio::time::timeout_at(deadline, inbound.recv_from(&mut buf)).await {
                    Ok(Ok((n, dst))) => {
                        pending.push((buf[..n].to_vec(), dst.clone()));
                        if dst == first_dst {
                            result = sniffer.feed(&buf[..n]);
                        }
                    }
                    Ok(Err(_)) => return,
                    Err(_) => break,
                }
            }
            if result == SniffResult::NeedMore {
                result = sniffer.finish();
            }
            if let SniffResult::Found(found) = result {
                sess.protocol = Some(found.protocol);
                sess.sniffed_host = found.host.filter(|h| usable_host(h));
            }
        }
        // With override, datagrams for the sniffed IP go to the domain.
        let rewrite = sess.sniff.override_destination
            && sess.target.ip().is_some()
            && sess.sniffed_host.is_some();
        let original_dst = sess.target.clone();
        Self::apply_override(&mut sess);
        let rewritten = sess.target.clone();
        let map_dst = move |dst: Target| {
            if rewrite && dst == original_dst {
                rewritten.clone()
            } else {
                dst
            }
        };
        self.resolve_process(&mut sess).await;

        let (tag, outbound, why) = match self.route(&sess).await {
            Route::Outbound(tag, outbound, why) => (tag, outbound, why),
            Route::Reject(why) => {
                info!(target: "sybau::route", "[{}] udp {} -> {}{} rejected ({}, {})", sess.id, source_label(&sess), sess.target, host_note(&sess), why, sess.inbound_tag);
                return;
            }
        };
        info!(target: "sybau::route", "[{}] udp {} -> {}{} via {} ({}, {})", sess.id, source_label(&sess), sess.target, host_note(&sess), tag, why, sess.inbound_tag);
        let guard = self.stats.track(&sess, &tag);
        let remote = match tokio::time::timeout(CONNECT_TIMEOUT, outbound.bind(&sess)).await {
            Ok(Ok(c)) => {
                guard.set_chain(sess.chain.lock().clone());
                c
            }
            Ok(Err(e)) => {
                warn!(target: "sybau::route", "[{}] udp {} via {}: {}", sess.id, sess.target, tag, e);
                return;
            }
            Err(_) => {
                warn!(target: "sybau::route", "[{}] udp {} via {}: bind timed out", sess.id, sess.target, tag);
                return;
            }
        };
        for (data, dst) in pending {
            let dst = map_dst(dst);
            if let Err(e) = remote.send_to(&data, &dst).await {
                debug!(target: "sybau::route", "[{}] udp send to {}: {}", sess.id, dst, e);
            }
            guard.counters.add_up(data.len());
        }

        let counters = guard.counters.clone();
        let (inbound2, remote2) = (inbound.clone(), remote.clone());
        let up = async move {
            loop {
                let (n, dst) = inbound2.recv_from(&mut buf).await?;
                counters.add_up(n);
                // A single unreachable destination must not kill the association.
                let _ = remote2.send_to(&buf[..n], &map_dst(dst)).await;
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

/// ` [tls example.com]` when sniffing found something, for the log.
fn host_note(sess: &Session) -> String {
    match (sess.protocol, &sess.sniffed_host) {
        (Some(p), Some(h)) => format!(" [{p} {h}]"),
        (Some(p), None) => format!(" [{p}]"),
        _ => String::new(),
    }
}
