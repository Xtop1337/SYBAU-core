//! DNS resolver of the core: picks a server per query by rules, applies
//! hosts, cache, fake-ip and the IPv4/IPv6 strategy.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use sybau_common::{
    io_err, ArcPacketConn, BoxStream, Host, Outbound, Resolver, Session, SocketOpts,
    SystemResolver, Target,
};
use sybau_config::route::{DnsConfig, RouteConfig};
use sybau_dns::cache::Cache;
use sybau_dns::fakeip::FakeIp;
use sybau_dns::message::{
    self, parse_client_subnet_option, ClientSubnet, Message, Record, RecordData, CLASS_IN,
    RCODE_NOERROR, TYPE_A, TYPE_AAAA,
};
use sybau_dns::upstream::{self, Address, Upstream};
use sybau_route::geodata::GeoCache;
use sybau_route::rule::{MatchContext, Rule, RuleSet};
use tracing::debug;

use crate::outbound::{internal_direct, OutboundManager};
use crate::route::{compile_rule, Assets};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    AsIs,
    PreferV4,
    PreferV6,
    V4Only,
    V6Only,
}

impl Strategy {
    pub fn parse(text: Option<&str>) -> Result<Option<Self>> {
        Ok(Some(match text {
            None => return Ok(None),
            Some(t) => match t.to_ascii_lowercase().as_str() {
                "as_is" | "asis" | "" => Strategy::AsIs,
                "prefer_ipv4" | "useipv4v6" => Strategy::PreferV4,
                "prefer_ipv6" | "useipv6v4" => Strategy::PreferV6,
                "ipv4_only" | "useipv4" => Strategy::V4Only,
                "ipv6_only" | "useipv6" => Strategy::V6Only,
                other => bail!("unknown DNS strategy `{other}`"),
            },
        }))
    }

    fn types(self) -> &'static [u16] {
        match self {
            Strategy::AsIs | Strategy::PreferV4 => &[TYPE_A, TYPE_AAAA],
            Strategy::PreferV6 => &[TYPE_AAAA, TYPE_A],
            Strategy::V4Only => &[TYPE_A],
            Strategy::V6Only => &[TYPE_AAAA],
        }
    }
}

enum Kind {
    Upstream(Arc<dyn Upstream>),
    FakeIp,
}

struct Server {
    kind: Kind,
    strategy: Option<Strategy>,
    client_subnet: Option<ClientSubnet>,
}

/// Resolves the server's own domain before dialing it, so that a DNS
/// server behind a direct outbound does not depend on DNS itself.
struct Bootstrapped {
    inner: Arc<dyn Outbound>,
    bootstrap: Arc<dyn Resolver>,
}

impl Bootstrapped {
    async fn resolve(&self, sess: &Session) -> io::Result<Session> {
        let mut s = sess.clone();
        if let Host::Domain(d) = &sess.target.host {
            let ip = *self
                .bootstrap
                .resolve(d)
                .await?
                .first()
                .ok_or_else(|| io_err(io::ErrorKind::NotFound, d.clone()))?;
            s.target = Target::new(Host::Ip(ip), sess.target.port);
        }
        Ok(s)
    }
}

#[async_trait]
impl Outbound for Bootstrapped {
    fn tag(&self) -> &str {
        self.inner.tag()
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    async fn connect(&self, sess: &Session) -> io::Result<BoxStream> {
        self.inner.connect(&self.resolve(sess).await?).await
    }
    async fn bind(&self, sess: &Session) -> io::Result<ArcPacketConn> {
        let s = self.resolve(sess).await?;
        let conn = self.inner.bind(&s).await?;
        Ok(Arc::new(RewriteDst {
            inner: conn,
            from: sess.target.clone(),
            to: s.target,
        }))
    }
}

/// Sends datagrams for the server's domain to its resolved address.
struct RewriteDst {
    inner: ArcPacketConn,
    from: Target,
    to: Target,
}

#[async_trait]
impl sybau_common::PacketConn for RewriteDst {
    async fn send_to(&self, buf: &[u8], dst: &Target) -> io::Result<usize> {
        let dst = if *dst == self.from { &self.to } else { dst };
        self.inner.send_to(buf, dst).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let (n, from) = self.inner.recv_from(buf).await?;
        Ok((
            n,
            if from == self.to {
                self.from.clone()
            } else {
                from
            },
        ))
    }
}

/// Resolver backed by one upstream, used as `address_resolver`.
struct UpstreamResolver(Arc<dyn Upstream>);

#[async_trait]
impl Resolver for UpstreamResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let mut out = Vec::new();
        for qtype in [TYPE_A, TYPE_AAAA] {
            if let Ok(reply) = self
                .0
                .exchange(&Message::query(rand::random(), host, qtype))
                .await
            {
                out.extend(reply.addresses());
            }
        }
        if out.is_empty() {
            return Err(io_err(
                io::ErrorKind::NotFound,
                format!("cannot resolve {host}"),
            ));
        }
        Ok(out)
    }
}

/// DNS settings used when the config has none but needs the DNS module:
/// the system's servers.
pub fn default_config() -> DnsConfig {
    serde_json::from_value(serde_json::json!({
        "servers": [{"tag": "local", "address": "local"}]
    }))
    .expect("valid default DNS config")
}

/// `local` while a TUN is active: the system's DNS servers, asked
/// through sockets that bypass the TUN.
fn system_upstream(tag: &str, direct: Arc<dyn Outbound>) -> Arc<dyn Upstream> {
    let servers = upstream::system_nameservers();
    if servers.is_empty() {
        tracing::warn!(target: "sybau::dns", "DNS server `{tag}`: no system DNS servers found; with the TUN active, system lookups may loop. Set an explicit server address.");
        return Arc::new(upstream::Local);
    }
    let list: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    debug!(target: "sybau::dns", "DNS server `{tag}`: system servers {}", list.join(", "));
    let upstreams = servers
        .into_iter()
        .map(|addr| {
            upstream::build(&Address::Udp(Target::from(addr)), direct.clone(), None)
                .expect("plain UDP upstream")
        })
        .collect();
    Arc::new(upstream::Fallback::new(
        format!("local ({})", list.join(", ")),
        upstreams,
    ))
}

pub struct DnsResolver {
    servers: HashMap<String, Server>,
    rules: Vec<(Rule, String)>,
    final_server: String,
    strategy: Strategy,
    hosts: HashMap<String, Vec<IpAddr>>,
    cache: Option<Cache>,
    fakeip: Option<FakeIp>,
    client_subnet: Option<ClientSubnet>,
}

#[allow(clippy::too_many_arguments)]
impl DnsResolver {
    pub fn build(
        cfg: &DnsConfig,
        route: &RouteConfig,
        outbounds: &OutboundManager,
        assets: &Assets,
        geo: &GeoCache,
        rule_sets: &HashMap<String, Arc<RuleSet>>,
        socket: SocketOpts,
        tun_active: bool,
    ) -> Result<Self> {
        let system: Arc<dyn Resolver> = Arc::new(SystemResolver);
        let direct = internal_direct(system.clone(), socket);
        let parsed: Vec<(&sybau_config::route::DnsServerConfig, Address)> = cfg
            .servers
            .iter()
            .map(|s| {
                Ok((
                    s,
                    Address::parse(&s.address)
                        .with_context(|| format!("DNS server `{}`", s.tag))?,
                ))
            })
            .collect::<Result<_>>()?;

        // Upstreams without address_resolver first, so they can bootstrap others.
        let mut upstreams: HashMap<String, Arc<dyn Upstream>> = HashMap::new();
        let mut servers = HashMap::new();
        for pass in 0..2 {
            for (s, address) in &parsed {
                if servers.contains_key(&s.tag) || (pass == 0 && s.address_resolver.is_some()) {
                    continue;
                }
                let kind = if *address == Address::FakeIp {
                    Kind::FakeIp
                } else {
                    let detour = match &s.detour {
                        Some(tag) => outbounds
                            .get(tag)
                            .ok_or_else(|| anyhow!("DNS server `{}`: unknown detour", s.tag))?
                            .clone(),
                        None => direct.clone(),
                    };
                    let bootstrap: Arc<dyn Resolver> = match &s.address_resolver {
                        Some(r) => Arc::new(UpstreamResolver(
                            upstreams.get(r).cloned().ok_or_else(|| anyhow!("DNS server `{}`: address_resolver `{r}` must be a network server without its own address_resolver", s.tag))?,
                        )),
                        None => system.clone(),
                    };
                    // Proxies resolve the server name remotely; direct paths bootstrap it.
                    let outbound: Arc<dyn Outbound> = if detour.kind() == "direct" {
                        Arc::new(Bootstrapped {
                            inner: detour,
                            bootstrap,
                        })
                    } else {
                        detour
                    };
                    let upstream = if *address == Address::Local && tun_active {
                        system_upstream(&s.tag, direct.clone())
                    } else {
                        upstream::build(address, outbound, s.tls.as_ref())
                            .with_context(|| format!("DNS server `{}`", s.tag))?
                    };
                    upstreams.insert(s.tag.clone(), upstream.clone());
                    Kind::Upstream(upstream)
                };
                let client_subnet = s
                    .client_subnet
                    .as_deref()
                    .map(parse_client_subnet_option)
                    .transpose()?;
                servers.insert(
                    s.tag.clone(),
                    Server {
                        kind,
                        strategy: Strategy::parse(s.strategy.as_deref())?,
                        client_subnet,
                    },
                );
            }
        }

        let mut rules = Vec::with_capacity(cfg.rules.len());
        for (i, r) in cfg.rules.iter().enumerate() {
            let types = r
                .query_type
                .iter()
                .map(|t| {
                    message::parse_type(t)
                        .ok_or_else(|| anyhow!("dns.rules[{i}]: unknown query_type `{t}`"))
                })
                .collect::<Result<Vec<_>>>()?;
            let rule = compile_rule(route, assets, geo, rule_sets, &r.conditions, types)
                .with_context(|| format!("dns.rules[{i}]"))?;
            rules.push((rule, r.server.clone()));
        }

        let mut hosts = HashMap::new();
        for (name, addrs) in &cfg.hosts {
            let ips = addrs
                .iter()
                .map(|a| {
                    a.parse::<IpAddr>()
                        .map_err(|_| anyhow!("dns.hosts `{name}`: `{a}` is not an IP address"))
                })
                .collect::<Result<Vec<_>>>()?;
            hosts.insert(sybau_route::domain::normalize(name), ips);
        }
        let uses_fakeip = servers.values().any(|s| matches!(s.kind, Kind::FakeIp));
        let fakeip = if uses_fakeip || cfg.fakeip.is_some() {
            let f = cfg.fakeip.clone().unwrap_or_default();
            Some(FakeIp::new(
                f.inet4_range.as_deref(),
                f.inet6_range.as_deref(),
                65536,
            )?)
        } else {
            None
        };
        let cache = cfg
            .cache
            .enabled
            .then(|| Cache::new(cfg.cache.max_entries, cfg.cache.min_ttl, cfg.cache.max_ttl));
        Ok(Self {
            servers,
            rules,
            final_server: cfg
                .r#final
                .clone()
                .unwrap_or_else(|| cfg.servers[0].tag.clone()),
            strategy: Strategy::parse(cfg.strategy.as_deref())?.unwrap_or(Strategy::AsIs),
            hosts,
            cache,
            fakeip,
            client_subnet: cfg
                .client_subnet
                .as_deref()
                .map(parse_client_subnet_option)
                .transpose()?,
        })
    }

    /// Server for a query. `internal` lookups (made by the core to dial
    /// a domain) never get fake addresses: like sing-box, fake-ip only
    /// answers applications.
    fn pick(&self, name: &str, qtype: u16, internal: bool) -> (&str, &Server) {
        let ctx = MatchContext {
            domain: Some(name),
            query_type: Some(qtype),
            ..Default::default()
        };
        let usable = |tag: &str| !(internal && matches!(self.servers[tag].kind, Kind::FakeIp));
        let tag = self
            .rules
            .iter()
            .find(|(r, t)| usable(t) && r.matches(&ctx))
            .map(|(_, t)| t.as_str())
            .or_else(|| usable(&self.final_server).then_some(self.final_server.as_str()))
            .or_else(|| {
                self.servers
                    .iter()
                    .find(|(t, _)| usable(t))
                    .map(|(t, _)| t.as_str())
            })
            .unwrap_or(&self.final_server);
        (tag, &self.servers[tag])
    }

    pub fn fakeip(&self) -> Option<&FakeIp> {
        self.fakeip.as_ref()
    }

    pub fn flush(&self) -> usize {
        self.cache.as_ref().map(Cache::clear).unwrap_or(0)
    }

    fn answer(
        query: &Message,
        name: &str,
        qtype: u16,
        ips: impl IntoIterator<Item = IpAddr>,
        ttl: u32,
    ) -> Message {
        let mut reply = query.reply(RCODE_NOERROR);
        for ip in ips {
            let data = match (ip, qtype) {
                (IpAddr::V4(v4), TYPE_A) => RecordData::A(v4),
                (IpAddr::V6(v6), TYPE_AAAA) => RecordData::Aaaa(v6),
                _ => continue,
            };
            reply.answers.push(Record {
                name: name.to_string(),
                rtype: qtype,
                class: CLASS_IN,
                ttl,
                data,
            });
        }
        reply
    }

    /// Answers a query from an application.
    pub async fn exchange(&self, query: &Message) -> Message {
        self.answer_query(query, false).await
    }

    async fn answer_query(&self, query: &Message, internal: bool) -> Message {
        let Some(q) = query.questions.first() else {
            return query.reply(message::RCODE_FORMERR);
        };
        let (name, qtype) = (q.name.clone(), q.qtype);
        if let Some(ips) = self.hosts.get(&name) {
            if qtype == TYPE_A || qtype == TYPE_AAAA {
                return Self::answer(query, &name, qtype, ips.iter().copied(), 600);
            }
        }
        let (tag, server) = self.pick(&name, qtype, internal);
        let strategy = server.strategy.unwrap_or(self.strategy);
        if (strategy == Strategy::V4Only && qtype == TYPE_AAAA)
            || (strategy == Strategy::V6Only && qtype == TYPE_A)
        {
            return query.reply(RCODE_NOERROR);
        }
        match &server.kind {
            Kind::FakeIp if internal => upstream::servfail(query),
            Kind::FakeIp => {
                let pool = self
                    .fakeip
                    .as_ref()
                    .expect("built when a fakeip server exists");
                let ip: Option<IpAddr> = match qtype {
                    TYPE_A => pool.v4(&name).map(Into::into),
                    TYPE_AAAA => pool.v6(&name).map(Into::into),
                    _ => None,
                };
                Self::answer(query, &name, qtype, ip, 1)
            }
            Kind::Upstream(up) => {
                if let Some(cache) = &self.cache {
                    if let Some(mut hit) = cache.get(tag, &name, qtype) {
                        hit.id = query.id;
                        return hit;
                    }
                }
                let mut q = query.clone();
                q.client_subnet = server
                    .client_subnet
                    .clone()
                    .or_else(|| self.client_subnet.clone())
                    .or(q.client_subnet);
                match up.exchange(&q).await {
                    Ok(reply) => {
                        debug!(target: "sybau::dns", "{name} {qtype} via {tag} ({}): {:?}", up.name(), reply.addresses());
                        if let Some(cache) = &self.cache {
                            if reply.rcode == RCODE_NOERROR
                                || reply.rcode == message::RCODE_NXDOMAIN
                            {
                                cache.put(tag, &name, qtype, &reply);
                            }
                        }
                        reply
                    }
                    Err(e) => {
                        debug!(target: "sybau::dns", "{name} {qtype} via {tag} ({}): {e}", up.name());
                        upstream::servfail(query)
                    }
                }
            }
        }
    }

    /// Addresses of `name` following the strategy of the chosen server.
    pub async fn lookup(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        let name = sybau_route::domain::normalize(name);
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let (_, server) = self.pick(&name, TYPE_A, true);
        let strategy = server.strategy.unwrap_or(self.strategy);
        let ask = |qtype: u16| {
            let query = Message::query(rand::random(), &name, qtype);
            async move { self.answer_query(&query, true).await }
        };
        let replies = match strategy.types() {
            [only] => vec![ask(*only).await],
            [first, second] => {
                let (a, b) = tokio::join!(ask(*first), ask(*second));
                vec![a, b]
            }
            _ => unreachable!("one or two query types"),
        };
        let mut ips: Vec<IpAddr> = replies.iter().flat_map(Message::addresses).collect();
        ips.dedup();
        if ips.is_empty() {
            return Err(io_err(
                io::ErrorKind::NotFound,
                format!("no addresses for {name}"),
            ));
        }
        Ok(ips)
    }
}

#[async_trait]
impl Resolver for DnsResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.lookup(host).await
    }
}

/// Resolver handed to outbounds before the DNS module exists; it forwards
/// to the DNS module once the configuration is complete.
#[derive(Default)]
pub struct LateResolver {
    target: OnceLock<Arc<dyn Resolver>>,
}

impl LateResolver {
    pub fn set(&self, resolver: Arc<dyn Resolver>) {
        let _ = self.target.set(resolver);
    }
}

#[async_trait]
impl Resolver for LateResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        match self.target.get() {
            Some(r) => r.resolve(host).await,
            None => SystemResolver.resolve(host).await,
        }
    }
}

/// Answers one DNS message from an application; `None` for garbage.
pub async fn answer(dns: &DnsResolver, packet: &[u8]) -> Option<Vec<u8>> {
    let query = Message::parse(packet).ok()?;
    if query.response {
        return None;
    }
    dns.exchange(&query).await.encode().ok()
}

const DNS_TCP_IDLE: std::time::Duration = std::time::Duration::from_secs(30);

/// DNS over TCP (length-prefixed messages), answered in order.
pub async fn serve_tcp<S>(dns: &DnsResolver, mut stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 65535];
    loop {
        let len = match tokio::time::timeout(DNS_TCP_IDLE, stream.read_u16()).await {
            Ok(Ok(len)) => usize::from(len),
            _ => return,
        };
        if stream.read_exact(&mut buf[..len]).await.is_err() {
            return;
        }
        let Some(reply) = answer(dns, &buf[..len]).await else {
            return;
        };
        let Ok(rlen) = u16::try_from(reply.len()) else {
            return;
        };
        let mut out = Vec::with_capacity(reply.len() + 2);
        out.extend_from_slice(&rlen.to_be_bytes());
        out.extend_from_slice(&reply);
        if stream.write_all(&out).await.is_err() || stream.flush().await.is_err() {
            return;
        }
    }
}

/// DNS module handed to `dns` outbounds once it is built (they are built
/// before it, since DNS servers may dial through outbounds).
pub type DnsSlot = Arc<OnceLock<Arc<DnsResolver>>>;

/// `dns` outbound: answers the queries it receives instead of relaying
/// them (Xray `dns` outbound, sing-box `hijack-dns`).
pub struct DnsOutbound {
    tag: Arc<str>,
    dns: DnsSlot,
}

impl DnsOutbound {
    pub fn new(tag: Arc<str>, dns: DnsSlot) -> Self {
        Self { tag, dns }
    }

    fn resolver(&self) -> io::Result<Arc<DnsResolver>> {
        self.dns
            .get()
            .cloned()
            .ok_or_else(|| io_err(io::ErrorKind::NotConnected, "DNS module is not ready"))
    }
}

#[async_trait]
impl Outbound for DnsOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "dns"
    }
    async fn connect(&self, _sess: &Session) -> io::Result<BoxStream> {
        let dns = self.resolver()?;
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move { serve_tcp(&dns, theirs).await });
        Ok(Box::new(ours))
    }
    async fn bind(&self, _sess: &Session) -> io::Result<ArcPacketConn> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Ok(Arc::new(DnsPackets {
            dns: self.resolver()?,
            replies: tx,
            pending: tokio::sync::Mutex::new(rx),
        }))
    }
}

/// Queries go in with `send_to`; answers come back from `recv_from` as if
/// sent by the server they were addressed to.
struct DnsPackets {
    dns: Arc<DnsResolver>,
    replies: tokio::sync::mpsc::UnboundedSender<(Vec<u8>, Target)>,
    pending: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, Target)>>,
}

#[async_trait]
impl sybau_common::PacketConn for DnsPackets {
    async fn send_to(&self, buf: &[u8], dst: &Target) -> io::Result<usize> {
        let (dns, tx, packet, dst) = (
            self.dns.clone(),
            self.replies.clone(),
            buf.to_vec(),
            dst.clone(),
        );
        // Answered concurrently: A and AAAA often arrive together.
        tokio::spawn(async move {
            if let Some(reply) = answer(&dns, &packet).await {
                let _ = tx.send((reply, dst));
            }
        });
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let (reply, from) = self
            .pending
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io_err(io::ErrorKind::UnexpectedEof, "closed"))?;
        let n = reply.len().min(buf.len());
        buf[..n].copy_from_slice(&reply[..n]);
        Ok((n, from))
    }
}
