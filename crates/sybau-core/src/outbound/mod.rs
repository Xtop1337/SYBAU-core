//! Outbound construction and the built-in `direct` / `block` outbounds.

pub mod group;
pub mod proxy;
pub mod shadowsocks;
pub mod udp;
pub mod upstream;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use sybau_common::net::ProtectFn;
use sybau_common::{
    io_err, ArcPacketConn, BoxStream, Dialer, Outbound, OutboundDialer, Resolver, Session,
    SocketOpts, SystemDialer,
};
use sybau_config::{OutboundConfig, OutboundKind};

/// Everything an outbound needs from its environment.
pub struct BuildContext {
    pub resolver: Arc<dyn Resolver>,
    pub protect: Option<ProtectFn>,
    /// Selector choices to restore (kept across config reloads).
    pub selections: HashMap<String, String>,
}

impl BuildContext {
    fn system_dialer(&self, opts: SocketOpts) -> Arc<dyn Dialer> {
        Arc::new(SystemDialer::new(
            self.resolver.clone(),
            SocketOpts {
                protect: self.protect.clone(),
                ..opts
            },
        ))
    }
}

/// All outbounds of a running configuration, addressable by tag.
pub struct OutboundManager {
    map: HashMap<Arc<str>, Arc<dyn Outbound>>,
    order: Vec<Arc<str>>,
    groups: HashMap<Arc<str>, Arc<dyn group::Group>>,
}

impl OutboundManager {
    /// Builds every outbound; detours are built before the outbounds that
    /// dial through them and cycles are rejected.
    pub fn build(configs: &[OutboundConfig], ctx: &BuildContext) -> Result<Self> {
        let by_tag: HashMap<&str, &OutboundConfig> =
            configs.iter().map(|c| (c.tag.as_str(), c)).collect();
        let mut mgr = Self {
            map: HashMap::new(),
            order: Vec::new(),
            groups: HashMap::new(),
        };
        for cfg in configs {
            mgr.build_one(cfg, &by_tag, ctx, &mut Vec::new())?;
        }
        mgr.order = configs.iter().map(|c| Arc::from(c.tag.as_str())).collect();
        Ok(mgr)
    }

    fn build_one<'a>(
        &mut self,
        cfg: &'a OutboundConfig,
        by_tag: &HashMap<&str, &'a OutboundConfig>,
        ctx: &BuildContext,
        stack: &mut Vec<&'a str>,
    ) -> Result<Arc<dyn Outbound>> {
        if let Some(existing) = self.map.get(cfg.tag.as_str()) {
            return Ok(existing.clone());
        }
        if stack.contains(&cfg.tag.as_str()) {
            bail!("outbound cycle: {} -> {}", stack.join(" -> "), cfg.tag);
        }
        stack.push(&cfg.tag);
        let detour: Option<Arc<dyn Dialer>> = match &cfg.detour {
            Some(d) => {
                let dcfg = by_tag
                    .get(d.as_str())
                    .ok_or_else(|| anyhow!("outbound `{}`: unknown detour `{d}`", cfg.tag))?;
                Some(Arc::new(OutboundDialer(
                    self.build_one(dcfg, by_tag, ctx, stack)?,
                )))
            }
            None => None,
        };
        // Group members are built before the group.
        let member_tags: &[String] = match &cfg.kind {
            OutboundKind::Selector(g) => &g.outbounds,
            OutboundKind::Balancer(g) => &g.outbounds,
            _ => &[],
        };
        let mut members = Vec::with_capacity(member_tags.len());
        for m in member_tags {
            let mcfg = by_tag
                .get(m.as_str())
                .ok_or_else(|| anyhow!("outbound `{}`: unknown member `{m}`", cfg.tag))?;
            members.push((
                Arc::<str>::from(m.as_str()),
                self.build_one(mcfg, by_tag, ctx, stack)?,
            ));
        }
        stack.pop();
        let tag: Arc<str> = Arc::from(cfg.tag.as_str());
        // Proxy outbounds dial their server through the detour or directly.
        let via = |detour: Option<Arc<dyn Dialer>>| {
            detour.unwrap_or_else(|| ctx.system_dialer(SocketOpts::default()))
        };
        let built: Result<Arc<dyn Outbound>> = match &cfg.kind {
            OutboundKind::Direct(d) => {
                let dialer = detour.unwrap_or_else(|| {
                    ctx.system_dialer(SocketOpts {
                        bind_interface: d.bind_interface.clone(),
                        fwmark: d.fwmark,
                        ..Default::default()
                    })
                });
                {
                    let fragment = match &d.fragment {
                        Some(f) => Some(sybau_transport::fragment::Fragment::from_config(f)?),
                        None => None,
                    };
                    Ok(Arc::new(Direct {
                        tag: tag.clone(),
                        dialer,
                        fragment,
                    }))
                }
            }
            OutboundKind::Block => Ok(Arc::new(Block { tag: tag.clone() })),
            OutboundKind::Socks(c) => {
                upstream::Socks5::new(tag.clone(), c, via(detour)).map(|o| Arc::new(o) as _)
            }
            OutboundKind::Http(c) => {
                upstream::HttpConnect::new(tag.clone(), c, via(detour)).map(|o| Arc::new(o) as _)
            }
            OutboundKind::Vless(c) => {
                proxy::Vless::new(tag.clone(), c, via(detour)).map(|o| Arc::new(o) as _)
            }
            OutboundKind::Vmess(c) => {
                proxy::Vmess::new(tag.clone(), c, via(detour)).map(|o| Arc::new(o) as _)
            }
            OutboundKind::Trojan(c) => {
                proxy::Trojan::new(tag.clone(), c, via(detour)).map(|o| Arc::new(o) as _)
            }
            OutboundKind::Shadowsocks(c) => {
                shadowsocks::Shadowsocks::new(tag.clone(), c, via(detour)).map(|o| Arc::new(o) as _)
            }
            OutboundKind::Selector(g) => {
                if cfg.detour.is_some() {
                    bail!("outbound `{}`: groups cannot have a detour", cfg.tag);
                }
                // A remembered choice wins over the configured default if
                // it is still a member.
                let remembered = ctx
                    .selections
                    .get(&cfg.tag)
                    .filter(|t| g.outbounds.contains(t));
                let initial = remembered.or(g.default.as_ref()).map(String::as_str);
                group::Selector::new(tag.clone(), members, initial).map(|sel| {
                    let sel = Arc::new(sel);
                    self.groups.insert(tag.clone(), sel.clone());
                    sel as Arc<dyn Outbound>
                })
            }
            OutboundKind::Balancer(g) => {
                if cfg.detour.is_some() {
                    bail!("outbound `{}`: groups cannot have a detour", cfg.tag);
                }
                let strategy = group::Strategy::parse(g.strategy.as_deref())?;
                let cooldown = match &g.failure_cooldown {
                    Some(d) => sybau_config::route::parse_duration(d)?,
                    None => std::time::Duration::from_secs(30),
                };
                group::Balancer::new(tag.clone(), members, strategy, cooldown).map(|b| {
                    let b = Arc::new(b);
                    self.groups.insert(tag.clone(), b.clone());
                    b as Arc<dyn Outbound>
                })
            }
        };
        let outbound =
            built.with_context(|| format!("outbound `{}` ({})", cfg.tag, cfg.kind.type_name()))?;
        self.map.insert(tag, outbound.clone());
        Ok(outbound)
    }

    pub fn group(&self, tag: &str) -> Option<&Arc<dyn group::Group>> {
        self.groups.get(tag)
    }

    pub fn get(&self, tag: &str) -> Option<&Arc<dyn Outbound>> {
        self.map.get(tag)
    }

    /// Tags in config order.
    pub fn tags(&self) -> &[Arc<str>] {
        &self.order
    }
}

/// Connects straight to the destination (or through its detour).
pub struct Direct {
    tag: Arc<str>,
    dialer: Arc<dyn Dialer>,
    fragment: Option<sybau_transport::fragment::Fragment>,
}

#[async_trait]
impl Outbound for Direct {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "direct"
    }
    async fn connect(&self, sess: &Session) -> io::Result<BoxStream> {
        let tcp = self.dialer.dial_tcp(&sess.target).await?;
        Ok(match self.fragment {
            Some(fragment) => Box::new(sybau_transport::fragment::FragmentStream::new(
                tcp, fragment,
            )),
            None => tcp,
        })
    }
    async fn bind(&self, sess: &Session) -> io::Result<ArcPacketConn> {
        self.dialer.dial_udp(&sess.target).await
    }
}

/// Refuses every connection.
pub struct Block {
    tag: Arc<str>,
}

#[async_trait]
impl Outbound for Block {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "block"
    }
    async fn connect(&self, _sess: &Session) -> io::Result<BoxStream> {
        Err(io_err(io::ErrorKind::ConnectionRefused, "blocked by route"))
    }
    async fn bind(&self, _sess: &Session) -> io::Result<ArcPacketConn> {
        Err(io_err(io::ErrorKind::ConnectionRefused, "blocked by route"))
    }
}
