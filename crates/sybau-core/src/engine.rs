//! Engine lifecycle (start / reload / stop) and the request side of the
//! control API.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sybau_common::net::ProtectFn;
use sybau_common::SystemResolver;
use sybau_config::{Config, DirectOutbound, OutboundConfig, OutboundKind};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::dispatch::Dispatcher;
use crate::inbound::BoundInbound;
use crate::outbound::{BuildContext, OutboundManager};
use crate::stats::Stats;
use crate::{logging, PRODUCT, VERSION};

/// Version of the control protocol; bumped on incompatible changes.
pub const CONTROL_PROTOCOL: u32 = 1;

/// JSON-RPC style error returned by the control API.
#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcError {
    pub fn parse(msg: impl ToString) -> Self {
        Self {
            code: -32700,
            message: msg.to_string(),
        }
    }
    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("unknown method `{method}`"),
        }
    }
    pub fn invalid_params(msg: impl ToString) -> Self {
        Self {
            code: -32602,
            message: msg.to_string(),
        }
    }
    pub fn failed(msg: impl ToString) -> Self {
        Self {
            code: -32000,
            message: msg.to_string(),
        }
    }
}

/// Loads and converts a config file of any supported format.
pub type ConfigLoader = Arc<dyn Fn(&Path) -> Result<Config> + Send + Sync>;

#[derive(Default)]
pub struct EngineOptions {
    /// Instance name; separates lock, control endpoint and state of
    /// several cores running side by side.
    pub profile: String,
    /// Config file to re-read on `core.reload` without parameters.
    pub config_path: Option<PathBuf>,
    pub loader: Option<ConfigLoader>,
    /// Android `VpnService.protect` hook applied to every outgoing socket.
    pub protect: Option<ProtectFn>,
}

struct Running {
    config: Config,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    dispatcher: Arc<Dispatcher>,
}

struct Inner {
    opts: EngineOptions,
    /// Parsed geo files, shared by reloads.
    geo: sybau_route::geodata::GeoCache,
    /// Selector choices made through the control API, kept across reloads.
    selections: parking_lot::Mutex<std::collections::HashMap<String, String>>,
    stats: Arc<Stats>,
    running: tokio::sync::Mutex<Option<Running>>,
    stop: CancellationToken,
    created: Instant,
}

/// Handle to the core. Cheap to clone.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

struct Prepared {
    config: Config,
    outbounds: OutboundManager,
    router: crate::route::Router,
    dns: Option<Arc<crate::dns::DnsResolver>>,
}

impl Engine {
    pub fn new(opts: EngineOptions) -> Self {
        Self {
            inner: Arc::new(Inner {
                opts,
                geo: Default::default(),
                selections: Default::default(),
                stats: Arc::new(Stats::default()),
                running: tokio::sync::Mutex::new(None),
                stop: CancellationToken::new(),
                created: Instant::now(),
            }),
        }
    }

    pub fn profile(&self) -> &str {
        &self.inner.opts.profile
    }

    pub fn stats(&self) -> &Arc<Stats> {
        &self.inner.stats
    }

    /// Cancelled when the core was asked to exit (`core.stop`).
    pub fn stop_token(&self) -> CancellationToken {
        self.inner.stop.clone()
    }

    /// Everything that can fail without side effects.
    fn prepare(&self, mut config: Config) -> Result<Prepared> {
        if config.outbounds.is_empty() {
            config.outbounds.push(OutboundConfig {
                tag: "direct".into(),
                detour: None,
                kind: OutboundKind::Direct(DirectOutbound::default()),
            });
        }
        config.validate()?;
        if logging::parse_level(&config.log.level).is_none() {
            bail!(
                "log.level `{}` is not one of trace/debug/info/warn/error/off",
                config.log.level
            );
        }
        // Outbounds resolve through the DNS module once it exists.
        let late = Arc::new(crate::dns::LateResolver::default());
        let ctx = BuildContext {
            resolver: late.clone(),
            protect: self.inner.opts.protect.clone(),
            selections: self.inner.selections.lock().clone(),
        };
        let outbounds = OutboundManager::build(&config.outbounds, &ctx)?;
        let final_tag: Arc<str> = match &config.route.r#final {
            Some(tag) => Arc::from(tag.as_str()),
            None => outbounds.tags()[0].clone(),
        };
        let assets = crate::route::Assets::standard(self.inner.opts.config_path.as_deref());
        let router =
            crate::route::Router::build(&config.route, final_tag, &assets, &self.inner.geo)?;
        let dns = match &config.dns {
            Some(dns_cfg) => {
                let dns = Arc::new(
                    crate::dns::DnsResolver::build(
                        dns_cfg,
                        &config.route,
                        &outbounds,
                        &assets,
                        &self.inner.geo,
                        &router.rule_sets,
                        self.inner.opts.protect.clone(),
                    )
                    .context("dns")?,
                );
                late.set(dns.clone());
                Some(dns)
            }
            None => None,
        };
        Ok(Prepared {
            config,
            outbounds,
            router,
            dns,
        })
    }

    async fn activate(&self, prepared: Prepared) -> Result<Running> {
        let Prepared {
            config,
            outbounds,
            router,
            dns,
        } = prepared;
        let mut bound = Vec::with_capacity(config.inbounds.len());
        for (i, ib) in config.inbounds.iter().enumerate() {
            bound.push(BoundInbound::bind(i, ib).await?);
        }
        logging::set_level(&config.log.level);
        let rules = router.rule_count();
        let dispatcher = Arc::new(Dispatcher {
            outbounds,
            stats: self.inner.stats.clone(),
            router,
            resolver: match &dns {
                Some(d) => d.clone(),
                None => Arc::new(SystemResolver),
            },
            dns,
        });
        let cancel = CancellationToken::new();
        let tasks = bound
            .into_iter()
            .map(|b| b.spawn(dispatcher.clone(), cancel.clone()))
            .collect();
        info!(
            target: "sybau::core",
            "{} {} started: {} inbound(s), {} outbound(s), {} rule(s), final `{}`",
            PRODUCT, VERSION, config.inbounds.len(), config.outbounds.len(), rules, dispatcher.router.final_tag
        );
        Ok(Running {
            config,
            cancel,
            tasks,
            dispatcher,
        })
    }

    async fn deactivate(&self, running: Running) {
        running.cancel.cancel();
        for task in running.tasks {
            let _ = task.await;
        }
    }

    /// Starts the core. Fails if it is already running.
    pub async fn start(&self, config: Config) -> Result<()> {
        let mut guard = self.inner.running.lock().await;
        if guard.is_some() {
            bail!("core is already running");
        }
        *guard = Some(self.activate(self.prepare(config)?).await?);
        Ok(())
    }

    /// Replaces the running configuration. If the new one cannot be
    /// applied the previous one keeps (or resumes) running.
    pub async fn reload(&self, config: Config) -> Result<()> {
        let prepared = self.prepare(config)?;
        let mut guard = self.inner.running.lock().await;
        let old_config = match guard.take() {
            Some(old) => {
                let cfg = old.config.clone();
                self.deactivate(old).await;
                Some(cfg)
            }
            None => None,
        };
        match self.activate(prepared).await {
            Ok(running) => {
                *guard = Some(running);
                Ok(())
            }
            Err(e) => {
                if let Some(cfg) = old_config {
                    match self.prepare(cfg) {
                        Ok(p) => match self.activate(p).await {
                            Ok(running) => *guard = Some(running),
                            Err(e2) => {
                                warn!(target: "sybau::core", "could not restore previous config: {e2:#}")
                            }
                        },
                        Err(e2) => {
                            warn!(target: "sybau::core", "could not restore previous config: {e2:#}")
                        }
                    }
                }
                Err(e.context("reload failed, previous configuration kept"))
            }
        }
    }

    /// Stops inbounds and closes every live connection.
    pub async fn stop(&self) {
        let running = self.inner.running.lock().await.take();
        if let Some(running) = running {
            self.deactivate(running).await;
            info!(target: "sybau::core", "{} stopped", PRODUCT);
        }
    }

    pub async fn is_running(&self) -> bool {
        self.inner.running.lock().await.is_some()
    }

    pub fn stats_json(&self) -> Value {
        let (up, down) = self.inner.stats.total.snapshot();
        json!({ "up": up, "down": down, "connections": self.inner.stats.connection_count() })
    }

    fn load_file(&self, path: &Path) -> Result<Config> {
        match &self.inner.opts.loader {
            Some(loader) => loader(path),
            None => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| anyhow!("cannot read {}: {e}", path.display()))?;
                sybau_config::parse_native(&text)
            }
        }
    }

    async fn running_dns(&self) -> Result<Arc<crate::dns::DnsResolver>, RpcError> {
        let guard = self.inner.running.lock().await;
        let running = guard
            .as_ref()
            .ok_or_else(|| RpcError::failed("core is not running"))?;
        running
            .dispatcher
            .dns
            .clone()
            .ok_or_else(|| RpcError::failed("no `dns` section in the configuration"))
    }

    /// Handles one request of the control API (everything except the
    /// streaming `*.subscribe` methods, which belong to the transport).
    pub async fn call(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        match method {
            "core.version" => Ok(json!({
                "name": PRODUCT,
                "version": VERSION,
                "protocol": CONTROL_PROTOCOL,
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            })),
            "core.status" => {
                let guard = self.inner.running.lock().await;
                let (up, down) = self.inner.stats.total.snapshot();
                Ok(json!({
                    "running": guard.is_some(),
                    "profile": self.profile(),
                    "pid": std::process::id(),
                    "uptime_s": self.inner.created.elapsed().as_secs(),
                    "connections": self.inner.stats.connection_count(),
                    "up": up,
                    "down": down,
                    "inbounds": guard.as_ref().map(|r| r.config.inbounds.iter().map(|i| json!({
                        "tag": i.tag, "type": i.kind.type_name(),
                    })).collect::<Vec<_>>()).unwrap_or_default(),
                }))
            }
            "core.stop" => {
                self.inner.stop.cancel();
                Ok(json!({ "ok": true }))
            }
            "core.reload" => {
                let config = if let Some(cfg) = params.get("config") {
                    let cfg: Config =
                        serde_json::from_value(cfg.clone()).map_err(RpcError::invalid_params)?;
                    cfg
                } else {
                    let path = match params.get("path").and_then(Value::as_str) {
                        Some(p) => PathBuf::from(p),
                        None => self
                            .inner
                            .opts
                            .config_path
                            .clone()
                            .ok_or_else(|| RpcError::invalid_params("no `config` or `path` given and the core was not started from a file"))?,
                    };
                    self.load_file(&path)
                        .map_err(|e| RpcError::failed(format!("{e:#}")))?
                };
                self.reload(config)
                    .await
                    .map_err(|e| RpcError::failed(format!("{e:#}")))?;
                Ok(json!({ "ok": true }))
            }
            "log.set_level" => {
                let level = params
                    .get("level")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RpcError::invalid_params("`level` is required"))?;
                if !logging::set_level(level) {
                    return Err(RpcError::invalid_params(format!(
                        "unknown log level `{level}`"
                    )));
                }
                Ok(json!({ "ok": true }))
            }
            "stats.get" => {
                let mut v = self.stats_json();
                v["outbounds"] = self.inner.stats.outbounds_json();
                Ok(v)
            }
            "connections.list" => Ok(self.inner.stats.connections_json()),
            "connections.close" => {
                if params.get("all").and_then(Value::as_bool) == Some(true) {
                    return Ok(json!({ "closed": self.inner.stats.close_all() }));
                }
                let id = params
                    .get("id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| RpcError::invalid_params("`id` or `all: true` is required"))?;
                Ok(json!({ "closed": usize::from(self.inner.stats.close(id)) }))
            }
            "outbounds.list" => {
                let guard = self.inner.running.lock().await;
                let running = guard
                    .as_ref()
                    .ok_or_else(|| RpcError::failed("core is not running"))?;
                let d = &running.dispatcher;
                Ok(Value::Array(
                    d.outbounds
                        .tags()
                        .iter()
                        .filter_map(|tag| d.outbounds.get(tag))
                        .map(|o| {
                            let (up, down) = self.inner.stats.outbound_counter(&Arc::from(o.tag())).snapshot();
                            let mut v = json!({ "tag": o.tag(), "type": o.kind(), "final": o.tag() == &*d.router.final_tag, "up": up, "down": down });
                            if let Some(g) = d.outbounds.group(o.tag()) {
                                v["group"] = g.info();
                            }
                            v
                        })
                        .collect(),
                ))
            }
            "dns.query" => {
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RpcError::invalid_params("`name` is required"))?;
                let qtype = params.get("type").and_then(Value::as_str).unwrap_or("A");
                let qtype = sybau_dns::message::parse_type(qtype)
                    .ok_or_else(|| RpcError::invalid_params(format!("unknown type `{qtype}`")))?;
                let dns = self.running_dns().await?;
                let reply = dns
                    .exchange(&sybau_dns::Message::query(rand::random(), name, qtype))
                    .await;
                Ok(json!({
                    "rcode": reply.rcode,
                    "answers": reply.answers.iter().map(|r| json!({
                        "name": r.name, "type": r.rtype, "ttl": r.ttl,
                        "data": match &r.data {
                            sybau_dns::RecordData::A(ip) => ip.to_string(),
                            sybau_dns::RecordData::Aaaa(ip) => ip.to_string(),
                            sybau_dns::RecordData::Cname(n) => n.clone(),
                            sybau_dns::RecordData::Other(raw) => format!("<{} bytes>", raw.len()),
                        },
                    })).collect::<Vec<_>>(),
                }))
            }
            "dns.flush" => Ok(json!({ "flushed": self.running_dns().await?.flush() })),
            "outbounds.select" => {
                let group = params
                    .get("group")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RpcError::invalid_params("`group` is required"))?;
                let member = params
                    .get("outbound")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RpcError::invalid_params("`outbound` is required"))?;
                let guard = self.inner.running.lock().await;
                let running = guard
                    .as_ref()
                    .ok_or_else(|| RpcError::failed("core is not running"))?;
                let g = running.dispatcher.outbounds.group(group).ok_or_else(|| {
                    RpcError::invalid_params(format!("`{group}` is not an outbound group"))
                })?;
                g.select(member)
                    .map_err(|e| RpcError::invalid_params(format!("{e:#}")))?;
                self.inner
                    .selections
                    .lock()
                    .insert(group.to_string(), member.to_string());
                // Connections through the old member keep running unless asked.
                if params.get("close_connections").and_then(Value::as_bool) == Some(true) {
                    self.inner.stats.close_all();
                }
                Ok(json!({ "ok": true }))
            }
            other => Err(RpcError::method_not_found(other)),
        }
    }
}
