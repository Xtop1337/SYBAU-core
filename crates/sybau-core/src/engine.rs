//! Engine lifecycle (start / reload / stop) and the request side of the
//! control API.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, Result};
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
    final_tag: Arc<str>,
}

impl Engine {
    pub fn new(opts: EngineOptions) -> Self {
        Self {
            inner: Arc::new(Inner {
                opts,
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
        let ctx = BuildContext {
            resolver: Arc::new(SystemResolver),
            protect: self.inner.opts.protect.clone(),
        };
        let outbounds = OutboundManager::build(&config.outbounds, &ctx)?;
        let final_tag: Arc<str> = match &config.route.r#final {
            Some(tag) => Arc::from(tag.as_str()),
            None => outbounds.tags()[0].clone(),
        };
        Ok(Prepared {
            config,
            outbounds,
            final_tag,
        })
    }

    async fn activate(&self, prepared: Prepared) -> Result<Running> {
        let Prepared {
            config,
            outbounds,
            final_tag,
        } = prepared;
        let mut bound = Vec::with_capacity(config.inbounds.len());
        for (i, ib) in config.inbounds.iter().enumerate() {
            bound.push(BoundInbound::bind(i, ib).await?);
        }
        logging::set_level(&config.log.level);
        let dispatcher = Arc::new(Dispatcher {
            outbounds,
            stats: self.inner.stats.clone(),
            final_tag,
        });
        let cancel = CancellationToken::new();
        let tasks = bound
            .into_iter()
            .map(|b| b.spawn(dispatcher.clone(), cancel.clone()))
            .collect();
        info!(
            target: "sybau::core",
            "{} {} started: {} inbound(s), {} outbound(s), final `{}`",
            PRODUCT, VERSION, config.inbounds.len(), config.outbounds.len(), dispatcher.final_tag
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
                            json!({ "tag": o.tag(), "type": o.kind(), "final": o.tag() == &*d.final_tag, "up": up, "down": down })
                        })
                        .collect(),
                ))
            }
            other => Err(RpcError::method_not_found(other)),
        }
    }
}
