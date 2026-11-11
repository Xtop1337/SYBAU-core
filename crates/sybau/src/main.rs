//! `sybau` / `sybau.exe` — SYBAU-CORE as a standalone process.

mod single_instance;
mod sysproxy;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use sybau_config::Config;
use sybau_core::{control, logging, Engine, EngineOptions};

/// Exit code of a launch that found the profile already running.
const EXIT_ALREADY_RUNNING: u8 = 3;

#[derive(Parser)]
#[command(
    name = "sybau",
    version,
    about = "SYBAU-CORE proxy core",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the core with a config file.
    Run {
        /// Config file.
        #[arg(short, long)]
        config: PathBuf,
        /// Instance name. One core runs per profile.
        #[arg(long, default_value = "default")]
        profile: String,
        /// Overrides `log.level` from the config.
        #[arg(long)]
        log_level: Option<String>,
    },
    /// Validate a config file (SYBAU, Xray or sing-box) without starting anything.
    Check {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Convert an Xray or sing-box config to the SYBAU format.
    Convert {
        /// Config file to convert.
        input: PathBuf,
        /// `xray`, `sing-box` or `auto`.
        #[arg(long, default_value = "auto")]
        from: String,
        /// Write here instead of standard output.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Turn share links or subscription content into outbounds
    /// (`vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`, `tuic://`,
    /// `wireguard://`, base64 lists, Clash YAML, sing-box JSON).
    Import {
        /// A link, or a file with links / subscription content; `-` reads stdin.
        source: String,
    },
    /// Remove the routes and the kill switch a TUN run left behind
    /// (after a crash or `kill -9`; a clean exit removes them itself).
    TunCleanup {
        /// Routing table of the TUN inbound (`table` in the config).
        #[arg(long, default_value_t = 2022)]
        table: u32,
    },
    /// Internal: restores the system proxy if the core with `pid` dies.
    #[command(hide = true)]
    SysproxyGuard {
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        profile: String,
    },
    /// Send a request to a running core, e.g. `sybau ctl stats.get`.
    Ctl {
        /// Method, e.g. `core.status`, `connections.list`, `core.reload`.
        method: String,
        /// Parameters as JSON, e.g. '{"id": 5}'.
        params: Option<String>,
        #[arg(long, default_value = "default")]
        profile: String,
        /// Control endpoint, if the config overrides the default.
        #[arg(long)]
        endpoint: Option<String>,
        /// Keep printing notifications (for `stats.subscribe`, `logs.subscribe`).
        #[arg(long)]
        follow: bool,
    },
}

/// Loads a config of any supported format; notes about settings that
/// could not be converted go to the log.
fn load_config(path: &Path) -> Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let imported =
        sybau_config::parse_any(&text).with_context(|| format!("in {}", path.display()))?;
    for w in &imported.warnings {
        eprintln!("warning: {w}");
    }
    Ok(imported.config)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Check { config } => {
            let cfg = load_config(&config)?;
            println!(
                "{}: OK ({} inbound(s), {} outbound(s))",
                config.display(),
                cfg.inbounds.len(),
                cfg.outbounds.len()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::TunCleanup { table } => {
            sybau_tun::routes::cleanup(table);
            println!("TUN routes and kill switch removed");
            Ok(ExitCode::SUCCESS)
        }
        Command::SysproxyGuard { pid, profile } => {
            check_profile(&profile)?;
            sysproxy::guard(pid, &profile)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Convert {
            input,
            from,
            output,
        } => {
            let text = std::fs::read_to_string(&input)
                .with_context(|| format!("cannot read {}", input.display()))?;
            let format = match from.as_str() {
                "auto" => None,
                other => Some(sybau_config::import::Format::parse(other)?),
            };
            let imported = sybau_config::import::load(&text, format)
                .with_context(|| format!("in {}", input.display()))?;
            for w in &imported.warnings {
                eprintln!("warning: {w}");
            }
            let json = imported.config.to_json_pretty();
            match output {
                Some(path) => std::fs::write(&path, json + "\n")
                    .with_context(|| format!("cannot write {}", path.display()))?,
                None => println!("{json}"),
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Import { source } => {
            let text = if source == "-" {
                std::io::read_to_string(std::io::stdin())?
            } else if source.contains("://") {
                source.clone()
            } else {
                std::fs::read_to_string(&source).with_context(|| format!("cannot read {source}"))?
            };
            let parsed = sybau_config::subscription::parse(&text)?;
            for w in &parsed.warnings {
                eprintln!("warning: {w}");
            }
            println!("{}", serde_json::to_string_pretty(&parsed.outbounds)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Ctl {
            method,
            params,
            profile,
            endpoint,
            follow,
        } => {
            check_profile(&profile)?;
            let params: Value = match params {
                Some(p) => serde_json::from_str(&p).context("params must be valid JSON")?,
                None => Value::Null,
            };
            let endpoint = endpoint.unwrap_or_else(|| control::default_endpoint(&profile));
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                if follow {
                    control::follow(&endpoint, &method, params, |line| println!("{line}")).await
                } else {
                    let result = control::request(&endpoint, &method, params).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    Ok(())
                }
            })?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Run {
            config,
            profile,
            log_level,
        } => {
            check_profile(&profile)?;
            logging::init(true);
            let mut cfg = load_config(&config)?;
            if let Some(level) = log_level {
                cfg.log.level = level;
            }
            // Taken before any port or pipe is touched, so a second launch
            // can never disturb the first one.
            let _lock = match single_instance::acquire(&profile)? {
                single_instance::Acquire::Acquired(lock) => lock,
                single_instance::Acquire::AlreadyRunning(pid) => {
                    match pid {
                        Some(pid) => eprintln!(
                            "SYBAU-CORE is already running for profile `{profile}` (pid {pid})"
                        ),
                        None => eprintln!("SYBAU-CORE is already running for profile `{profile}`"),
                    }
                    return Ok(ExitCode::from(EXIT_ALREADY_RUNNING));
                }
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("sybau-worker")
                .build()?;
            rt.block_on(serve(cfg, config, profile))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn check_profile(profile: &str) -> Result<()> {
    if !single_instance::valid_profile(profile) {
        bail!("profile name may only contain letters, digits, `-` and `_`");
    }
    Ok(())
}

async fn serve(cfg: Config, path: PathBuf, profile: String) -> Result<()> {
    let control_cfg = cfg.control.clone();
    // Settings left by a run that was killed together with its guard.
    if cfg!(windows) {
        sysproxy::recover(&profile);
    }
    let system_proxy_cfg = cfg.system_proxy.clone().filter(|s| s.enabled);
    let system_proxy_server = system_proxy_cfg
        .as_ref()
        .map(|sp| sysproxy::proxy_server(&cfg, sp));
    let engine = Engine::new(EngineOptions {
        profile: profile.clone(),
        config_path: Some(path),
        loader: Some(Arc::new(load_config)),
        protect: None,
    });
    engine.start(cfg).await?;
    // Enabled only once the inbounds listen; restored when dropped.
    let _system_proxy = match (system_proxy_cfg, system_proxy_server) {
        (Some(sp), Some(Some(server))) if cfg!(windows) => {
            match sysproxy::SystemProxy::enable(&profile, &server, &sp.bypass) {
                Ok(p) => {
                    tracing::info!(target: "sybau::core", "system proxy set to {server}");
                    Some(p)
                }
                Err(e) => {
                    tracing::warn!(target: "sybau::core", "cannot set the system proxy: {e:#}");
                    None
                }
            }
        }
        (Some(_), Some(None)) => {
            tracing::warn!(target: "sybau::core", "system_proxy: no mixed or http inbound to announce; set system_proxy.server");
            None
        }
        (Some(_), _) => {
            tracing::warn!(target: "sybau::core", "system_proxy is only supported on Windows");
            None
        }
        _ => None,
    };

    let control_cancel = engine.stop_token().child_token();
    let control_task = if control_cfg.enabled {
        let endpoint = control_cfg
            .path
            .unwrap_or_else(|| control::default_endpoint(&profile));
        Some(control::serve(
            engine.clone(),
            &endpoint,
            control_cancel.clone(),
        )?)
    } else {
        None
    };

    let stop = engine.stop_token();
    loop {
        tokio::select! {
            sig = wait_signal() => match sig {
                Signal::Terminate => break,
                Signal::Reload => {
                    if let Err(e) = engine.call("core.reload", &Value::Null).await {
                        tracing::warn!(target: "sybau::core", "reload: {}", e.message);
                    }
                }
            },
            _ = stop.cancelled() => {
                // Let the reply to `core.stop` reach the client.
                tokio::time::sleep(Duration::from_millis(100)).await;
                break;
            }
        }
    }
    engine.stop().await;
    control_cancel.cancel();
    if let Some(task) = control_task {
        let _ = task.await;
    }
    Ok(())
}

#[cfg_attr(windows, allow(dead_code))]
enum Signal {
    Terminate,
    Reload,
}

#[cfg(unix)]
async fn wait_signal() -> Signal {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut hup = signal(SignalKind::hangup()).expect("install SIGHUP handler");
    tokio::select! {
        _ = term.recv() => Signal::Terminate,
        _ = int.recv() => Signal::Terminate,
        _ = hup.recv() => Signal::Reload,
    }
}

#[cfg(windows)]
async fn wait_signal() -> Signal {
    use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown};
    let mut c = ctrl_c().expect("install Ctrl+C handler");
    let mut brk = ctrl_break().expect("install Ctrl+Break handler");
    let mut close = ctrl_close().expect("install close handler");
    let mut shutdown = ctrl_shutdown().expect("install shutdown handler");
    tokio::select! {
        _ = c.recv() => Signal::Terminate,
        _ = brk.recv() => Signal::Terminate,
        _ = close.recv() => Signal::Terminate,
        _ = shutdown.recv() => Signal::Terminate,
    }
}
