//! `sybau` / `sybau.exe` — SYBAU-CORE as a standalone process.

mod single_instance;

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
    /// Validate a config file without starting anything.
    Check {
        #[arg(short, long)]
        config: PathBuf,
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

fn load_config(path: &Path) -> Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    sybau_config::parse_native(&text).with_context(|| format!("in {}", path.display()))
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
    let engine = Engine::new(EngineOptions {
        profile: profile.clone(),
        config_path: Some(path),
        loader: Some(Arc::new(load_config)),
        protect: None,
    });
    engine.start(cfg).await?;

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
