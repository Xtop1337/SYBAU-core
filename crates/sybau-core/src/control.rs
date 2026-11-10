//! Control channel: newline-delimited JSON-RPC 2.0 over a named pipe
//! (Windows) or a unix domain socket (everything else).
//!
//! Request:      `{"id": 1, "method": "core.version", "params": {}}`
//! Response:     `{"id": 1, "result": {...}}` or `{"id": 1, "error": {"code": .., "message": ..}}`
//! Notification: `{"method": "stats", "params": {...}}` after `stats.subscribe`,
//!               `{"method": "log", "params": {...}}` after `logs.subscribe`.

use std::io;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use sybau_common::BoxStream;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::engine::{Engine, RpcError};
use crate::logging;

const MAX_LINE: usize = 8 * 1024 * 1024;

/// Directory for the control socket and the instance lock.
#[cfg(unix)]
pub fn runtime_dir() -> std::path::PathBuf {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from) {
        if dir.is_dir() {
            return dir;
        }
    }
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let dir = std::env::temp_dir().join(format!("sybau-{uid}"));
    if std::fs::DirBuilder::new().mode(0o700).create(&dir).is_err() {
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    dir
}

#[cfg(windows)]
pub fn runtime_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("sybau-core");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Default control endpoint of a profile.
pub fn default_endpoint(profile: &str) -> String {
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\sybau-core-{profile}")
    }
    #[cfg(unix)]
    {
        runtime_dir()
            .join(format!("sybau-core-{profile}.sock"))
            .to_string_lossy()
            .into_owned()
    }
}

/// Starts serving the control API. The endpoint is created before this
/// function returns, so clients may connect immediately afterwards.
pub fn serve(engine: Engine, endpoint: &str, cancel: CancellationToken) -> Result<JoinHandle<()>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // A stale socket of a dead instance; the instance lock guarantees
        // that no live core owns it.
        let _ = std::fs::remove_file(endpoint);
        let listener = tokio::net::UnixListener::bind(endpoint)
            .with_context(|| format!("cannot create control socket {endpoint}"))?;
        let _ = std::fs::set_permissions(endpoint, std::fs::Permissions::from_mode(0o600));
        info!(target: "sybau::control", "control API on {endpoint}");
        let path = endpoint.to_string();
        Ok(tokio::spawn(async move {
            loop {
                tokio::select! {
                    r = listener.accept() => match r {
                        Ok((stream, _)) => { tokio::spawn(serve_conn(engine.clone(), stream)); }
                        Err(e) => {
                            warn!(target: "sybau::control", "control accept: {e}");
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    },
                    _ = cancel.cancelled() => break,
                }
            }
            let _ = std::fs::remove_file(path);
        }))
    }
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(endpoint)
            .with_context(|| format!("cannot create control pipe {endpoint}"))?;
        info!(target: "sybau::control", "control API on {endpoint}");
        let name = endpoint.to_string();
        Ok(tokio::spawn(async move {
            loop {
                tokio::select! {
                    r = server.connect() => {
                        if let Err(e) = r {
                            warn!(target: "sybau::control", "control accept: {e}");
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                        // The next instance must exist before this one is
                        // handed off, otherwise clients see "file not found".
                        let next = match ServerOptions::new().reject_remote_clients(true).create(&name) {
                            Ok(n) => n,
                            Err(e) => {
                                warn!(target: "sybau::control", "control pipe: {e}");
                                break;
                            }
                        };
                        let conn = std::mem::replace(&mut server, next);
                        tokio::spawn(serve_conn(engine.clone(), conn));
                    }
                    _ = cancel.cancelled() => break,
                }
            }
        }))
    }
}

fn response(id: &Value, result: Result<Value, RpcError>) -> String {
    match result {
        Ok(v) => json!({ "id": id, "result": v }).to_string(),
        Err(e) => {
            json!({ "id": id, "error": { "code": e.code, "message": e.message } }).to_string()
        }
    }
}

/// Serves one control connection until the peer disconnects.
pub async fn serve_conn<S>(engine: Engine, stream: S)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<String>(256);
    let writer_task = tokio::spawn(async move {
        while let Some(mut line) = rx.recv().await {
            line.push('\n');
            if writer.write_all(line.as_bytes()).await.is_err() || writer.flush().await.is_err() {
                break;
            }
        }
    });
    let mut subscriptions: Vec<JoinHandle<()>> = Vec::new();
    let mut lines = BufReader::new(reader).lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(e) => {
                debug!(target: "sybau::control", "control read: {e}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > MAX_LINE {
            let _ = tx
                .send(response(
                    &Value::Null,
                    Err(RpcError::parse("request too large")),
                ))
                .await;
            break;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let _ = tx
                    .send(response(&Value::Null, Err(RpcError::parse(e))))
                    .await;
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let params = req.get("params").cloned().unwrap_or(Value::Null);
        let Some(method) = req.get("method").and_then(Value::as_str) else {
            let _ = tx
                .send(response(&id, Err(RpcError::parse("`method` is required"))))
                .await;
            continue;
        };
        let result = match method {
            "stats.subscribe" => {
                let interval = params
                    .get("interval_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(1000)
                    .clamp(100, 60_000);
                subscriptions.push(tokio::spawn(stats_feed(
                    engine.clone(),
                    tx.clone(),
                    Duration::from_millis(interval),
                )));
                Ok(json!({ "subscribed": true, "interval_ms": interval }))
            }
            "logs.subscribe" => {
                let level = params
                    .get("level")
                    .and_then(Value::as_str)
                    .unwrap_or("trace");
                match logging::parse_level(level) {
                    Some(max) => {
                        subscriptions.push(tokio::spawn(log_feed(tx.clone(), max)));
                        Ok(json!({ "subscribed": true }))
                    }
                    None => Err(RpcError::invalid_params(format!(
                        "unknown log level `{level}`"
                    ))),
                }
            }
            other => engine.call(other, &params).await,
        };
        if tx.send(response(&id, result)).await.is_err() {
            break;
        }
    }
    for s in subscriptions {
        s.abort();
    }
    drop(tx);
    let _ = writer_task.await;
}

async fn stats_feed(engine: Engine, tx: mpsc::Sender<String>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    let (mut last_up, mut last_down) = engine.stats().total.snapshot();
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let (up, down) = engine.stats().total.snapshot();
        let secs = interval.as_secs_f64();
        let msg = json!({ "method": "stats", "params": {
            "up": up, "down": down,
            "up_rate": ((up - last_up) as f64 / secs) as u64,
            "down_rate": ((down - last_down) as f64 / secs) as u64,
            "connections": engine.stats().connection_count(),
        }});
        (last_up, last_down) = (up, down);
        if tx.send(msg.to_string()).await.is_err() {
            return;
        }
    }
}

async fn log_feed(tx: mpsc::Sender<String>, max_level: u8) {
    let mut rx = logging::subscribe();
    loop {
        match rx.recv().await {
            Ok(line) => {
                if logging::parse_level(line.level).unwrap_or(0) > max_level {
                    continue;
                }
                let msg = json!({ "method": "log", "params": line });
                if tx.send(msg.to_string()).await.is_err() {
                    return;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => return,
        }
    }
}

/// Connects to the control endpoint of a running core.
pub async fn connect(endpoint: &str) -> io::Result<BoxStream> {
    #[cfg(unix)]
    {
        Ok(Box::new(tokio::net::UnixStream::connect(endpoint).await?))
    }
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        const ERROR_PIPE_BUSY: i32 = 231;
        for _ in 0..50 {
            match ClientOptions::new().open(endpoint) {
                Ok(c) => return Ok(Box::new(c)),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "control pipe is busy",
        ))
    }
}

/// Sends one request and waits for its response.
pub async fn request(endpoint: &str, method: &str, params: Value) -> Result<Value> {
    let stream = connect(endpoint)
        .await
        .with_context(|| format!("cannot connect to {endpoint}"))?;
    let (reader, mut writer) = tokio::io::split(stream);
    let line = json!({ "id": 1, "method": method, "params": params }).to_string() + "\n";
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let v: Value = serde_json::from_str(&line).context("malformed response")?;
        if v.get("id") != Some(&json!(1)) {
            continue;
        }
        if let Some(err) = v.get("error") {
            return Err(anyhow!(
                "{}",
                err.get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
            ));
        }
        return Ok(v.get("result").cloned().unwrap_or(Value::Null));
    }
    Err(anyhow!("connection closed before a response arrived"))
}

/// Sends one request and prints every line the core sends back until the
/// connection closes. Used for the streaming `*.subscribe` methods.
pub async fn follow(
    endpoint: &str,
    method: &str,
    params: Value,
    mut on_line: impl FnMut(&str),
) -> Result<()> {
    let stream = connect(endpoint)
        .await
        .with_context(|| format!("cannot connect to {endpoint}"))?;
    let (reader, mut writer) = tokio::io::split(stream);
    let line = json!({ "id": 1, "method": method, "params": params }).to_string() + "\n";
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        on_line(&line);
    }
    Ok(())
}
