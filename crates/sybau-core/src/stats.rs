//! Traffic counters and the table of live connections.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use parking_lot::Mutex;
use serde_json::{json, Value};
use sybau_common::Session;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct Counter {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

impl Counter {
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
        )
    }
}

struct ConnEntry {
    network: &'static str,
    inbound: Arc<str>,
    outbound: Arc<str>,
    source: String,
    target: String,
    host: Option<String>,
    started: SystemTime,
    counter: Arc<Counter>,
    cancel: CancellationToken,
}

/// Process-wide statistics. Survives config reloads.
#[derive(Default)]
pub struct Stats {
    pub total: Counter,
    outbounds: Mutex<HashMap<Arc<str>, Arc<Counter>>>,
    conns: Mutex<HashMap<u64, ConnEntry>>,
}

impl Stats {
    pub fn outbound_counter(&self, tag: &Arc<str>) -> Arc<Counter> {
        self.outbounds
            .lock()
            .entry(tag.clone())
            .or_default()
            .clone()
    }

    /// Registers a live connection; it disappears when the guard is dropped.
    pub fn track(self: &Arc<Self>, sess: &Session, outbound: &Arc<str>) -> ConnGuard {
        let counter = Arc::new(Counter::default());
        let cancel = CancellationToken::new();
        self.conns.lock().insert(
            sess.id,
            ConnEntry {
                network: sess.network.as_str(),
                inbound: sess.inbound_tag.clone(),
                outbound: outbound.clone(),
                source: sess.source.map(|s| s.to_string()).unwrap_or_default(),
                target: sess.target.to_string(),
                host: sess.sniffed_host.clone(),
                started: SystemTime::now(),
                counter: counter.clone(),
                cancel: cancel.clone(),
            },
        );
        ConnGuard {
            id: sess.id,
            stats: self.clone(),
            counters: Counters {
                conn: counter,
                outbound: self.outbound_counter(outbound),
                stats: self.clone(),
            },
            cancel,
        }
    }

    pub fn connection_count(&self) -> usize {
        self.conns.lock().len()
    }

    pub fn connections_json(&self) -> Value {
        let conns = self.conns.lock();
        let mut list: Vec<(u64, Value)> = conns
            .iter()
            .map(|(id, c)| {
                let (up, down) = c.counter.snapshot();
                let started = c.started.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
                (
                    *id,
                    json!({
                        "id": id, "network": c.network, "inbound": &*c.inbound, "outbound": &*c.outbound,
                        "source": c.source, "target": c.target, "host": c.host,
                        "started_ms": started, "up": up, "down": down,
                    }),
                )
            })
            .collect();
        list.sort_by_key(|(id, _)| *id);
        Value::Array(list.into_iter().map(|(_, v)| v).collect())
    }

    /// Closes one connection; returns `false` if it does not exist.
    pub fn close(&self, id: u64) -> bool {
        match self.conns.lock().get(&id) {
            Some(c) => {
                c.cancel.cancel();
                true
            }
            None => false,
        }
    }

    pub fn close_all(&self) -> usize {
        let conns = self.conns.lock();
        conns.values().for_each(|c| c.cancel.cancel());
        conns.len()
    }

    pub fn outbounds_json(&self) -> Value {
        let map = self.outbounds.lock();
        let mut obj = serde_json::Map::new();
        for (tag, c) in map.iter() {
            let (up, down) = c.snapshot();
            obj.insert(tag.to_string(), json!({"up": up, "down": down}));
        }
        Value::Object(obj)
    }
}

/// The three counters every relayed byte is added to.
#[derive(Clone)]
pub struct Counters {
    conn: Arc<Counter>,
    outbound: Arc<Counter>,
    stats: Arc<Stats>,
}

impl Counters {
    /// Counters that belong to no connection yet (used while sniffing).
    pub fn detached() -> Self {
        let stats = Arc::new(Stats::default());
        Self {
            conn: Arc::new(Counter::default()),
            outbound: Arc::new(Counter::default()),
            stats,
        }
    }

    #[inline]
    pub fn add_up(&self, n: usize) {
        let n = n as u64;
        self.conn.up.fetch_add(n, Ordering::Relaxed);
        self.outbound.up.fetch_add(n, Ordering::Relaxed);
        self.stats.total.up.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_down(&self, n: usize) {
        let n = n as u64;
        self.conn.down.fetch_add(n, Ordering::Relaxed);
        self.outbound.down.fetch_add(n, Ordering::Relaxed);
        self.stats.total.down.fetch_add(n, Ordering::Relaxed);
    }
}

pub struct ConnGuard {
    id: u64,
    stats: Arc<Stats>,
    pub counters: Counters,
    pub cancel: CancellationToken,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.stats.conns.lock().remove(&self.id);
    }
}

/// Wraps the client side of a relayed stream: bytes read from it count as
/// upload, bytes written to it as download.
pub struct CountedStream<S> {
    inner: S,
    counters: Counters,
}

impl<S> CountedStream<S> {
    pub fn new(inner: S, counters: Counters) -> Self {
        Self { inner, counters }
    }

    pub fn set_counters(&mut self, counters: Counters) {
        self.counters = counters;
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            self.counters.add_up(buf.filled().len() - before);
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            self.counters.add_down(*n);
        }
        res
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
