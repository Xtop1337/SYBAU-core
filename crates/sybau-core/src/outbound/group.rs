//! Outbound groups: `selector` (chosen by hand) and `balancer`.
//!
//! Balancers learn member health from real traffic: a failed connect
//! puts the member aside for a cooldown and the connection is retried on
//! the next one; successful connects record the handshake time used by
//! the `least_ping` strategy.

use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use serde_json::{json, Value};
use sybau_common::{io_err, ArcPacketConn, BoxStream, Outbound, Session};
use tracing::{info, warn};

pub type Member = (Arc<str>, Arc<dyn Outbound>);

/// Notes the chosen member in the session; returns the chain length
/// before it, to undo the entry if the member fails.
fn push_chain(sess: &Session, tag: Arc<str>) -> usize {
    let mut chain = sess.chain.lock();
    let position = chain.len();
    chain.push(tag);
    position
}

/// Group-specific operations exposed through the control API.
pub trait Group: Send + Sync {
    fn info(&self) -> Value;
    /// Switches a selector; balancers refuse.
    fn select(&self, member: &str) -> Result<()>;
}

pub struct Selector {
    tag: Arc<str>,
    members: Vec<Member>,
    selected: RwLock<usize>,
}

impl Selector {
    pub fn new(tag: Arc<str>, members: Vec<Member>, initial: Option<&str>) -> Result<Self> {
        if members.is_empty() {
            bail!("a selector needs at least one outbound");
        }
        let selected = match initial {
            Some(t) => members
                .iter()
                .position(|(m, _)| &**m == t)
                .ok_or_else(|| anyhow::anyhow!("`{t}` is not a member"))?,
            None => 0,
        };
        Ok(Self {
            tag,
            members,
            selected: RwLock::new(selected),
        })
    }

    pub fn current(&self) -> Member {
        self.members[*self.selected.read()].clone()
    }
}

impl Group for Selector {
    fn info(&self) -> Value {
        json!({
            "now": &*self.current().0,
            "all": self.members.iter().map(|(t, _)| t.to_string()).collect::<Vec<_>>(),
        })
    }

    fn select(&self, member: &str) -> Result<()> {
        let index = self
            .members
            .iter()
            .position(|(t, _)| &**t == member)
            .ok_or_else(|| anyhow::anyhow!("`{member}` is not a member of `{}`", self.tag))?;
        *self.selected.write() = index;
        info!(target: "sybau::route", "selector `{}` now uses `{member}`", self.tag);
        Ok(())
    }
}

#[async_trait]
impl Outbound for Selector {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "selector"
    }
    async fn connect(&self, sess: &Session) -> io::Result<BoxStream> {
        let (tag, outbound) = self.current();
        let position = push_chain(sess, tag);
        let result = outbound.connect(sess).await;
        if result.is_err() {
            sess.chain.lock().truncate(position);
        }
        result
    }
    async fn bind(&self, sess: &Session) -> io::Result<ArcPacketConn> {
        let (tag, outbound) = self.current();
        let position = push_chain(sess, tag);
        let result = outbound.bind(sess).await;
        if result.is_err() {
            sess.chain.lock().truncate(position);
        }
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    RoundRobin,
    Random,
    Fallback,
    LeastPing,
}

impl Strategy {
    pub fn parse(name: Option<&str>) -> Result<Self> {
        Ok(match name.unwrap_or("round_robin").to_ascii_lowercase().as_str() {
            "round_robin" | "roundrobin" => Strategy::RoundRobin,
            "random" => Strategy::Random,
            "fallback" => Strategy::Fallback,
            "least_ping" | "leastping" => Strategy::LeastPing,
            other => bail!("unknown balancer strategy `{other}` (round_robin, random, fallback, least_ping)"),
        })
    }

    fn name(self) -> &'static str {
        match self {
            Strategy::RoundRobin => "round_robin",
            Strategy::Random => "random",
            Strategy::Fallback => "fallback",
            Strategy::LeastPing => "least_ping",
        }
    }
}

#[derive(Default)]
struct Health {
    /// Moving average of connect time in microseconds; 0 = unknown.
    latency_us: AtomicU64,
    down_until: Mutex<Option<Instant>>,
    failures: AtomicU64,
}

impl Health {
    fn is_up(&self, now: Instant) -> bool {
        self.down_until.lock().is_none_or(|t| now >= t)
    }

    fn record_ok(&self, took: Duration) {
        *self.down_until.lock() = None;
        let sample = took.as_micros().max(1) as u64;
        let old = self.latency_us.load(Ordering::Relaxed);
        let new = if old == 0 {
            sample
        } else {
            (old * 3 + sample) / 4
        };
        self.latency_us.store(new, Ordering::Relaxed);
    }

    fn record_failure(&self, cooldown: Duration) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        *self.down_until.lock() = Some(Instant::now() + cooldown);
    }
}

pub struct Balancer {
    tag: Arc<str>,
    members: Vec<Member>,
    health: Vec<Health>,
    strategy: Strategy,
    cooldown: Duration,
    next: AtomicUsize,
}

impl Balancer {
    pub fn new(
        tag: Arc<str>,
        members: Vec<Member>,
        strategy: Strategy,
        cooldown: Duration,
    ) -> Result<Self> {
        if members.is_empty() {
            bail!("a balancer needs at least one outbound");
        }
        let health = members.iter().map(|_| Health::default()).collect();
        Ok(Self {
            tag,
            members,
            health,
            strategy,
            cooldown,
            next: AtomicUsize::new(0),
        })
    }

    /// Members in the order they should be tried for one connection.
    fn candidates(&self) -> Vec<usize> {
        let n = self.members.len();
        let now = Instant::now();
        let mut order: Vec<usize> = match self.strategy {
            Strategy::Fallback => (0..n).collect(),
            Strategy::RoundRobin => {
                let start = self.next.fetch_add(1, Ordering::Relaxed) % n;
                (0..n).map(|i| (start + i) % n).collect()
            }
            Strategy::Random => {
                let start = rand::thread_rng().gen_range(0..n);
                (0..n).map(|i| (start + i) % n).collect()
            }
            Strategy::LeastPing => {
                let mut v: Vec<usize> = (0..n).collect();
                // Unknown latency sorts first, so every member gets measured.
                v.sort_by_key(|i| self.health[*i].latency_us.load(Ordering::Relaxed));
                v
            }
        };
        // Healthy members first; members in cooldown remain as a last resort.
        order.sort_by_key(|i| !self.health[*i].is_up(now));
        order
    }

    async fn attempt<T, F, Fut>(&self, sess: &Session, op: F) -> io::Result<T>
    where
        F: Fn(Arc<dyn Outbound>) -> Fut,
        Fut: std::future::Future<Output = io::Result<T>>,
    {
        let mut last = io_err(io::ErrorKind::NotConnected, "no members");
        for index in self.candidates() {
            let (tag, outbound) = &self.members[index];
            let started = Instant::now();
            let position = push_chain(sess, tag.clone());
            match op(outbound.clone()).await {
                Ok(v) => {
                    self.health[index].record_ok(started.elapsed());
                    return Ok(v);
                }
                Err(e) => {
                    sess.chain.lock().truncate(position);
                    warn!(target: "sybau::route", "balancer `{}`: member `{tag}` failed: {e}", self.tag);
                    self.health[index].record_failure(self.cooldown);
                    last = e;
                }
            }
        }
        Err(last)
    }
}

impl Group for Balancer {
    fn info(&self) -> Value {
        let now = Instant::now();
        json!({
            "strategy": self.strategy.name(),
            "all": self.members.iter().map(|(t, _)| t.to_string()).collect::<Vec<_>>(),
            "members": self.members.iter().zip(&self.health).map(|((t, _), h)| json!({
                "tag": &**t,
                "up": h.is_up(now),
                "latency_ms": h.latency_us.load(Ordering::Relaxed) as f64 / 1000.0,
                "failures": h.failures.load(Ordering::Relaxed),
            })).collect::<Vec<_>>(),
        })
    }

    fn select(&self, _member: &str) -> Result<()> {
        bail!(
            "`{}` is a balancer; only selectors can be switched",
            self.tag
        )
    }
}

#[async_trait]
impl Outbound for Balancer {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "balancer"
    }
    async fn connect(&self, sess: &Session) -> io::Result<BoxStream> {
        self.attempt(sess, |o| async move { o.connect(sess).await })
            .await
    }
    async fn bind(&self, sess: &Session) -> io::Result<ArcPacketConn> {
        self.attempt(sess, |o| async move { o.bind(sess).await })
            .await
    }
}
