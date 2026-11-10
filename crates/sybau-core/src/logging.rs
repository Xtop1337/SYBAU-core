//! Log sink shared by the executable and the library: writes to stderr
//! (optional) and fans out to subscribers of the control API.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::OnceLock;

use serde::Serialize;
use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub time: String,
    pub level: &'static str,
    pub target: String,
    pub message: String,
}

static LEVEL: AtomicU8 = AtomicU8::new(3);
static STDERR: AtomicBool = AtomicBool::new(true);
static BUS: OnceLock<broadcast::Sender<LogLine>> = OnceLock::new();

fn bus() -> &'static broadcast::Sender<LogLine> {
    BUS.get_or_init(|| broadcast::channel(1024).0)
}

fn level_num(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 1,
        Level::WARN => 2,
        Level::INFO => 3,
        Level::DEBUG => 4,
        Level::TRACE => 5,
    }
}

pub fn parse_level(s: &str) -> Option<u8> {
    Some(match s.to_ascii_lowercase().as_str() {
        "off" | "none" | "silent" => 0,
        "error" => 1,
        "warn" | "warning" => 2,
        "info" => 3,
        "debug" => 4,
        "trace" => 5,
        _ => return None,
    })
}

/// Installs the global log sink. Safe to call more than once.
pub fn init(stderr: bool) {
    STDERR.store(stderr, Ordering::Relaxed);
    let _ = tracing_subscriber::registry().with(SybauLayer).try_init();
}

pub fn set_level(level: &str) -> bool {
    match parse_level(level) {
        Some(n) => {
            LEVEL.store(n, Ordering::Relaxed);
            true
        }
        None => false,
    }
}

pub fn subscribe() -> broadcast::Receiver<LogLine> {
    bus().subscribe()
}

struct SybauLayer;

fn enabled(meta: &Metadata<'_>) -> bool {
    let configured = LEVEL.load(Ordering::Relaxed);
    let n = level_num(meta.level());
    if meta.target().starts_with("sybau") {
        n <= configured
    } else {
        // Dependencies are only heard at `warn` and above unless tracing.
        n <= configured && (n <= 2 || configured >= 5)
    }
}

struct MessageVisitor {
    message: String,
    fields: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={}", field.name(), value);
        }
    }
}

impl<S: Subscriber> Layer<S> for SybauLayer {
    fn enabled(&self, meta: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        enabled(meta)
    }

    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if !enabled(meta) {
            return;
        }
        let mut visitor = MessageVisitor {
            message: String::new(),
            fields: String::new(),
        };
        event.record(&mut visitor);
        visitor.message.push_str(&visitor.fields);
        let line = LogLine {
            time: humantime::format_rfc3339_millis(std::time::SystemTime::now()).to_string(),
            level: match *meta.level() {
                Level::ERROR => "error",
                Level::WARN => "warn",
                Level::INFO => "info",
                Level::DEBUG => "debug",
                Level::TRACE => "trace",
            },
            target: meta.target().to_string(),
            message: visitor.message,
        };
        if STDERR.load(Ordering::Relaxed) {
            eprintln!(
                "{} {:5} {}",
                line.time,
                line.level.to_ascii_uppercase(),
                line.message
            );
        }
        let _ = bus().send(line);
    }
}
