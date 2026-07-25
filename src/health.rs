//! In-process health surface: a ring buffer of recent warnings/errors.
//!
//! Operators run this server with file logging turned off — the log volume is
//! large and the disk is not — which leaves no way to notice that, say, a hash
//! blocklist failed to parse or a UDP socket never bound. This module keeps the
//! last N warning-and-above events in memory so the web panel can show them
//! without anything being written to disk.
//!
//! The buffer is deliberately small and bounded: it is a "what went wrong
//! recently" view, not a log store.
//!
//! ## Why the layer carries its own filter
//!
//! The ring layer is installed with its OWN `LevelFilter::WARN` rather than
//! inheriting the global `EnvFilter`. That is the whole point: when the operator
//! sets `log.level = "error"` (or silences logging entirely) the console stays
//! quiet, but warnings still reach the panel. Attaching the env filter globally
//! would gate this layer too and defeat the feature exactly when it is needed.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

/// How many events to keep. Each entry is a couple of hundred bytes, so the
/// whole buffer is well under 100 KB.
const CAPACITY: usize = 200;

#[derive(Clone, serde::Serialize)]
pub struct LogEntry {
    /// Seconds since the Unix epoch (the panel renders local time).
    pub ts: u64,
    /// "ERROR" or "WARN".
    pub level: &'static str,
    /// The event's message field.
    pub message: String,
    /// Remaining structured fields, rendered as `key=value` pairs.
    pub fields: String,
}

pub struct LogRing {
    inner: Mutex<VecDeque<LogEntry>>,
    /// Total events ever seen, so the panel can tell "200 shown" from
    /// "200 shown, 5000 happened".
    total: Mutex<u64>,
}

impl LogRing {
    fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(CAPACITY)),
            total: Mutex::new(0),
        }
    }

    fn push(&self, entry: LogEntry) {
        // A poisoned lock here must never take the server down: this is
        // diagnostics. Drop the event instead.
        if let Ok(mut q) = self.inner.lock() {
            if q.len() == CAPACITY {
                q.pop_front();
            }
            q.push_back(entry);
        }
        if let Ok(mut t) = self.total.lock() {
            *t += 1;
        }
    }

    /// Newest entries first, at most `limit`.
    pub fn snapshot(&self, limit: usize) -> Vec<LogEntry> {
        match self.inner.lock() {
            Ok(q) => q.iter().rev().take(limit).cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn total_seen(&self) -> u64 {
        self.total.lock().map(|t| *t).unwrap_or(0)
    }
}

static RING: OnceLock<LogRing> = OnceLock::new();

/// The process-wide ring buffer. Created on first use, so the tracing layer and
/// the web handler reach the same instance without threading it through state.
pub fn ring() -> &'static LogRing {
    RING.get_or_init(LogRing::new)
}

/// Collects a tracing event's fields into a message plus a `key=value` tail.
#[derive(Default)]
struct FieldCollector {
    message: String,
    fields: String,
}

impl FieldCollector {
    fn add(&mut self, name: &str, value: String) {
        if name == "message" {
            self.message = value;
        } else {
            if !self.fields.is_empty() {
                self.fields.push(' ');
            }
            self.fields.push_str(name);
            self.fields.push('=');
            self.fields.push_str(&value);
        }
    }
}

impl tracing::field::Visit for FieldCollector {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.add(field.name(), value.to_string());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.add(field.name(), format!("{value:?}"));
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.add(field.name(), value.to_string());
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.add(field.name(), value.to_string());
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.add(field.name(), value.to_string());
    }
}

/// Tracing layer that copies WARN/ERROR events into [`ring`].
pub struct RingLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for RingLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();
        let level = match *meta.level() {
            tracing::Level::ERROR => "ERROR",
            tracing::Level::WARN => "WARN",
            // Anything below WARN is filtered out before we get here, but be
            // explicit rather than relying on the filter alone.
            _ => return,
        };

        let mut collector = FieldCollector::default();
        event.record(&mut collector);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        ring().push(LogEntry {
            ts,
            level,
            message: collector.message,
            fields: collector.fields,
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Repeat suppression
// ─────────────────────────────────────────────────────────────────────────────

/// Rate limiter for log events that a single misbehaving peer can repeat forever.
///
/// A banned publisher whose client auto-reconnects every 30 s, or a peer stuck in
/// a connect-timeout loop, produces hundreds of identical warnings per hour.
/// Measured live: two such addresses generated ~400 WARN/h between them, which
/// overflowed the 200-entry ring in half an hour — real events (CSAM blocks) were
/// pushed out before an operator could see them. The events still matter, but the
/// 118th copy does not.
///
/// First occurrence is logged immediately; repeats within the window are counted
/// and reported as `suppressed=N` on the next one that gets through.
pub struct LogThrottle {
    seen: dashmap::DashMap<(std::net::IpAddr, &'static str), (std::time::Instant, u32)>,
}

impl LogThrottle {
    fn new() -> Self {
        Self { seen: dashmap::DashMap::new() }
    }

    /// `None` → suppress this occurrence. `Some(n)` → log it, where `n` is how many
    /// were suppressed since the last logged one (0 the first time).
    pub fn allow(
        &self,
        ip: std::net::IpAddr,
        kind: &'static str,
        window: std::time::Duration,
    ) -> Option<u32> {
        use dashmap::mapref::entry::Entry;
        let now = std::time::Instant::now();
        match self.seen.entry((ip, kind)) {
            // Never seen from this peer → log it.
            Entry::Vacant(v) => {
                v.insert((now, 0));
                Some(0)
            }
            Entry::Occupied(mut o) => {
                let (last, suppressed) = *o.get();
                if now.duration_since(last) >= window {
                    o.insert((now, 0));
                    Some(suppressed)
                } else {
                    o.insert((last, suppressed.saturating_add(1)));
                    None
                }
            }
        }
    }

    /// Drop entries untouched for longer than `max_age`. Called from the periodic
    /// cleanup so the map cannot grow with every IP ever seen.
    pub fn sweep(&self, max_age: std::time::Duration) -> usize {
        let before = self.seen.len();
        self.seen.retain(|_, (last, _)| last.elapsed() < max_age);
        before - self.seen.len()
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

static THROTTLE: OnceLock<LogThrottle> = OnceLock::new();

pub fn throttle() -> &'static LogThrottle {
    THROTTLE.get_or_init(LogThrottle::new)
}

/// How long one peer's repeat of the same event stays quiet.
pub const SUPPRESS_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);
