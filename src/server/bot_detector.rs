//! Bot detection: identify clients with abnormal query patterns.
//!
//! Bots are characterized by:
//!  1. High query rate (>60 queries/minute is suspicious; >120/min is almost
//!     certainly a bot, since real users browse and download, not flood-search).
//!  2. Low inter-query interval variance (bots often query at fixed intervals,
//!     e.g. every 1.0s exactly; humans have high jitter).
//!
//! We track a sliding 60-second window of query timestamps per IP. The
//! detector is invoked from the UDP search/sources handlers on every packet,
//! so it must stay cheap: most work bails out early when the window is small,
//! and the expensive variance computation only runs once per 5 seconds per IP.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use crate::state::{BotDetection, BotTracker, ServerState};

const WINDOW: Duration = Duration::from_secs(60);
/// A normal eMule client does a few searches per minute. Above 200 is suspicious.
/// Below this rate, we don't even try to flag.
const RATE_THRESHOLD: f64 = 200.0;
/// "Very high rate" — alone is enough to flag, regardless of timing.
const FLOOD_RATE: f64 = 600.0;
/// Inter-query interval stddev below this AT HIGH RATE = robotic timing.
const STDDEV_THRESHOLD_MS: f64 = 50.0;
/// Need at least this many samples in window before computing stddev.
const MIN_SAMPLES_FOR_VARIANCE: usize = 30;
const DETECTION_COOLDOWN: Duration = Duration::from_secs(30);

/// Record a single search/sources query from `ip`. Cheap on most packets:
/// pushes a timestamp and bails. Heavy work (stddev + insert) is gated by
/// DETECTION_COOLDOWN.
pub fn record_query(state: &Arc<ServerState>, ip: Ipv4Addr) {
    let now = Instant::now();
    let tracker = state.bot_query_log.entry(ip).or_default();
    let mut times = tracker.query_times.lock().unwrap();
    times.push_back(now);
    while let Some(t) = times.front() {
        if now.duration_since(*t) > WINDOW {
            times.pop_front();
        } else { break; }
    }
    let n = times.len();
    // Early bail-out: not enough samples → can't tell if it's a bot yet.
    if n < MIN_SAMPLES_FOR_VARIANCE {
        return;
    }
    // Cheap rate check first — most non-bot IPs fail this and we skip everything below.
    let window_secs = now.duration_since(*times.front().unwrap()).as_secs_f64().max(0.001);
    let qpm = (n as f64 / window_secs) * 60.0;
    if qpm < RATE_THRESHOLD {
        return;
    }
    // Throttle expensive work: skip if we already updated this IP recently.
    if let Some(existing) = state.bot_detections.get(&ip) {
        if let Ok(age) = SystemTime::now().duration_since(existing.last_seen) {
            if age < DETECTION_COOLDOWN {
                return;
            }
        }
    }

    // Compute interval stddev only now that we know this IP is rate-suspicious.
    let intervals: Vec<f64> = times.iter().zip(times.iter().skip(1))
        .map(|(a, b)| b.duration_since(*a).as_secs_f64() * 1000.0)
        .collect();
    drop(times);  // release the per-IP mutex before we touch other DashMaps
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let stddev_ms = var.sqrt();

    let mut reason = String::new();
    // Flag if rate alone is extreme.
    if qpm > FLOOD_RATE {
        reason = format!("flood {:.0} qpm", qpm);
    }
    // OR if high-rate (>200) AND uniform timing.
    else if qpm > RATE_THRESHOLD && stddev_ms < STDDEV_THRESHOLD_MS {
        reason = format!("{:.0} qpm + uniform timing ({:.0}ms stddev)", qpm, stddev_ms);
    }
    if reason.is_empty() {
        return;
    }

    let country = state.country_db.try_read()
        .ok()
        .and_then(|db| db.lookup(ip).map(|(c, _)| c))
        .unwrap_or_else(|| "??".to_string());

    let (first_seen, prev_count) = match state.bot_detections.get(&ip) {
        Some(e) => (e.first_seen, e.query_count),
        None => (SystemTime::now(), 0),
    };

    // Auto-ban this flood bot for 24h. Its UDP datagrams will be dropped at
    // the top of the recv loop (before parsing), so the flood becomes free and
    // record_query() stops being called for it. The static ipfilter is no use
    // here — these IPs are dynamic — but a time-boxed in-memory ban kills the
    // active flood, and a rotated IP gets flagged + banned the same way.
    state.ban_bot(ip);

    state.bot_detections.insert(ip, BotDetection {
        first_seen,
        last_seen: SystemTime::now(),
        query_count: prev_count + 1,
        queries_per_minute: qpm,
        interval_stddev_ms: stddev_ms,
        country,
        reason: reason.clone(),
    });

    // Count UNIQUE detection events (gated by DETECTION_COOLDOWN above), not every packet.
    *state.block_stats.entry("bot".to_string()).or_insert(0) += 1;

    tracing::warn!(ip = %ip, qpm = %qpm, stddev_ms = %stddev_ms,
                  reason = %reason, "bot detected — banned 24h");
}

// Keep BotTracker visible in the public API.
#[allow(dead_code)]
const _: fn() = || {
    let _: fn() -> BotTracker = BotTracker::default;
};
