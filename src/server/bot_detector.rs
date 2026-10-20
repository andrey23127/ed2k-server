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

use crate::state::{BotDetection, BotHashes, BotTracker, FileHash, ServerState};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

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

/// What one UDP query was, for the counters shown with a detection.
#[derive(Debug, Clone, Copy)]
pub struct QueryInfo {
    /// A search; false for a source request.
    pub search: bool,
    /// File hashes in a source request, 0 for a search.
    pub hashes: u32,
    pub obfuscated: bool,
    /// The port of ours it arrived on (TCP+4, TCP+12, TCP+14 …).
    pub our_port: u16,
}

/// Record a single search/sources query from `peer`. Cheap on most packets:
/// pushes a timestamp and bails. Heavy work (stddev + insert) is gated by
/// DETECTION_COOLDOWN.
///
/// The address may be either family; it is keyed by source (IPv4 address,
/// IPv6 /64 by default), so a flood spread across one IPv6 prefix is one bot.
pub fn record_query(state: &Arc<ServerState>, peer: SocketAddr, q: QueryInfo, hashes: &[FileHash]) {
    let raw_ip = peer.ip();
    let ip = state.source_key(raw_ip);
    let now = Instant::now();
    let tracker = state.bot_query_log.entry(ip).or_default();
    {
        let m = &tracker.mix;
        if q.search {
            m.searches.fetch_add(1, Relaxed);
        } else {
            m.source_requests.fetch_add(1, Relaxed);
            m.source_hashes.fetch_add(q.hashes as u64, Relaxed);
        }
        if q.obfuscated {
            m.obfuscated.fetch_add(1, Relaxed);
        }
        let prev = m.last_src_port.swap(peer.port() as u32, Relaxed);
        if prev != 0 && prev != peer.port() as u32 {
            m.src_port_changes.fetch_add(1, Relaxed);
        }
        m.last_our_port.store(q.our_port as u32, Relaxed);
    }
    if !hashes.is_empty() {
        let mut r = tracker.recent_hashes.lock().unwrap_or_else(|e| e.into_inner());
        for h in hashes {
            if r.len() >= BotHashes::TRACKER_RECENT {
                r.pop_front();
            }
            r.push_back(*h);
        }
    }
    let mut times = tracker.query_times.lock().unwrap();
    times.push_back(now);
    while let Some(t) = times.front() {
        if now.duration_since(*t) > WINDOW {
            times.pop_front();
        } else {
            break;
        }
    }
    let n = times.len();
    // Early bail-out: not enough samples → can't tell if it's a bot yet.
    if n < MIN_SAMPLES_FOR_VARIANCE {
        return;
    }
    // Cheap rate check first — most non-bot IPs fail this and we skip everything below.
    let window_secs = now
        .duration_since(*times.front().unwrap())
        .as_secs_f64()
        .max(0.001);
    // ⚠ A RATE NEEDS TIME TO BE ONE. Thirty packets in a burst of 15 ms read as
    //   120 000 qpm and earned a 24-hour ban, though the source sent 67
    //   requests in all: an aMule user behind a VPN exit. Judge a source only
    //   once its window spans `bots.min_span_secs`.
    let min_span = state.live_cfg.load().bots.min_span_secs as f64;
    if window_secs < min_span {
        return;
    }
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
    let intervals: Vec<f64> = times
        .iter()
        .zip(times.iter().skip(1))
        .map(|(a, b)| b.duration_since(*a).as_secs_f64() * 1000.0)
        .collect();
    drop(times); // release the per-IP mutex before we touch other DashMaps
    let mix = tracker.mix.snapshot();
    let seen: Vec<FileHash> = tracker
        .recent_hashes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .copied()
        .collect();
    drop(tracker); // and the bot_query_log shard
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let stddev_ms = var.sqrt();

    let mut reason = String::new();
    let mut flood = false;
    // Flag if rate alone is extreme.
    if qpm > FLOOD_RATE {
        reason = format!("flood {:.0} qpm", qpm);
        flood = true;
    }
    // OR if high-rate (>200) AND uniform timing.
    else if qpm > RATE_THRESHOLD && stddev_ms < STDDEV_THRESHOLD_MS {
        reason = format!(
            "{:.0} qpm + uniform timing ({:.0}ms stddev)",
            qpm, stddev_ms
        );
    }
    if reason.is_empty() {
        return;
    }

    let (country, provider) = state
        .country_db
        .try_read()
        .ok()
        .map(|db| (db.lookup(ip).map(|(c, _)| c), db.provider(ip)))
        .unwrap_or((None, None));
    let country = country.unwrap_or_else(|| "??".to_string());

    let prev_client = state.bot_detections.get(&ip).and_then(|e| e.tcp_client.clone());
    // A UDP query says nothing about the program that sent it. A TCP login
    // from the same address does, so look for one, but only when the address
    // has a TCP connection at all: the scan walks every client, and this runs
    // at most once per DETECTION_COOLDOWN per bot. Behind a NAT this may be a
    // different program on the same address, which is why it is shown as
    // "TCP client on this IP", not as the bot's software.
    let tcp_client = tcp_client_on(state, raw_ip).or(prev_client);

    // Auto-ban this flood bot for 24h. Its UDP datagrams will be dropped at
    // the top of the recv loop (before parsing), so the flood becomes free and
    // record_query() stops being called for it. The static ipfilter is no use
    // here — these IPs are dynamic — but a time-boxed in-memory ban kills the
    // active flood, and a rotated IP gets flagged + banned the same way.
    // A flood is banned. A "uniform timing" source is, by what the panel has
    // shown, mostly one client build with broken UDP pacing (~567 qpm, one
    // hash per packet, a few dozen downloads): ordinary users. It is
    // throttled to `bots.throttle_qpm` and still answered, unless the config
    // says "ban".
    let bots_cfg = state.live_cfg.load().bots.clone();
    let throttled = !flood && bots_cfg.throttle_uniform();
    if throttled {
        state.throttle_bot(ip, bots_cfg.throttle_qpm);
    } else {
        state.ban_bot(ip);
    }

    let now_sys = SystemTime::now();
    {
        // Updated in place: the hashes and the after-ban counters of an
        // earlier detection of the same source carry over.
        let mut d = state.bot_detections.entry(ip).or_insert_with(|| BotDetection {
            first_seen: now_sys,
            last_seen: now_sys,
            query_count: 0,
            queries_per_minute: 0.0,
            interval_stddev_ms: 0.0,
            country: String::new(),
            reason: String::new(),
            mix: Default::default(),
            tcp_client: None,
            provider: None,
            hashes: BotHashes::default(),
            dropped_after_ban: 0,
            last_dropped: None,
            throttled: false,
            ipfilter_added: false,
        });
        d.throttled = throttled;
        d.last_seen = now_sys;
        d.query_count += 1;
        d.queries_per_minute = qpm;
        d.interval_stddev_ms = stddev_ms;
        d.country = country;
        d.reason = reason.clone();
        d.mix = mix.clone();
        d.tcp_client = tcp_client;
        d.provider = provider;
        // The tracker kept only the last few hashes; the total before the
        // ban comes from the counter, so it is not understated.
        if d.query_count == 1 {
            d.hashes.total += mix.source_hashes.saturating_sub(seen.len() as u64);
        }
        for h in seen {
            d.hashes.add(h);
        }
        ledger(state, ledger_entry("detected", ip, &d));
    }

    // Count UNIQUE detection events (gated by DETECTION_COOLDOWN above), not every packet.
    *state.block_stats.entry("bot".to_string()).or_insert(0) += 1;

    tracing::warn!(ip = %ip, qpm = %qpm, stddev_ms = %stddev_ms,
                  reason = %reason, "bot detected — banned 24h");
}

/// One hour of source requests from one source, for the scanner and hammer
/// rules (`record_sources`).
#[derive(Default)]
pub struct ScanWindow {
    start: Option<Instant>,
    /// Files asked in source requests (TCP and UDP), repeats included.
    files: u32,
    /// Different files, counted once the window has `HLL_FROM` files: an
    /// ordinary client asks fewer than 200 an hour (live, 2026-10-20), so
    /// most sources never pay for the 64 bytes.
    distinct: Option<Box<crate::server::activity::Hll>>,
    /// Judged in this window already.
    flagged: bool,
}

const SCAN_WINDOW: Duration = Duration::from_secs(3600);
const HLL_FROM: u32 = 200;

impl ScanWindow {
    fn distinct(&self) -> f64 {
        self.distinct.as_ref().map_or(0.0, |h| h.estimate().min(self.files as f64))
    }
    pub fn has_distinct(&self) -> bool {
        self.distinct.is_some()
    }
    pub fn expired(&self) -> bool {
        self.start.map_or(true, |s| s.elapsed() >= SCAN_WINDOW)
    }
}

/// Source requests of `raw_ip` (TCP or UDP), judged per hour against two
/// rules measured on the live server (2026-10-20, 91 000 sources over 7 h):
///
/// - **Scanner**: at least `bots.scan_min_files` files asked (2 000) of which
///   at least `bots.scan_min_distinct` different (1 000). It walks a list.
///   An ordinary eMule asks 15 files every 5 minutes, about 180 an hour,
///   however long its download list; the busiest ordinary source asked
///   under 1 000 an hour. Banned by default (`scan_action`).
/// - **Hammer**: at least `bots.hammer_min_files` files asked (3 000) of
///   fewer than `bots.hammer_max_distinct` different ones (100): the same
///   file or two, over and over, up to 10 a second. Mostly one mobile client
///   build with a bug; its users are real, so it is throttled by default.
pub fn record_sources(state: &Arc<ServerState>, raw_ip: IpAddr, hashes: &[FileHash], tcp: bool) {
    if hashes.is_empty() {
        return;
    }
    let ip = state.source_key(raw_ip);
    let cfg = state.live_cfg.load();
    let b = &cfg.bots;
    let verdict = {
        let mut w = state.scan_windows.entry(ip).or_default();
        if w.expired() {
            *w = ScanWindow { start: Some(Instant::now()), ..Default::default() };
        }
        w.files = w.files.saturating_add(hashes.len() as u32);
        if w.files >= HLL_FROM || w.distinct.is_some() {
            let h = w.distinct.get_or_insert_with(Default::default);
            for x in hashes {
                h.add(x);
            }
        }
        if w.flagged {
            return;
        }
        let files = w.files as u64;
        // Cheap test first: both rules need this many files.
        if files < b.scan_min_files.min(b.hammer_min_files) {
            return;
        }
        let distinct = w.distinct();
        let mins = w.start.map_or(0.0, |s| s.elapsed().as_secs_f64() / 60.0).max(1.0);
        let v = if files >= b.scan_min_files && distinct >= b.scan_min_distinct as f64 {
            Some((
                format!("scanner: {files} files ({distinct:.0} different) in {mins:.0} min"),
                b.scan_action.clone(),
            ))
        } else if files >= b.hammer_min_files && distinct < b.hammer_max_distinct as f64 {
            Some((
                format!("hammer: {files} requests for {distinct:.0} file(s) in {mins:.0} min"),
                b.hammer_action.clone(),
            ))
        } else {
            None
        };
        if v.is_some() {
            w.flagged = true;
        }
        v.map(|(r, a)| (r, a, files as f64 / mins))
    };
    let Some((reason, action, per_min)) = verdict else { return };
    let action = action.trim().to_ascii_lowercase();
    if action == "log" || action == "off" {
        tracing::warn!(%ip, tcp, %reason, "bot rule matched (action = log, nothing done)");
        ledger(state, serde_json::json!({
            "time": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "event": "matched", "ip": ip.to_string(), "reason": reason, "tcp": tcp,
        }));
        return;
    }
    let throttled = action == "throttle";
    flag(state, ip, raw_ip, reason, per_min, -1.0, throttled, hashes);
}

/// Ban or throttle `ip` for 24 h and record it as a detection, as the rate
/// rules do. Used by `record_sources`.
#[allow(clippy::too_many_arguments)]
fn flag(
    state: &Arc<ServerState>,
    ip: IpAddr,
    raw_ip: IpAddr,
    reason: String,
    qpm: f64,
    stddev_ms: f64,
    throttled: bool,
    hashes: &[FileHash],
) {
    if throttled {
        state.throttle_bot(ip, state.live_cfg.load().bots.throttle_qpm);
    } else {
        state.ban_bot(ip);
    }
    let (country, provider) = state
        .country_db
        .try_read()
        .ok()
        .map(|db| (db.lookup(ip).map(|(c, _)| c), db.provider(ip)))
        .unwrap_or((None, None));
    let mix = state.bot_query_log.get(&ip).map(|t| t.mix.snapshot()).unwrap_or_default();
    let tcp_client = tcp_client_on(state, raw_ip);
    let now_sys = SystemTime::now();
    {
        let mut d = state.bot_detections.entry(ip).or_insert_with(|| BotDetection {
            first_seen: now_sys,
            last_seen: now_sys,
            query_count: 0,
            queries_per_minute: 0.0,
            interval_stddev_ms: 0.0,
            country: String::new(),
            reason: String::new(),
            mix: Default::default(),
            tcp_client: None,
            provider: None,
            hashes: BotHashes::default(),
            dropped_after_ban: 0,
            last_dropped: None,
            throttled: false,
            ipfilter_added: false,
        });
        d.throttled = throttled;
        d.last_seen = now_sys;
        d.query_count += 1;
        d.queries_per_minute = qpm;
        d.interval_stddev_ms = stddev_ms;
        d.country = country.unwrap_or_else(|| "??".to_string());
        d.reason = reason.clone();
        d.mix = mix;
        if tcp_client.is_some() {
            d.tcp_client = tcp_client;
        }
        d.provider = provider;
        for h in hashes {
            d.hashes.add(*h);
        }
        ledger(state, ledger_entry("detected", ip, &d));
    }
    *state.block_stats.entry("bot".to_string()).or_insert(0) += 1;
    tracing::warn!(%ip, %reason, action = if throttled { "throttled" } else { "banned" },
                   "bot detected — 24h");
}

/// The file hashes in a UDP source request: 0x9A carries bare hashes, 0x94
/// hash + size (+ 8 bytes when the 32-bit size is 0, a large file). At most
/// 64, as the handler answers.
pub fn query_hashes(opcode: u8, payload: &[u8]) -> Vec<FileHash> {
    const MAX: usize = 64;
    let mut out = Vec::new();
    match opcode {
        0x9A => {
            for c in payload.chunks_exact(16).take(MAX) {
                out.push(c.try_into().unwrap());
            }
        }
        0x94 => {
            let mut i = 0;
            while i + 20 <= payload.len() && out.len() < MAX {
                out.push(payload[i..i + 16].try_into().unwrap());
                let lo = &payload[i + 16..i + 20];
                i += 20;
                if lo == [0, 0, 0, 0] {
                    if i + 8 > payload.len() {
                        break;
                    }
                    i += 8;
                }
            }
        }
        _ => {}
    }
    out
}

/// A datagram from a banned source, dropped. Counted, and the hashes of a
/// plain source request are kept; nothing is parsed beyond that and nothing
/// is answered. An obfuscated datagram is only counted: decoding it would
/// spend on the bot the work the ban saves.
pub fn note_banned(state: &Arc<ServerState>, ip: IpAddr, datagram: &[u8]) {
    let key = state.source_key(ip);
    let Some(mut d) = state.bot_detections.get_mut(&key) else { return };
    d.dropped_after_ban += 1;
    d.last_dropped = Some(SystemTime::now());
    if datagram.len() > 2 && datagram[0] == 0xE3 {
        for h in query_hashes(datagram[1], &datagram[2..]) {
            d.hashes.add(h);
        }
    }
    // Kept sending into silence long enough: into the IP filter for good.
    // Exactly at the threshold, so it is tried once per source.
    let min = state.live_cfg.load().bots.ipfilter_min_dropped;
    let need = if d.throttled { min.saturating_mul(10) } else { min };
    if min > 0 && !d.ipfilter_added && d.dropped_after_ban >= need {
        if let IpAddr::V4(v4) = key {
            d.ipfilter_added = true;
            let entry = ledger_entry("ipfilter_added", key, &d);
            drop(d);
            ledger(state, entry);
            crate::server::bot_ipfilter::add_async(state, v4);
        }
    }
}

/// A source's 24-hour ban (or throttle) ran out: write what it did meanwhile
/// to the ledger.
pub fn ban_ended(state: &ServerState, key: IpAddr) {
    if let Some(d) = state.bot_detections.get(&key) {
        let ev = if d.throttled { "throttle_ended" } else { "ban_ended" };
        ledger(state, ledger_entry(ev, key, &d));
    }
}

/// Where the ledger goes: the configured path, `bot-log.jsonl` next to the
/// config file when empty, or nowhere for "off".
pub fn ledger_path(configured: &str, config_file: &std::path::Path) -> Option<std::path::PathBuf> {
    match configured.trim() {
        "off" => None,
        "" => Some(
            config_file
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."))
                .join("bot-log.jsonl"),
        ),
        p => Some(p.into()),
    }
}

/// One ledger line. Hex hashes, newest last; no file names, so the ledger can
/// be shared as it is.
pub fn ledger_entry(event: &str, key: IpAddr, d: &BotDetection) -> serde_json::Value {
    let sample: Vec<String> = d.hashes.recent.iter().map(hex::encode).collect();
    serde_json::json!({
        "time": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "event": event,
        "ip": key.to_string(),
        "country": d.country,
        "provider": d.provider,
        "reason": d.reason,
        "qpm": d.queries_per_minute.round(),
        "stddev_ms": d.interval_stddev_ms.round(),
        "tcp_client": d.tcp_client,
        "searches": d.mix.searches,
        "source_requests": d.mix.source_requests,
        "obfuscated": d.mix.obfuscated,
        "src_port": d.mix.src_port,
        "src_port_changes": d.mix.src_port_changes,
        "our_port": d.mix.our_port,
        "hashes_total": d.hashes.total,
        "hashes_distinct": d.hashes.distinct.len(),
        "dropped_after_ban": d.dropped_after_ban,
        "action": if d.throttled { "throttled" } else { "banned" },
        "ipfilter_added": d.ipfilter_added,
        "hash_sample": sample,
    })
}

/// Append a line to the ledger, off the caller's thread when there is a
/// runtime. A failure is logged and otherwise ignored: the ledger is a
/// record, not something the server depends on.
pub fn ledger(state: &ServerState, entry: serde_json::Value) {
    let Some(Some(path)) = state.bot_log_path.get() else { return };
    let path = path.clone();
    let write = move || {
        use std::io::Write;
        let r = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut f| writeln!(f, "{entry}"));
        if let Err(e) = r {
            tracing::warn!(path = %path.display(), error = %e, "bot ledger write failed");
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(h) => {
            h.spawn_blocking(write);
        }
        Err(_) => write(),
    }
}

/// "eMule v0.50a (nick)" for a client logged in from `ip`, if any; with
/// several, the count is added.
fn tcp_client_on(state: &ServerState, ip: IpAddr) -> Option<String> {
    if !state.conn_per_ip.contains_key(&ip) {
        return None;
    }
    let mut first = None;
    let mut n = 0u32;
    for c in state.clients.iter() {
        if c.ip == ip {
            n += 1;
            if first.is_none() {
                let nick: String = c.nick.chars().take(40).collect();
                first = Some(format!("{} ({nick})", c.software_detail));
            }
        }
    }
    first.map(|f| if n > 1 { format!("{f} +{} more", n - 1) } else { f })
}

// Keep BotTracker visible in the public API.
#[allow(dead_code)]
const _: fn() = || {
    let _: fn() -> BotTracker = BotTracker::default;
};

#[cfg(test)]
mod source_key_tests {
    use super::*;

    /// A state whose detector judges at once (no minimum span), so the tests
    /// can send their packets back to back.
    fn test_state() -> Arc<ServerState> {
        let st = Arc::new(ServerState::for_test());
        let mut cfg = (**st.live_cfg.load()).clone();
        cfg.bots.min_span_secs = 0;
        st.live_cfg.store(Arc::new(cfg));
        st
    }

    #[test]
    fn a_short_burst_is_not_a_flood() {
        // Default span: 40 packets in a burst are judged as nothing.
        let st = Arc::new(ServerState::for_test());
        let q = QueryInfo { search: false, hashes: 1, obfuscated: false, our_port: 6086 };
        for _ in 0..40 {
            record_query(&st, SocketAddr::new("198.51.100.20".parse().unwrap(), 4672), q, &[[1; 16]]);
        }
        assert!(st.bot_detections.is_empty());
        assert!(!st.is_bot_banned("198.51.100.20".parse().unwrap()));
    }

    #[test]
    fn uniform_timing_is_throttled_and_a_flood_banned() {
        let st = test_state();
        let ip: IpAddr = "198.51.100.30".parse().unwrap();
        // ~600 qpm with even 100 ms gaps, faked by spreading the timestamps.
        {
            let t = st.bot_query_log.entry(st.source_key(ip)).or_default();
            let mut times = t.query_times.lock().unwrap();
            let now = Instant::now();
            for k in (0..40u64).rev() {
                times.push_back(now - Duration::from_millis(k * 110));
            }
        }
        let q = QueryInfo { search: false, hashes: 1, obfuscated: false, our_port: 6086 };
        record_query(&st, SocketAddr::new(ip, 4672), q, &[[2; 16]]);
        assert!(st.is_bot_throttled(ip), "uniform → throttled");
        assert!(!st.is_bot_banned(ip));
        // The throttle lets a few through, then drops.
        let passed = (0..20).filter(|_| st.bot_throttle_admit(ip) == Some(true)).count();
        assert!((1..=6).contains(&passed), "burst of 5 (+refill), got {passed}");
        assert!(st.bot_detections.get(&ip).unwrap().throttled);
    }

    #[test]
    fn a_source_that_keeps_sending_through_its_ban_is_marked_for_the_ipfilter() {
        let st = test_state();
        let mut cfg = (**st.live_cfg.load()).clone();
        cfg.bots.ipfilter_min_dropped = 3;
        st.live_cfg.store(Arc::new(cfg));
        let ip: IpAddr = "203.0.113.77".parse().unwrap();
        let q = QueryInfo { search: false, hashes: 1, obfuscated: false, our_port: 6086 };
        for _ in 0..40 {
            record_query(&st, SocketAddr::new(ip, 4672), q, &[[3; 16]]);
        }
        assert!(st.is_bot_banned(ip));
        note_banned(&st, ip, &[0x4F]);
        note_banned(&st, ip, &[0x4F]);
        assert!(!st.bot_detections.get(&ip).unwrap().ipfilter_added);
        note_banned(&st, ip, &[0x4F]);
        assert!(st.bot_detections.get(&ip).unwrap().ipfilter_added, "at the threshold");
    }

    fn flood(state: &Arc<ServerState>, ips: impl Iterator<Item = IpAddr>) {
        let q = QueryInfo { search: false, hashes: 1, obfuscated: false, our_port: 4665 };
        for ip in ips {
            record_query(state, SocketAddr::new(ip, 4672), q, &[[7; 16]]);
        }
    }

    #[test]
    fn a_detection_keeps_what_the_bot_sent() {
        let st = test_state();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        for i in 0..40u16 {
            let q = QueryInfo { search: i % 4 == 0, hashes: 3, obfuscated: i % 2 == 0, our_port: 4665 };
            record_query(&st, SocketAddr::new(ip, 4672 + (i / 20)), q, &[[i as u8; 16]]);
        }
        // Flagged at the 30th query; the cooldown keeps that snapshot.
        let d = st.bot_detections.get(&ip).expect("flagged");
        assert_eq!(d.mix.searches + d.mix.source_requests, 30);
        assert_eq!(d.mix.searches, 8);
        assert_eq!(d.mix.source_hashes, 66);
        assert_eq!(d.mix.obfuscated, 15);
        assert_eq!(d.mix.src_port, 4673);
        assert_eq!(d.mix.src_port_changes, 1);
        assert_eq!(d.mix.our_port, 4665);
        assert!(d.tcp_client.is_none(), "no TCP session from it");
        // The tracker's last 16 hashes seed the detection.
        assert_eq!(d.hashes.recent.len(), BotHashes::TRACKER_RECENT);
        assert_eq!(*d.hashes.recent.back().unwrap(), [29u8; 16]);
        drop(d);

        // After the ban: counted, and plain source requests keep their hashes.
        assert!(st.is_bot_banned(ip));
        let mut pkt = vec![0xE3, 0x94];
        pkt.extend_from_slice(&[0xAB; 16]);
        pkt.extend_from_slice(&1000u32.to_le_bytes());
        note_banned(&st, ip, &pkt);
        note_banned(&st, ip, &[0x4F, 0x12, 0x34]); // obfuscated: counted only
        let d = st.bot_detections.get(&ip).unwrap();
        assert_eq!(d.dropped_after_ban, 2);
        assert!(d.hashes.distinct.contains(&[0xAB; 16]));
        assert_eq!(*d.hashes.recent.back().unwrap(), [0xAB; 16]);
    }

    #[test]
    fn source_request_hashes_are_read_exactly() {
        let mut p = Vec::new();
        p.extend_from_slice(&[1; 16]);
        p.extend_from_slice(&5u32.to_le_bytes());
        p.extend_from_slice(&[2; 16]);
        p.extend_from_slice(&0u32.to_le_bytes()); // large file: 8 more bytes
        p.extend_from_slice(&(5u64 << 32).to_le_bytes());
        p.extend_from_slice(&[3; 16]);
        p.extend_from_slice(&9u32.to_le_bytes());
        assert_eq!(query_hashes(0x94, &p), vec![[1; 16], [2; 16], [3; 16]]);
        assert_eq!(query_hashes(0x9A, &[[4u8; 16], [5; 16]].concat()), vec![[4; 16], [5; 16]]);
        assert!(query_hashes(0x98, &p).is_empty());
    }

    #[test]
    fn ledger_lines_are_appended() {
        let st = test_state();
        let dir = std::env::temp_dir().join(format!("botlog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bot-log.jsonl");
        let _ = std::fs::remove_file(&path);
        st.bot_log_path.set(Some(path.clone())).unwrap();
        flood(&st, (0..40).map(|_| "198.51.100.4".parse().unwrap()));
        ban_ended(&st, "198.51.100.4".parse().unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> =
            text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], "detected");
        assert_eq!(lines[1]["event"], "ban_ended");
        assert_eq!(lines[0]["hash_sample"][0], hex::encode([7u8; 16]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_ledger_sits_next_to_the_config_by_default() {
        let cfg = std::path::Path::new("/etc/ed2k-server/config.toml");
        assert_eq!(ledger_path("", cfg), Some("/etc/ed2k-server/bot-log.jsonl".into()));
        assert_eq!(ledger_path("off", cfg), None);
        assert_eq!(ledger_path("/var/log/bots.jsonl", cfg), Some("/var/log/bots.jsonl".into()));
        assert_eq!(ledger_path("", std::path::Path::new("c.toml")), Some("./bot-log.jsonl".into()));
    }

    #[test]
    fn an_ipv6_flood_spread_over_one_prefix_is_one_banned_bot() {
        let st = test_state();
        // 40 queries, each from a different address in 2001:db8:1:2::/64.
        flood(&st, (1..=40u16).map(|i| {
            IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 7, i))
        }));
        assert_eq!(st.bot_detections.len(), 1, "one source, one detection");
        let same_prefix: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let other_prefix: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(st.is_bot_banned(same_prefix));
        assert!(!st.is_bot_banned(other_prefix));
    }

    #[test]
    fn ipv4_and_mapped_ipv4_are_the_same_source() {
        let st = test_state();
        let v4: IpAddr = "203.0.113.9".parse().unwrap();
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        flood(&st, (0..20).map(|_| v4).chain((0..20).map(|_| mapped)));
        assert!(st.is_bot_banned(v4));
        assert!(st.is_bot_banned(mapped));
        assert!(!st.is_bot_banned("203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn a_slow_querier_is_not_flagged() {
        let st = test_state();
        flood(&st, (0..10).map(|_| "2001:db8::1".parse().unwrap()));
        assert!(st.bot_detections.is_empty());
        assert!(!st.is_bot_banned("2001:db8::1".parse().unwrap()));
    }
}

#[cfg(test)]
mod scan_rule_tests {
    use super::*;

    fn h(i: u32) -> FileHash {
        let mut x = [0u8; 16];
        x[..4].copy_from_slice(&i.to_le_bytes());
        x[8..12].copy_from_slice(&i.wrapping_mul(2_654_435_761).to_le_bytes());
        x
    }

    fn st() -> Arc<ServerState> {
        Arc::new(ServerState::for_test())
    }

    #[test]
    fn an_ordinary_client_with_a_long_list_is_left_alone() {
        // 15 files every 5 minutes is what eMule does; even a whole hour of
        // it, over a list of 3 000 files, is nowhere near the rule.
        let s = st();
        let ip: IpAddr = "198.51.100.30".parse().unwrap();
        for i in 0..180 {
            record_sources(&s, ip, &[h(i)], true);
        }
        assert!(!s.is_bot_banned(ip));
        assert!(s.bot_throttle_admit(ip).is_none());
        assert!(s.bot_detections.get(&ip).is_none());
    }

    #[test]
    fn a_list_scanner_is_banned() {
        let s = st();
        let ip: IpAddr = "198.51.100.31".parse().unwrap();
        for i in 0..1999 {
            record_sources(&s, ip, &[h(i)], true);
        }
        assert!(!s.is_bot_banned(ip), "not before 2 000 files");
        record_sources(&s, ip, &[h(1999)], true);
        assert!(s.is_bot_banned(ip));
        let d = s.bot_detections.get(&ip).unwrap();
        assert!(d.reason.starts_with("scanner"), "{}", d.reason);
        assert!(!d.throttled);
    }

    #[test]
    fn batched_udp_requests_count_by_file() {
        let s = st();
        let ip: IpAddr = "198.51.100.32".parse().unwrap();
        for r in 0..80u32 {
            let batch: Vec<FileHash> = (0..25).map(|k| h(r * 25 + k)).collect();
            record_sources(&s, ip, &batch, false);
        }
        assert!(s.is_bot_banned(ip), "2 000 different files in 80 requests");
    }

    #[test]
    fn a_hammer_is_throttled_not_banned() {
        let s = st();
        let ip: IpAddr = "198.51.100.33".parse().unwrap();
        for i in 0..3000u32 {
            record_sources(&s, ip, &[h(i % 2)], true);
        }
        assert!(!s.is_bot_banned(ip));
        assert!(s.bot_throttle_admit(ip).is_some());
        let d = s.bot_detections.get(&ip).unwrap();
        assert!(d.reason.starts_with("hammer"), "{}", d.reason);
        assert!(d.throttled);
    }

    #[test]
    fn many_files_asked_a_few_times_each_is_neither() {
        // 2 500 requests over 500 files: above the hammer's distinct limit,
        // below the scanner's.
        let s = st();
        let ip: IpAddr = "198.51.100.34".parse().unwrap();
        for i in 0..2500u32 {
            record_sources(&s, ip, &[h(i % 500)], true);
        }
        assert!(!s.is_bot_banned(ip));
        assert!(s.bot_throttle_admit(ip).is_none());
    }

    #[test]
    fn action_log_only_records() {
        let s = st();
        let mut cfg = (**s.live_cfg.load()).clone();
        cfg.bots.scan_action = "log".into();
        s.live_cfg.store(Arc::new(cfg));
        let ip: IpAddr = "198.51.100.35".parse().unwrap();
        for i in 0..2000 {
            record_sources(&s, ip, &[h(i)], true);
        }
        assert!(!s.is_bot_banned(ip));
        assert!(s.bot_detections.get(&ip).is_none());
    }

    #[test]
    fn a_ban_wakes_the_tcp_sessions() {
        let s = st();
        let rx = s.ip_filter_gen.subscribe();
        s.ban_bot("198.51.100.36".parse().unwrap());
        assert!(rx.has_changed().unwrap());
    }
}
