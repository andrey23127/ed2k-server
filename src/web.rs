//! Minimal admin web interface (SPEC: localhost-only, read-mostly).
//!
//! Binds to 127.0.0.1 ONLY. Never exposed publicly — accessed via SSH tunnel:
//!     ssh -L 8080:127.0.0.1:8080 your-vps
//! Then open http://localhost:8080 in your browser.
//!
//! There is no auth in the web server itself — access control is delegated
//! to SSH. This keeps the admin surface tiny and removes the most common
//! class of bugs (auth bypass). Adding HTTP-level auth here would be a
//! redundant second wall against the same attacker.
//!
//! Endpoints:
//!   GET  /                    HTML dashboard (Status / Stats / Clients tabs)
//!   GET  /api/status          JSON: uptime, file count, client count, seckey hex
//!   GET  /api/stats           JSON: process CPU/RSS, traffic counters, cache hit
//!   GET  /api/clients         JSON: connected clients (ip, nick, files, dur)
//!   GET  /api/peers           JSON: known peer servers + ServerKey learned?
//!   POST /api/reload          trigger SIGHUP-equivalent config + filter reload

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::config::Config;
use crate::state::ServerState;

/// Live-collected counters wired into hot paths. Atomic so they can be
/// touched from any task without locks. The web handler just reads them.
#[derive(Default)]
pub struct Metrics {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub searches_total: AtomicU64,
    pub get_sources_total: AtomicU64,
    pub get_sources_cache_hits: AtomicU64,
    /// Wallclock instant when the server started.
    pub start: once_cell::sync::OnceCell<Instant>,
}

impl Metrics {
    pub fn new() -> Self {
        let m = Self::default();
        let _ = m.start.set(Instant::now());
        m
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start
            .get()
            .map(|s| s.elapsed().as_secs())
            .unwrap_or(0)
    }
}

/// Snapshot of `/proc/self/stat` and `/proc/self/status` for CPU/RAM metrics.
/// Linux-only; on other OSes returns zeros. Cheap enough to read per-request.
fn read_proc_stats() -> ProcStats {
    let mut s = ProcStats::default();

    // RSS from /proc/self/status (line: "VmRSS:  <kB> kB")
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                if let Some(n) = rest.split_whitespace().next() {
                    s.rss_kib = n.parse().unwrap_or(0);
                }
            } else if let Some(rest) = line.strip_prefix("VmPeak:") {
                if let Some(n) = rest.split_whitespace().next() {
                    s.peak_kib = n.parse().unwrap_or(0);
                }
            } else if let Some(rest) = line.strip_prefix("Threads:") {
                if let Some(n) = rest.split_whitespace().next() {
                    s.threads = n.parse().unwrap_or(0);
                }
            }
        }
    }

    // CPU jiffies from /proc/self/stat (fields 14, 15: utime, stime; 22: starttime)
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        // The comm field can contain spaces, so split after the last ')'.
        if let Some(after_comm) = stat.rsplit_once(')') {
            let fields: Vec<&str> = after_comm.1.split_whitespace().collect();
            // fields[0]=state, ..., fields[11]=utime, fields[12]=stime, fields[19]=starttime
            // (all 0-indexed after the ')' split; matches /proc/[pid]/stat column offsets minus 3)
            if fields.len() > 19 {
                s.utime_jiffies  = fields[11].parse().unwrap_or(0);
                s.stime_jiffies  = fields[12].parse().unwrap_or(0);
                s.starttime_jiffy = fields[19].parse().unwrap_or(0);
            }
        }
    }

    s
}

#[derive(Default, Clone, Copy)]
struct ProcStats {
    rss_kib: u64,
    peak_kib: u64,
    utime_jiffies: u64,
    stime_jiffies: u64,
    starttime_jiffy: u64,  // ticks since system boot when process started
    threads: u64,
}

/// Shared state for the web layer.
#[derive(Clone)]
pub struct WebState {
    pub server: Arc<ServerState>,
    pub config: Arc<Config>,
    pub metrics: Arc<Metrics>,
    pub seckey_hex: String,
    /// Path to the TOML config file (for the Settings tab read/write).
    /// Empty string disables the Settings editor.
    pub config_path: String,
    /// Triggered to request a hot reload of the content filter and other
    /// safely-reloadable config. Read by the main task's reload watcher.
    pub reload_flag: Arc<std::sync::atomic::AtomicBool>,
    /// Cached public IPv4 string. Computed once at startup so /api/status
    /// doesn't re-parse /proc/net/fib_trie on every 5s poll.
    pub cached_public_ip: String,
}

/// Spawn the admin HTTP server on 127.0.0.1:port. Never binds to a public
/// address even if config asked for one — that would be a footgun.
pub fn spawn_admin(state: WebState, port: u16) {
    tokio::spawn(async move {
        let app = Router::new()
            .route("/", get(dashboard))
            .route("/api/status", get(api_status))
            .route("/api/stats", get(api_stats))
            .route("/api/clients", get(api_clients))
            .route("/api/peers", get(api_peers))
            .route("/api/reload", post(api_reload))
            .route("/api/client_stats", get(api_client_stats))
            .route("/api/country_stats", get(api_country_stats))
            .route("/api/filter_info", get(api_filter_info))
            .route("/api/ipfilter_hits", get(api_ipfilter_hits))
            .route("/api/config", get(api_config_get))
            .route("/api/config", post(api_config_set))
            .route("/api/bots", get(api_bots))
            .route("/api/block_stats", get(api_block_stats))
            .route("/api/memdebug", get(api_memdebug))
            .route("/api/memsize", get(api_memsize))
            .with_state(state);

        let bind = format!("127.0.0.1:{port}");
        match TcpListener::bind(&bind).await {
            Ok(listener) => {
                info!(addr = %bind, "admin web UI listening (localhost only)");
                if let Err(e) = axum::serve(listener, app).await {
                    warn!(error = %e, "admin web server stopped");
                }
            }
            Err(e) => {
                warn!(addr = %bind, error = %e, "admin web bind failed — UI disabled");
            }
        }
    });
}

#[derive(Serialize)]
struct StatusResp {
    server_name: String,
    description: String,
    version: String,
    public_ip: String,
    tcp_port: u16,
    udp_port: u16,
    uptime_seconds: u64,
    client_count: u64,
    low_id_count: u64,
    file_count: u64,
    keyword_count: u64,
    seckey_hex: String,
    /// Diagnostics: sizes of the previously-unbounded IP-keyed caches, plus the
    /// current flood-bot ban count. Surfaced so RAM growth can be watched live.
    obf_decode_cache_entries: u64,
    incoming_seed_challenges_entries: u64,
    banned_bots: u64,
    /// Number of currently-connected clients that advertised NAT-traversal
    /// capability (sent CT_EMULE_UDPPORTS at login = our client mod). Lets the
    /// operator watch adoption of the NAT-traversal client mod.
    natt_capable_clients: u64,
    /// How many LowID↔LowID hole punches the server has coordinated since start.
    natt_coordinated: u64,
}

async fn api_status(State(s): State<WebState>) -> Json<StatusResp> {
    Json(StatusResp {
        server_name: s.config.server.name.clone(),
        description: s.config.server.desc.clone(),
        version: format!(
            "{}.{} (ed2k-server {})",
            s.config.server.version_major, s.config.server.version_minor,
            env!("CARGO_PKG_VERSION")
        ),
        public_ip: s.cached_public_ip.clone(),
        tcp_port: s.config.network.tcp_port,
        udp_port: s.config.network.udp_port,
        uptime_seconds: s.metrics.uptime_secs(),
        client_count: s.server.clients.len() as u64,
        low_id_count: s.server.lowid_count_cached.load(std::sync::atomic::Ordering::Relaxed) as u64,
        file_count: s.server.file_slab.live_count() as u64,
        keyword_count: s.server.keyword_index.keyword_count() as u64,
        seckey_hex: s.seckey_hex.clone(),
        obf_decode_cache_entries: s.server.obf_decode_cache.len() as u64,
        incoming_seed_challenges_entries: s.server.incoming_seed_challenges.len() as u64,
        banned_bots: s.server.banned_bots.len() as u64,
        natt_capable_clients: s.server.clients.iter().filter(|c| c.natt_capable).count() as u64,
        natt_coordinated: s.server.block_stats.get("holepunch_coordinated").map(|v| *v).unwrap_or(0),
    })
}

#[derive(Serialize)]
struct StatsResp {
    // Process
    rss_kib: u64,
    peak_kib: u64,
    threads: u64,
    cpu_user_jiffies: u64,
    cpu_sys_jiffies: u64,
    // Application traffic counters (self-counted in hot paths)
    bytes_in: u64,
    bytes_out: u64,
    // Operation counters
    searches_total: u64,
    get_sources_total: u64,
    get_sources_cache_hits: u64,
    get_sources_cache_hit_rate: f32,
    smart_sources_cache_entries: u64,
    // Friendly computed fields referenced by the dashboard JS
    cpu_pct: f64,
    rss_mb: f64,
    /// jemalloc `allocated` in MB — the non-evictable working set (in-use bytes,
    /// no reusable free pages). 0.0 if jemalloc isn't the allocator.
    allocated_mb: f64,
    /// Bytes per indexed file computed from `allocated` (not RSS), so it tracks
    /// real structural cost without lazy-page noise. 0.0 if no files / no jemalloc.
    bytes_per_file: f64,
    cache_hit_pct: f64,
}

async fn api_stats(State(s): State<WebState>) -> Json<StatsResp> {
    let proc = read_proc_stats();
    let m = &s.metrics;
    // GETSOURCES cache hit rate comes from the SmartSources cache's own
    // hit/miss counters. (The Metrics::get_sources_* atomics were never wired
    // to the hot path, which is why this used to read a constant 0.0%.)
    let (gs_hits, gs_misses) = s.server.smart_sources.stats();
    let gs_total = gs_hits + gs_misses;
    let hit_rate = if gs_total > 0 {
        (gs_hits as f32) / (gs_total as f32)
    } else {
        0.0
    };
    Json(StatsResp {
        rss_kib: proc.rss_kib,
        peak_kib: proc.peak_kib,
        threads: proc.threads,
        cpu_user_jiffies: proc.utime_jiffies,
        cpu_sys_jiffies: proc.stime_jiffies,
        bytes_in: m.bytes_in.load(Ordering::Relaxed),
        bytes_out: m.bytes_out.load(Ordering::Relaxed),
        searches_total: m.searches_total.load(Ordering::Relaxed),
        get_sources_total: gs_total,
        get_sources_cache_hits: gs_hits,
        get_sources_cache_hit_rate: hit_rate,
        smart_sources_cache_entries: s.server.smart_sources.len() as u64,
        cpu_pct: {
            // Accurate CPU% = (utime+stime) / process_uptime_jiffies * 100
            // where process_uptime = system_uptime_secs * CLK_TCK - starttime_jiffies
            // CLK_TCK = 100 on virtually all Linux systems.
            // /proc/uptime gives system uptime in seconds.
            let sys_uptime_secs = std::fs::read_to_string("/proc/uptime").ok()
                .and_then(|s| s.split_whitespace().next()
                    .and_then(|v| v.parse::<f64>().ok()))
                .unwrap_or(0.0);
            const CLK_TCK: f64 = 100.0;
            let sys_uptime_ticks = sys_uptime_secs * CLK_TCK;
            let proc_uptime_ticks = (sys_uptime_ticks - proc.starttime_jiffy as f64).max(1.0);
            let cpu_ticks = (proc.utime_jiffies + proc.stime_jiffies) as f64;
            (cpu_ticks / proc_uptime_ticks * 100.0).min(100.0 * proc.threads.max(1) as f64)
        },
        rss_mb: proc.rss_kib as f64 / 1024.0,
        allocated_mb: {
            jemalloc_allocated().map(|b| b as f64 / 1_048_576.0).unwrap_or(0.0)
        },
        bytes_per_file: {
            let files = s.server.file_slab.live_count() as f64;
            match jemalloc_allocated() {
                Some(b) if files > 0.0 => b as f64 / files,
                _ => 0.0,
            }
        },
        cache_hit_pct: hit_rate as f64 * 100.0,
    })
}

#[derive(Serialize)]
struct ClientRow {
    ip: String,
    nick: String,
    country: String,
    software: String,
    shared_files: u32,
    high_id: bool,
    connected_seconds: u64,
}

async fn api_clients(State(s): State<WebState>) -> Json<Vec<ClientRow>> {
    // Take a snapshot of current clients. DashMap iteration is consistent
    // enough for an admin view — we accept a touch of staleness.
    let now = Instant::now();
    let rows: Vec<ClientRow> = s
        .server
        .clients
        .iter()
        .map(|entry| {
            let c = entry.value();
            ClientRow {
                ip: c.ip.to_string(),
                nick: c.nick.clone(),
                country: c.country.clone(),
                software: c.software.clone(),
                shared_files: c.shared_files,
                high_id: c.is_high_id,
                connected_seconds: now.saturating_duration_since(c.connected_at).as_secs(),
            }
        })
        .collect();
    Json(rows)
}

#[derive(Serialize)]
struct PeerRow {
    ip: String,
    port: u16,
    has_server_key: bool,
    /// True if this server answered our 0x96 ping (and is thus handed out to
    /// clients). Unverified entries are kept here for the operator to see but
    /// are NOT propagated — the mldonkey filter.
    verified: bool,
}

async fn api_peers(State(s): State<WebState>) -> Json<Vec<PeerRow>> {
    let list = s.server.server_list.read().await;
    let rows: Vec<PeerRow> = list
        .iter()
        .map(|addr| PeerRow {
            ip: addr.ip().to_string(),
            port: addr.port(),
            has_server_key: s.server.seed_server_keys.contains_key(addr.ip()),
            verified: s.server.verified_servers.contains_key(addr.ip())
                || s.server.seed_server_keys.contains_key(addr.ip()),
        })
        .collect();
    Json(rows)
}

async fn api_reload(State(s): State<WebState>) -> impl IntoResponse {
    s.reload_flag
        .store(true, std::sync::atomic::Ordering::Relaxed);
    (StatusCode::OK, "reload requested")
}

#[derive(Serialize)]
struct ClientStatEntry { software: String, count: u64 }

async fn api_client_stats(State(s): State<WebState>) -> Json<Vec<ClientStatEntry>> {
    // Compute from CURRENTLY connected clients (not cumulative history).
    let mut map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for entry in s.server.clients.iter() {
        *map.entry(entry.value().software.clone()).or_insert(0) += 1;
    }
    let mut entries: Vec<ClientStatEntry> = map.into_iter()
        .map(|(software, count)| ClientStatEntry { software, count })
        .collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count));
    Json(entries)
}

#[derive(Serialize)]
struct CountryStatEntry { code: String, count: u64 }

async fn api_country_stats(State(s): State<WebState>) -> Json<Vec<CountryStatEntry>> {
    // Compute from CURRENTLY connected clients.
    let mut map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for entry in s.server.clients.iter() {
        *map.entry(entry.value().country.clone()).or_insert(0) += 1;
    }
    let mut entries: Vec<CountryStatEntry> = map.into_iter()
        .map(|(code, count)| CountryStatEntry { code, count })
        .collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count));
    Json(entries)
}

#[derive(Serialize)]
struct FilterInfoResp {
    ipfilter_ranges: usize,
    country_db_loaded: bool,
}

async fn api_filter_info(State(s): State<WebState>) -> Json<FilterInfoResp> {
    let ipfilter_ranges = s.server.ip_filter.read().await.len();
    let country_db_loaded = s.server.country_db.read().await.is_loaded();
    Json(FilterInfoResp { ipfilter_ranges, country_db_loaded })
}

#[derive(Serialize)]
struct IpFilterHitRow {
    range: String,
    count: u32,
    description: String,
}

/// Per-range guarding.p2p block statistics: only ranges that have actually
/// blocked an IP, sorted by hit count. Descriptions are resolved from the source
/// file on demand (not held in RAM), so this reads the file — fine for an
/// occasional admin view. Capped to the top rows to keep the response small.
async fn api_ipfilter_hits(State(s): State<WebState>) -> Json<Vec<IpFilterHitRow>> {
    let path = std::path::PathBuf::from(&s.config.storage.ipfilter_path);
    let rows = {
        let filter = s.server.ip_filter.read().await;
        filter.hit_report(&path)
    };
    let out: Vec<IpFilterHitRow> = rows
        .into_iter()
        .take(500)
        .map(|r| IpFilterHitRow {
            range: format!(
                "{} - {}",
                std::net::Ipv4Addr::from(r.start),
                std::net::Ipv4Addr::from(r.end)
            ),
            count: r.count,
            description: r.desc,
        })
        .collect();
    Json(out)
}

// ─── CONFIG TAB — read/write config.toml from the web UI ─────────────────

#[derive(Serialize)]
struct ConfigGetResp {
    path: String,
    content: String,
    read_only: bool,
    error: Option<String>,
}

async fn api_config_get(State(s): State<WebState>) -> Json<ConfigGetResp> {
    if s.config_path.is_empty() {
        return Json(ConfigGetResp {
            path: String::new(),
            content: String::new(),
            read_only: true,
            error: Some("config_path not set (server was launched without a config file)".into()),
        });
    }
    match std::fs::read_to_string(&s.config_path) {
        Ok(content) => Json(ConfigGetResp {
            path: s.config_path.clone(),
            content,
            read_only: false,
            error: None,
        }),
        Err(e) => Json(ConfigGetResp {
            path: s.config_path.clone(),
            content: String::new(),
            read_only: true,
            error: Some(format!("cannot read {}: {}", s.config_path, e)),
        }),
    }
}

#[derive(serde::Deserialize)]
struct ConfigSetReq { content: String }

#[derive(Serialize)]
struct ConfigSetResp { ok: bool, error: Option<String>, hint: Option<String> }

async fn api_config_set(
    State(s): State<WebState>,
    Json(req): Json<ConfigSetReq>,
) -> Json<ConfigSetResp> {
    if s.config_path.is_empty() {
        return Json(ConfigSetResp {
            ok: false,
            error: Some("config_path not set".into()),
            hint: None,
        });
    }
    // 1. Parse the new TOML into a proper Config struct.
    let new_cfg: crate::config::Config = match toml::from_str(&req.content) {
        Ok(c) => c,
        Err(e) => return Json(ConfigSetResp {
            ok: false,
            error: Some(format!("config parse error: {}", e)),
            hint: Some("config file was not modified".into()),
        }),
    };

    // 2. Detect non-hot-reloadable changes (require restart) for the user message.
    let old = s.server.live_cfg.load();
    let mut restart_needed: Vec<String> = Vec::new();
    if old.network.tcp_port != new_cfg.network.tcp_port {
        restart_needed.push("network.tcp_port".into());
    }
    if old.network.udp_port != new_cfg.network.udp_port {
        restart_needed.push("network.udp_port".into());
    }
    if old.admin.port != new_cfg.admin.port || old.admin.enabled != new_cfg.admin.enabled {
        restart_needed.push("admin.port / admin.enabled".into());
    }

    // 3. Write to tempfile + atomic rename.
    let tmp_path = format!("{}.tmp", s.config_path);
    if let Err(e) = std::fs::write(&tmp_path, &req.content) {
        return Json(ConfigSetResp {
            ok: false, error: Some(format!("write tempfile failed: {}", e)), hint: None,
        });
    }
    if let Err(e) = std::fs::rename(&tmp_path, &s.config_path) {
        return Json(ConfigSetResp {
            ok: false, error: Some(format!("rename failed: {}", e)), hint: None,
        });
    }

    // 4. Atomically swap live_cfg. Hot paths reading state.live_cfg.load()
    //    will immediately see the new values for limits, name, desc, version,
    //    this_ip, storage paths, etc. (Fields requiring re-bind like ports
    //    are stored but not effective until restart.)
    s.server.live_cfg.store(Arc::new(new_cfg));

    // 5. Trigger filter/ipfilter/country-db reload via the existing flag.
    //    The reload watcher in main.rs reads paths from live_cfg.
    s.reload_flag.store(true, std::sync::atomic::Ordering::Relaxed);

    let hint = if restart_needed.is_empty() {
        "saved & applied live. Hot-reloadable settings updated immediately.".to_string()
    } else {
        format!(
            "saved. Hot-reloadable settings applied immediately. \
             Restart required to apply changes to: {}",
            restart_needed.join(", ")
        )
    };
    Json(ConfigSetResp { ok: true, error: None, hint: Some(hint) })
}

// ─── BOT DETECTION + BLOCK STATS API ─────────────────────────────────────

#[derive(Serialize)]
struct BotRow {
    ip: String,
    country: String,
    query_count: u64,
    queries_per_minute: f64,
    interval_stddev_ms: f64,
    reason: String,
    first_seen_secs_ago: u64,
    last_seen_secs_ago: u64,
    /// True if this IP is currently within its 24h flood-ban window (its UDP
    /// traffic is being dropped at the recv loop).
    banned: bool,
}

async fn api_bots(State(s): State<WebState>) -> Json<Vec<BotRow>> {
    let now = std::time::SystemTime::now();
    let mut rows: Vec<BotRow> = s.server.bot_detections.iter()
        .map(|e| {
            let d = e.value();
            // Sanitize floats so JSON serialization never sees NaN/INFINITY.
            // (serde_json represents them as null, but JS code expects numbers.)
            let qpm = if d.queries_per_minute.is_finite() {
                d.queries_per_minute
            } else { 0.0 };
            let stddev = if d.interval_stddev_ms.is_finite() {
                d.interval_stddev_ms
            } else { -1.0 };  // sentinel: "not measured"
            BotRow {
                ip: e.key().to_string(),
                country: d.country.clone(),
                query_count: d.query_count,
                queries_per_minute: qpm,
                interval_stddev_ms: stddev,
                reason: d.reason.clone(),
                first_seen_secs_ago: now.duration_since(d.first_seen).map(|d|d.as_secs()).unwrap_or(0),
                last_seen_secs_ago: now.duration_since(d.last_seen).map(|d|d.as_secs()).unwrap_or(0),
                banned: s.server.is_bot_banned(e.key()),
            }
        })
        .collect();
    // total_cmp gives a total order on f64 (no panic on NaN). Sort by qpm desc.
    rows.sort_by(|a, b| b.queries_per_minute.total_cmp(&a.queries_per_minute));
    Json(rows)
}

#[derive(Serialize)]
struct BlockStatRow {
    reason: String,
    count: u64,
    /// Optional: distinct IPs that hit this filter (e.g. CSAM block_stats counts
    /// file publishes but a single user can publish many files).
    unique_ips: Option<u64>,
}

async fn api_memsize(State(s): State<WebState>) -> Json<serde_json::Value> {
    // Per-container byte breakdown by CAPACITY (see ServerState::memsize_report).
    // Keys ending in _TOTAL are subtotals of the lines above them; GRAND_TOTAL_tracked
    // sums the subtotals. `unaccounted_bytes` is what jemalloc holds beyond that:
    // size-class rounding, DashMap per-shard control state, Arc/Box control blocks,
    // tokio socket buffers and per-thread allocator caches.
    let report = s.server.memsize_report();
    let tracked: u64 = report
        .iter()
        .find(|(k, _)| k == "GRAND_TOTAL_tracked")
        .map(|(_, v)| *v)
        .unwrap_or(0);
    let sizes: serde_json::Map<String, serde_json::Value> = report
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v)))
        .collect();
    let allocated = jemalloc_allocated().unwrap_or(0);
    Json(serde_json::json!({
        "sizes_bytes": sizes,
        "tracked_total_bytes": tracked,
        "jemalloc_allocated_bytes": allocated,
        "unaccounted_bytes": allocated.saturating_sub(tracked),
        // Element counts for the same structures, so bytes-per-element can be
        // derived directly (capacity vs live shows the peak-plateau slack).
        "counts": {
            "files": s.server.file_count(),
            "slab_slots": s.server.file_slab.slot_count(),
            "keyword_keys": s.server.keyword_index.posting_stats().0,
            "keyword_cold_keys": s.server.keyword_index.tier_sizes().0,
            "keyword_hot_keys": s.server.keyword_index.tier_sizes().1,
            "keyword_pending_removal_keys": s.server.keyword_index.tier_sizes().2,
            "keyword_postings": s.server.keyword_index.posting_stats().1,
            "unique_names": s.server.name_interner.len(),
            "clients": s.server.clients.len(),
            "user_files_users": s.server.user_files.len(),
            "smart_sources_entries": s.server.smart_sources.entry_count(),
            "ipfilter_ranges": s.server.ip_filter.try_read().map(|f| f.len()).unwrap_or(0),
            "geoip_ranges": s.server.country_db.try_read().map(|d| d.range_count()).unwrap_or(0),
        },
    }))
}

async fn api_memdebug(State(s): State<WebState>) -> Json<serde_json::Value> {
    // Structure element counts (what logically holds memory).
    let report = s.server.memory_report();
    // Raw /proc/self/status memory lines (what the OS actually accounts).
    let mut proc_mem: Vec<(String, String)> = Vec::new();
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Vm") || line.starts_with("Rss") {
                if let Some((k, v)) = line.split_once(':') {
                    proc_mem.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
        }
    }
    let structures: serde_json::Map<String, serde_json::Value> = report
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v)))
        .collect();
    let procm: serde_json::Map<String, serde_json::Value> = proc_mem
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v)))
        .collect();
    Json(serde_json::json!({
        "structures": structures,
        "proc_status": procm,
        "jemalloc": jemalloc_stats(),
    }))
}

/// jemalloc internal stats, to distinguish real app data from fragmentation:
/// - `allocated`: bytes the app actually holds (live data)
/// - `active`/`resident`: pages backing allocations / physically resident
/// - `retained`: virtual memory kept (not resident, reusable)
/// - `metadata`: allocator bookkeeping
/// `resident - allocated` ≈ fragmentation + cached free pages. If that gap is
/// large while `allocated` is small, RSS growth is allocator retention
/// (plateaus / tunable via decay), not real structural growth (tombstones, etc.).
#[cfg(not(target_env = "msvc"))]
fn jemalloc_stats() -> serde_json::Value {
    use tikv_jemalloc_ctl::{epoch, stats};
    // stats are cached; advancing the epoch refreshes them.
    if epoch::advance().is_err() {
        return serde_json::Value::Null;
    }
    let rd = |r: Result<usize, _>| r.map(|v| v as u64).unwrap_or(0);
    serde_json::json!({
        "allocated": rd(stats::allocated::read()),
        "active": rd(stats::active::read()),
        "metadata": rd(stats::metadata::read()),
        "resident": rd(stats::resident::read()),
        "retained": rd(stats::retained::read()),
    })
}

#[cfg(target_env = "msvc")]
fn jemalloc_stats() -> serde_json::Value {
    serde_json::Value::Null
}

/// Just the jemalloc `allocated` figure (bytes the app actually holds, with no
/// reusable free pages) — the "non-evictable" working set. None when jemalloc is
/// not the allocator (msvc). Surfaced in the status card so the operator sees the
/// real in-use memory next to RSS (which also counts lazily-freed pages).
#[cfg(not(target_env = "msvc"))]
fn jemalloc_allocated() -> Option<u64> {
    use tikv_jemalloc_ctl::{epoch, stats};
    if epoch::advance().is_err() {
        return None;
    }
    stats::allocated::read().ok().map(|v| v as u64)
}

#[cfg(target_env = "msvc")]
fn jemalloc_allocated() -> Option<u64> {
    None
}

async fn api_block_stats(State(s): State<WebState>) -> Json<Vec<BlockStatRow>> {
    let mut rows: Vec<BlockStatRow> = s.server.block_stats.iter()
        .map(|e| {
            let reason = e.key().clone();
            // For CSAM: also report distinct IPs blocked (one user can publish many files).
            let unique_ips = if reason == "csam" {
                Some(s.server.csam_unique_ips.len() as u64)
            } else { None };
            BlockStatRow { reason, count: *e.value(), unique_ips }
        })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count));
    Json(rows)
}

/// Single-page dashboard. Plain HTML + a tiny bit of JS — no build step.
async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ed2k-server admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
header{background:#1a1d27;border-bottom:1px solid #2d3148;padding:14px 24px;display:flex;align-items:center;gap:12px}
header h1{font-size:1.1rem;font-weight:600;color:#fff}
header .ver{font-size:.75rem;color:#6b7280;margin-left:auto}
nav{background:#13151f;border-bottom:1px solid #252840;display:flex;gap:0;overflow-x:auto}
nav button{background:none;border:none;color:#9ca3af;padding:12px 20px;cursor:pointer;font-size:.85rem;border-bottom:2px solid transparent;white-space:nowrap}
nav button.active{color:#6366f1;border-bottom-color:#6366f1}
nav button:hover{color:#c7d2fe}
.tab{display:none;padding:20px}.tab.active{display:block}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-bottom:20px}
.card{background:#1a1d27;border:1px solid #252840;border-radius:8px;padding:16px}
.card .lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:#6b7280;margin-bottom:4px}
.card .val{font-size:1.5rem;font-weight:700;color:#a5b4fc}
.card .sub{font-size:.75rem;color:#6b7280;margin-top:2px}
.section{background:#1a1d27;border:1px solid #252840;border-radius:8px;padding:16px;margin-bottom:16px}
.section h3{font-size:.85rem;font-weight:600;color:#9ca3af;margin-bottom:12px;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{text-align:left;padding:7px 10px;color:#6b7280;border-bottom:1px solid #252840;font-weight:500;font-size:.75rem;text-transform:uppercase}
td{padding:7px 10px;border-bottom:1px solid #1e2035;color:#cbd5e1}
tr:hover td{background:#1e2035}
.badge{display:inline-block;padding:2px 8px;border-radius:9999px;font-size:.7rem;font-weight:600}
.badge.yes{background:#1e3a2f;color:#4ade80}.badge.no{background:#3b1f1f;color:#f87171}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.72rem;background:#252840;color:#a5b4fc;margin:2px}
.bar-wrap{display:flex;align-items:center;gap:8px}
.bar{height:8px;border-radius:4px;background:#6366f1;min-width:2px;transition:width .3s}
.bar-label{font-size:.72rem;color:#9ca3af;min-width:40px;text-align:right}
.flag{font-size:1.1rem;margin-right:4px}
#refreshed{font-size:.72rem;color:#4b5563;margin-top:10px;text-align:right}
.reload-btn{background:#252840;color:#a5b4fc;border:1px solid #6366f1;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:.83rem}
.reload-btn:hover{background:#2d3060}
#reload-out{font-size:.82rem;color:#6b7280;margin-top:8px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:640px){.grid2{grid-template-columns:1fr}}
.empty{color:#4b5563;font-size:.83rem;padding:12px 0}
</style>
</head>
<body>
<header>
  <span>🖥</span>
  <h1>ed2k-server</h1>
  <div class="ver" id="hdr-ver">loading...</div>
</header>
<nav>
  <button class="active" onclick="showTab('status',this)">Status</button>
  <button onclick="showTab('clients',this)">Clients</button>
  <button onclick="showTab('peers',this)">Peers</button>
  <button onclick="showTab('filter',this)">Filter</button>
  <button onclick="showTab('bots',this)">Bots</button>
  <button onclick="showTab('blocks',this)">Blocks</button>
  <button onclick="showTab('settings',this)">Settings</button>
</nav>

<!-- STATUS TAB -->
<div id="tab-status" class="tab active">
  <div class="cards" id="cards"></div>
  <div class="section">
    <h3>System</h3>
    <div id="sys-info"></div>
  </div>
</div>

<!-- CLIENTS TAB -->
<div id="tab-clients" class="tab">
  <div class="grid2">
    <div class="section">
      <h3>Client Software</h3>
      <div id="sw-chart"></div>
    </div>
    <div class="section">
      <h3>Country Distribution</h3>
      <div id="country-chart"></div>
    </div>
  </div>
  <div class="section">
    <h3>Connected Now</h3>
    <div id="clients-table"></div>
  </div>
</div>

<!-- PEERS TAB -->
<div id="tab-peers" class="tab">
  <div class="section">
    <h3>Gossip Peer Servers</h3>
    <div id="peers-table"></div>
  </div>
</div>

<!-- FILTER TAB -->
<div id="tab-filter" class="tab">
  <div class="section">
    <h3>IP Filter (guarding.p2p)</h3>
    <div id="filter-info"></div>
    <div style="margin-top:14px">
      <button class="reload-btn" onclick="doReload()">↺ Reload filters (SIGHUP)</button>
      <div id="reload-out"></div>
    </div>
  </div>
  <div class="section" style="margin-top:16px">
    <h3>Range Hit Statistics</h3>
    <p style="font-size:.82rem;color:#9ca3af;line-height:1.6">
      Per-range block counts since startup. Only ranges that actually blocked an
      IP are shown. Descriptions are read from the source file on demand (not kept
      in RAM), so this loads on click rather than auto-refreshing.
    </p>
    <button class="reload-btn" onclick="loadIpfilterHits()">↓ Load range hit stats</button>
    <div id="ipfilter-hits" style="margin-top:12px"></div>
  </div>
  <div class="section" style="margin-top:16px">
    <h3>About IP Filter</h3>
    <p style="font-size:.82rem;color:#9ca3af;line-height:1.6">
      Place <code style="background:#252840;padding:2px 6px;border-radius:3px">guarding.p2p</code>
      in the path configured at <code style="background:#252840;padding:2px 6px;border-radius:3px">[storage] ipfilter_path</code>.
      Format: <code style="background:#252840;padding:2px 6px;border-radius:3px">AAA.BBB.CCC.DDD - EEE.FFF.GGG.HHH , priority , description</code>
      (eMule-compatible). Reloaded without restart via the button above.
    </p>
  </div>
</div>

<!-- SETTINGS TAB -->
<!-- BOTS TAB -->
<div id="tab-bots" class="tab">
  <div class="section">
    <h3>Bot Detection</h3>
    <p style="font-size:.78rem;color:#9ca3af;margin-bottom:10px">
      IPs flagged for abnormal query patterns. Thresholds: <strong>flood</strong> &gt; 600 qpm OR <strong>uniform timing</strong> &gt; 200 qpm with stddev &lt; 50 ms. Flagged IPs are <strong>auto-banned for 24h</strong> — their UDP traffic (global search/sources) is dropped at the recv loop; their TCP session, if any, is unaffected. Bans auto-expire; a rotated IP is re-flagged the same way.
    </p>
    <div id="bots-table"></div>
  </div>
</div>

<!-- BLOCKS TAB -->
<div id="tab-blocks" class="tab">
  <div class="section">
    <h3>Block Statistics</h3>
    <p style="font-size:.78rem;color:#9ca3af;margin-bottom:10px">
      Counts since server start. Cleared on restart.
    </p>
    <div id="blocks-table"></div>
  </div>
</div>

<div id="tab-settings" class="tab">
  <div class="section">
    <h3>Edit config.toml</h3>
    <div id="settings-path" style="font-size:.78rem;color:#9ca3af;margin-bottom:8px"></div>
    <div id="settings-error" style="display:none;background:#3b1f1f;color:#f87171;padding:10px;border-radius:6px;margin-bottom:10px;font-size:.85rem"></div>
    <textarea id="settings-content" spellcheck="false"
      style="width:100%;min-height:500px;background:#0f1117;color:#e2e8f0;border:1px solid #252840;border-radius:6px;padding:12px;font-family:ui-monospace,'Cascadia Code','Source Code Pro',monospace;font-size:.82rem;line-height:1.5;resize:vertical"></textarea>
    <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <button class="reload-btn" onclick="saveSettings()">💾 Save & Reload</button>
      <button class="reload-btn" style="background:#252840;border-color:#6b7280" onclick="refreshSettings()">↻ Reload from disk</button>
      <div id="settings-out" style="font-size:.83rem;color:#6b7280"></div>
    </div>
  </div>
  <div class="section" style="margin-top:16px">
    <h3>About Settings</h3>
    <p style="font-size:.82rem;color:#9ca3af;line-height:1.6">
      Edits the TOML config file directly. On Save:
      <br>• File is validated as TOML before being written (atomic rename).
      <br>• Hot-reloadable sections are applied immediately (<code>[filter]</code>, <code>[storage].ipfilter_path</code>).
      <br>• Changes to ports, seckey, server name require <code>systemctl restart ed2k-server</code>.
    </p>
  </div>
</div>

<div id="refreshed" style="padding:0 20px 10px"></div>

<script>
function showTab(name, btn) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  if (btn) btn.classList.add('active');
}
function fmt(n) { return n >= 1e6 ? (n/1e6).toFixed(2)+'M' : n >= 1e3 ? (n/1e3).toFixed(1)+'k' : String(n); }
function fmtDur(s) {
  if (s < 60) return s+'s';
  if (s < 3600) return Math.floor(s/60)+'m '+( s%60)+'s';
  return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';
}
function countryFlag(code) {
  if (!code || code === '??') return '🌐';
  try {
    return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
  } catch { return '🌐'; }
}

async function refreshStatus() {
  const [st, sys] = await Promise.all([
    fetch('/api/status').then(r=>r.json()),
    fetch('/api/stats').then(r=>r.json()),
  ]);
  document.getElementById('hdr-ver').textContent = st.server_name + ' v' + st.version;
  document.getElementById('cards').innerHTML =
    card('Clients', fmt(st.client_count), st.low_id_count + ' Low ID') +
    card('Files', fmt(st.file_count), 'in index') +
    card('Uptime', fmtDur(st.uptime_seconds), '') +
    card('CPU', sys.cpu_pct.toFixed(1)+'%', sys.rss_mb.toFixed(0)+' MB RSS') +
    card('Memory', sys.allocated_mb.toFixed(0)+' MB', sys.bytes_per_file.toFixed(0)+' B/file · in-use, non-evictable');
  document.getElementById('sys-info').innerHTML =
    `<table><tr><th>Key</th><th>Value</th></tr>
     <tr><td>Server IP</td><td>${st.public_ip || '(auto)'}</td></tr>
     <tr><td>TCP Port</td><td>${st.tcp_port}</td></tr>
     <tr><td>Seckey</td><td><code style="font-size:.75rem">${st.seckey_hex}</code></td></tr>
     <tr><td>Cache hits</td><td>${sys.cache_hit_pct.toFixed(1)}%</td></tr>
     <tr><td>Banned bots (24h)</td><td>${fmt(st.banned_bots)}</td></tr>
     <tr><td>NAT-T capable clients</td><td>${fmt(st.natt_capable_clients)} <span style="color:#6b7280;font-size:.75rem">connected clients with the NAT-traversal mod</span></td></tr>
     <tr><td>NAT-T punches coordinated</td><td>${fmt(st.natt_coordinated)} <span style="color:#6b7280;font-size:.75rem">LowID↔LowID since start</span></td></tr>
     <tr><td>obf_decode_cache</td><td>${fmt(st.obf_decode_cache_entries)} <span style="color:#6b7280;font-size:.75rem">entries (capped at 8192)</span></td></tr>
     <tr><td>seed_challenges</td><td>${fmt(st.incoming_seed_challenges_entries)} <span style="color:#6b7280;font-size:.75rem">entries (capped at 2048)</span></td></tr>
     </table>`;
}
function card(lbl, val, sub) {
  return `<div class="card"><div class="lbl">${lbl}</div><div class="val">${val}</div><div class="sub">${sub}</div></div>`;
}

async function refreshClients() {
  const [rows, sw, countries] = await Promise.all([
    fetch('/api/clients').then(r=>r.json()),
    fetch('/api/client_stats').then(r=>r.json()),
    fetch('/api/country_stats').then(r=>r.json()),
  ]);
  const total = sw.reduce((a,e)=>a+e.count, 0);
  document.getElementById('sw-chart').innerHTML = sw.length === 0
    ? '<div class="empty">No data yet.</div>'
    : sw.map(e => {
        const pct = total ? (e.count/total*100).toFixed(1) : 0;
        return `<div style="margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;margin-bottom:3px">
            <span class="tag">${e.software}</span>
            <span style="font-size:.78rem;color:#9ca3af">${e.count} (${pct}%)</span>
          </div>
          <div class="bar-wrap"><div class="bar" style="width:${pct}%"></div></div>
        </div>`;
      }).join('');
  const ctotal = countries.reduce((a,e)=>a+e.count,0);
  document.getElementById('country-chart').innerHTML = countries.length === 0
    ? '<div class="empty">No data yet or country DB not loaded.</div>'
    : countries.slice(0,20).map(e => {
        const pct = ctotal ? (e.count/ctotal*100).toFixed(1) : 0;
        return `<div style="margin-bottom:8px">
          <div style="display:flex;justify-content:space-between;margin-bottom:3px">
            <span>${countryFlag(e.code)} ${e.code}</span>
            <span style="font-size:.78rem;color:#9ca3af">${e.count} (${pct}%)</span>
          </div>
          <div class="bar-wrap"><div class="bar" style="width:${pct}%;background:#818cf8"></div></div>
        </div>`;
      }).join('');
  document.getElementById('clients-table').innerHTML = rows.length === 0
    ? '<div class="empty">No clients connected.</div>'
    : '<table><thead><tr><th>IP</th><th>Country</th><th>Software</th><th>Nick</th><th>Files</th><th>ID</th><th>Connected</th></tr></thead><tbody>'
      + rows.slice(0,100).map(c =>
          `<tr><td>${c.ip}</td>`
          + `<td>${countryFlag(c.country)} ${c.country}</td>`
          + `<td><span class="tag">${c.software||'?'}</span></td>`
          + `<td>${c.nick}</td>`
          + `<td>${c.shared_files||0}</td>`
          + `<td><span class="badge ${c.high_id?'yes':'no'}">${c.high_id?'High':'Low'}</span></td>`
          + `<td>${fmtDur(c.connected_seconds)}</td></tr>`).join('')
      + (rows.length>100?`<tr><td colspan="5" style="color:#6b7280">… and ${rows.length-100} more</td></tr>`:'')
      + '</tbody></table>';
}

async function refreshPeers() {
  const r = await fetch('/api/peers').then(r=>r.json());
  document.getElementById('peers-table').innerHTML = r.length === 0
    ? '<div class="empty">No peer servers known yet.</div>'
    : '<table><thead><tr><th>IP</th><th>Port</th><th>ServerKey</th></tr></thead><tbody>'
      + r.map(p => `<tr><td>${p.ip}</td><td>${p.port}</td>`
               + `<td><span class="badge ${p.has_server_key?'yes':'no'}">${p.has_server_key?'✓ known':'pending'}</span></td></tr>`).join('')
      + '</tbody></table>';
}

async function refreshFilter() {
  const f = await fetch('/api/filter_info').then(r=>r.json());
  document.getElementById('filter-info').innerHTML =
    `<table><tr><th>Setting</th><th>Value</th></tr>
     <tr><td>IP filter ranges</td><td>${f.ipfilter_ranges === 0 ? '<span class="badge no">not loaded</span>' : '<span class="badge yes">'+f.ipfilter_ranges.toLocaleString()+' ranges</span>'}</td></tr>
     <tr><td>Country DB</td><td><span class="badge ${f.country_db_loaded?'yes':'no'}">${f.country_db_loaded?'loaded':'not loaded'}</span></td></tr>
     </table>`;
}

async function loadIpfilterHits() {
  const out = document.getElementById('ipfilter-hits');
  out.textContent = 'loading...';
  try {
    const rows = await fetch('/api/ipfilter_hits').then(r=>r.json());
    if (!rows.length) {
      out.innerHTML = '<span class="badge no">no blocks recorded yet</span>';
      return;
    }
    let html = '<table><tr><th>IP range</th><th>Hits</th><th>Description</th></tr>';
    for (const r of rows) {
      const desc = (r.description || '').replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
      html += `<tr><td><code style="font-size:.75rem">${r.range}</code></td><td>${fmt(r.count)}</td><td>${desc}</td></tr>`;
    }
    html += '</table>';
    out.innerHTML = html;
  } catch (e) {
    out.innerHTML = '<span class="badge no">failed to load</span>';
  }
}

async function doReload() {
  const out = document.getElementById('reload-out');
  out.textContent = 'sending...';
  try {
    const r = await fetch('/api/reload', {method:'POST'});
    out.textContent = r.ok ? '✓ Reload triggered — watch journalctl for details.' : '✗ Failed: HTTP ' + r.status;
  } catch (e) { out.textContent = '✗ Error: ' + e; }
}

let settingsLoaded = false;
async function refreshSettings() {
  const ta = document.getElementById('settings-content');
  const pathEl = document.getElementById('settings-path');
  const errEl = document.getElementById('settings-error');
  errEl.style.display = 'none';
  try {
    const r = await fetch('/api/config').then(r => r.json());
    if (r.error) {
      errEl.style.display = 'block';
      errEl.textContent = r.error;
      ta.value = '';
      ta.disabled = true;
    } else {
      ta.value = r.content;
      ta.disabled = r.read_only;
      pathEl.textContent = '📄 ' + r.path + (r.read_only ? ' (read-only)' : '');
    }
    settingsLoaded = true;
  } catch (e) {
    errEl.style.display = 'block';
    errEl.textContent = 'fetch error: ' + e;
  }
}

async function saveSettings() {
  const ta = document.getElementById('settings-content');
  const out = document.getElementById('settings-out');
  const errEl = document.getElementById('settings-error');
  errEl.style.display = 'none';
  out.textContent = 'saving...';
  try {
    const r = await fetch('/api/config', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({content: ta.value}),
    }).then(r => r.json());
    if (r.ok) {
      out.textContent = '✓ Saved. ' + (r.hint || '');
      out.style.color = '#4ade80';
    } else {
      errEl.style.display = 'block';
      errEl.textContent = r.error + (r.hint ? ' — ' + r.hint : '');
      out.textContent = '';
    }
  } catch (e) {
    errEl.style.display = 'block';
    errEl.textContent = 'request error: ' + e;
    out.textContent = '';
  }
}

// Hook into showTab to load settings lazily on first open
const origShowTab = showTab;
showTab = function(name, btn) {
  origShowTab(name, btn);
  if (name === 'settings' && !settingsLoaded) refreshSettings();
};

async function refreshBots() {
  const rows = await fetch('/api/bots').then(r => r.json());
  const el = document.getElementById('bots-table');
  if (!rows || rows.length === 0) {
    el.innerHTML = '<div class="empty">No bots detected.</div>';
    return;
  }
  el.innerHTML = '<table><thead><tr>'
    + '<th>IP</th><th>Country</th><th>QPM</th><th>Stddev (ms)</th>'
    + '<th>Reason</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>'
    + rows.map(b => {
        // -1 is our sentinel for "not enough samples to compute stddev"
        const stddev = (b.interval_stddev_ms < 0) ? '—' : b.interval_stddev_ms.toFixed(0);
        return `<tr><td>${b.ip}</td>`
          + `<td>${countryFlag(b.country)} ${b.country}</td>`
          + `<td>${b.queries_per_minute.toFixed(0)}</td>`
          + `<td>${stddev}</td>`
          + `<td><span class="badge no">${b.reason}</span>${b.banned ? ' <span class="badge no" style="background:#7f1d1d;color:#fecaca;border-color:#b91c1c">BANNED 24h</span>' : ''}</td>`
          + `<td>${fmtDur(b.first_seen_secs_ago)} ago</td>`
          + `<td>${fmtDur(b.last_seen_secs_ago)} ago</td></tr>`;
      }).join('')
    + '</tbody></table>';
}

async function refreshBlocks() {
  const rows = await fetch('/api/block_stats').then(r => r.json());
  const el = document.getElementById('blocks-table');
  if (!rows || rows.length === 0) {
    el.innerHTML = '<div class="empty">No blocks recorded yet.</div>';
    return;
  }
  el.innerHTML = '<table><thead><tr><th>Reason</th><th>Count</th><th>Unique IPs</th><th>Counts what</th></tr></thead><tbody>'
    + rows.map(r => {
        const meta = {
          'ipfilter':                { label: 'IP filter (guarding.p2p)',  desc: 'TCP connections dropped' },
          'csam':                    { label: 'CSAM filter (total)',       desc: 'unique blocked files (sum of all layers). "Unique IPs" = distinct publishers' },
          'csam_L1_jargon':          { label: '  └ Layer 1 — jargon',      desc: 'sealed CSAM-marker term list (long substrings)' },
          'csam_L2_age':             { label: '  └ Layer 2 — age + sex',   desc: 'filename contains both a minor-age token AND a sexual-context term' },
          'csam_L3_hash':            { label: '  └ Layer 3 — hash list',   desc: 'MD4 file hash matches operator-loaded CSAM hash blocklist' },
          'csam_L4_extra':           { label: '  └ Layer 4 — operator',    desc: 'custom term list from [content_filter].extra_terms_file' },
          'bot':                     { label: 'Bot detection (flagged)',   desc: 'detection events (cooldown 30s/IP)' },
          'bot_ban':                 { label: '  └ Bots banned (24h)',     desc: 'distinct flood-bot IPs auto-banned; UDP dropped for 24h' },
          'rate_limit':              { label: 'Rate limit',                desc: 'queries throttled' },
          'max_connections_per_ip':  { label: 'Too many connections',      desc: 'TCP connections rejected from same IP' },
        }[r.reason] || { label: r.reason, desc: '' };
        const uniq = (r.unique_ips != null) ? r.unique_ips.toLocaleString() : '—';
        return `<tr><td>${meta.label}</td><td>${r.count.toLocaleString()}</td>`
          + `<td>${uniq}</td>`
          + `<td style="color:#6b7280;font-size:.78rem">${meta.desc}</td></tr>`;
      }).join('')
    + '</tbody></table>';
}

async function refresh() {
  await Promise.all([refreshStatus(), refreshClients(), refreshPeers(), refreshFilter(),
                      refreshBots(), refreshBlocks()]);
  document.getElementById('refreshed').textContent = 'last updated: ' + new Date().toLocaleTimeString();
}
refresh();
setInterval(refresh, 5000);
</script>
</body></html>
"##;