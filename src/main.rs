use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use ed2k_server::config::Config;
use ed2k_server::filter::ContentFilter;
use ed2k_server::server::connection::handle_connection;
use ed2k_server::server::gossip::{parse_seed, spawn_gossip};
use ed2k_server::server::keepalive::spawn_keepalive;
use ed2k_server::server::obfuscated_conn::make_stream;
use ed2k_server::server::udp::UdpServer;
use ed2k_server::state::ServerState;

// Stage 4 (memory): use jemalloc instead of the system (glibc) allocator.
// The index workload is still many small allocations — one Vec<FileId> per
// keyword posting and one hash_to_id entry per file (the per-file Vec<Source>
// was inlined into FileRecord via SmallVec in Stage 2). glibc malloc fragments
// badly on this pattern and is slow to return freed pages to the OS, so RSS
// sits above the live data; jemalloc's per-thread arenas cut that fragmentation
// and reclaim memory more aggressively, typically without costing CPU (its
// multithreaded alloc path is faster, not slower). Guarded off MSVC/Windows,
// which jemalloc does not support — there it falls back to the system allocator.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser, Debug)]
#[command(name = "ed2k-server", about = "Modern eDonkey index server (MVP)")]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "config/config.toml")]
    config: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    // Read config synchronously BEFORE starting the runtime so we can choose
    // single-threaded vs multi-threaded based on cfg.log.worker_threads.
    let cfg_preview = Config::load_from_file(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;
    let worker_threads = cfg_preview.log.worker_threads.max(1);

    let rt = if worker_threads == 1 {
        // Single-threaded runtime: one OS thread, no work-stealing, no DashMap
        // shard contention. Closer to Lugdunum's single-thread + epoll model.
        // For ed2k workloads this is typically the cheapest config.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building single-threaded tokio runtime")?
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
            .context("building multi-threaded tokio runtime")?
    };
    rt.block_on(async_main(args, cfg_preview))
}

async fn async_main(args: Args, cfg: Config) -> Result<()> {
    // Set up tracing per config.log.level (env RUST_LOG overrides if set).
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.log.level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "ed2k-server starting");

    // Build content filter (always-on per §7.6)
    let mut filter = ContentFilter::new();

    // Load operator-supplied extra terms file, if present
    if let Some(path) = &cfg.content_filter.extra_terms_file {
        let path = PathBuf::from(path);
        if path.exists() {
            match ContentFilter::load_terms_file(&path) {
                Ok(terms) => {
                    info!(
                        count = terms.len(),
                        path = %path.display(),
                        "extra CSAM terms loaded"
                    );
                    filter = filter.with_extra_terms(terms);
                }
                Err(e) => error!(error = %e, "failed to load extra terms"),
            }
        }
    }

    // Load operator-supplied Layer 1 jargon list, if present. Absent ⇒ L1 off.
    if let Some(path) = &cfg.content_filter.jargon_terms_file {
        let path = PathBuf::from(path);
        if path.exists() {
            match ContentFilter::load_terms_file(&path) {
                Ok(terms) => {
                    info!(
                        count = terms.len(),
                        path = %path.display(),
                        "L1 jargon terms loaded"
                    );
                    filter = filter.with_jargon_terms(terms);
                }
                Err(e) => error!(error = %e, "failed to load jargon terms"),
            }
        }
    }

    // Load hash blocklists
    let mut total_blocked = 0;
    for path in &cfg.content_filter.hash_blocklists {
        let path = PathBuf::from(path);
        match ContentFilter::load_hash_file(&path) {
            Ok(hashes) => {
                let n = hashes.len();
                total_blocked += n;
                info!(
                    count = n,
                    path = %path.display(),
                    "hash blocklist loaded"
                );
                filter = filter.with_hash_blocklist(hashes);
            }
            Err(e) => error!(path = %path.display(), error = %e, "blocklist load failed"),
        }
    }

    // Load whitelist
    if let Some(path) = &cfg.content_filter.whitelist_hashes_file {
        let path = PathBuf::from(path);
        if path.exists() {
            match ContentFilter::load_hash_file(&path) {
                Ok(hashes) => {
                    info!(count = hashes.len(), "hash whitelist loaded");
                    filter = filter.with_hash_whitelist(hashes);
                }
                Err(e) => error!(error = %e, "whitelist load failed"),
            }
        }
    }

    info!(
        public = cfg.server.public,
        blocklist_size = total_blocked,
        extra_terms = filter.extra_terms_count(),
        jargon_terms = filter.jargon_terms_count(),
        "content filter configured"
    );

    let cfg = Arc::new(cfg);
    let state = Arc::new(ServerState::new(Arc::new(filter), Arc::clone(&cfg)));

    // ─── Load auxiliary data files ───────────────────────────────────────────
    // IP filter (guarding.p2p format). Blocks connections from known bad ranges.
    {
        use ed2k_server::filter::ipfilter::IpFilter;
        let ipfilter_path = std::path::Path::new(&cfg.storage.ipfilter_path);
        let f = IpFilter::load(ipfilter_path);
        *state.ip_filter.write().await = f;
    }
    // Country database (ip-to-country.csv). Used for stats only, not blocking.
    {
        use ed2k_server::filter::geoip::CountryDb;
        let country_path = std::path::Path::new(&cfg.storage.country_db_path);
        *state.country_db.write().await = CountryDb::load(country_path);
    }

    // The file index is NOT persisted across restarts (snapshots were removed):
    // it rebuilds naturally from clients' OFFERFILES as they reconnect. Source-
    // less entries are skipped in search responses (see src/server/search.rs),
    // and any orphan a client never republishes within 30 minutes is evicted by
    // the orphan-cleanup task below.

    // Bind TCP listener
    let bind_addr = format!("{}:{}", cfg.network.listen_ip, cfg.network.tcp_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding {}", bind_addr))?;

    info!(addr = %bind_addr, "TCP listener ready");

    // Start UDP listener (SPEC.md §3.8, §3.10)
    // Bind first so we can share the socket with gossip (must come from port 4665).
    // Resolve the server-to-server obfuscation secret ONCE — all UDP
    // listeners must share it so they derive identical per-peer keys.
    // Derived purely from server IP + TCP port; not stored in config. It
    // rotates automatically if the IP or port changes (a different network
    // identity = a different server), and is shown in the web UI.
    let seckey = ed2k_server::server::udp::resolve_seckey(&cfg);
    info!(
        seckey_hex = hex::encode(seckey),
        this_ip = %cfg.server.this_ip.trim(),
        tcp_port = cfg.network.tcp_port,
        "obfuscation seckey (derived from server IP + TCP port; view in web UI)"
    );

    // Admin web UI (localhost-only). Spawned early so it's ready when the
    // operator opens it via SSH tunnel. Includes Metrics counters that
    // hot paths increment; the UI polls every 5s for live stats.
    let metrics = Arc::new(ed2k_server::web::Metrics::new());
    let admin_reload_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    if cfg.admin.enabled {
        // Compute public IP ONCE at startup, not on every /api/status call.
        // /proc/net/fib_trie is large; parsing it 12 times/minute is wasteful.
        let cached_public_ip = {
            let cfg_ip = cfg.server.this_ip.trim().to_string();
            if !cfg_ip.is_empty() && cfg_ip != "0.0.0.0" {
                cfg_ip
            } else {
                std::fs::read_to_string("/proc/net/fib_trie").ok()
                    .and_then(|s| {
                        let lines: Vec<&str> = s.lines().collect();
                        for i in 1..lines.len() {
                            if lines[i].contains("LOCAL") || lines[i].contains("32 HOST") {
                                if let Some(prev) = lines.get(i.saturating_sub(1)) {
                                    let ip_str = prev.trim().split_whitespace().next().unwrap_or("");
                                    if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                                        if !ip.is_loopback() && !ip.is_private()
                                            && !ip.is_unspecified() && !ip.is_multicast() {
                                            return Some(ip.to_string());
                                        }
                                    }
                                }
                            }
                        }
                        None
                    })
                    .unwrap_or_else(|| "(auto)".to_string())
            }
        };
        let web_state = ed2k_server::web::WebState {
            server: Arc::clone(&state),
            config: Arc::clone(&cfg),
            metrics: Arc::clone(&metrics),
            seckey_hex: hex::encode(seckey),
            config_path: args.config.to_string_lossy().to_string(),
            reload_flag: Arc::clone(&admin_reload_flag),
            cached_public_ip,
        };
        ed2k_server::web::spawn_admin(web_state, cfg.admin.port);
    }

    // Main UDP listener (TCP+4 = 4665) — primary GLOBSERVSTATREQ/GETSOURCES channel
    let udp = UdpServer::bind(Arc::clone(&cfg), Arc::clone(&state), seckey).await?;
    let udp_socket = udp.socket();
    tokio::spawn(async move { udp.run().await });

    // Additional UDP listeners — Lugdunum binds these too (eserver.c default ports):
    //   TCP+8  (port_4669)  — secondary plain server-to-server channel
    //   TCP+12 (4673)       — OBFUSCATED server-to-server channel (THE important one)
    //                         — eserver.c servgetrandkey: this port uses s->random_part
    //                         — seed servers send obfuscated probes here, NOT to +14
    //                         — captured: 45.82.80.155 sends to our 4673
    //   TCP+14 (4675)       — portUDPobf — obfuscated channel for CLIENT queries
    // All share the same dispatch logic; our obfuscated-decode path triggers on
    // any non-0xE3 first byte and tries IPObfuscate(seckey, sender_ip).
    {
        let port_4669 = cfg.network.tcp_port.wrapping_add(8);
        match UdpServer::bind_on_port(Arc::clone(&cfg), Arc::clone(&state), port_4669, seckey).await {
            Ok(srv) => { tokio::spawn(async move { srv.run().await }); }
            Err(e) => warn!(port = port_4669, error = %e, "could not bind port_4669"),
        }

        // TCP+12 — the s2s obfuscated channel. WITHOUT THIS, real eD2k servers
        // send obfuscated probes to a port we don't listen on, the kernel drops
        // them, and we never appear in server.met. This is the single most
        // important port for server discovery.
        let port_s2s_obf = cfg.network.tcp_port.wrapping_add(12);
        match UdpServer::bind_on_port(Arc::clone(&cfg), Arc::clone(&state), port_s2s_obf, seckey).await {
            Ok(srv) => { tokio::spawn(async move { srv.run().await }); }
            Err(e) => warn!(port = port_s2s_obf, error = %e, "could not bind server-to-server obf port"),
        }

        let port_obf = cfg.network.tcp_port.wrapping_add(14);
        match UdpServer::bind_on_port(Arc::clone(&cfg), Arc::clone(&state), port_obf, seckey).await {
            Ok(srv) => { tokio::spawn(async move { srv.run().await }); }
            Err(e) => warn!(port = port_obf, error = %e, "could not bind portUDPobf"),
        }
    }

    // Keepalive: ping all clients every ping_delay_seconds (SPEC.md §3.7)
    spawn_keepalive(Arc::clone(&state), cfg.limits.ping_delay_seconds);
    info!(interval_s = cfg.limits.ping_delay_seconds, "keepalive started");

    // Periodic server_list cleanup. Three filters applied every 60 seconds:
    //  1. Remove IPs that are currently connected as clients.
    //  2. Remove IPs that recently connected as clients (within 30 min TTL).
    //  3. Remove IPs that have been in server_list > 10 min without ever sending
    //     us a 0x97 GLOBSERVSTATRES reply (so they never proved they're servers).
    //     This catches mldonkey CLIENTS that other seeds wrongly include in their
    //     0xA1 server lists — they're real IPs of real eD2k peers, but eD2k
    //     clients, not servers, and they will never answer 0x96 ping.
    {
        let state_clean = Arc::clone(&state);
        tokio::spawn(async move {
            const CLIENT_BLOCK_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);
            const VERIFY_GRACE: std::time::Duration = std::time::Duration::from_secs(10 * 60);
            const VERIFIED_TTL: std::time::Duration = std::time::Duration::from_secs(60 * 60);
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.tick().await;
            loop {
                tick.tick().await;
                state_clean.recent_client_ips.retain(|_, ts| ts.elapsed() < CLIENT_BLOCK_TTL);
                state_clean.verified_servers.retain(|_, ts| ts.elapsed() < VERIFIED_TTL);
                // Same TTL for the ip:port-keyed set that gates hand-out, so a server
                // that stops answering pings stops being advertised (and a phantom
                // port, which never answers, is never verified in the first place).
                state_clean.verified_sockets.retain(|_, ts| ts.elapsed() < VERIFIED_TTL);
                // Bot detector keeps per-IP sliding windows. IPs that haven't
                // queried in 5 minutes can be dropped — their window is empty
                // and re-creating it on next query is cheap. Without this
                // cleanup, bot_query_log grew unbounded (memory leak under load).
                state_clean.bot_query_log.retain(|_, tracker| {
                    let times = tracker.query_times.lock().unwrap();
                    times.back().is_some_and(|t| t.elapsed().as_secs() < 300)
                });

                // Sweep expired flood-bot bans (24h TTL). Keeps banned_bots
                // bounded by the number of bots seen in a rolling 24h window.
                state_clean
                    .banned_bots
                    .retain(|_, since| since.elapsed() < ServerState::BOT_BAN_TTL);

                // Q1: sweep expired CSAM-publisher bans and stale per-user
                // distinct-file sets. Ban TTL = configured publisher_blacklist_
                // seconds; the per-user sets expire after the same window (a user
                // idle that long starts fresh). Without this both maps only grow.
                {
                    let pub_ttl = std::time::Duration::from_secs(
                        state_clean.live_cfg.load().content_filter.publisher_blacklist_seconds);
                    state_clean
                        .banned_publishers
                        .retain(|_, since| since.elapsed() < pub_ttl);
                    state_clean
                        .csam_files_by_user
                        .retain(|_, (_, last)| last.elapsed() < pub_ttl);
                }

                // obf_decode_cache (re-derivable RC4-key cache) and
                // incoming_seed_challenges (only needed during an active gossip
                // handshake) are keyed by arbitrary remote IPs and have no
                // natural eviction — under internet-wide UDP churn they grow
                // unbounded (observed RSS climbing linearly with uptime). Both
                // are caches: drop them when oversized. obf_decode_cache just
                // re-derives the key on the next packet; incoming_seed_challenges
                // re-handshakes on the next 60s probe. Real seeds (a few dozen)
                // never reach the cap, so only scanner/churn noise is swept.
                const OBF_CACHE_CAP: usize = 8192;
                const SEED_CHAL_CAP: usize = 2048;
                if state_clean.obf_decode_cache.len() > OBF_CACHE_CAP {
                    let n = state_clean.obf_decode_cache.len();
                    state_clean.obf_decode_cache.clear();
                    info!(cleared = n, "obf_decode_cache over cap, swept");
                }
                if state_clean.incoming_seed_challenges.len() > SEED_CHAL_CAP {
                    let n = state_clean.incoming_seed_challenges.len();
                    state_clean.incoming_seed_challenges.clear();
                    info!(cleared = n, "incoming_seed_challenges over cap, swept");
                }

                let blocked: std::collections::HashSet<std::net::Ipv4Addr> = {
                    let mut set = std::collections::HashSet::new();
                    for e in state_clean.clients.iter() {
                        if let std::net::IpAddr::V4(v4) = e.ip { set.insert(v4); }
                    }
                    for e in state_clean.recent_client_ips.iter() {
                        set.insert(*e.key());
                    }
                    set
                };
                let now = std::time::Instant::now();
                let mut list = state_clean.server_list.write().await;
                let before = list.len();
                list.retain(|s| {
                    let ip = *s.ip();
                    let verified = state_clean.verified_servers.contains_key(&ip)
                        || state_clean.seed_server_keys.contains_key(&ip);
                    // Filter 1+2: known client IPs (current or recent) — but a
                    // VERIFIED server is kept even if it also shows up as a
                    // client. A server can legitimately send us UDP (gossip,
                    // pings) and thereby land in recent_client_ips; without this
                    // exemption it flaps out of server_list every cleanup and is
                    // re-added every gossip cycle (observed: 91.119.202.44 added
                    // 52×). An mldonkey client cannot fake plain 0x97 or the obf
                    // handshake, so the leak stays closed: unverified client IPs
                    // are still dropped here, unverified non-clients fall to
                    // filter 3.
                    if !verified && blocked.contains(&ip) { return false; }
                    // Filter 3: unverified entries past their grace period.
                    let added = state_clean.server_list_added_at.get(&ip)
                        .map(|e| *e.value())
                        .unwrap_or(now);
                    let in_list_for = now.duration_since(added);
                    if in_list_for > VERIFY_GRACE && !verified {
                        return false;
                    }
                    true
                });
                let purged = before - list.len();
                if purged > 0 {
                    info!(purged, total = list.len(),
                          "periodic cleanup: removed IPs (clients or unverified)");
                }
            }
        });
        info!("periodic server_list cleanup started (60s interval)");
    }

    // Periodic ORPHAN FILE cleanup. Every 10 minutes, remove files from the
    // index that have no sources. Orphans arise from a rare race in
    // remove_sources_of where a source removal races a concurrent re-publish,
    // leaving a hash in the index with an empty sources Vec. If no client
    // re-publishes that hash, the file would otherwise stay as a dead entry
    // forever, so the cleanup task reaps it.
    //
    // 30-minute grace period: gives clients enough time to reconnect and
    // re-publish after a server restart before we drop their files. Most
    // eMule clients send OFFERFILES within a few minutes of login.
    {
        let state_orphan = Arc::clone(&state);
        tokio::spawn(async move {
            const GRACE: std::time::Duration = std::time::Duration::from_secs(30 * 60);
            // First sweep after the grace period so we don't immediately drop
            // freshly restored files before any client has a chance to log in.
            tokio::time::sleep(GRACE).await;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(10 * 60));
            loop {
                tick.tick().await;
                let mut removed = 0usize;
                // Collect orphan FileIds (no sources) via the slab. We collect
                // first, then evict, so we never hold a shard read lock while
                // taking the write locks tombstone/remove_file need.
                // NOTE: Arc<str> (a DST behind the pointer) must be the LAST
                // tuple element, so the layout is (id, hash, name).
                let mut to_evict: Vec<(ed2k_server::state::file_id::FileId, [u8; 16], std::sync::Arc<str>)> = Vec::new();
                state_orphan.file_slab.for_each_live(|id, r| {
                    if r.sources.is_empty() {
                        to_evict.push((id, r.hash, r.name.clone()));
                    }
                });
                let evicted_ids: Vec<ed2k_server::state::file_id::FileId> =
                    to_evict.iter().map(|(id, _, _)| *id).collect();
                for (fid, _h, name) in to_evict {
                    // Remove the keyword postings, then tombstone the slab slot
                    // (id retired, never reused).
                    state_orphan.keyword_index.remove_file(fid, &name);
                    if state_orphan.file_slab.tombstone(fid) {
                        removed += 1;
                    }
                }
                if removed > 0 {
                    let remaining = state_orphan.file_slab.live_count();
                    // Reclaim keyword-index memory left behind by the removals
                    // (empty posting sets + over-large set capacity). Off the
                    // hot path, so the shrink cost is fine here.
                    let dropped_kw = state_orphan.keyword_index.compact();
                    // CRITICAL: also purge the evicted hashes from the
                    // `user_files` reverse index. Orphan-cleanup bypasses
                    // remove_sources_of (the only other place that touches
                    // user_files), so without this the reverse index retains
                    // dead FileHash entries forever — the real RSS leak.
                    state_orphan.purge_ids_from_user_files(&evicted_ids);
                    // Note: slab slots are tombstoned (not freed) by design —
                    // ids must never be reused. Heavy fields (name/sources) are
                    // already cleared on tombstone, so the per-record residue is
                    // just the small packed header.
                    state_orphan.user_files.shrink_to_fit();
                    info!(removed, remaining, dropped_kw,
                          "orphan file cleanup: evicted files with no sources, compacted index + reverse index");
                }

                // Free interned names that no live record references any more.
                //
                // This MUST run every cycle, not only when files were evicted.
                // Names are interned on paths that may not end in a stored record
                // (a re-published hash whose name changed drops the old Arc; a file
                // rejected by the content filter after interning; a tombstoned
                // record clearing its name), so unreferenced names accumulate even
                // in cycles with zero evictions. Keeping the sweep under
                // `if removed > 0` let that garbage pile up between evictions —
                // observed live as 449k interned names against 327k live files
                // (~37% dead), growing with uptime and inflating bytes-per-file.
                //
                // Cost is a scan of the interner every 10 min, off the hot path.
                let dropped_names = state_orphan.name_interner.sweep_unused();
                if dropped_names > 0 {
                    info!(dropped_names,
                          interned = state_orphan.name_interner.len(),
                          "name interner: freed unreferenced names");
                }
            }
        });
        info!("orphan-file cleanup started (10min interval after 30min grace)");
    }

    // Hot-reload of the Layer 4 CSAM extra-terms file. The operator edits the
    // file (e.g. /etc/ed2k-server/csam_terms_extra.txt) and the new terms take
    // effect within the poll interval — NO restart. L1 and L4 reload from their
    // files (see watchers below/above); L2 is compiled-in logic and L3 hashes
    // load at startup. We watch the file mtime;
    // on change we re-read and atomically swap the term list via ArcSwap.
    {
        let state_terms = Arc::clone(&state);
        if let Some(path) = state_terms
            .live_cfg
            .load()
            .content_filter
            .extra_terms_file
            .clone()
        {
            let path = std::path::PathBuf::from(path);
            tokio::spawn(async move {
                let mut last_mtime = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok();
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let mtime = match std::fs::metadata(&path).and_then(|m| m.modified()) {
                        Ok(t) => t,
                        // File missing/unreadable (e.g. mid atomic-rename) —
                        // keep the current term list, retry next tick.
                        Err(_) => continue,
                    };
                    if Some(mtime) != last_mtime {
                        match ed2k_server::filter::ContentFilter::load_terms_file(&path) {
                            Ok(terms) => {
                                let n = terms.len();
                                state_terms.filter.reload_extra_terms(terms);
                                last_mtime = Some(mtime);
                                info!(count = n, path = %path.display(),
                                      "L4 CSAM extra terms hot-reloaded");
                            }
                            Err(e) => warn!(error = %e,
                                "L4 terms reload failed; keeping current list"),
                        }
                    }
                }
            });
            info!("L4 extra-terms hot-reload watcher started (30s mtime poll)");
        }
    }

    // Hot-reload of the Layer 1 jargon file — same mechanism as L4. Operator
    // edits the jargon list and it takes effect within the poll interval, no
    // restart. Absent file ⇒ no watcher (L1 stays inactive).
    {
        let state_jargon = Arc::clone(&state);
        if let Some(path) = state_jargon
            .live_cfg
            .load()
            .content_filter
            .jargon_terms_file
            .clone()
        {
            let path = std::path::PathBuf::from(path);
            tokio::spawn(async move {
                let mut last_mtime = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok();
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let mtime = match std::fs::metadata(&path).and_then(|m| m.modified()) {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    if Some(mtime) != last_mtime {
                        match ed2k_server::filter::ContentFilter::load_terms_file(&path) {
                            Ok(terms) => {
                                let n = terms.len();
                                state_jargon.filter.reload_jargon_terms(terms);
                                last_mtime = Some(mtime);
                                info!(count = n, path = %path.display(),
                                      "L1 jargon terms hot-reloaded");
                            }
                            Err(e) => warn!(error = %e,
                                "L1 jargon reload failed; keeping current list"),
                        }
                    }
                }
            });
            info!("L1 jargon hot-reload watcher started (30s mtime poll)");
        }
    }

    // Hot-reload of the Layer 3 hash blocklist(s). The operator edits any file
    // in `hash_blocklists` (e.g. /etc/ed2k-server/csam_hashes.txt) and the new
    // hashes take effect within the poll interval — NO restart (v0.9.46+).
    // We watch the max mtime across all configured files; on change we re-read
    // ALL of them, union, and atomically swap via ArcSwap. (Whitelist is still
    // load-at-startup — it changes rarely and is an FP-override, not a leak.)
    {
        let state_bl = Arc::clone(&state);
        let paths: Vec<std::path::PathBuf> = state_bl
            .live_cfg
            .load()
            .content_filter
            .hash_blocklists
            .iter()
            .map(std::path::PathBuf::from)
            .collect();
        if !paths.is_empty() {
            tokio::spawn(async move {
                let max_mtime = |ps: &[std::path::PathBuf]| -> Option<std::time::SystemTime> {
                    ps.iter()
                        .filter_map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
                        .max()
                };
                let mut last_mtime = max_mtime(&paths);
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let mtime = match max_mtime(&paths) {
                        Some(t) => t,
                        None => continue, // all files unreadable right now; retry
                    };
                    if Some(mtime) != last_mtime {
                        // Re-read and union every configured blocklist file.
                        let mut all: Vec<[u8; 16]> = Vec::new();
                        let mut ok = true;
                        for p in &paths {
                            match ed2k_server::filter::ContentFilter::load_hash_file(p) {
                                Ok(h) => all.extend(h),
                                Err(e) => {
                                    warn!(path = %p.display(), error = %e,
                                        "L3 blocklist reload: file read failed; keeping current list");
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok {
                            let n = all.len();
                            state_bl.filter.reload_hash_blocklist(all);
                            last_mtime = Some(mtime);
                            info!(count = n, "L3 hash blocklist hot-reloaded");
                        }
                    }
                }
            });
            info!("L3 hash-blocklist hot-reload watcher started (30s mtime poll)");
        }
    }

    // Periodic server_list verification probe. Every 60 seconds, pick up to N
    // entries that haven't been verified yet and send them a plain 0x96
    // GLOBSERVSTATREQ. Real eD2k servers reply with 0x97 (handle_pingreply
    // marks them verified). Clients ignore — they will be evicted by the
    // cleanup task after the 10-minute grace period.
    {
        let state_probe = Arc::clone(&state);
        let udp_sock_probe = Arc::clone(&udp_socket);
        tokio::spawn(async move {
            const PROBE_BATCH: usize = 50;  // probe up to 50 unverified entries per minute
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.tick().await;
            loop {
                tick.tick().await;
                let list_snapshot: Vec<std::net::SocketAddrV4> = {
                    let list = state_probe.server_list.read().await;
                    list.iter().copied().collect()
                };
                let mut probed = 0usize;
                for addr in list_snapshot {
                    if probed >= PROBE_BATCH { break; }
                    let ip = *addr.ip();
                    if state_probe.verified_servers.contains_key(&ip)
                        || state_probe.seed_server_keys.contains_key(&ip)
                    {
                        continue;
                    }
                    // Build a plain 0x96 GLOBSERVSTATREQ: e3 96 + 4-byte random challenge
                    // (using 0x55AA prefix as eMule does — but we don't actually need
                    // server-probe semantics here, just any valid 0x96).
                    let challenge: u32 = 0x55AA_0000 | (rand_u16_simple() as u32);
                    let mut pkt = vec![0xE3u8, 0x96];
                    pkt.extend_from_slice(&challenge.to_le_bytes());
                    // UDP port for eD2k server probes is TCP+4. We have the addr's TCP
                    // port; send to TCP+4. But we don't know seed's UDP port from just
                    // the server_list entry — try addr.port()+4 (Lugdunum/eMule convention).
                    let udp_port = addr.port().wrapping_add(4);
                    let dst = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, udp_port));
                    if udp_sock_probe.send_to(&pkt, dst).await.is_ok() {
                        probed += 1;
                    }
                }
                if probed > 0 {
                    info!(probed, "verification probe: sent 0x96 to unverified server_list entries");
                }
            }
        });
        info!("server_list verification probe started (60s interval, 50/batch)");
    }

    // Helper for the probe task — tiny xorshift since we don't need crypto-grade randomness.
    fn rand_u16_simple() -> u16 {
        use std::cell::Cell;
        thread_local! {
            static S: Cell<u32> = Cell::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos()).unwrap_or(0x12345678).wrapping_mul(0x9E3779B9));
        }
        S.with(|c| {
            let mut s = c.get();
            s ^= s << 13; s ^= s >> 17; s ^= s << 5;
            c.set(s);
            s as u16
        })
    }

    // SIGHUP → hot-reload content filter without restarting.
    // Usage on VPS: kill -HUP $(systemctl show -p MainPID ed2k-server | cut -d= -f2)
    // or:           systemctl kill -s HUP ed2k-server
    // The /api/reload web endpoint sets the same flag via reload_flag below.
    let reload_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        use std::sync::atomic::Ordering;
        // SIGHUP handler needs a global slot — set up once.
        use once_cell::sync::OnceCell;
        static SIGHUP_FLAG: OnceCell<Arc<std::sync::atomic::AtomicBool>> = OnceCell::new();
        let _ = SIGHUP_FLAG.set(Arc::clone(&reload_flag));

        unsafe {
            libc::signal(libc::SIGHUP, {
                extern "C" fn handler(_: libc::c_int) {
                    if let Some(f) = SIGHUP_FLAG.get() {
                        f.store(true, Ordering::Relaxed);
                    }
                }
                handler as *const () as libc::sighandler_t
            });
        }

        let state_reload = Arc::clone(&state);
        let cfg_reload   = Arc::clone(&cfg);
        let flag_reload  = Arc::clone(&reload_flag);
        let admin_flag   = Arc::clone(&admin_reload_flag);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                // Either SIGHUP or the admin /api/reload endpoint trips a reload.
                let sighup = flag_reload.swap(false, std::sync::atomic::Ordering::Relaxed);
                let webreq = admin_flag.swap(false, std::sync::atomic::Ordering::Relaxed);
                if !sighup && !webreq { continue; }

                info!(via_sighup = sighup, via_web = webreq, "reload triggered — reloading content filter");

                // Reload hash blocklists — hot-swapped LIVE (L3 is an ArcSwap
                // since v0.9.46). Union all configured files, then swap. Uses
                // load_hash_file so ';' inline comments parse correctly.
                {
                    let mut all: Vec<[u8; 16]> = Vec::new();
                    let mut ok = true;
                    for path in &cfg_reload.content_filter.hash_blocklists {
                        match ed2k_server::filter::ContentFilter::load_hash_file(
                            std::path::Path::new(path),
                        ) {
                            Ok(h) => all.extend(h),
                            Err(e) => {
                                warn!(path, error = %e, "failed to reload hash blocklist");
                                ok = false;
                            }
                        }
                    }
                    if ok {
                        let n = all.len();
                        state_reload.filter.reload_hash_blocklist(all);
                        info!(count = n, "hash blocklist hot-reloaded (live)");
                    }
                }

                // Reload extra CSAM terms — hot-swapped LIVE into the running
                // filter (L4 is an ArcSwap). Both this path (SIGHUP /
                // /api/reload) and the standalone mtime watcher call
                // reload_extra_terms; either applies without a restart.
                if let Some(path) = &cfg_reload.content_filter.extra_terms_file {
                    match ed2k_server::filter::ContentFilter::load_terms_file(
                        std::path::Path::new(path),
                    ) {
                        Ok(terms) => {
                            let n = terms.len();
                            state_reload.filter.reload_extra_terms(terms);
                            info!(count = n, path, "extra CSAM terms hot-reloaded (live)");
                        }
                        Err(e) => warn!(path, error = %e, "failed to reload extra terms"),
                    }
                }

                // Reload L1 jargon list live, same as L4.
                if let Some(path) = &cfg_reload.content_filter.jargon_terms_file {
                    match ed2k_server::filter::ContentFilter::load_terms_file(
                        std::path::Path::new(path),
                    ) {
                        Ok(terms) => {
                            let n = terms.len();
                            state_reload.filter.reload_jargon_terms(terms);
                            info!(count = n, path, "L1 jargon terms hot-reloaded (live)");
                        }
                        Err(e) => warn!(path, error = %e, "failed to reload jargon terms"),
                    }
                }

                // L3 blocklist + L4 extra terms are now applied live (ArcSwap).
                // Only the hash WHITELIST still loads at startup (rare FP-override
                // changes), so changing the whitelist requires a restart.
                info!("content filter reload: L3 blocklist + L4 terms applied live. Whitelist requires restart.");

                // Hot-reload IP filter (guarding.p2p) — fully supported without restart.
                if !cfg_reload.storage.ipfilter_path.is_empty() {
                    use ed2k_server::filter::ipfilter::IpFilter;
                    let path = std::path::Path::new(&cfg_reload.storage.ipfilter_path);
                    let new_filter = IpFilter::load(path);
                    let ranges = new_filter.len();
                    *state_reload.ip_filter.write().await = new_filter;
                    info!(ranges, path = &cfg_reload.storage.ipfilter_path, "IP filter reloaded");
                }
            }
        });
    }

    // Server-to-server gossip using the main UDP socket (port 4665).
    // Seed servers see requests from our real server port and can add us
    // to their peer lists — this is how Lugdunum gets discovered quickly.
    {
        let seeds: Vec<_> = cfg.server.seed_servers.iter()
            .filter_map(|s| parse_seed(s))
            .collect();

        let our_ip: std::net::Ipv4Addr = cfg.server.this_ip.parse()
            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

        if !seeds.is_empty() {
            info!(seeds = seeds.len(), "starting gossip with seed servers");
        }

        // Plain bootstrap + keepalive on TCP+4 channel.
        spawn_gossip(
            Arc::clone(&state),
            seeds.clone(),
            our_ip,
            cfg.network.tcp_port,
            udp_socket,
            seckey,
        );

        // Note: OBF ping is now performed inline by gossip's per-seed
        // handshake (gossip::seed_loop). The standalone obf_ping_loop was
        // retired because the OBF ping reply must arrive on the SAME
        // ephemeral socket that subsequently sends the obfuscated 0xA0+0xA4
        // gossip — splitting the work across two tasks broke that.
    }

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // Enable TCP keepalive on the accepted socket. NAT-T LowID
                // sources are silent on TCP for long stretches (they only share
                // files — no searches, no source requests, no downloads through
                // the server link). A consumer/provider NAT drops an idle TCP
                // mapping after a few minutes, but the OS only discovers the
                // dead socket when it next tries to send and the retransmits
                // finally time out (~13-30 min with default tcp_retries2) —
                // surfacing as "frame error: Connection timed out (os error
                // 110)". During that window the client is silently unreachable
                // yet still listed, so its shared files vanish from search even
                // though the client thinks it is connected. Kernel-level TCP
                // keepalive probes both keep the NAT mapping warm AND detect a
                // genuinely dead peer in ~2 min instead of ~18. The UDP NAT-T
                // keepalive cannot do this — it keeps the UDP mapping alive, not
                // the separate TCP mapping the server index entry rides on.
                {
                    use socket2::{SockRef, TcpKeepalive};
                    // TCP keepalive tuned to tolerate a TEMPORARY NAT outage
                    // without evicting a live client, while still reaping a
                    // genuinely dead socket promptly.
                    //
                    // Timeline: first probe after 60s of TCP silence, then a
                    // probe every 30s, giving up after 8 unanswered probes:
                    //   60 + 30*8 = 300s = 5 minutes of tolerance.
                    //
                    // Why 5 minutes: a NAT-T LowID peer behind a weak consumer
                    // NAT (the 168.x client) saturates its UDP path during a
                    // download; the overloaded NAT then briefly stops forwarding
                    // the TCP keepalive probes, so they go unanswered for a
                    // minute or two even though the client is perfectly alive.
                    // The previous 140s budget (interval=20,retries=4) tripped
                    // mid-download and dropped it. 300s rides through the burst.
                    // Lugdunum survives the same client by never probing at all
                    // (purely reactive on epoll EPOLLERR/EPOLLHUP), so it simply
                    // never notices the transient outage — we approximate that
                    // forgiveness by probing gently instead of not at all, which
                    // keeps our ability to detect a truly dead socket.
                    //
                    // Why not longer: a dead socket is removed in 5 min, so even
                    // a flood of stale sessions drains far faster than it builds;
                    // the application idle timeout (idle_after = 900s, refreshed
                    // by the 0x9F UDP keepalive) is the slower backstop for a
                    // peer that has gone fully dark on both TCP and UDP.
                    let ka = TcpKeepalive::new()
                        .with_time(std::time::Duration::from_secs(60))
                        .with_interval(std::time::Duration::from_secs(30));
                    #[cfg(any(
                        target_os = "linux",
                        target_os = "android",
                        target_os = "freebsd",
                        target_os = "netbsd",
                        target_os = "macos",
                        target_os = "ios",
                    ))]
                    let ka = ka.with_retries(8);
                    let sref = SockRef::from(&stream);
                    if let Err(e) = sref.set_tcp_keepalive(&ka) {
                        tracing::debug!(ip = %peer.ip(), error = %e,
                            "failed to enable TCP keepalive on client socket");
                    }
                }
                let cfg = Arc::clone(&cfg);
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    // Bound the setup phase (TCP accept → obfuscation
                    // handshake → first frame). Without this, make_stream's
                    // read_exact() blocks forever on a silent peer (port
                    // scanner, half-open TCP). After 12 hours of accumulation
                    // the runtime drowns in stuck tasks — observed as gradual
                    // CPU climb to 100% and unresponsive admin UI.
                    //
                    // 5 seconds is generous: a legitimate client completes
                    // DH handshake in tens of milliseconds. handle_connection
                    // has its own login + idle timeouts for the post-setup
                    // phase.
                    let setup_timeout = std::time::Duration::from_secs(5);
                    let crypt_stream = match tokio::time::timeout(
                        setup_timeout,
                        make_stream(stream, cfg.network.support_crypt),
                    ).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            tracing::debug!(ip = %peer.ip(), error = %e,
                                "stream setup failed");
                            return;
                        }
                        Err(_) => {
                            tracing::debug!(ip = %peer.ip(),
                                "setup timed out — silent peer or stuck handshake");
                            return;
                        }
                    };
                    if let Err(e) = handle_connection(cfg, state, crypt_stream, peer).await {
                        tracing::debug!(ip = %peer.ip(), error = %e, "connection ended");
                    }
                });
            }
            Err(e) => { error!(error = %e, "accept failed"); }
        }
    }
}
