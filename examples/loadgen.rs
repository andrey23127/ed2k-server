//! In-process memory load generator.
//!
//! Populates a REAL `ServerState` with N synthetic files through the REAL
//! publish path (`add_file_with_source`: name interning → slab `get_or_insert`
//! (intrusive hash index) → keyword index → user_files), then reports process
//! RSS. This answers "how much RAM do the index structures take at 33M files?"
//! WITHOUT needing real users or the network — and with the user/file ratio
//! FIXED, so the per-file number is clean and extrapolates linearly (unlike our
//! noisy cross-run server measurements, which were confounded by varying user
//! and client counts).
//!
//! It uses the SAME global allocator as the server (jemalloc) — an example is a
//! separate binary and does NOT inherit the `#[global_allocator]` from main.rs,
//! so we set it here too, or the numbers would reflect glibc instead.
//!
//! BUILD/RUN (release is mandatory — jemalloc + optimizations):
//!     cargo run --release --example loadgen -- <num_files> [num_users] [unique_name_pct]
//!
//! Examples:
//!     cargo run --release --example loadgen -- 5000000        # 5M files, auto users
//!     cargo run --release --example loadgen -- 33252559       # full target
//!     cargo run --release --example loadgen -- 10000000 16260 # explicit users
//!
//! `num_users` defaults to num_files / 614 (the real target ratio:
//! 33,252,559 files / 54,128 users ≈ 614 files/user), keeping per-user index
//! sizes realistic at any scale. `unique_name_pct` (default 70) is the percent
//! of distinct file names — controls name-interner dedup and keyword sharing.
//!
//! Pick a num_files your WSL RAM can hold (~0.7 KB/file ⇒ 5M ≈ 3.5 GB,
//! 10M ≈ 7 GB, 33M ≈ 23 GB). Progress prints every report interval, so even a
//! run you stop early yields a usable bytes/file figure.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use ed2k_server::config::Config;
use ed2k_server::filter::ContentFilter;
use ed2k_server::state::ServerState;

// Match the server's allocator so RSS reflects production behavior.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Bijective 64-bit mix (splitmix64 finalizer). Bijective ⇒ distinct inputs give
/// distinct outputs, so deriving hashes/user-ids from a counter never collides.
#[inline]
fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Tokens per file (matches the real ~7.2 keyword postings/file).
const KW_PER_FILE: usize = 7;

/// 2-letter country codes for synthetic clients (rough real-ish mix).
const COUNTRIES: &[&str] = &[
    "DE", "US", "FR", "RU", "CN", "ES", "IT", "BR", "GB", "NL", "PL", "??",
];

/// Client software strings (weighted toward eMule by repetition), as they would
/// be stored uninterned per ClientHandle.
const SOFTWARE: &[&str] = &[
    "eMule", "eMule", "eMule", "eMule", "eMule", "aMule", "aMule", "Shareaza",
    "mldonkey", "StulleMule", "eMule MorphXT", "xMule",
];

/// Build a name for a given distinct-name index, drawing `KW_PER_FILE` tokens
/// from a vocabulary of `kw_vocab` distinct tokens. Sizing kw_vocab to
/// ~0.72×num_files reproduces the REAL keyword cardinality (≈0.72 distinct
/// keywords per file — a huge long tail of rare tokens), which is what actually
/// drives keyword-index memory (millions of small DashMap entries + Vecs). A
/// tiny fixed word pool (the previous version) collapsed this to ~10k keys and
/// grossly under-counted that cost. Deterministic in `name_idx`, so files that
/// share a name_idx share the same name string (interner dedup) and tokens.
fn make_name(name_idx: u64, kw_vocab: u64) -> String {
    let mut s = mix(name_idx ^ 0x9e37_79b9_7f4a_7c15);
    let mut out = String::with_capacity(64);
    for k in 0..KW_PER_FILE {
        if k > 0 {
            out.push(' ');
        }
        s = mix(s);
        let tok = s % kw_vocab;
        out.push('w');
        out.push_str(itoa_u64(tok).as_str());
    }
    out.push_str(".bin");
    out
}

/// Tiny no-alloc-ish u64→String (avoids pulling a dep just for the loadgen).
fn itoa_u64(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut buf = [0u8; 20];
    let mut i = 20;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    String::from_utf8_lossy(&buf[i..]).into_owned()
}

/// Read a /proc/self/status field (e.g. "VmRSS") in kB.
fn status_kb(field: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            // line looks like "VmRSS:\t  123456 kB"
            return rest
                .trim_start_matches(':')
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }
    0
}

fn report(files: u64, baseline_kb: u64) {
    let rss = status_kb("VmRSS");
    let hwm = status_kb("VmHWM");
    let net = rss.saturating_sub(baseline_kb);
    let bpf = if files > 0 {
        (rss as f64 * 1024.0) / files as f64
    } else {
        0.0
    };
    let bpf_net = if files > 0 {
        (net as f64 * 1024.0) / files as f64
    } else {
        0.0
    };
    println!(
        "files={:>10}  RSS={:>7} MB  HWM={:>7} MB  bytes/file={:>6.1} (net of baseline {:>6.1})",
        files,
        rss / 1024,
        hwm / 1024,
        bpf,
        bpf_net,
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let num_files: u64 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000_000);
    // Default to the real target ratio so per-user index sizes are realistic.
    let num_users: u64 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or((num_files / 614).max(1));
    let unique_pct: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(70);
    let unique_names = ((num_files * unique_pct) / 100).max(1);
    // Keyword vocabulary sized to reproduce the real ratio (~0.72 distinct
    // keywords per file); this is what drives keyword-index memory at scale.
    let kw_vocab = ((num_files * 72) / 100).max(1);

    let report_every = (num_files / 20).max(1); // ~20 progress lines

    println!(
        "loadgen: files={} users={} unique_names={} ({}%) kw_vocab={} — real publish path, jemalloc",
        num_files, num_users, unique_names, unique_pct, kw_vocab
    );

    let cfg = Arc::new(Config::minimal_test_config());
    let filter = Arc::new(ContentFilter::new());
    let state = ServerState::new(filter, cfg);

    let baseline_kb = status_kb("VmRSS");
    println!("baseline RSS = {} MB", baseline_kb / 1024);
    let t0 = Instant::now();

    for i in 0..num_files {
        // Unique, uniformly distributed 16-byte hash from the counter.
        let h0 = mix(i);
        let h1 = mix(i ^ 0xa5a5_a5a5_5a5a_5a5a);
        let mut hash = [0u8; 16];
        hash[0..8].copy_from_slice(&h0.to_le_bytes());
        hash[8..16].copy_from_slice(&h1.to_le_bytes());

        // Name with controlled duplication (many files → one distinct name),
        // tokens drawn from a realistically large keyword vocabulary.
        let name = make_name(i % unique_names, kw_vocab);

        // One source per file, publisher spread across the user pool.
        let user_idx = i % num_users;
        let mut uh = [0u8; 16];
        uh[0..8].copy_from_slice(&mix(user_idx).to_le_bytes());

        let ip = IpAddr::V4(Ipv4Addr::from((h0 >> 32) as u32));
        let port = (h1 as u16) | 1;

        state.add_file_with_source(hash, h1, name, (uh, ip, port, true));

        if (i + 1) % report_every == 0 {
            report(i + 1, baseline_kb);
        }
    }

    let elapsed = t0.elapsed();
    let rss_after_files = status_kb("VmRSS");
    println!("\n=== after files ===");
    report(num_files, baseline_kb);
    println!(
        "inserted {} files in {:.1}s ({:.0} files/s)",
        num_files,
        elapsed.as_secs_f64(),
        num_files as f64 / elapsed.as_secs_f64()
    );

    // Model connected clients: one live ClientHandle per user (the same users
    // that published files). This adds the per-connection heap the file-only loop
    // omits — nick/country/software strings, the push channel, the activity
    // atomic, and the clients DashMap entry. Clients scale with USERS (not
    // files), and num_users tracks the real files/user ratio, so this folds into
    // bytes/file consistently across scales.
    println!("\n--- modeling {} connected clients ---", num_users);
    for uid in 0..num_users {
        let mut uh = [0u8; 16];
        uh[0..8].copy_from_slice(&mix(uid).to_le_bytes());
        let ip = IpAddr::V4(Ipv4Addr::from(mix(uid ^ 0xdead_beef) as u32));
        let nick = format!("emule_user_{:07}", uid % 10_000_000);
        let country = COUNTRIES[(uid as usize) % COUNTRIES.len()].to_string();
        let software = SOFTWARE[(mix(uid) as usize) % SOFTWARE.len()].to_string();
        // ~1 in 5 advertise a NAT-T UDP port (mod adoption), like the real mix.
        let udp = if uid % 5 == 0 {
            1024 + (uid as u16 & 0x3fff)
        } else {
            0
        };
        state.register_synthetic_client(uh, uid as u32, ip, nick, country, software, udp);
    }
    let rss_after_clients = status_kb("VmRSS");
    let client_kb = rss_after_clients.saturating_sub(rss_after_files);
    println!(
        "clients added: +{} MB  ({:.0} bytes/client over {} clients)",
        client_kb / 1024,
        (client_kb as f64 * 1024.0) / num_users.max(1) as f64,
        num_users,
    );

    println!("\n=== FINAL (files + clients) ===");
    report(num_files, baseline_kb);

    // Structure counts (same data the web /api/memdebug exposes), to sanity-check
    // the workload shape (sources/file, postings/file, unique names, etc).
    println!("\n--- structures ---");
    for (k, v) in state.memory_report() {
        println!("{:>28} = {}", k, v);
    }

    // Extrapolation helper to the real target.
    let rss_kb = status_kb("VmRSS");
    let bpf = (rss_kb as f64 * 1024.0) / num_files as f64;
    let proj_gb = bpf * 33_252_559.0 / (1024.0 * 1024.0 * 1024.0);
    println!(
        "\nat {:.1} bytes/file → projected ~{:.1} GB for 33,252,559 files (target box: 16 GB)",
        bpf, proj_gb
    );
}
