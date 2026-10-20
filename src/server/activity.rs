//! Search activity per source: how often clients search and ask for sources,
//! how many files a request carries, how many different files a source asks
//! about. Temporary: collected to choose the criteria that tell a bot or a
//! list scanner from a client (`[bots] activity_stats`), read through
//! `/api/activity`.
//!
//! The 0.9.84 rate detector judges a source by queries per minute, and a
//! scanner walking a list of 4 400 files at ~150 requests a minute is below
//! any rate an ordinary client could not reach. What sets it apart is how many
//! different files it asks about. This table measures that for every source,
//! so the threshold comes from the data and not from a guess.
//!
//! Cost: one record per source key (IPv4 address, IPv6 /64), about 200 bytes,
//! at most `bots.activity_max_sources` of them; a source beyond the cap is
//! only counted in the totals. Distinct files are estimated with a 64-register
//! HyperLogLog (±13%), so no hash is stored.

use crate::state::FileHash;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

/// What a request was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    TcpSearch,
    UdpSearch,
    /// OP_QUERY_MORE_RESULT: the next page of a TCP search.
    TcpMore,
    TcpSources,
    UdpSources,
}

impl Kind {
    fn index(self) -> usize {
        self as usize
    }
    fn is_sources(self) -> bool {
        matches!(self, Kind::TcpSources | Kind::UdpSources)
    }
}

const KINDS: usize = 5;

/// Gaps between two requests of one source: <1 s, 1-10 s, 10-60 s, 1-10 min,
/// 10-60 min, > 1 h.
pub const GAP_BUCKETS: [&str; 6] = ["lt1s", "1-10s", "10-60s", "1-10m", "10-60m", "gt1h"];
const GAP_LIMITS_MS: [u64; 5] = [1_000, 10_000, 60_000, 600_000, 3_600_000];

/// Files in one source request: 1, 2-4, 5-16, 17-32, 33+.
pub const PER_REQ_BUCKETS: [&str; 5] = ["1", "2-4", "5-16", "17-32", "33+"];

fn per_req_bucket(n: usize) -> usize {
    match n {
        0 | 1 => 0,
        2..=4 => 1,
        5..=16 => 2,
        17..=32 => 3,
        _ => 4,
    }
}

fn gap_bucket(ms: u64) -> usize {
    GAP_LIMITS_MS
        .iter()
        .position(|&l| ms < l)
        .unwrap_or(GAP_LIMITS_MS.len())
}

/// 64-register HyperLogLog over file hashes. MD4 output is uniform already,
/// so the hash bytes are used as they are.
#[derive(Clone)]
pub struct Hll([u8; 64]);

impl Default for Hll {
    fn default() -> Self {
        Hll([0; 64])
    }
}

impl Hll {
    pub fn add(&mut self, h: &FileHash) {
        // Mixed first: a real MD4 is uniform, but not every hash a client
        // sends is one. On the live server sources asking 700 files were
        // estimated at 6 000, from hashes with long runs of zero bytes, which
        // the raw bytes turn into high register ranks. Mixed, any 16 bytes
        // spread evenly.
        let lo = u64::from_le_bytes(h[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(h[8..16].try_into().unwrap());
        let x = mix64(lo ^ mix64(hi));
        let idx = (x & 63) as usize;
        let w = x >> 6;
        let rank = (w.leading_zeros() - 6 + 1).min(58) as u8;
        if rank > self.0[idx] {
            self.0[idx] = rank;
        }
    }
    pub fn estimate(&self) -> f64 {
        let m = 64.0f64;
        let mut sum = 0.0;
        let mut zeros = 0u32;
        for &r in &self.0 {
            sum += 2f64.powi(-(r as i32));
            if r == 0 {
                zeros += 1;
            }
        }
        let e = 0.709 * m * m / sum;
        if e <= 2.5 * m && zeros > 0 {
            m * (m / zeros as f64).ln()
        } else {
            e
        }
    }
}

/// splitmix64's finaliser.
fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// One source's activity since the period began.
#[derive(Clone, Default)]
pub struct Rec {
    /// Seconds since the period start.
    pub first_s: u32,
    pub last_s: u32,
    /// Requests by `Kind`.
    pub n: [u32; KINDS],
    /// Files asked about in source requests, repeats included.
    pub hashes: u64,
    pub per_req: [u32; 5],
    /// Search results sent (TCP: the whole result set; UDP: datagrams sent).
    pub results: u64,
    pub zero_result: u32,
    pub gaps: [u32; 6],
    /// Milliseconds since the period start of the last request.
    last_ms: u64,
    minute: u32,
    minute_n: u32,
    pub peak_per_min: u32,
    pub distinct: Hll,
    /// Seen over a TCP session (logged in here).
    pub tcp: bool,
}

impl Rec {
    pub fn searches(&self) -> u32 {
        self.n[Kind::TcpSearch.index()] + self.n[Kind::UdpSearch.index()]
    }
    pub fn source_requests(&self) -> u32 {
        self.n[Kind::TcpSources.index()] + self.n[Kind::UdpSources.index()]
    }
    pub fn requests(&self) -> u64 {
        self.n.iter().map(|&x| x as u64).sum()
    }
    /// Different files asked about: the estimate, never above the files asked.
    pub fn distinct_est(&self) -> f64 {
        self.distinct.estimate().min(self.hashes as f64)
    }
    pub fn active_secs(&self) -> u32 {
        self.last_s.saturating_sub(self.first_s)
    }
    /// Requests per hour over the time the source was seen, at least a minute.
    pub fn per_hour(&self) -> f64 {
        self.requests() as f64 * 3600.0 / (self.active_secs().max(60) as f64)
    }
}

pub struct Activity {
    started: Mutex<(Instant, SystemTime)>,
    map: DashMap<IpAddr, Rec>,
    /// Requests by `Kind`, every source (also those beyond the cap).
    totals: [AtomicU64; KINDS],
    total_hashes: AtomicU64,
    /// Requests from sources that did not fit under the cap.
    untracked: AtomicU64,
    /// Requests by UTC hour of day.
    by_hour: [AtomicU64; 24],
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            started: Mutex::new((Instant::now(), SystemTime::now())),
            map: DashMap::new(),
            totals: Default::default(),
            total_hashes: AtomicU64::new(0),
            untracked: AtomicU64::new(0),
            by_hour: Default::default(),
        }
    }
}

impl Activity {
    fn since_start_ms(&self) -> u64 {
        self.started
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .elapsed()
            .as_millis() as u64
    }

    pub fn started_at(&self) -> SystemTime {
        self.started.lock().unwrap_or_else(|e| e.into_inner()).1
    }

    pub fn period_secs(&self) -> u64 {
        self.since_start_ms() / 1000
    }

    /// Record one request of `key` (a source key). `hashes`: the files of a
    /// source request. `max`: `bots.activity_max_sources`.
    pub fn note(&self, key: IpAddr, kind: Kind, hashes: &[FileHash], tcp: bool, max: usize) {
        self.totals[kind.index()].fetch_add(1, Relaxed);
        self.total_hashes.fetch_add(hashes.len() as u64, Relaxed);
        let hour = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| (d.as_secs() / 3600) % 24)
            .unwrap_or(0) as usize;
        self.by_hour[hour].fetch_add(1, Relaxed);

        let ms = self.since_start_ms();
        let s = (ms / 1000).min(u32::MAX as u64) as u32;
        let mut rec = match self.map.get_mut(&key) {
            Some(r) => r,
            None => {
                if self.map.len() >= max {
                    self.untracked.fetch_add(1, Relaxed);
                    return;
                }
                self.map.entry(key).or_insert_with(|| Rec {
                    first_s: s,
                    last_s: s,
                    last_ms: ms,
                    ..Default::default()
                })
            }
        };
        let r = rec.value_mut();
        if r.requests() > 0 {
            r.gaps[gap_bucket(ms.saturating_sub(r.last_ms))] += 1;
        }
        r.last_ms = ms;
        r.last_s = s;
        r.n[kind.index()] = r.n[kind.index()].saturating_add(1);
        r.tcp |= tcp;
        let minute = s / 60;
        if minute == r.minute {
            r.minute_n += 1;
        } else {
            r.minute = minute;
            r.minute_n = 1;
        }
        r.peak_per_min = r.peak_per_min.max(r.minute_n);
        if kind.is_sources() {
            r.hashes += hashes.len() as u64;
            r.per_req[per_req_bucket(hashes.len())] += 1;
            for h in hashes {
                r.distinct.add(h);
            }
        }
    }

    /// The results a search of `key` got. Called after `note`.
    pub fn note_results(&self, key: IpAddr, n: usize) {
        if let Some(mut r) = self.map.get_mut(&key) {
            r.results += n as u64;
            if n == 0 {
                r.zero_result += 1;
            }
        }
    }

    pub fn reset(&self) {
        *self.started.lock().unwrap_or_else(|e| e.into_inner()) =
            (Instant::now(), SystemTime::now());
        self.map.clear();
        self.map.shrink_to_fit();
        for t in &self.totals {
            t.store(0, Relaxed);
        }
        self.total_hashes.store(0, Relaxed);
        self.untracked.store(0, Relaxed);
        for h in &self.by_hour {
            h.store(0, Relaxed);
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.map.capacity()
    }

    /// A copy of every record, for the API.
    pub fn snapshot(&self) -> Vec<(IpAddr, Rec)> {
        self.map
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect()
    }

    /// Server-wide figures and the distribution of the per-source ones.
    pub fn summary(&self, rows: &[(IpAddr, Rec)]) -> serde_json::Value {
        use serde_json::json;
        let kinds = [
            "tcp_search",
            "udp_search",
            "tcp_more",
            "tcp_sources",
            "udp_sources",
        ];
        let totals: serde_json::Map<String, serde_json::Value> = kinds
            .iter()
            .zip(&self.totals)
            .map(|(k, v)| (k.to_string(), json!(v.load(Relaxed))))
            .collect();
        let searchers: Vec<&Rec> = rows
            .iter()
            .map(|(_, r)| r)
            .filter(|r| r.searches() > 0)
            .collect();
        let askers: Vec<&Rec> = rows
            .iter()
            .map(|(_, r)| r)
            .filter(|r| r.source_requests() > 0)
            .collect();
        let all: Vec<&Rec> = rows.iter().map(|(_, r)| r).collect();

        let mut per_req = [0u64; 5];
        let mut gaps = [0u64; 6];
        for r in &all {
            for (a, b) in per_req.iter_mut().zip(r.per_req) {
                *a += b as u64;
            }
            for (a, b) in gaps.iter_mut().zip(r.gaps) {
                *a += b as u64;
            }
        }
        let named = |names: &[&str], v: &[u64]| -> serde_json::Value {
            names
                .iter()
                .zip(v)
                .map(|(k, n)| (k.to_string(), json!(n)))
                .collect::<serde_json::Map<_, _>>()
                .into()
        };
        const COUNT_EDGES: [u64; 7] = [1, 2, 6, 21, 101, 1001, 10_001];
        const COUNT_NAMES: [&str; 7] = [
            "1",
            "2-5",
            "6-20",
            "21-100",
            "101-1000",
            "1001-10000",
            "gt10000",
        ];
        let hist = |vals: &[f64]| -> serde_json::Value {
            let mut b = [0u64; 7];
            for &v in vals {
                let v = v.round() as u64;
                if v == 0 {
                    continue;
                }
                let i = COUNT_EDGES.iter().rposition(|&e| v >= e).unwrap_or(0);
                b[i] += 1;
            }
            named(&COUNT_NAMES, &b)
        };
        let col = |set: &[&Rec], f: &dyn Fn(&Rec) -> f64| -> Vec<f64> {
            set.iter().map(|r| f(r)).collect()
        };

        let searches = col(&searchers, &|r| r.searches() as f64);
        let results = col(&searchers, &|r| {
            r.results as f64 / r.searches().max(1) as f64
        });
        let zero_share = col(&searchers, &|r| {
            r.zero_result as f64 / r.searches().max(1) as f64
        });
        let src = col(&askers, &|r| r.source_requests() as f64);
        let hashes = col(&askers, &|r| r.hashes as f64);
        let per_request = col(&askers, &|r| {
            r.hashes as f64 / r.source_requests().max(1) as f64
        });
        let distinct = col(&askers, &|r| r.distinct_est());
        let repeats = col(&askers, &|r| {
            r.hashes as f64 / r.distinct_est().max(1.0)
        });
        let peak = col(&all, &|r| r.peak_per_min as f64);
        let per_hour = col(&all, &|r| r.per_hour());
        let active_h = col(&all, &|r| r.active_secs() as f64 / 3600.0);
        let mean_gap_s = col(&all, &|r| {
            let n = r.requests();
            if n > 1 {
                r.active_secs() as f64 / (n - 1) as f64
            } else {
                -1.0
            }
        });
        let mean_gap_s: Vec<f64> = mean_gap_s.into_iter().filter(|&g| g >= 0.0).collect();

        json!({
            "period_start": chrono::DateTime::<chrono::Utc>::from(self.started_at())
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "period_secs": self.period_secs(),
            "sources": all.len(),
            "sources_tcp": all.iter().filter(|r| r.tcp).count(),
            "sources_searching": searchers.len(),
            "sources_asking_sources": askers.len(),
            "requests_untracked": self.untracked.load(Relaxed),
            "totals": totals,
            "total_hashes": self.total_hashes.load(Relaxed),
            "requests_by_utc_hour": self.by_hour.iter().map(|h| h.load(Relaxed)).collect::<Vec<_>>(),
            "files_per_source_request": named(&PER_REQ_BUCKETS, &per_req),
            "gaps_between_requests": named(&GAP_BUCKETS, &gaps),
            "per_source": {
                "searches": dist(&searches),
                "results_per_search": dist(&results),
                "zero_result_share": dist(&zero_share),
                "source_requests": dist(&src),
                "files_asked": dist(&hashes),
                "files_per_request": dist(&per_request),
                "distinct_files": dist(&distinct),
                "repeats_per_file": dist(&repeats),
                "peak_requests_per_minute": dist(&peak),
                "requests_per_hour": dist(&per_hour),
                "hours_active": dist(&active_h),
                "mean_gap_secs": dist(&mean_gap_s),
            },
            "histograms": {
                "searches": hist(&searches),
                "source_requests": hist(&src),
                "distinct_files": hist(&distinct),
                "peak_requests_per_minute": hist(&peak),
            },
        })
    }
}

/// mean and percentiles of `v`.
fn dist(v: &[f64]) -> serde_json::Value {
    if v.is_empty() {
        return serde_json::json!({"n": 0});
    }
    let mut s: Vec<f64> = v.iter().copied().filter(|x| x.is_finite()).collect();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| -> f64 {
        let i = ((s.len() - 1) as f64 * q).round() as usize;
        (s[i] * 100.0).round() / 100.0
    };
    let mean = s.iter().sum::<f64>() / s.len() as f64;
    serde_json::json!({
        "n": s.len(),
        "mean": (mean * 100.0).round() / 100.0,
        "p50": p(0.5), "p90": p(0.9), "p99": p(0.99), "p999": p(0.999),
        "max": p(1.0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(i: u32) -> FileHash {
        // Spread like MD4 output.
        let mut x = [0u8; 16];
        let mut v = (i as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        for b in x.iter_mut() {
            v ^= v >> 29;
            v = v.wrapping_mul(0xBF58_476D_1CE4_E5B9);
            *b = (v >> 56) as u8;
        }
        x
    }

    #[test]
    fn hll_estimates_within_a_fair_margin() {
        for &n in &[10u32, 100, 1000, 5000] {
            let mut s = Hll::default();
            for i in 0..n {
                s.add(&h(i));
                s.add(&h(i)); // repeats do not count
            }
            let e = s.estimate();
            let err = (e - n as f64).abs() / n as f64;
            assert!(err < 0.35, "n={n} est={e}");
        }
    }

    #[test]
    fn structured_hashes_are_not_overcounted() {
        // 700 hashes that are mostly zero bytes: the raw bytes gave an
        // estimate several times too high.
        let mut s = Hll::default();
        for i in 0..700u32 {
            let mut x = [0u8; 16];
            x[12..16].copy_from_slice(&i.to_le_bytes());
            s.add(&x);
        }
        let e = s.estimate();
        assert!((e - 700.0).abs() / 700.0 < 0.35, "est={e}");
    }

    #[test]
    fn requests_are_counted_by_kind_and_source() {
        let a = Activity::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        a.note(ip, Kind::TcpSearch, &[], true, 10);
        a.note_results(ip, 0);
        a.note(ip, Kind::UdpSources, &[h(1), h(2), h(3)], false, 10);
        a.note(ip, Kind::TcpSources, &[h(1)], true, 10);
        let rows = a.snapshot();
        assert_eq!(rows.len(), 1);
        let r = &rows[0].1;
        assert_eq!((r.searches(), r.source_requests(), r.hashes), (1, 2, 4));
        assert_eq!(r.per_req, [1, 1, 0, 0, 0]);
        assert_eq!(r.zero_result, 1);
        assert_eq!(r.gaps[0], 2, "back to back: two gaps under a second");
        assert_eq!(r.peak_per_min, 3);
        assert!(r.tcp);
        let s = a.summary(&rows);
        assert_eq!(s["sources"], 1);
        assert_eq!(s["totals"]["udp_sources"], 1);
        assert_eq!(s["total_hashes"], 4);
    }

    #[test]
    fn the_cap_holds_and_reset_clears() {
        let a = Activity::default();
        for i in 0..5u8 {
            a.note(IpAddr::from([10, 0, 0, i]), Kind::UdpSearch, &[], false, 3);
        }
        assert_eq!(a.len(), 3);
        assert_eq!(a.untracked.load(Relaxed), 2);
        assert_eq!(a.totals[Kind::UdpSearch.index()].load(Relaxed), 5);
        a.reset();
        assert!(a.is_empty());
        assert_eq!(a.totals[Kind::UdpSearch.index()].load(Relaxed), 0);
    }
}
