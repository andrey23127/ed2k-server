//! IP filter: load guarding.p2p (eMule/Lugdunum format) and block IPs.
//!
//! Format: "aaa.bbb.ccc.ddd - eee.fff.ggg.hhh , PRIORITY , DESCRIPTION"
//! Lugdunum and eMule use zero-padded octets (001.002.003.004). Rust's
//! `Ipv4Addr` rejects leading zeros, so we normalize each octet first.
//! We treat every entry in the file as blocked (don't parse priority byte).

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

/// Sorted list of (start_u32, end_u32) IP ranges to block, plus a parallel
/// per-range hit counter. guarding.p2p ranges are fully disjoint, so the list is
/// kept 1:1 with the file's lines (sorted) and binary-searched directly.
#[derive(Default)]
pub struct IpFilter {
    ranges: Vec<(u32, u32)>,
    /// Per-range block-hit counters, SAME index as `ranges`. u32 is ample.
    /// Interior-mutable so `is_blocked` records a hit through `&self`.
    /// Descriptions are deliberately NOT kept in RAM (100k+ distinct, ~2.9 MB of
    /// text); they are resolved from the source file on demand by `hit_report`,
    /// and only for ranges that actually blocked something. Steady-state cost of
    /// stats is just this counter vector (~4 bytes/range).
    hits: Vec<AtomicU32>,
}

/// One guarding.p2p line that has blocked ≥1 IP, for the stats UI.
pub struct HitRow {
    pub start: u32,
    pub end: u32,
    pub count: u32,
    pub desc: String,
}

impl IpFilter {
    /// Load from a guarding.p2p-format file. If the file doesn't exist or is
    /// unreadable, returns an empty (pass-all) filter and logs a warning.
    pub fn load(path: &Path) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    tracing::info!(path = %path.display(), "no IP filter file — all IPs allowed");
                } else {
                    tracing::warn!(path = %path.display(), error = %e, "could not read IP filter");
                }
                return IpFilter::default();
            }
        };

        let mut ranges: Vec<(u32, u32)> = Vec::new();
        let mut skipped = 0usize;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match parse_line(line) {
                Some(pair) => ranges.push(pair),
                None => skipped += 1,
            }
        }

        ranges.sort_unstable();
        let ranges = merge_ranges(ranges);
        // One zeroed hit counter per final range (parallel index).
        let hits = (0..ranges.len()).map(|_| AtomicU32::new(0)).collect();

        if skipped > 0 {
            tracing::debug!(skipped, "IP filter: lines that couldn't be parsed");
        }
        tracing::info!(
            ranges = ranges.len(),
            path = %path.display(),
            "IP filter loaded"
        );
        IpFilter { ranges, hits }
    }

    /// Returns true if `ip` falls inside any blocked range, recording a hit on
    /// the matching range for the stats report.
    pub fn is_blocked(&self, ip: Ipv4Addr) -> bool {
        if self.ranges.is_empty() {
            return false;
        }
        let n = u32::from(ip);
        // Find the last range whose start ≤ n, then check n ≤ end.
        let idx = self.ranges.partition_point(|&(start, _)| start <= n);
        if idx == 0 {
            return false;
        }
        if n <= self.ranges[idx - 1].1 {
            // Record the hit. `.get` guards tests that set `ranges` without `hits`.
            if let Some(h) = self.hits.get(idx - 1) {
                h.fetch_add(1, Ordering::Relaxed);
            }
            true
        } else {
            false
        }
    }

    /// Resolve per-range block hits into human-readable rows by re-reading the
    /// source file. Only ranges with count > 0 are returned (the UI shows just
    /// the lines actually catching traffic). Descriptions live on disk, not RAM,
    /// so this is a single streaming pass — cheap for an occasional admin view,
    /// zero steady-state memory. Rows are sorted by hit count, descending.
    pub fn hit_report(&self, path: &Path) -> Vec<HitRow> {
        use std::collections::HashMap;
        // (start,end) → count, only for ranges that have blocked something.
        // Typically a small fraction of all ranges.
        let mut needed: HashMap<(u32, u32), u32> = HashMap::new();
        for (i, &(s, e)) in self.ranges.iter().enumerate() {
            let c = self
                .hits
                .get(i)
                .map(|h| h.load(Ordering::Relaxed))
                .unwrap_or(0);
            if c > 0 {
                needed.insert((s, e), c);
            }
        }
        if needed.is_empty() {
            return Vec::new();
        }
        let mut rows: Vec<HitRow> = Vec::with_capacity(needed.len());
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((s, e)) = parse_line(line) {
                    if let Some(&count) = needed.get(&(s, e)) {
                        // Description is everything after the 2nd " , " (it may
                        // itself contain commas / pipes, so splitn, not rsplit).
                        let mut it = line.splitn(3, " , ");
                        it.next();
                        it.next();
                        let desc = it.next().unwrap_or("").trim().to_string();
                        rows.push(HitRow { start: s, end: e, count, desc });
                    }
                }
            }
        }
        rows.sort_unstable_by(|a, b| b.count.cmp(&a.count));
        rows
    }

    /// Total number of block hits recorded across all ranges (for a summary).
    pub fn total_hits(&self) -> u64 {
        self.hits.iter().map(|h| h.load(Ordering::Relaxed) as u64).sum()
    }

    pub fn len(&self) -> usize   { self.ranges.len() }
    pub fn is_empty(&self) -> bool { self.ranges.is_empty() }
}

/// Parse one line. Returns None on malformed input (silently skipped).
fn parse_line(line: &str) -> Option<(u32, u32)> {
    // "001.000.000.000 - 001.000.000.255 , 000 , description"
    let dash = line.find(" - ")?;
    let start_raw = line[..dash].trim();
    let rest      = &line[dash + 3..];
    let end_raw   = rest.find(" , ")
        .map(|c| &rest[..c])
        .unwrap_or(rest)
        .trim();

    Some((ip_to_u32(start_raw)?, ip_to_u32(end_raw)?))
}

/// Parse a possibly zero-padded IPv4 string into a u32.
/// Accepts "001.002.003.004" as well as "1.2.3.4".
fn ip_to_u32(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut n: u32 = 0;
    for part in &parts {
        // parse() on &str gives u8 range check for free; leading zeros OK.
        let octet: u8 = part.parse().ok()?;
        n = (n << 8) | octet as u32;
    }
    Some(n)
}

/// Merge overlapping or adjacent ranges (input must be sorted by start).
fn merge_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if ranges.is_empty() {
        return ranges;
    }
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    merged.push(ranges.remove(0));
    for (s, e) in ranges {
        let last = merged.last_mut().unwrap();
        if s <= last.1.saturating_add(1) {
            last.1 = last.1.max(e);
        } else {
            merged.push((s, e));
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_zero_padded() {
        let (s, e) = parse_line("001.000.000.000 - 001.000.000.255 , 000 , cloudflare").unwrap();
        assert_eq!(s, u32::from(Ipv4Addr::new(1, 0, 0, 0)));
        assert_eq!(e, u32::from(Ipv4Addr::new(1, 0, 0, 255)));
    }

    #[test]
    fn parse_normal() {
        let (s, e) = parse_line("10.0.0.0 - 10.0.0.255 , 127 , LAN").unwrap();
        assert_eq!(s, u32::from(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(e, u32::from(Ipv4Addr::new(10, 0, 0, 255)));
    }

    #[test]
    fn blocked_and_allowed() {
        let mut f = IpFilter::default();
        f.ranges = vec![
            (u32::from(Ipv4Addr::new(10, 0, 0, 0)),   u32::from(Ipv4Addr::new(10, 0, 0, 255))),
            (u32::from(Ipv4Addr::new(192, 168, 1, 0)), u32::from(Ipv4Addr::new(192, 168, 1, 255))),
        ];
        assert!(f.is_blocked("10.0.0.100".parse().unwrap()));
        assert!(f.is_blocked("10.0.0.0".parse().unwrap()));
        assert!(f.is_blocked("10.0.0.255".parse().unwrap()));
        assert!(!f.is_blocked("10.0.1.0".parse().unwrap()));
        assert!(f.is_blocked("192.168.1.50".parse().unwrap()));
        assert!(!f.is_blocked("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn merging() {
        // adjacent ranges get merged
        let r = merge_ranges(vec![(0, 10), (11, 20), (25, 30)]);
        assert_eq!(r, vec![(0, 20), (25, 30)]);
    }

    #[test]
    fn load_from_sample() {
        // Build a minimal guarding.p2p in memory and exercise load via a tempfile
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "001.000.000.000 - 001.000.000.255 , 000 , cloudflare").unwrap();
        writeln!(f, "010.000.000.000 - 010.255.255.255 , 000 , private").unwrap();
        f.flush().unwrap();
        let filter = IpFilter::load(f.path());
        assert_eq!(filter.len(), 2);
        assert!(filter.is_blocked("1.0.0.128".parse().unwrap()));
        assert!(filter.is_blocked("10.50.0.1".parse().unwrap()));
        assert!(!filter.is_blocked("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn hit_report_counts_and_resolves_descriptions() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "001.000.000.000 - 001.000.000.255 , 000 , cloudflare:AS13335").unwrap();
        writeln!(f, "010.000.000.000 - 010.255.255.255 , 000 , Botnet on Example, Inc.").unwrap();
        writeln!(f, "020.000.000.000 - 020.000.000.255 , 000 , never hit").unwrap();
        f.flush().unwrap();
        let filter = IpFilter::load(f.path());

        // Block some IPs: range 0 twice, range 1 once, range 2 never.
        assert!(filter.is_blocked("1.0.0.5".parse().unwrap()));
        assert!(filter.is_blocked("1.0.0.200".parse().unwrap()));
        assert!(filter.is_blocked("10.1.2.3".parse().unwrap()));
        assert_eq!(filter.total_hits(), 3);

        let rows = filter.hit_report(f.path());
        // Only the two ranges with hits appear, sorted by count desc.
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].count, 2);
        assert_eq!(rows[0].desc, "cloudflare:AS13335");
        assert_eq!(rows[1].count, 1);
        // Description containing a comma is preserved (splitn, not rsplit).
        assert_eq!(rows[1].desc, "Botnet on Example, Inc.");
        // The never-hit range is absent.
        assert!(!rows.iter().any(|r| r.desc == "never hit"));
    }
}
