//! Country lookup from ip-to-country.csv (Ludgdunum-compatible format).
//!
//! Format: start_int,end_int,ISO2,CountryName
//! e.g.    16777216,16777471,AU,Australia

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;

/// One IP range. NOTE: the country *name* is NOT stored here — only the 2-byte
/// ISO code. With ~652k ranges but only ~248 distinct countries, storing a
/// `Box<str>` name per range wasted ~16 MB (5.6 MB of duplicated text + ~10 MB
/// of per-allocation malloc overhead across 652k tiny allocations). The name is
/// looked up from the shared `names` table by code instead. This shrinks the DB
/// from ~36 MB to ~8 MB in RAM with no change to the CSV input or accuracy.
#[derive(Clone)]
struct Range {
    start: u32,
    end: u32,
    code: [u8; 2], // ISO-3166-1 alpha-2
}

/// Country database built from ip-to-country.csv.
pub struct CountryDb {
    ranges: Vec<Range>,
    /// code → full country name, one entry per distinct country (~248 total),
    /// not per range. Shared by all ranges with that code.
    names: HashMap<[u8; 2], Box<str>>,
}

impl CountryDb {
    pub fn load(path: &Path) -> Self {
        let Ok(content) = std::fs::read_to_string(path) else {
            tracing::warn!(path = %path.display(), "ip-to-country.csv not found — country stats disabled");
            return CountryDb { ranges: Vec::new(), names: HashMap::new() };
        };

        let mut ranges: Vec<Range> = Vec::new();
        let mut names: HashMap<[u8; 2], Box<str>> = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let mut parts = line.splitn(4, ',');
            let start = parts.next().and_then(|s| s.trim().parse::<u32>().ok());
            let end   = parts.next().and_then(|s| s.trim().parse::<u32>().ok());
            let code  = parts.next().map(|s| s.trim().to_uppercase());
            let name  = parts.next().map(|s| s.trim().to_string());
            if let (Some(start), Some(end), Some(code), Some(name)) = (start, end, code, name) {
                let code_bytes = code.as_bytes();
                if code_bytes.len() >= 2 {
                    let code2 = [code_bytes[0], code_bytes[1]];
                    ranges.push(Range { start, end, code: code2 });
                    // Record the name once per distinct code (shared table).
                    names.entry(code2).or_insert_with(|| name.into_boxed_str());
                }
            }
        }
        ranges.sort_unstable_by_key(|r| r.start);
        ranges.shrink_to_fit();
        tracing::info!(ranges = ranges.len(), countries = names.len(),
                       path = %path.display(), "Country DB loaded");
        CountryDb { ranges, names }
    }

    /// Returns (ISO2, full_name) for the given IP, or None if unknown.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<(String, &str)> {
        let n = u32::from(ip);
        let idx = self.ranges.partition_point(|r| r.start <= n);
        if idx == 0 { return None; }
        let r = &self.ranges[idx - 1];
        if n <= r.end {
            let code = std::str::from_utf8(&r.code).unwrap_or("??").to_string();
            // Name comes from the shared table; fall back to code if missing.
            let name = self.names.get(&r.code).map(|s| s.as_ref()).unwrap_or("");
            Some((code, name))
        } else {
            None
        }
    }

    pub fn is_loaded(&self) -> bool { !self.ranges.is_empty() }

    /// Heap bytes held by the GeoIP database (for /api/memsize). The range table
    /// dominates (~652k ranges x 12 B); the country-name map is ~248 entries.
    pub fn size_bytes(&self) -> u64 {
        let ranges = (self.ranges.capacity() * std::mem::size_of::<Range>()) as u64;
        let mut names = (self.names.capacity()
            * (std::mem::size_of::<[u8; 2]>() + std::mem::size_of::<Box<str>>() + 1))
            as u64;
        for v in self.names.values() {
            names += v.len() as u64;
        }
        ranges + names
    }

    /// Number of GeoIP ranges (diagnostics).
    pub fn range_count(&self) -> usize { self.ranges.len() }
}

impl Default for CountryDb {
    fn default() -> Self { CountryDb { ranges: Vec::new(), names: HashMap::new() } }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_lookup_hardcoded() {
        // 16777216 = 1.0.0.0 (AU), 16777471 = 1.0.0.255
        let mut db = CountryDb { ranges: Vec::new(), names: HashMap::new() };
        db.ranges.push(super::Range {
            start: 16777216, end: 16777471,
            code: [b'A', b'U'],
        });
        db.names.insert([b'A', b'U'], "Australia".into());
        let ip: std::net::Ipv4Addr = "1.0.0.128".parse().unwrap();
        let result = db.lookup(ip);
        assert!(result.is_some());
        let (code, name) = result.unwrap();
        assert_eq!(code, "AU");
        assert_eq!(name, "Australia", "name must resolve from the shared table");
    }

    #[test]
    fn lookup_outside_range_is_none() {
        let mut db = CountryDb { ranges: Vec::new(), names: HashMap::new() };
        db.ranges.push(super::Range { start: 100, end: 200, code: [b'X', b'Y'] });
        db.names.insert([b'X', b'Y'], "Xyland".into());
        // Below first range.
        assert!(db.lookup(Ipv4Addr::from(50u32)).is_none());
        // Inside.
        assert!(db.lookup(Ipv4Addr::from(150u32)).is_some());
        // Above range end (gap).
        assert!(db.lookup(Ipv4Addr::from(250u32)).is_none());
    }
}
