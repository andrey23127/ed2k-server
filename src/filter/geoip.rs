//! Country (and provider) lookup for client and peer addresses.
//!
//! Two sources, tried in this order:
//! 1. a MaxMind DB file — `ipinfo_lite.mmdb` (IPinfo Lite) or a GeoLite2
//!    Country file. IPv4 and IPv6, plus the network's ASN and provider name
//!    where the file has them. The whole file is held in memory (~23 MB for
//!    IPinfo Lite) and searched in place; see [`super::mmdb`].
//! 2. `ip-to-country.csv` (Lugdunum format), IPv4 only:
//!    `start_int,end_int,ISO2,CountryName`, e.g. `16777216,16777471,AU,Australia`.
//!
//! [`CountryDb::load`] picks the first that loads; with neither, lookups
//! return `None` and the server runs without country data.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::mmdb::Mmdb;

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

#[derive(Default)]
enum Backend {
    #[default]
    None,
    Csv {
        ranges: Vec<Range>,
        /// code → full country name, one entry per distinct country (~248
        /// total), not per range. Shared by all ranges with that code.
        names: HashMap<[u8; 2], Box<str>>,
    },
    Mmdb(Mmdb),
}

/// The loaded country database.
#[derive(Default)]
pub struct CountryDb {
    backend: Backend,
    /// The file it came from, for the admin panel.
    path: PathBuf,
}

/// The default name of the MaxMind DB file looked for next to the CSV.
pub const DEFAULT_MMDB_NAME: &str = "ipinfo_lite.mmdb";

/// Where to look for the MaxMind DB file.
///
/// `configured` is `storage.geoip_mmdb_path`: a path, or `"off"` to use the
/// CSV only. Empty means "next to the CSV", named [`DEFAULT_MMDB_NAME`].
pub fn mmdb_path(configured: &str, csv_path: &str) -> Option<PathBuf> {
    let c = configured.trim();
    if c.eq_ignore_ascii_case("off") {
        return None;
    }
    if !c.is_empty() {
        return Some(PathBuf::from(c));
    }
    let csv = csv_path.trim();
    if csv.is_empty() {
        return None;
    }
    let dir = Path::new(csv).parent().unwrap_or(Path::new(""));
    Some(dir.join(DEFAULT_MMDB_NAME))
}

impl CountryDb {
    /// Load the MaxMind DB at `mmdb` if there is one and it opens, else the CSV
    /// at `csv` (empty = none). Logs which one, and why the first was skipped.
    pub fn load(mmdb: Option<&Path>, csv: &Path) -> Self {
        if let Some(p) = mmdb {
            match Self::load_mmdb(p) {
                Ok(db) => return db,
                Err(e) if p.exists() => tracing::warn!(path = %p.display(), error = %e,
                    "GeoIP: MaxMind DB unreadable — falling back to the CSV (IPv4 only)"),
                Err(_) => tracing::info!(path = %p.display(),
                    "GeoIP: no MaxMind DB — using the CSV (IPv4 only)"),
            }
        }
        if csv.as_os_str().is_empty() {
            return Self::default();
        }
        Self::load_csv(csv)
    }

    pub fn load_mmdb(path: &Path) -> Result<Self, String> {
        let db = Mmdb::open(path)?;
        let built = chrono::DateTime::from_timestamp(db.build_epoch as i64, 0)
            .map(|t| t.format("%Y-%m-%d").to_string())
            .unwrap_or_default();
        tracing::info!(path = %path.display(), kind = %db.database_type, built = %built,
            ipv6 = db.has_ipv6(), mb = db.size_bytes() / (1024 * 1024),
            "GeoIP: MaxMind DB loaded");
        Ok(CountryDb {
            backend: Backend::Mmdb(db),
            path: path.to_path_buf(),
        })
    }

    pub fn load_csv(path: &Path) -> Self {
        // Lossy decode — country names in third-party CSVs are often Latin-1.
        let Ok(content) = std::fs::read(path).map(|b| String::from_utf8_lossy(&b).into_owned())
        else {
            tracing::warn!(path = %path.display(), "ip-to-country.csv not found — country stats disabled");
            return Self::default();
        };

        let mut ranges: Vec<Range> = Vec::new();
        let mut names: HashMap<[u8; 2], Box<str>> = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(4, ',');
            let start = parts.next().and_then(|s| s.trim().parse::<u32>().ok());
            let end = parts.next().and_then(|s| s.trim().parse::<u32>().ok());
            let code = parts.next().map(|s| s.trim().to_uppercase());
            let name = parts.next().map(|s| s.trim().to_string());
            if let (Some(start), Some(end), Some(code), Some(name)) = (start, end, code, name) {
                let code_bytes = code.as_bytes();
                if code_bytes.len() >= 2 {
                    let code2 = [code_bytes[0], code_bytes[1]];
                    ranges.push(Range {
                        start,
                        end,
                        code: code2,
                    });
                    // Record the name once per distinct code (shared table).
                    names.entry(code2).or_insert_with(|| name.into_boxed_str());
                }
            }
        }
        ranges.sort_unstable_by_key(|r| r.start);
        ranges.shrink_to_fit();
        tracing::info!(ranges = ranges.len(), countries = names.len(),
                       path = %path.display(), "GeoIP: CSV loaded (IPv4 only)");
        if ranges.is_empty() {
            return Self::default();
        }
        CountryDb {
            backend: Backend::Csv { ranges, names },
            path: path.to_path_buf(),
        }
    }

    /// Returns (ISO2, full name) for `ip`, or None if unknown. IPv6 resolves
    /// only from a MaxMind DB; an IPv4-mapped IPv6 address is looked up as
    /// the IPv4 one.
    pub fn lookup(&self, ip: impl Into<IpAddr>) -> Option<(String, String)> {
        let ip = unmap(ip.into());
        match &self.backend {
            Backend::None => None,
            Backend::Csv { ranges, names } => {
                let IpAddr::V4(v4) = ip else { return None };
                let n = u32::from(v4);
                let idx = ranges.partition_point(|r| r.start <= n);
                let r = ranges.get(idx.checked_sub(1)?)?;
                if n > r.end {
                    return None;
                }
                let code = std::str::from_utf8(&r.code).unwrap_or("??").to_string();
                let name = names.get(&r.code).map(|s| s.to_string()).unwrap_or_default();
                Some((code, name))
            }
            Backend::Mmdb(db) => {
                let r = db.lookup(ip)?;
                Some((r.country_code?, r.country_name.unwrap_or_default()))
            }
        }
    }

    /// The network's provider, "AS3269 Telecom Italia S.p.A.", when the
    /// database carries it (IPinfo Lite does; the CSV does not).
    pub fn provider(&self, ip: impl Into<IpAddr>) -> Option<String> {
        let Backend::Mmdb(db) = &self.backend else { return None };
        let r = db.lookup(unmap(ip.into()))?;
        match (r.asn, r.as_name) {
            (Some(a), Some(n)) => Some(format!("{a} {n}")),
            (a, n) => a.or(n),
        }
    }

    pub fn is_loaded(&self) -> bool {
        !matches!(self.backend, Backend::None)
    }

    pub fn supports_ipv6(&self) -> bool {
        matches!(&self.backend, Backend::Mmdb(db) if db.has_ipv6())
    }

    /// One line for the admin panel: which source, what it covers.
    pub fn describe(&self) -> String {
        match &self.backend {
            Backend::None => "not loaded".into(),
            Backend::Csv { ranges, .. } => format!(
                "{} — CSV, IPv4 only, {} ranges",
                self.path.display(),
                ranges.len()
            ),
            Backend::Mmdb(db) => {
                let built = chrono::DateTime::from_timestamp(db.build_epoch as i64, 0)
                    .map(|t| t.format(", built %Y-%m-%d").to_string())
                    .unwrap_or_default();
                format!(
                    "{} — MaxMind DB ({}), {}{}",
                    self.path.display(),
                    db.database_type,
                    if db.has_ipv6() { "IPv4 + IPv6" } else { "IPv4 only" },
                    built
                )
            }
        }
    }

    /// Heap bytes held by the GeoIP database (for /api/memsize).
    pub fn size_bytes(&self) -> u64 {
        match &self.backend {
            Backend::None => 0,
            Backend::Csv { ranges, names } => {
                let r = (ranges.capacity() * std::mem::size_of::<Range>()) as u64;
                let mut n = (names.capacity()
                    * (std::mem::size_of::<[u8; 2]>() + std::mem::size_of::<Box<str>>() + 1))
                    as u64;
                for v in names.values() {
                    n += v.len() as u64;
                }
                r + n
            }
            Backend::Mmdb(db) => db.size_bytes(),
        }
    }

    /// Size of the loaded table, for diagnostics: CSV ranges, or MaxMind DB
    /// search-tree nodes. 0 when nothing is loaded.
    pub fn range_count(&self) -> usize {
        match &self.backend {
            Backend::None => 0,
            Backend::Csv { ranges, .. } => ranges.len(),
            Backend::Mmdb(db) => db.node_count() as usize,
        }
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn csv_db(ranges: Vec<Range>, names: &[([u8; 2], &str)]) -> CountryDb {
        CountryDb {
            backend: Backend::Csv {
                ranges,
                names: names.iter().map(|(c, n)| (*c, (*n).into())).collect(),
            },
            path: PathBuf::new(),
        }
    }

    #[test]
    fn test_lookup_hardcoded() {
        // 16777216 = 1.0.0.0 (AU), 16777471 = 1.0.0.255
        let db = csv_db(
            vec![Range { start: 16777216, end: 16777471, code: *b"AU" }],
            &[(*b"AU", "Australia")],
        );
        let ip: Ipv4Addr = "1.0.0.128".parse().unwrap();
        let (code, name) = db.lookup(ip).unwrap();
        assert_eq!(code, "AU");
        assert_eq!(name, "Australia", "name must resolve from the shared table");
        // IPv4-mapped IPv6 resolves as IPv4; plain IPv6 has no CSV data.
        let mapped: IpAddr = "::ffff:1.0.0.128".parse().unwrap();
        assert_eq!(db.lookup(mapped).map(|(c, _)| c).as_deref(), Some("AU"));
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(db.lookup(v6).is_none());
        assert!(!db.supports_ipv6());
        assert!(db.provider(ip).is_none());
    }

    #[test]
    fn lookup_outside_range_is_none() {
        let db = csv_db(
            vec![Range { start: 100, end: 200, code: *b"XY" }],
            &[(*b"XY", "Xyland")],
        );
        assert!(db.lookup(Ipv4Addr::from(50u32)).is_none());
        assert!(db.lookup(Ipv4Addr::from(150u32)).is_some());
        assert!(db.lookup(Ipv4Addr::from(250u32)).is_none());
    }

    #[test]
    fn mmdb_path_defaults_next_to_the_csv() {
        assert_eq!(
            mmdb_path("", "/etc/ed2k-server/ip-to-country.csv"),
            Some(PathBuf::from("/etc/ed2k-server/ipinfo_lite.mmdb"))
        );
        assert_eq!(mmdb_path("", "ip-to-country.csv"), Some(PathBuf::from("ipinfo_lite.mmdb")));
        assert_eq!(mmdb_path("/x/geo.mmdb", ""), Some(PathBuf::from("/x/geo.mmdb")));
        assert_eq!(mmdb_path("off", "/etc/a.csv"), None);
        assert_eq!(mmdb_path("", ""), None);
    }

    #[test]
    fn falls_back_to_csv_and_to_nothing() {
        let dir = std::env::temp_dir().join(format!("geoip-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("ip-to-country.csv");
        std::fs::write(&csv, "16777216,16777471,AU,Australia\n").unwrap();
        let bad = dir.join("ipinfo_lite.mmdb");
        std::fs::write(&bad, b"not a database").unwrap();
        let db = CountryDb::load(Some(&bad), &csv);
        assert!(db.is_loaded() && !db.supports_ipv6(), "corrupt mmdb → CSV");
        let db = CountryDb::load(Some(&dir.join("missing.mmdb")), &csv);
        assert_eq!(db.lookup(Ipv4Addr::new(1, 0, 0, 1)).map(|(c, _)| c).as_deref(), Some("AU"));
        let db = CountryDb::load(None, &dir.join("missing.csv"));
        assert!(!db.is_loaded());
        let db = CountryDb::load(None, Path::new(""));
        assert!(!db.is_loaded());
        std::fs::remove_dir_all(&dir).ok();
    }
}
