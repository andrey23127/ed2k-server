//! Minimal reader for MaxMind DB (`.mmdb`) files, enough for a country and
//! provider lookup by IPv4 or IPv6 address.
//!
//! Written here rather than pulled in as a crate: the format is small and fully
//! specified (<https://maxmind.github.io/MaxMind-DB/>), only lookups are
//! needed, and every read of the untrusted file is bounds-checked in one place.
//! Malformed input yields `None` or an `Err` from [`Mmdb::from_bytes`], never a
//! panic.
//!
//! Layout: a binary search tree (`node_count` nodes, two records of
//! `record_size` bits each), 16 zero bytes, a data section of typed values, and
//! a metadata map after the marker `\xAB\xCD\xEFMaxMind.com` near the end.
//!
//! Two record layouts are understood:
//! * IPinfo Lite: top-level `country_code`, `country`, `asn`, `as_name`;
//! * MaxMind GeoLite2/GeoIP2 Country: `country.iso_code`, `country.names.en`
//!   (and `registered_country` when `country` is absent).

use std::cell::Cell;
use std::net::IpAddr;

const METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";
/// Nesting deeper than this is treated as corrupt (the real files use 2-3).
const MAX_DEPTH: u32 = 32;

/// An opened database. Holds the whole file in memory.
pub struct Mmdb {
    buf: Vec<u8>,
    node_count: u32,
    record_size: u16,
    ip_version: u16,
    /// Start of the data section in `buf`.
    data_start: usize,
    /// Where IPv4 lookups start in an IPv6 tree (the node after 96 zero bits).
    ipv4_start: u32,
    pub database_type: String,
    /// UNIX time the file was built.
    pub build_epoch: u64,
}

/// What one address resolves to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoRecord {
    /// ISO-3166-1 alpha-2, upper case.
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    /// e.g. "AS3269".
    pub asn: Option<String>,
    /// e.g. "Telecom Italia S.p.A.".
    pub as_name: Option<String>,
}

/// A decoded value header: its type, its size field, and where its payload
/// starts. Pointers are already followed.
#[derive(Clone, Copy)]
struct Header {
    typ: u8,
    size: usize,
    payload: usize,
}

const T_POINTER: u8 = 1;
const T_STRING: u8 = 2;
const T_U16: u8 = 5;
const T_U32: u8 = 6;
const T_MAP: u8 = 7;
const T_U64: u8 = 9;
const T_U128: u8 = 10;
const T_ARRAY: u8 = 11;
const T_BOOL: u8 = 14;
/// Values decoded per lookup, at most. A hostile file could point a map at
/// itself and make a depth-bounded walk exponential; this caps the work.
const DECODE_BUDGET: u32 = 20_000;

/// Decoder over one section (data or metadata). Offsets, including pointer
/// targets, are relative to the start of `buf`.
struct Dec<'a> {
    buf: &'a [u8],
    budget: Cell<u32>,
}

impl<'a> Dec<'a> {
    fn byte(&self, pos: usize) -> Option<u8> {
        self.buf.get(pos).copied()
    }

    fn be(&self, pos: usize, n: usize) -> Option<u64> {
        let b = self.buf.get(pos..pos.checked_add(n)?)?;
        Some(b.iter().fold(0u64, |a, &x| (a << 8) | x as u64))
    }

    /// Read the control byte(s) at `pos`. Returns the header and the position
    /// right after the encoded value's header (for a pointer: after the
    /// pointer itself, since its target is read in place).
    fn raw_header(&self, pos: usize) -> Option<(u8, usize, usize)> {
        let left = self.budget.get().checked_sub(1)?;
        self.budget.set(left);
        let ctrl = self.byte(pos)?;
        let mut p = pos + 1;
        let mut typ = ctrl >> 5;
        if typ == 0 {
            typ = 7u8.checked_add(self.byte(p)?)?;
            p += 1;
        }
        let size_bits = (ctrl & 0x1f) as usize;
        if typ == T_POINTER {
            return Some((typ, size_bits, p));
        }
        let size = match size_bits {
            29 => {
                let s = 29 + self.byte(p)? as usize;
                p += 1;
                s
            }
            30 => {
                let s = 285 + self.be(p, 2)? as usize;
                p += 2;
                s
            }
            31 => {
                let s = 65_821 + self.be(p, 3)? as usize;
                p += 3;
                s
            }
            n => n,
        };
        Some((typ, size, p))
    }

    /// Header of the value at `pos`, following a pointer if there is one, and
    /// the position just after the value's encoding AT `pos` when that is
    /// known without walking it (scalars and pointers); maps and arrays need
    /// [`Dec::skip`].
    fn header(&self, pos: usize) -> Option<(Header, Option<usize>)> {
        let (typ, size, p) = self.raw_header(pos)?;
        if typ == T_POINTER {
            let ss = (size >> 3) & 0x3;
            let vvv = (size & 0x7) as u64;
            let (target, after) = match ss {
                0 => ((vvv << 8) | self.be(p, 1)?, p + 1),
                1 => (((vvv << 16) | self.be(p, 2)?) + 2048, p + 2),
                2 => (((vvv << 24) | self.be(p, 3)?) + 526_336, p + 3),
                _ => (self.be(p, 4)?, p + 4),
            };
            let (t2, s2, p2) = self.raw_header(usize::try_from(target).ok()?)?;
            // A pointer to a pointer is invalid per the spec.
            if t2 == T_POINTER {
                return None;
            }
            return Some((Header { typ: t2, size: s2, payload: p2 }, Some(after)));
        }
        let h = Header { typ, size, payload: p };
        let end = match typ {
            T_MAP | T_ARRAY => None,
            T_BOOL => Some(p),
            _ => Some(p.checked_add(size)?),
        };
        Some((h, end))
    }

    /// Position after the whole value encoded at `pos`.
    fn skip(&self, pos: usize, depth: u32) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        let (h, end) = self.header(pos)?;
        if let Some(e) = end {
            return (e <= self.buf.len()).then_some(e);
        }
        let mut p = h.payload;
        let items = if h.typ == T_MAP { h.size.checked_mul(2)? } else { h.size };
        for _ in 0..items {
            p = self.skip(p, depth + 1)?;
        }
        Some(p)
    }

    fn string(&self, h: Header) -> Option<&'a str> {
        if h.typ != T_STRING {
            return None;
        }
        let b = self.buf.get(h.payload..h.payload.checked_add(h.size)?)?;
        std::str::from_utf8(b).ok()
    }

    fn uint(&self, h: Header) -> Option<u64> {
        match h.typ {
            T_U16 | T_U32 | T_U64 | T_U128 if h.size <= 8 => self.be(h.payload, h.size),
            _ => None,
        }
    }

    /// Value header for `key` in the map at `map_pos`.
    fn map_get(&self, map_pos: usize, key: &str) -> Option<Header> {
        let (m, _) = self.header(map_pos)?;
        if m.typ != T_MAP {
            return None;
        }
        let mut p = m.payload;
        for _ in 0..m.size {
            let (kh, kend) = self.header(p)?;
            let k = self.string(kh)?;
            let vpos = kend?;
            if k == key {
                return self.header(vpos).map(|(h, _)| h);
            }
            p = self.skip(vpos, 1)?;
        }
        None
    }

    /// Like [`Dec::map_get`] but returns the position of the value so it can
    /// be used as a nested map.
    fn map_get_pos(&self, map_pos: usize, key: &str) -> Option<usize> {
        let (m, _) = self.header(map_pos)?;
        if m.typ != T_MAP {
            return None;
        }
        let mut p = m.payload;
        for _ in 0..m.size {
            let (kh, kend) = self.header(p)?;
            let k = self.string(kh)?;
            let vpos = kend?;
            if k == key {
                return Some(vpos);
            }
            p = self.skip(vpos, 1)?;
        }
        None
    }

    fn map_str(&self, map_pos: usize, key: &str) -> Option<&'a str> {
        self.map_get(map_pos, key).and_then(|h| self.string(h))
    }
}

impl Mmdb {
    /// Parse and sanity-check a database held in memory.
    pub fn from_bytes(buf: Vec<u8>) -> Result<Self, String> {
        // The marker is within the last 128 KiB; take its LAST occurrence.
        let from = buf.len().saturating_sub(128 * 1024);
        let marker_at = buf[from..]
            .windows(METADATA_MARKER.len())
            .rposition(|w| w == METADATA_MARKER)
            .map(|i| from + i)
            .ok_or("not a MaxMind DB file: metadata marker not found")?;
        let meta = Dec {
            buf: &buf[marker_at + METADATA_MARKER.len()..],
            budget: Cell::new(DECODE_BUDGET),
        };
        let uint = |k: &str| meta.map_get(0, k).and_then(|h| meta.uint(h));
        let node_count = uint("node_count").ok_or("metadata: node_count missing")?;
        let record_size = uint("record_size").ok_or("metadata: record_size missing")?;
        let ip_version = uint("ip_version").ok_or("metadata: ip_version missing")?;
        let database_type = meta.map_str(0, "database_type").unwrap_or("").to_string();
        let build_epoch = uint("build_epoch").unwrap_or(0);

        if !matches!(record_size, 24 | 28 | 32) {
            return Err(format!("unsupported record size {record_size}"));
        }
        if !matches!(ip_version, 4 | 6) {
            return Err(format!("unsupported ip_version {ip_version}"));
        }
        let node_count = u32::try_from(node_count).map_err(|_| "node_count too large")?;
        let tree_size = node_count as usize * record_size as usize / 4;
        let data_start = tree_size + 16;
        if data_start > marker_at {
            return Err("search tree runs past the end of the file".into());
        }
        let mut db = Mmdb {
            buf,
            node_count,
            record_size: record_size as u16,
            ip_version: ip_version as u16,
            data_start,
            ipv4_start: 0,
            database_type,
            build_epoch,
        };
        if db.ip_version == 6 {
            let mut node = 0u32;
            for _ in 0..96 {
                if node >= db.node_count {
                    break;
                }
                node = db.record(node, 0).ok_or("search tree truncated")?;
            }
            db.ipv4_start = node;
        }
        Ok(db)
    }

    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        let buf = std::fs::read(path).map_err(|e| e.to_string())?;
        Self::from_bytes(buf)
    }

    /// Bytes held in memory.
    pub fn size_bytes(&self) -> u64 {
        self.buf.len() as u64
    }

    pub fn node_count(&self) -> u32 {
        self.node_count
    }

    pub fn has_ipv6(&self) -> bool {
        self.ip_version == 6
    }

    /// Record `side` (0 = left, 1 = right) of node `n`.
    fn record(&self, n: u32, side: u8) -> Option<u32> {
        let rs = self.record_size as usize;
        let base = n as usize * rs / 4;
        let b = self.buf.get(base..base + rs / 4)?;
        let v = match (rs, side) {
            (24, 0) => u32::from_be_bytes([0, b[0], b[1], b[2]]),
            (24, _) => u32::from_be_bytes([0, b[3], b[4], b[5]]),
            (28, 0) => u32::from_be_bytes([(b[3] & 0xF0) >> 4, b[0], b[1], b[2]]),
            (28, _) => u32::from_be_bytes([b[3] & 0x0F, b[4], b[5], b[6]]),
            (32, 0) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            _ => u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        };
        Some(v)
    }

    /// Offset into the data section of the record for `ip`, if any.
    fn find(&self, ip: IpAddr) -> Option<usize> {
        let ip = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            v4 => v4,
        };
        let (bits, nbits, mut node): (u128, u32, u32) = match (ip, self.ip_version) {
            (IpAddr::V4(v4), 6) => (u32::from(v4) as u128, 32, self.ipv4_start),
            (IpAddr::V4(v4), _) => (u32::from(v4) as u128, 32, 0),
            (IpAddr::V6(v6), 6) => (u128::from(v6), 128, 0),
            (IpAddr::V6(_), _) => return None,
        };
        for i in 0..nbits {
            if node >= self.node_count {
                break;
            }
            let bit = ((bits >> (nbits - 1 - i)) & 1) as u8;
            node = self.record(node, bit)?;
        }
        if node <= self.node_count {
            // == node_count: no data for this address. < node_count would be
            // a tree deeper than the address, which is corrupt.
            return None;
        }
        let off = (node - self.node_count) as usize;
        off.checked_sub(16)
    }

    fn data(&self) -> Dec<'_> {
        Dec {
            buf: self.buf.get(self.data_start..).unwrap_or(&[]),
            budget: Cell::new(DECODE_BUDGET),
        }
    }

    /// Country and provider for `ip`.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoRecord> {
        let pos = self.find(ip)?;
        let d = self.data();
        let mut r = GeoRecord::default();
        // IPinfo Lite: flat strings.
        if let Some(cc) = d.map_str(pos, "country_code") {
            r.country_code = Some(cc.to_ascii_uppercase());
            r.country_name = d.map_str(pos, "country").map(str::to_string);
        } else {
            // MaxMind GeoLite2/GeoIP2: country.{iso_code, names.en}.
            let c = d
                .map_get_pos(pos, "country")
                .or_else(|| d.map_get_pos(pos, "registered_country"));
            if let Some(c) = c {
                r.country_code = d.map_str(c, "iso_code").map(str::to_ascii_uppercase);
                r.country_name = d
                    .map_get_pos(c, "names")
                    .and_then(|n| d.map_str(n, "en"))
                    .map(str::to_string);
            }
        }
        r.asn = d.map_str(pos, "asn").map(str::to_string);
        r.as_name = d.map_str(pos, "as_name").map(str::to_string);
        // GeoLite2-ASN style, for completeness.
        if r.asn.is_none() {
            if let Some(n) = d
                .map_get(pos, "autonomous_system_number")
                .and_then(|h| d.uint(h))
            {
                r.asn = Some(format!("AS{n}"));
            }
            r.as_name = r.as_name.or_else(|| {
                d.map_str(pos, "autonomous_system_organization")
                    .map(str::to_string)
            });
        }
        // A two-letter code is all the rest of the server can use.
        if r.country_code.as_deref().is_some_and(|c| c.len() != 2) {
            r.country_code = None;
        }
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny IPv6 database by hand: one IPv4 network 1.2.3.0/24 and
    /// one IPv6 network 2001:db8::/32, record size 24.
    ///
    /// The tree is a straight path per network; every other branch is
    /// "no data" (= node_count).
    fn build_db(record_size: u16) -> Vec<u8> {
        // Data section: record A (IPinfo style) and record B (GeoLite2 style).
        let mut data = Vec::new();
        fn s(out: &mut Vec<u8>, v: &str) {
            assert!(v.len() < 29);
            out.push(0x40 | v.len() as u8);
            out.extend_from_slice(v.as_bytes());
        }
        fn map(out: &mut Vec<u8>, n: u8) {
            out.push(0xE0 | n);
        }
        let rec_a = data.len();
        map(&mut data, 4);
        s(&mut data, "country_code");
        s(&mut data, "it");
        s(&mut data, "country");
        s(&mut data, "Italy");
        s(&mut data, "asn");
        s(&mut data, "AS3269");
        s(&mut data, "as_name");
        // A pointer to the earlier "Italy" string's header, to exercise
        // pointer decoding: the "Italy" value starts after
        // map(1) + "country_code"(13) + "it"(3) + "country"(8) = 25.
        data.push(0x20); // pointer, ss=0, vvv=0
        data.push(25);
        let rec_b = data.len();
        map(&mut data, 1);
        s(&mut data, "country");
        map(&mut data, 2);
        s(&mut data, "iso_code");
        s(&mut data, "DE");
        s(&mut data, "names");
        map(&mut data, 1);
        s(&mut data, "en");
        s(&mut data, "Germany");

        // Tree: path for ::1.2.3.0/24 (96 zeros + 24 bits) and 2001:db8::/32.
        let mut nodes: Vec<[u32; 2]> = Vec::new();
        let paths: Vec<(u128, u32, usize)> = vec![
            (u128::from(0x0102_0300u32), 120, rec_a),
            (0x2001_0db8u128 << 96, 32, rec_b),
        ];
        // Leaves are filled in after node_count is known; mark as usize::MAX.
        let mut leaves: Vec<(usize, u8, usize)> = Vec::new();
        nodes.push([u32::MAX, u32::MAX]);
        for (bits, plen, rec) in paths {
            let mut n = 0usize;
            for i in 0..plen {
                let bit = ((bits >> (127 - i)) & 1) as usize;
                if i == plen - 1 {
                    leaves.push((n, bit as u8, rec));
                    break;
                }
                let next = nodes[n][bit];
                if next == u32::MAX {
                    nodes.push([u32::MAX, u32::MAX]);
                    let id = (nodes.len() - 1) as u32;
                    nodes[n][bit] = id;
                    n = id as usize;
                } else {
                    n = next as usize;
                }
            }
        }
        let nc = nodes.len() as u32;
        for nd in nodes.iter_mut() {
            for r in nd.iter_mut() {
                if *r == u32::MAX {
                    *r = nc;
                }
            }
        }
        for (n, side, rec) in leaves {
            nodes[n][side as usize] = nc + 16 + rec as u32;
        }
        let mut out = Vec::new();
        for nd in &nodes {
            match record_size {
                24 => {
                    out.extend_from_slice(&nd[0].to_be_bytes()[1..]);
                    out.extend_from_slice(&nd[1].to_be_bytes()[1..]);
                }
                28 => {
                    let l = nd[0].to_be_bytes();
                    let r = nd[1].to_be_bytes();
                    out.extend_from_slice(&l[1..]);
                    out.push((l[0] << 4) | (r[0] & 0x0F));
                    out.extend_from_slice(&r[1..]);
                }
                _ => {
                    out.extend_from_slice(&nd[0].to_be_bytes());
                    out.extend_from_slice(&nd[1].to_be_bytes());
                }
            }
        }
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&data);
        out.extend_from_slice(METADATA_MARKER);
        let mut meta = Vec::new();
        map(&mut meta, 4);
        s(&mut meta, "node_count");
        meta.push(0xC4); // uint32, 4 bytes
        meta.extend_from_slice(&nc.to_be_bytes());
        s(&mut meta, "record_size");
        meta.push(0xA2); // uint16, 2 bytes
        meta.extend_from_slice(&record_size.to_be_bytes());
        s(&mut meta, "ip_version");
        meta.push(0xA1);
        meta.push(6);
        s(&mut meta, "database_type");
        s(&mut meta, "test");
        out.extend_from_slice(&meta);
        out
    }

    #[test]
    fn looks_up_v4_and_v6_in_both_layouts_for_every_record_size() {
        for rs in [24u16, 28, 32] {
            let db = Mmdb::from_bytes(build_db(rs)).unwrap();
            assert_eq!(db.database_type, "test");
            let it = db.lookup("1.2.3.200".parse().unwrap()).unwrap();
            assert_eq!(it.country_code.as_deref(), Some("IT"), "rs {rs}");
            assert_eq!(it.country_name.as_deref(), Some("Italy"));
            assert_eq!(it.asn.as_deref(), Some("AS3269"));
            assert_eq!(it.as_name.as_deref(), Some("Italy"), "pointer followed");
            let de = db.lookup("2001:db8::42".parse().unwrap()).unwrap();
            assert_eq!(de.country_code.as_deref(), Some("DE"));
            assert_eq!(de.country_name.as_deref(), Some("Germany"));
            assert_eq!(db.lookup("1.2.4.1".parse().unwrap()), None);
            assert_eq!(db.lookup("2001:db9::1".parse().unwrap()), None);
            // IPv4-mapped IPv6 is looked up as the IPv4 address.
            assert!(db.lookup("::ffff:1.2.3.4".parse().unwrap()).is_some());
        }
    }

    #[test]
    fn rejects_garbage_and_truncation_without_panicking() {
        assert!(Mmdb::from_bytes(Vec::new()).is_err());
        assert!(Mmdb::from_bytes(b"hello".to_vec()).is_err());
        let good = build_db(24);
        // Every truncation either fails to open or answers None — never panics.
        for cut in 0..good.len() {
            if let Ok(db) = Mmdb::from_bytes(good[..cut].to_vec()) {
                let _ = db.lookup("1.2.3.4".parse().unwrap());
                let _ = db.lookup("2001:db8::1".parse().unwrap());
            }
        }
        // A map whose values point back at the map itself: a pointer is
        // skipped by its own bytes, so walking it terminates.
        {
            let mut evil = vec![0xE0 | 28u8];
            for _ in 0..28 {
                evil.extend_from_slice(&[0x41, b'k', 0x20, 0x00]);
            }
            let d = Dec { buf: &evil, budget: Cell::new(DECODE_BUDGET) };
            assert_eq!(d.skip(0, 0), Some(evil.len()));
            assert_eq!(d.map_str(0, "x"), None);
            assert!(d.map_get_pos(0, "k").is_some());
        }
        // Flip every byte of the data section in turn.
        for i in 0..good.len() {
            let mut b = good.clone();
            b[i] ^= 0xFF;
            if let Ok(db) = Mmdb::from_bytes(b) {
                let _ = db.lookup("1.2.3.4".parse().unwrap());
                let _ = db.lookup("2001:db8::1".parse().unwrap());
            }
        }
    }
}
