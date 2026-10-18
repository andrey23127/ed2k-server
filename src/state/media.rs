//! Media metadata of indexed files: length, bitrate and codec.
//!
//! Lugdunum keeps the same three in its file record (`f__length`, a 29-bit
//! `f__bitrate`, and `f__codec`, a one-byte index into a 255-entry codec
//! table). Here they live in a side table per slab shard, keyed by the slot,
//! because only about one offered file in seven carries any of them (measured
//! on the live server, 2026-10-18: 13.7% of 18.6M offers): a field in every
//! record would cost the other six files for nothing.
//!
//! Artist, album and title (0xD0-0xD2) are not kept, as in Lugdunum: 0.6% of
//! offers carry them, and a search on them is matched against the file name.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Length, bitrate and codec packed in one u64:
/// bits 0-26 length (seconds, up to ~4 years), 27-55 bitrate (29 bits, as
/// Lugdunum), 56-63 codec index (0 = none).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Media(u64);

impl Media {
    const LEN_BITS: u32 = 27;
    const RATE_BITS: u32 = 29;
    const LEN_MAX: u32 = (1 << Self::LEN_BITS) - 1;
    const RATE_MAX: u32 = (1 << Self::RATE_BITS) - 1;

    pub fn new(length: u32, bitrate: u32, codec: u8) -> Self {
        let l = length.min(Self::LEN_MAX) as u64;
        let r = bitrate.min(Self::RATE_MAX) as u64;
        Media(l | (r << Self::LEN_BITS) | ((codec as u64) << (Self::LEN_BITS + Self::RATE_BITS)))
    }
    pub fn length(self) -> u32 {
        (self.0 & Self::LEN_MAX as u64) as u32
    }
    pub fn bitrate(self) -> u32 {
        ((self.0 >> Self::LEN_BITS) & Self::RATE_MAX as u64) as u32
    }
    pub fn codec(self) -> u8 {
        (self.0 >> (Self::LEN_BITS + Self::RATE_BITS)) as u8
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    /// Fill the fields this one lacks from `other`, keeping the ones it has:
    /// what Lugdunum does when a known file is offered again.
    pub fn merged(self, other: Media) -> Media {
        let pick = |a: u32, b: u32| if a != 0 { a } else { b };
        let codec = if self.codec() != 0 { self.codec() } else { other.codec() };
        Media::new(
            pick(self.length(), other.length()),
            pick(self.bitrate(), other.bitrate()),
            codec,
        )
    }
}

/// A slot index is already well spread; this only has to be cheap.
#[derive(Default, Clone, Copy)]
pub struct SlotHasher(u64);

impl std::hash::Hasher for SlotHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0.rotate_left(8) ^ *b as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
    }
    fn write_u32(&mut self, n: u32) {
        self.0 = (n as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

pub type SlotMap = HashMap<u32, Media, std::hash::BuildHasherDefault<SlotHasher>>;

/// Bytes a `SlotMap` holds: its slots (key + value) and one control byte each.
pub fn slot_map_bytes(m: &SlotMap) -> u64 {
    m.capacity() as u64 * (std::mem::size_of::<(u32, Media)>() as u64 + 1)
}

/// Codec names, interned to a one-byte index (1..=255; 0 = none).
///
/// Normalised as Lugdunum does: ASCII lowercase, at most 19 bytes, printable
/// ASCII only (anything else is not stored). Once 255 names are known a new
/// one is not stored either. The live server saw 129 distinct names in 18.6M
/// offers, so the cap is not close.
#[derive(Default)]
pub struct CodecTable {
    inner: RwLock<CodecInner>,
}

#[derive(Default)]
struct CodecInner {
    index: HashMap<Arc<str>, u8>,
    /// names[i - 1] is the name of index i.
    names: Vec<Arc<str>>,
}

impl CodecTable {
    pub const MAX: usize = 255;
    pub const MAX_LEN: usize = 19;

    /// The stored form of a codec string, or None if it cannot be stored.
    pub fn normalise(s: &str) -> Option<String> {
        let t = s.trim();
        if t.is_empty() || !t.bytes().all(|b| (0x20..0x7F).contains(&b)) {
            return None;
        }
        Some(t.to_ascii_lowercase().chars().take(Self::MAX_LEN).collect())
    }

    /// The index of an already normalised name, interning it if new. 0 when
    /// the table is full.
    pub fn intern(&self, name: &str) -> u8 {
        if let Some(&i) = self.inner.read().unwrap_or_else(|e| e.into_inner()).index.get(name) {
            return i;
        }
        let mut w = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if let Some(&i) = w.index.get(name) {
            return i;
        }
        if w.names.len() >= Self::MAX {
            return 0;
        }
        let a: Arc<str> = Arc::from(name);
        w.names.push(a.clone());
        let i = w.names.len() as u8;
        w.index.insert(a, i);
        i
    }

    /// The index of a name a search asks for, without interning; None when
    /// no file was ever offered with it.
    pub fn lookup(&self, raw: &str) -> Option<u8> {
        let n = Self::normalise(raw)?;
        self.inner.read().unwrap_or_else(|e| e.into_inner()).index.get(n.as_str()).copied()
    }

    pub fn name(&self, i: u8) -> Option<Arc<str>> {
        if i == 0 {
            return None;
        }
        self.inner.read().unwrap_or_else(|e| e.into_inner()).names.get(i as usize - 1).cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parse a length given as text, as eMule's old "length" tag carries it:
/// "h:m:s", "m:s" or plain seconds. Anything else is 0, as in Lugdunum.
pub fn parse_length_text(s: &str) -> u32 {
    let mut total: u64 = 0;
    let mut cur: u64 = 0;
    for c in s.trim().chars() {
        match c {
            '0'..='9' => cur = (cur * 10 + c as u64 - '0' as u64).min(u32::MAX as u64),
            ':' => {
                total = (total + cur) * 60;
                cur = 0;
            }
            _ => return 0,
        }
    }
    (total + cur).min(u32::MAX as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packing_round_trips_and_saturates() {
        let m = Media::new(5400, 1200, 7);
        assert_eq!((m.length(), m.bitrate(), m.codec()), (5400, 1200, 7));
        let big = Media::new(u32::MAX, u32::MAX, 255);
        assert_eq!(big.length(), (1 << 27) - 1);
        assert_eq!(big.bitrate(), (1 << 29) - 1);
        assert_eq!(big.codec(), 255);
        assert!(Media::default().is_empty());
    }

    #[test]
    fn a_reoffer_fills_only_the_missing_fields() {
        let have = Media::new(0, 1200, 0);
        let m = have.merged(Media::new(5400, 999, 3));
        assert_eq!((m.length(), m.bitrate(), m.codec()), (5400, 1200, 3));
    }

    #[test]
    fn codecs_are_normalised_and_interned() {
        let t = CodecTable::default();
        let n = CodecTable::normalise(" H264 ").unwrap();
        assert_eq!(n, "h264");
        let i = t.intern(&n);
        assert_eq!(i, 1);
        assert_eq!(t.intern("h264"), 1);
        assert_eq!(t.lookup("h264"), Some(1));
        assert_eq!(t.lookup("H264"), Some(1));
        assert_eq!(t.lookup("xvid"), None);
        assert_eq!(t.name(1).as_deref(), Some("h264"));
        assert_eq!(CodecTable::normalise("aac lc (advanced audio)").unwrap(), "aac lc (advanced au");
        assert_eq!(CodecTable::normalise("кодек"), None);
        for k in 0..300 {
            t.intern(&format!("c{k}"));
        }
        assert_eq!(t.len(), CodecTable::MAX);
        assert_eq!(t.intern("one more"), 0);
    }

    #[test]
    fn text_lengths_parse_like_lugdunum() {
        assert_eq!(parse_length_text("1:30:00"), 5400);
        assert_eq!(parse_length_text("3:05"), 185);
        assert_eq!(parse_length_text("42"), 42);
        assert_eq!(parse_length_text("-1"), 0);
        assert_eq!(parse_length_text("abc"), 0);
    }
}
