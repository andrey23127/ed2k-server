//! Delta + LEB128-varint codec for keyword posting lists.
//!
//! A posting list is the set of files that contain a given keyword. Today it is a
//! `Vec<FileId>` — 4 bytes per entry, sorted ascending and deduplicated (see the
//! INVARIANT in `keyword_index`). At 33M files this is the single largest growing
//! consumer (~2 GB of raw `FileId`s plus one heap allocation *per keyword*, whose
//! size-class rounding is itself a big slice of the "unaccounted" heap).
//!
//! Because the list is sorted and dense-ish, storing the **gap** to the previous
//! entry instead of the absolute value, then LEB128-varint-encoding that gap, packs
//! the common case (small gaps) into 1–2 bytes instead of 4. `FileId` is
//! `(shard << 26) | index`, so consecutive allocations in the same shard differ by
//! `64` (round-robin over 64 shards) → the typical gap fits in one byte; a shard
//! rollover produces a larger gap, which varint still handles (up to 5 bytes).
//!
//! This module is deliberately standalone and depends only on `FileId`: it is
//! introduced and unit-tested on its own (Stage 0) *before* being wired into the
//! index, so the encode/decode round-trip can be proven exhaustively off the hot
//! path and with zero risk to the running server.
//!
//! ## Format
//! ```text
//! [count: varint]              number of postings
//! [first: varint]              first FileId, absolute (delta from 0)
//! [gap: varint] * (count - 1)  each subsequent FileId as (this - previous)
//! ```
//! An empty list encodes to a single byte (`count = 0`). Gaps are always ≥ 1
//! because the input is strictly ascending (deduplicated), but the decoder does not
//! rely on that — it simply accumulates, so a malformed/duplicated input would
//! round-trip rather than corrupt neighbouring data.

use crate::state::file_id::FileId;

/// Append `v` to `out` as an unsigned LEB128 varint (7 bits per byte, MSB = continue).
#[inline]
fn write_varint(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
}

/// Read one unsigned LEB128 varint from `data[*pos..]`, advancing `*pos`.
///
/// Returns `None` on truncation or on an overlong encoding that would overflow u32
/// (more than 5 bytes, or a 5th byte with bits above the 32-bit range). Being strict
/// here means a corrupt blob is rejected outright instead of yielding a wrong value.
#[inline]
fn read_varint(data: &[u8], pos: &mut usize) -> Option<u32> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        if shift >= 32 {
            return None; // more than 5 bytes → overflow
        }
        let payload = (byte & 0x7F) as u32;
        // On the 5th byte only the low 4 bits are valid (28 bits already consumed).
        if shift == 28 && (byte & 0x7F) > 0x0F {
            return None;
        }
        result |= payload << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
}

/// Encode a **sorted, deduplicated** slice of `FileId` into a delta-varint blob.
///
/// The caller guarantees ascending order (the index maintains it as an invariant);
/// if that is violated the output is still self-consistent (it round-trips), it just
/// stops being space-optimal. Never panics.
pub fn encode(ids: &[FileId]) -> Vec<u8> {
    // Heuristic reserve: most gaps are 1 byte, first value up to 5, count up to 5.
    let mut out = Vec::with_capacity(ids.len() + 8);
    write_varint(&mut out, ids.len() as u32);
    let mut prev: u32 = 0;
    for id in ids {
        let cur = id.0;
        // Wrapping keeps us panic-free even if the input is not ascending; for valid
        // (ascending) input `cur >= prev` so this is the true gap.
        write_varint(&mut out, cur.wrapping_sub(prev));
        prev = cur;
    }
    out
}

/// Decode a blob produced by [`encode`] back into a `Vec<FileId>`.
///
/// Returns `None` if the blob is truncated, has a varint overflow, or does not
/// contain exactly `count` postings — i.e. any corruption is detected rather than
/// silently returning a partial/wrong list.
pub fn decode(data: &[u8]) -> Option<Vec<FileId>> {
    let mut pos = 0usize;
    let count = read_varint(data, &mut pos)? as usize;
    let mut out = Vec::with_capacity(count);
    let mut acc: u32 = 0;
    for _ in 0..count {
        let gap = read_varint(data, &mut pos)?;
        acc = acc.wrapping_add(gap);
        out.push(FileId(acc));
    }
    // Reject trailing garbage: a well-formed blob is consumed exactly.
    if pos != data.len() {
        return None;
    }
    Some(out)
}

/// Number of postings in a blob without materialising the `Vec` (reads only the
/// leading count varint). Useful for stats / cheap length checks.
pub fn decoded_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    read_varint(data, &mut pos).map(|c| c as usize)
}

/// Streaming reader over an encoded posting blob.
///
/// Stage 2 makes the compressed blob the ONLY store, so intersection can no longer
/// binary-search a `Vec`. Fully decoding every non-seed posting on every search
/// would allocate and defeat the memory win. Instead we walk the blob's monotonic
/// deltas in place: the cursor exposes the current ascending `FileId` via `peek()`
/// and advances with `bump()`, allocation-free. Because both the cursor and the
/// query's result set are ascending, [`PostingCursor::contains`] never rewinds, so
/// intersecting an M-element result against an N-element posting is O(M + N) total.
pub struct PostingCursor<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: usize,
    acc: u32,
    /// Current head value (already accumulated), or None before the first bump / at
    /// end. `started` disambiguates "haven't read yet" from "exhausted".
    cur: Option<FileId>,
    started: bool,
}

impl<'a> PostingCursor<'a> {
    /// Create a cursor over `data`, priming the first element. Returns `None` if the
    /// header count varint is malformed.
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let mut pos = 0usize;
        let count = read_varint(data, &mut pos)? as usize;
        let mut c = Self { data, pos, remaining: count, acc: 0, cur: None, started: false };
        c.bump();
        Some(c)
    }

    /// Postings not yet consumed (including the current head).
    #[inline]
    pub fn len(&self) -> usize {
        self.remaining + if self.cur.is_some() { 1 } else { 0 }
    }

    /// The current head value without consuming it.
    #[inline]
    pub fn peek(&self) -> Option<FileId> { self.cur }

    /// Advance to the next value, updating `peek()`. Sets head to None at end or on a
    /// malformed tail.
    #[inline]
    pub fn bump(&mut self) {
        self.started = true;
        if self.remaining == 0 {
            self.cur = None;
            return;
        }
        match read_varint(self.data, &mut self.pos) {
            Some(gap) => {
                self.acc = self.acc.wrapping_add(gap);
                self.remaining -= 1;
                self.cur = Some(FileId(self.acc));
            }
            None => {
                self.remaining = 0;
                self.cur = None;
            }
        }
    }

    /// Advance until head >= `target`; return true iff head == target.
    ///
    /// Query results are ascending, so successive targets only move the cursor
    /// forward — never back — giving amortised O(1) per membership test across a
    /// whole intersection pass.
    #[inline]
    pub fn contains(&mut self, target: FileId) -> bool {
        while let Some(head) = self.cur {
            if head.0 < target.0 {
                self.bump();
            } else {
                return head.0 == target.0;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[u32]) -> Vec<FileId> {
        v.iter().copied().map(FileId).collect()
    }

    /// Encode then decode must reproduce the input exactly.
    fn round_trip(v: &[u32]) {
        let input = ids(v);
        let blob = encode(&input);
        let out = decode(&blob).expect("decode failed");
        assert_eq!(out, input, "round-trip mismatch for {:?}", v);
        assert_eq!(decoded_len(&blob), Some(v.len()));
    }

    #[test]
    fn empty() {
        round_trip(&[]);
        // An empty list is a single byte (count = 0).
        assert_eq!(encode(&[]).len(), 1);
    }

    #[test]
    fn single() {
        round_trip(&[0]);
        round_trip(&[1]);
        round_trip(&[127]);
        round_trip(&[128]);
        round_trip(&[u32::MAX]);
    }

    #[test]
    fn small_dense_gaps() {
        // The common case: same-shard round-robin allocation → gaps of 64.
        round_trip(&[64, 128, 192, 256, 320]);
        round_trip(&[1, 2, 3, 4, 5]);
    }

    #[test]
    fn shard_rollover_large_gaps() {
        // FileId = (shard << 26) | index. Crossing shards produces multi-MB gaps.
        let a = (0u32 << 26) | 5;
        let b = (1u32 << 26) | 5; // +67M
        let c = (63u32 << 26) | 9;
        round_trip(&[a, b, c]);
    }

    #[test]
    fn boundary_values() {
        // Values straddling every varint width boundary.
        round_trip(&[0x7F, 0x80, 0x3FFF, 0x4000, 0x1F_FFFF, 0x20_0000, 0x0FFF_FFFF, 0x1000_0000]);
    }

    #[test]
    fn max_span() {
        // First tiny, last = u32::MAX → the final gap is nearly the whole range.
        round_trip(&[0, u32::MAX]);
        round_trip(&[1, u32::MAX - 1, u32::MAX]);
    }

    #[test]
    fn large_realistic_list() {
        // ~50k postings with realistic same-shard stride plus occasional jumps.
        let mut v = Vec::new();
        let mut cur = 64u32;
        for i in 0..50_000u32 {
            cur = cur.wrapping_add(64);
            if i % 500 == 0 {
                cur = cur.wrapping_add(1u32 << 26); // shard hop
            }
            v.push(cur);
        }
        v.sort_unstable();
        v.dedup();
        round_trip(&v);
    }

    #[test]
    fn full_shard_dense() {
        // A keyword present in every file of one shard: indices 0..N contiguous.
        let v: Vec<u32> = (0..10_000u32).map(|i| (7u32 << 26) | i).collect();
        round_trip(&v);
        // Dense +1 gaps must pack to ~1 byte each (plus count + first).
        let blob = encode(&ids(&v));
        assert!(blob.len() < v.len() * 2, "dense list should be ~1 byte/entry");
    }

    // ----- corruption / robustness -----

    #[test]
    fn truncated_blob_rejected() {
        let blob = encode(&ids(&[64, 128, 192]));
        for cut in 0..blob.len() {
            // Any prefix shorter than the whole thing must not decode successfully
            // (it is either truncated mid-varint or missing postings).
            assert!(decode(&blob[..cut]).is_none(), "prefix len {cut} decoded", );
        }
    }

    #[test]
    fn trailing_garbage_rejected() {
        let mut blob = encode(&ids(&[1, 2, 3]));
        blob.push(0x00);
        assert!(decode(&blob).is_none(), "trailing byte must be rejected");
    }

    #[test]
    fn overlong_varint_rejected() {
        // Six 0x80 continuation bytes then 0 → overflow, must be rejected not wrapped.
        let bad = [0x01u8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
        assert!(decode(&bad).is_none());
    }

    #[test]
    fn empty_input_slice_rejected() {
        // Zero bytes isn't even a valid count.
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn varint_width_is_minimal() {
        // Spot-check the encoded width of the first value.
        assert_eq!(encode(&ids(&[0]))[1..].len(), 1); // count byte + 1 for value 0
        assert_eq!(encode(&ids(&[127]))[1..].len(), 1);
        assert_eq!(encode(&ids(&[128]))[1..].len(), 2);
        assert_eq!(encode(&ids(&[16383]))[1..].len(), 2);
        assert_eq!(encode(&ids(&[16384]))[1..].len(), 3);
    }

    #[test]
    fn cursor_iterates_in_order() {
        let v = ids(&[64, 128, 4096, (5u32 << 26) | 3, u32::MAX]);
        let blob = encode(&v);
        let mut cur = PostingCursor::new(&blob).unwrap();
        let mut got = Vec::new();
        while let Some(id) = cur.peek() {
            got.push(id);
            cur.bump();
        }
        assert_eq!(got, v);
    }

    #[test]
    fn cursor_contains_matches_binary_search() {
        // Cursor.contains over ascending targets must equal Vec::binary_search.
        let v = ids(&[10, 64, 65, 200, 1000, 1_000_000, (9u32 << 26) | 1]);
        let blob = encode(&v);
        let mut cur = PostingCursor::new(&blob).unwrap();
        let targets = ids(&[9, 10, 11, 64, 66, 200, 999, 1000, 1_000_001, (9u32 << 26) | 1]);
        for t in &targets {
            let expected = v.binary_search(t).is_ok();
            assert_eq!(cur.contains(*t), expected, "contains mismatch for {}", t.0);
        }
    }

    #[test]
    fn cursor_empty() {
        let blob = encode(&[]);
        let mut cur = PostingCursor::new(&blob).unwrap();
        assert!(cur.peek().is_none());
        assert!(!cur.contains(FileId(0)));
        assert_eq!(cur.len(), 0);
    }

    #[test]
    fn cursor_intersection_equivalence() {
        // Full intersection via cursors must equal the naive set intersection.
        let a = ids(&[1, 2, 3, 5, 8, 13, 21, 34, 55]);
        let b = ids(&[2, 3, 5, 7, 11, 13, 17, 34]);
        let blob_b = encode(&b);
        let mut cur = PostingCursor::new(&blob_b).unwrap();
        let got: Vec<FileId> = a.iter().copied().filter(|x| cur.contains(*x)).collect();
        let want: Vec<FileId> = a.iter().copied().filter(|x| b.binary_search(x).is_ok()).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn pseudo_random_fuzz() {
        // Deterministic LCG — no rand dependency. Many random ascending lists.
        let mut seed: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        for _ in 0..2000 {
            let n = (next() % 300) as usize;
            let mut v: Vec<u32> = (0..n).map(|_| next()).collect();
            v.sort_unstable();
            v.dedup();
            round_trip(&v);
        }
    }
}
