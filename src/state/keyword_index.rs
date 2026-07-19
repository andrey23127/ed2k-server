//! Keyword inverted index.
//!
//! Maps lowercase tokens to file hashes for SEARCHREQUEST lookup.

use crate::state::file_id::FileId;
use crate::state::posting_codec;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// 32-bit token hash type. Keywords are stored by the FNV-1a hash of the
/// lowercase token, NOT the token string itself (the Lugdunum approach). This
/// removes all keyword-string memory (~0.7 GB at 30M files). Hash collisions
/// map two distinct words to one posting bucket, producing occasional
/// false-positive *candidates* — these are harmless because both search paths
/// (search.rs, udp.rs) re-check every candidate's real filename with
/// `evaluate(tree, name, size)` before returning it, so a word that isn't
/// actually in the name is filtered out.
pub type TokenHash = u32;

/// FNV-1a 32-bit. Chosen over std's DefaultHasher because it is:
///  - deterministic across runs/processes (std SipHash is randomly seeded),
///    which matters: the keyword index is rebuilt from filenames on restore,
///    and a stable hash keeps behavior identical run-to-run;
///  - fast and allocation-free on short ASCII tokens.
#[inline]
pub fn token_hash(token: &str) -> TokenHash {
    let mut h: u32 = 0x811c_9dc5; // FNV offset basis
    for b in token.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193); // FNV prime
    }
    h
}

/// Minimum token length to index. 2 chars covers "HD", "UK", "OS" etc.
const MIN_KEYWORD_LEN: usize = 2;

/// Stop-words that are so common they add no selectivity.
/// NOTE: do NOT include file extensions (mp3, avi, mkv…) — users actively
/// search for them and eMule's type filter sends them as tokens.
const COMMON_WORDS_SKIP: &[&str] = &[
    "the", "and", "for", "with", "from", "this", "that",
    "web", "www", "com", "net", "org",
];

/// Word-boundary characters used by the tokenizer.
fn is_separator(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '_' | '-' | '.' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
                | '!' | '?' | '@' | '#' | '$' | '%' | '^' | '&' | '*'
                | '+' | '=' | '/' | '\\' | '|' | '<' | '>' | '"' | '\''
                | '`' | '~'
        )
}

/// Tokenize a filename into indexable keywords. Returns owned Strings; callers
/// that just want to iterate without keeping the Vec should use
/// [`tokenize_into`] for a callback-based variant.
///
/// Performance: filenames in eD2k traffic are predominantly ASCII (Roman
/// alphabet + digits + punctuation). For ASCII-only filenames we avoid
/// Unicode case mapping (saves ~3% CPU at scale per v0.9.37 profile).
pub fn tokenize(filename: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(8);
    tokenize_into(filename, |t| out.push(t.to_string()));
    out
}

/// Visit each indexable lowercase token in `filename`. The token is borrowed
/// from a working buffer and remains valid only for the duration of the
/// callback. This avoids the per-token `String` allocation that
/// `tokenize` does — used by [`KeywordIndex::add_file`] and `remove_file`.
fn tokenize_into<F: FnMut(&str)>(filename: &str, mut visit: F) {
    // Fast ASCII path: lowercase once into a single buffer, then split.
    // Falls back to per-token Unicode lowercase if non-ASCII is present.
    if filename.is_ascii() {
        let mut buf: String = String::with_capacity(filename.len());
        buf.push_str(filename);
        // Safe because we just verified ASCII; make_ascii_lowercase is in-place.
        buf.make_ascii_lowercase();
        for tok in buf.split(is_separator) {
            if tok.len() < MIN_KEYWORD_LEN { continue; }
            if COMMON_WORDS_SKIP.contains(&tok) { continue; }
            visit(tok);
        }
    } else {
        // Mixed / non-ASCII: do Unicode-aware lowercase per token.
        for raw in filename.split(is_separator) {
            if raw.len() < MIN_KEYWORD_LEN { continue; }
            let lc = raw.to_lowercase();
            if COMMON_WORDS_SKIP.contains(&lc.as_str()) { continue; }
            visit(&lc);
        }
    }
}

/// Inverted index: token-hash -> SORTED, DEDUPED list of FileIds.
///
/// Key is a 32-bit FNV-1a hash of the lowercase token (see `token_hash`), not
/// the token string — this is the Lugdunum memory optimization (no keyword
/// strings stored). Postings are sorted+deduped `Vec<FileId>` (lever B): 4 bytes per
/// entry instead of the 16-byte hash — the core Stage-1 memory saving.
/// INVARIANT: every Vec is sorted ascending and contains no duplicates.
/// STAGE 2: the posting lists are stored ONLY in delta-varint form.
///
/// Each keyword maps to a compressed blob (see `posting_codec`) instead of a
/// `Vec<FileId>`. Reads walk the blob with a zero-alloc `PostingCursor`; the raw
/// `Vec<FileId>` and the Stage-1 shadow store are both gone. This is where the
/// memory win lands — no 4-bytes-per-entry Vec, no per-keyword Vec header slack,
/// and the blob is 1–4x smaller than the raw list on long postings.
///
/// Trade-off carried over from Stage 1: a single add/remove still
/// decodes → edits → re-encodes the whole blob, so publish-heavy load costs CPU.
/// That is addressed in Stage 3 (a small uncompressed "hot" tier merged into the
/// blob in `compact()`), deliberately kept as a separate, separately-tested step.
/// STAGE 3: two-tier storage — a small uncompressed "hot" tier absorbs writes,
/// a compressed "cold" tier holds the bulk.
///
/// Stage 2 stored everything compressed, but a single add/remove had to
/// decode → edit → re-encode the WHOLE blob. For a hot keyword present in hundreds
/// of thousands of files, every publish re-encoded that whole posting — quadratic
/// under publish load (measured: CPU jumped from ~3% to ~21%).
///
/// Stage 3 splits the store:
/// * `hot`  — recent, un-merged postings as plain `Vec<FileId>`. Writes land here,
///   so add/remove is a cheap sorted-Vec op again, independent of the cold size.
/// * `cold` — the compressed blobs, rebuilt in bulk only by `compact()` (every
///   ~10 min, off the hot path), which drains `hot` into `cold`.
///
/// A keyword's true posting is `merge(cold[k], hot[k])`. Reads merge the two tiers;
/// `hot` is small (only what accumulated since the last compact), so the merge is
/// cheap. Memory: `cold` keeps the Stage-2 savings; `hot` is bounded by the write
/// volume between compactions.
#[derive(Default)]
pub struct KeywordIndex {
    /// Compressed, ascending, deduped posting blobs (the bulk of the index).
    ///
    /// Stored as `Box<[u8]>` (ptr+len, 16 B) rather than `Vec<u8>` (ptr+len+cap,
    /// 24 B): a cold blob is rebuilt whole by `compact()` and never grown in place,
    /// so the spare-capacity field a `Vec` carries is pure waste — 8 B per keyword
    /// (~7.6 MB now, ~180 MB projected at 33M keys).
    cold: DashMap<TokenHash, Box<[u8]>>,
    /// Recent additions not yet merged into `cold`, as plain sorted+deduped Vecs.
    hot: DashMap<TokenHash, Vec<FileId>>,
    /// Deletions not yet applied to `cold`, as plain sorted+deduped Vecs.
    ///
    /// Symmetric to `hot`. Applying a removal directly to the cold tier means
    /// decode + re-encode of the whole blob per deleted file per token; profiling
    /// showed that `posting_codec::encode` was ~24% of process CPU, essentially all
    /// of it from `remove_file` (client disconnects and orphan eviction delete far
    /// more than "rare"). Marking here is O(log n) on a small Vec, and `compact()`
    /// applies the whole batch in the same single decode+encode per key it already
    /// does for `hot`.
    ///
    /// INVARIANT: `pending_removals[k]` and `hot[k]` are disjoint — `add_file`
    /// clears an id from pending when it re-adds it, so a delete-then-re-add
    /// sequence cannot resurrect the deletion at compact time.
    pending_removals: DashMap<TokenHash, Vec<FileId>>,
}

impl KeywordIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Index a file by filename. Idempotent — re-adding the same id under a token
    /// is a no-op (it is already in the decoded list).
    pub fn add_file(&self, id: FileId, filename: &str) {
        tokenize_into(filename, |token| {
            let th = token_hash(token);
            // Cheap: insert into the small hot Vec. No cold decode/encode — the cost
            // is O(hot posting) regardless of how large the cold posting is. If the
            // id is already in cold it will be deduped when hot merges in compact()
            // (and a transient duplicate across tiers is removed by the read merge).
            let mut v = self.hot.entry(th).or_default();
            if let Err(pos) = v.binary_search(&id) {
                v.insert(pos, id);
            }
            drop(v);
            // Re-add cancels a not-yet-applied delete, keeping hot/pending disjoint.
            if let Some(mut pend) = self.pending_removals.get_mut(&th) {
                if let Ok(pos) = pend.binary_search(&id) {
                    pend.remove(pos);
                }
            }
        });
    }

    /// Remove a file from all its postings (file eviction / source removal).
    pub fn remove_file(&self, id: FileId, filename: &str) {
        tokenize_into(filename, |token| {
            let th = token_hash(token);
            // Remove from the hot tier if present (cheap).
            if let Some(mut v) = self.hot.get_mut(&th) {
                if let Ok(pos) = v.binary_search(&id) {
                    v.remove(pos);
                }
            }
            // For the cold tier, only MARK the deletion — do not touch the blob.
            // compact() applies the batch. Reads subtract pending, so the file stops
            // being returned immediately even though the blob still contains it.
            // Only worth marking if the key actually has a cold blob.
            if self.cold.contains_key(&th) {
                let mut pend = self.pending_removals.entry(th).or_default();
                if let Err(pos) = pend.binary_search(&id) {
                    pend.insert(pos, id);
                }
            }
        });
    }

    /// Materialise a keyword's full posting = merge(cold blob, hot Vec).
    ///
    /// Both tiers are sorted+deduped; the merge is a linear two-pointer pass that
    /// drops the cross-tier duplicate (an id added to `hot` that is also still in
    /// `cold`). Returns an owned ascending, deduped Vec. `None` iff the keyword is
    /// absent from BOTH tiers.
    fn materialize(&self, th: TokenHash) -> Option<Vec<FileId>> {
        let out = self.materialize_raw(th)?;
        // Subtract not-yet-applied deletions. hot and pending are disjoint, so this
        // only drops ids still physically present in the cold blob.
        match self.pending_removals.get(&th) {
            Some(pend) if !pend.is_empty() => {
                let p = pend.value();
                Some(out.into_iter().filter(|id| p.binary_search(id).is_err()).collect())
            }
            _ => Some(out),
        }
    }

    /// merge(cold, hot) WITHOUT applying pending removals.
    fn materialize_raw(&self, th: TokenHash) -> Option<Vec<FileId>> {
        let cold = self.cold.get(&th);
        let hot = self.hot.get(&th);
        match (cold, hot) {
            (None, None) => None,
            (Some(c), None) => posting_codec::decode(c.value()),
            (None, Some(h)) => Some(h.value().clone()),
            (Some(c), Some(h)) => {
                let cv = posting_codec::decode(c.value())?;
                let hv = h.value();
                let mut out = Vec::with_capacity(cv.len() + hv.len());
                let (mut i, mut j) = (0usize, 0usize);
                while i < cv.len() && j < hv.len() {
                    match cv[i].0.cmp(&hv[j].0) {
                        std::cmp::Ordering::Less => { out.push(cv[i]); i += 1; }
                        std::cmp::Ordering::Greater => { out.push(hv[j]); j += 1; }
                        std::cmp::Ordering::Equal => { out.push(cv[i]); i += 1; j += 1; }
                    }
                }
                out.extend_from_slice(&cv[i..]);
                out.extend_from_slice(&hv[j..]);
                Some(out)
            }
        }
    }

    /// Posting length across both tiers WITHOUT fully decoding cold — good enough
    /// for rarest-seed selection. Overcounts by at most the cross-tier duplicates,
    /// which is fine for a heuristic.
    fn approx_len(&self, th: TokenHash) -> usize {
        let cold = self
            .cold
            .get(&th)
            .and_then(|c| posting_codec::decoded_len(c.value()))
            .unwrap_or(0);
        let hot = self.hot.get(&th).map(|h| h.value().len()).unwrap_or(0);
        let pending = self
            .pending_removals
            .get(&th)
            .map(|p| p.value().len())
            .unwrap_or(0);
        (cold + hot).saturating_sub(pending)
    }

    /// Look up file ids that have ALL of the given tokens.
    ///
    /// Two-tier aware: the seed posting is materialised (cold+hot merged), then each
    /// other token is materialised and intersected. Result is ascending. Token
    /// hashing + collision behaviour unchanged (collisions add false positives that
    /// the caller's filename re-check discards).
    pub fn find_intersection(&self, tokens: &[String]) -> Vec<FileId> {
        if tokens.is_empty() {
            return Vec::new();
        }
        let hashes: Vec<TokenHash> = tokens.iter().map(|t| token_hash(t)).collect();

        // Rarest seed by approximate combined length.
        let seed_idx = hashes
            .iter()
            .enumerate()
            .min_by_key(|(_, h)| {
                let n = self.approx_len(**h);
                if n == 0 { usize::MAX } else { n }
            })
            .map(|(i, _)| i)
            .unwrap_or(0);

        let mut result = match self.materialize(hashes[seed_idx]) {
            Some(v) if !v.is_empty() => v,
            _ => return Vec::new(),
        };

        // Intersect against each other token WITHOUT materialising its full posting.
        //
        // `result` is ascending (the seed was sorted). For each other token we hold
        // its cold blob and hot Vec and test membership per result element: the cold
        // side via a monotonic `PostingCursor` (no allocation, no full decode into a
        // Vec), the hot side via binary_search. Because `retain` visits `result` in
        // ascending order, the cursor only moves forward — so a common word like
        // "the" (a huge posting) is never decoded into a multi-MB Vec on every
        // search; we stream past it once. (Stage 3 regressed this to a full
        // materialize per token; this restores the streaming intersection.)
        for (i, h) in hashes.iter().enumerate() {
            if i == seed_idx {
                continue;
            }
            let cold_ref = self.cold.get(h);
            let hot_ref = self.hot.get(h);
            if cold_ref.is_none() && hot_ref.is_none() {
                return Vec::new(); // token absent entirely → empty intersection
            }
            // Deletions not yet applied to the cold blob: an id found by the cursor
            // that is listed here must be treated as absent.
            let pend_ref = self.pending_removals.get(h);
            // Cursor over the cold blob (if any and well-formed).
            let mut cursor = match &cold_ref {
                Some(c) => posting_codec::PostingCursor::new(c.value()),
                None => None,
            };
            result.retain(|fh| {
                let in_cold = match cursor.as_mut() {
                    Some(cur) => cur.contains(*fh),
                    None => false,
                };
                if in_cold {
                    // Still in the blob, but scheduled for deletion → not a match.
                    let deleted = match &pend_ref {
                        Some(p) => p.value().binary_search(fh).is_ok(),
                        None => false,
                    };
                    if !deleted {
                        return true;
                    }
                }
                match &hot_ref {
                    Some(h) => h.value().binary_search(fh).is_ok(),
                    None => false,
                }
            });
            if result.is_empty() {
                break;
            }
        }
        result
    }

    /// Number of distinct keywords in the index (union of both tiers).
    pub fn keyword_count(&self) -> usize {
        // Most hot keys also exist in cold after the first compact; this can slightly
        // overcount keys added since the last compact. Good enough for a stat.
        self.cold.len().max(self.hot.len())
    }

    /// Diagnostic: (keyword keys, total postings across all lists). The second
    /// number reads each blob's count header only (no full decode). Off hot path.
    pub fn posting_stats(&self) -> (u64, u64) {
        let mut total: u64 = 0;
        for e in self.cold.iter() {
            total += posting_codec::decoded_len(e.value()).unwrap_or(0) as u64;
        }
        for e in self.hot.iter() {
            total += e.value().len() as u64;
        }
        (self.cold.len().max(self.hot.len()) as u64, total)
    }

    /// (cold_keys, hot_keys, pending_removal_keys) — the deferred-tier split, for /api/memsize observability.
    /// Lets us confirm the cold tier is the compressed Box<[u8]> store and see how
    /// much sits un-merged in hot between compactions.
    pub fn tier_sizes(&self) -> (usize, usize, usize) {
        (self.cold.len(), self.hot.len(), self.pending_removals.len())
    }

    /// Byte-level breakdown for /api/memsize. Returns
    /// (blob_data_bytes, blob_vec_headers_bytes, key_slots_bytes).
    ///
    /// - `blob_data_bytes`: the encoded posting blobs, by capacity.
    /// - `blob_vec_headers_bytes`: the `Vec<u8>` header (ptr+len+cap) per keyword.
    /// - `key_slots_bytes`: hashbrown table slots (key + value + 1 ctrl), by the
    ///   map's capacity — the power-of-two/never-shrink-on-retain cost.
    pub fn size_report(&self) -> (u64, u64, u64) {
        let blob_hdr = std::mem::size_of::<Box<[u8]>>() as u64;
        let idvec_hdr = std::mem::size_of::<Vec<FileId>>() as u64;
        let id_sz = std::mem::size_of::<FileId>() as u64;
        let key_sz = std::mem::size_of::<TokenHash>() as u64;

        // data = compressed cold blobs (exact-sized) + raw hot Vecs (un-merged tier)
        let mut data = 0u64;
        for e in self.cold.iter() {
            data += e.value().len() as u64;
        }
        for e in self.hot.iter() {
            data += e.value().capacity() as u64 * id_sz;
        }
        for e in self.pending_removals.iter() {
            data += e.value().capacity() as u64 * id_sz;
        }
        // headers = one Vec header per cold key + one per hot key
        let headers = self.cold.len() as u64 * blob_hdr
            + (self.hot.len() + self.pending_removals.len()) as u64 * idvec_hdr;
        // slots = both maps' table capacity
        let slots = self.cold.capacity() as u64 * (key_sz + blob_hdr + 1)
            + (self.hot.capacity() + self.pending_removals.capacity()) as u64
                * (key_sz + idvec_hdr + 1);

        (data, headers, slots)
    }

    /// Reclaim memory after churn: shrink each blob's backing buffer to its length
    /// and drop keywords whose posting became empty. Called periodically from the
    /// cleanup task, never on the hot path. Returns empty entries removed.
    ///
    /// An empty posting encodes to a single `count=0` byte, so "empty" means the
    /// blob decodes to length 0.
    pub fn compact(&self) -> usize {
        // Drain BOTH deferred tiers into the compressed cold blobs in bulk: the hot
        // additions and the pending removals. Each affected keyword costs exactly
        // one decode + one merge/filter + one encode per cycle, instead of one per
        // individual add/remove on the hot path — that is what keeps publish and
        // disconnect traffic off the codec.
        let mut keys: Vec<TokenHash> = self.hot.iter().map(|e| *e.key()).collect();
        keys.extend(self.pending_removals.iter().map(|e| *e.key()));
        keys.sort_unstable();
        keys.dedup();

        for th in keys {
            // Take both deferred sets out first, so we hold at most one map lock at
            // a time and never overlap with the cold entry lock below.
            let hv = self.hot.remove(&th).map(|(_, v)| v).unwrap_or_default();
            let pend = self
                .pending_removals
                .remove(&th)
                .map(|(_, v)| v)
                .unwrap_or_default();
            if hv.is_empty() && pend.is_empty() {
                continue;
            }

            let mut cold_entry = self.cold.entry(th).or_default();
            let cold_ids = posting_codec::decode(cold_entry.value()).unwrap_or_default();

            // Apply deletions to the cold side first, then merge the additions.
            // Order matters: hot and pending are disjoint (add_file clears an id
            // from pending), so a delete-then-re-add ends up present, correctly.
            let mut merged = Vec::with_capacity(cold_ids.len() + hv.len());
            let (mut i, mut j) = (0usize, 0usize);
            while i < cold_ids.len() && j < hv.len() {
                match cold_ids[i].0.cmp(&hv[j].0) {
                    std::cmp::Ordering::Less => {
                        if pend.binary_search(&cold_ids[i]).is_err() {
                            merged.push(cold_ids[i]);
                        }
                        i += 1;
                    }
                    std::cmp::Ordering::Greater => { merged.push(hv[j]); j += 1; }
                    std::cmp::Ordering::Equal => { merged.push(cold_ids[i]); i += 1; j += 1; }
                }
            }
            for id in &cold_ids[i..] {
                if pend.binary_search(id).is_err() {
                    merged.push(*id);
                }
            }
            merged.extend_from_slice(&hv[j..]);

            *cold_entry.value_mut() = posting_codec::encode(&merged).into_boxed_slice();
        }

        // Box<[u8]> blobs are exact-sized (rebuilt whole above). Drop keywords whose
        // posting became empty, plus any leftover empty deferred entries.
        let before = self.cold.len();
        self.cold
            .retain(|_, blob| posting_codec::decoded_len(blob).unwrap_or(0) != 0);
        self.hot.retain(|_, v| !v.is_empty());
        self.pending_removals.retain(|_, v| !v.is_empty());
        before - self.cold.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::file_id::FileId;

    #[test]
    fn tokenize_separators() {
        let toks = tokenize("[Quality] Inception (2010) 1080p.mkv");
        // "mkv" now indexed (format extensions searchable)
        assert!(toks.contains(&"quality".to_string()));
        assert!(toks.contains(&"inception".to_string()));
        assert!(toks.contains(&"2010".to_string()));
        assert!(toks.contains(&"1080p".to_string()));
        assert!(toks.iter().any(|t| t == "mkv")); // now indexed
    }

    #[test]
    fn tokenize_min_len() {
        let toks = tokenize("a be cat dog");
        // "a" too short (< 2 chars); "be", "cat", "dog" pass
        assert!(!toks.contains(&"a".to_string()));
        assert!(toks.contains(&"be".to_string()));
        assert!(toks.contains(&"cat".to_string()));
        assert!(toks.contains(&"dog".to_string()));
    }

    #[test]
    fn index_and_lookup() {
        let idx = KeywordIndex::new();
        let h1 = FileId(1);
        let h2 = FileId(2);
        let h3 = FileId(3);
        idx.add_file(h1, "Linux Mint Cinnamon 22.iso");
        idx.add_file(h2, "Linux Debian 12.iso");
        idx.add_file(h3, "Windows 11 Pro.iso");

        let result = idx.find_intersection(&["linux".into()]);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&h1));
        assert!(result.contains(&h2));

        let result = idx.find_intersection(&["linux".into(), "debian".into()]);
        assert_eq!(result.len(), 1);
        assert!(result.contains(&h2));

        let result = idx.find_intersection(&["macos".into()]);
        assert!(result.is_empty());
    }

    #[test]
    fn rarest_first() {
        let idx = KeywordIndex::new();
        // 100 files with "common", 1 with "rare"
        for i in 0..100u8 {
            idx.add_file(FileId(i as u32), "common file something.bin");
        }
        let rare_hash = FileId(200);
        idx.add_file(rare_hash, "common rare file.bin");

        let result = idx.find_intersection(&["common".into(), "rare".into()]);
        assert_eq!(result.len(), 1);
        assert!(result.contains(&rare_hash));
    }

    #[test]
    fn postings_stay_sorted_and_deduped() {
        let idx = KeywordIndex::new();
        // Insert hashes out of order under the same token.
        idx.add_file(FileId(5), "alpha.bin");
        idx.add_file(FileId(1), "alpha.bin");
        idx.add_file(FileId(3), "alpha.bin");
        // Re-add an existing one (idempotent — must NOT duplicate).
        idx.add_file(FileId(3), "alpha.bin");
        let r = idx.find_intersection(&["alpha".into()]);
        assert_eq!(r.len(), 3, "duplicate add must not grow the posting");
        // Result is sorted ascending (postings are sorted).
        let mut sorted = r.clone();
        sorted.sort();
        assert_eq!(r, sorted, "posting must be sorted");
    }

    #[test]
    fn remove_keeps_sorted_invariant() {
        let idx = KeywordIndex::new();
        for h in [2u8, 4, 6, 8] {
            idx.add_file(FileId(h as u32), "beta.bin");
        }
        idx.remove_file(FileId(4), "beta.bin");
        idx.remove_file(FileId(8), "beta.bin");
        let r = idx.find_intersection(&["beta".into()]);
        assert_eq!(r, vec![FileId(2), FileId(6)], "remove must preserve sort order");
        // Removing a non-existent hash is a no-op.
        idx.remove_file(FileId(99), "beta.bin");
        assert_eq!(idx.find_intersection(&["beta".into()]).len(), 2);
    }

    #[test]
    fn deferred_removals_are_invisible_before_compact() {
        let idx = KeywordIndex::new();
        let a = crate::state::file_id::FileId(64);
        let b = crate::state::file_id::FileId(128);
        let c = crate::state::file_id::FileId(4096);
        idx.add_file(a, "Linux Mint.iso");
        idx.add_file(b, "Linux Debian.iso");
        idx.add_file(c, "Linux Arch.iso");
        idx.compact(); // everything now lives in the cold blob

        // Remove b: only MARKED, the blob still contains it. tier_sizes counts
        // KEYS with pending removals, and this filename has three tokens
        // (linux, debian, iso), so all three get a mark.
        idx.remove_file(b, "Linux Debian.iso");
        assert_eq!(idx.tier_sizes().2, 3, "removal was not deferred");
        // ...but search must not return it.
        assert_eq!(idx.find_intersection(&["linux".to_string()]), vec![a, c]);

        // Compact applies the deletion; result unchanged, pending drained.
        idx.compact();
        assert_eq!(idx.tier_sizes().2, 0, "pending not drained by compact");
        assert_eq!(idx.find_intersection(&["linux".to_string()]), vec![a, c]);
    }

    #[test]
    fn re_add_cancels_a_pending_removal() {
        let idx = KeywordIndex::new();
        let a = crate::state::file_id::FileId(64);
        let b = crate::state::file_id::FileId(128);
        idx.add_file(a, "Linux Mint.iso");
        idx.add_file(b, "Linux Debian.iso");
        idx.compact();

        idx.remove_file(b, "Linux Debian.iso");
        idx.add_file(b, "Linux Debian.iso"); // re-published before compact ran
        assert_eq!(idx.find_intersection(&["linux".to_string()]), vec![a, b]);

        // The delete must NOT resurface when compact applies the batch.
        idx.compact();
        assert_eq!(idx.find_intersection(&["linux".to_string()]), vec![a, b],
            "re-added file was wrongly deleted at compact");
    }

    #[test]
    fn two_tier_correct_across_compact() {
        let idx = KeywordIndex::new();
        let a = crate::state::file_id::FileId(64);
        let b = crate::state::file_id::FileId(128);
        let c = crate::state::file_id::FileId((3u32 << 26) | 7);

        // Adds land in hot; search must already see them (hot tier).
        idx.add_file(a, "Linux Mint.iso");
        idx.add_file(b, "Linux Debian.iso");
        idx.add_file(c, "Linux Arch.iso");
        assert_eq!(idx.find_intersection(&["linux".to_string()]), vec![a, b, c]);

        // Compact drains hot -> cold; result must be identical.
        idx.compact();
        assert!(idx.hot.is_empty(), "hot not drained by compact");
        assert_eq!(idx.find_intersection(&["linux".to_string()]), vec![a, b, c]);

        // A new add after compact goes to hot; search merges cold+hot.
        let d = crate::state::file_id::FileId(4096);
        idx.add_file(d, "Linux Fedora.iso");
        assert_eq!(idx.find_intersection(&["linux".to_string()]), vec![a, b, d, c]
            .into_iter().collect::<std::collections::BTreeSet<_>>()
            .into_iter().collect::<Vec<_>>());

        // Remove hits whichever tier holds it; b is in cold, d in hot.
        idx.remove_file(b, "Linux Debian.iso");
        idx.remove_file(d, "Linux Fedora.iso");
        let mut got = idx.find_intersection(&["linux".to_string()]);
        got.sort_unstable();
        assert_eq!(got, vec![a, c]);

        // Idempotent re-add across a compact must not duplicate.
        idx.add_file(a, "Linux Mint.iso");
        idx.compact();
        idx.add_file(a, "Linux Mint.iso");
        let got = idx.find_intersection(&["linux".to_string()]);
        assert_eq!(got, vec![a, c], "cross-tier duplicate not deduped");

        // Multi-token intersection.
        idx.add_file(a, "debian");
        assert_eq!(idx.find_intersection(&["linux".to_string(), "debian".to_string()]), vec![a]);
    }

    #[test]
    fn token_hash_is_deterministic() {
        // Stable across calls (and processes — FNV is not seeded). This is what
        // lets the index be rebuilt identically from filenames on restore.
        assert_eq!(token_hash("ubuntu"), token_hash("ubuntu"));
        assert_ne!(token_hash("ubuntu"), token_hash("debian"));
        // Known FNV-1a 32-bit vector for "a" = 0xe40c292c.
        assert_eq!(token_hash("a"), 0xe40c292c);
    }

    #[test]
    fn lookup_works_through_hash_keying() {
        // End-to-end: add by filename, find by token — proves the hash keying
        // round-trips (add and find both hash the same way).
        let idx = KeywordIndex::new();
        idx.add_file(FileId(1), "Ubuntu Linux 24.04.iso");
        idx.add_file(FileId(2), "Debian Linux 12.iso");
        // Both share "linux"
        let r = idx.find_intersection(&["linux".into()]);
        assert_eq!(r.len(), 2);
        // "ubuntu" only the first
        let r2 = idx.find_intersection(&["ubuntu".into()]);
        assert_eq!(r2, vec![FileId(1)]);
        // unknown token -> empty
        assert!(idx.find_intersection(&["windows".into()]).is_empty());
    }
}
