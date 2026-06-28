//! Keyword inverted index.
//!
//! Maps lowercase tokens to file hashes for SEARCHREQUEST lookup.

use crate::state::file_id::FileId;
use dashmap::DashMap;

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
#[derive(Default)]
pub struct KeywordIndex {
    posting: DashMap<TokenHash, Vec<FileId>>,
}

impl KeywordIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Index a file by its filename. Idempotent — re-adding the same hash under
    /// a token is a no-op (binary_search finds it, we skip).
    pub fn add_file(&self, id: FileId, filename: &str) {
        tokenize_into(filename, |token| {
            let mut v = self.posting.entry(token_hash(token)).or_default();
            // Keep sorted + deduped: insert at the sorted position only if absent.
            if let Err(pos) = v.binary_search(&id) {
                v.insert(pos, id);
            }
        });
    }

    /// Remove a file from all postings (called when file is removed).
    pub fn remove_file(&self, id: FileId, filename: &str) {
        tokenize_into(filename, |token| {
            if let Some(mut entry) = self.posting.get_mut(&token_hash(token)) {
                if let Ok(pos) = entry.binary_search(&id) {
                    entry.remove(pos);
                }
            }
        });
    }

    /// Look up file hashes that have ALL of the given tokens.
    /// Picks the rarest token as the seed (SPEC.md §3.4.1 heuristic), then
    /// intersects against each other token's SORTED posting via binary_search.
    /// Returns a sorted Vec (postings are sorted, so the result is too).
    ///
    /// Tokens are hashed (FNV-1a) before lookup — the index keys on token hash,
    /// not the string. Collisions can only ADD false-positive candidates, which
    /// the caller's filename re-check (`evaluate`) discards; they never drop a
    /// real match.
    pub fn find_intersection(&self, tokens: &[String]) -> Vec<FileId> {
        if tokens.is_empty() {
            return Vec::new();
        }

        // Hash each query token once (FNV-1a), matching how add_file keyed them.
        let hashes: Vec<TokenHash> = tokens.iter().map(|t| token_hash(t)).collect();

        tracing::debug!(
            ?tokens,
            index_keyword_count = self.posting.len(),
            "find_intersection: looking up tokens"
        );

        // Find the rarest token (smallest posting) to seed from.
        let seed_idx = hashes
            .iter()
            .enumerate()
            .min_by_key(|(_, h)| {
                self.posting
                    .get(*h)
                    .map(|p| p.len())
                    .unwrap_or(usize::MAX)
            })
            .map(|(i, _)| i)
            .unwrap_or(0);

        let mut result: Vec<FileId> = match self.posting.get(&hashes[seed_idx]) {
            Some(p) => p.clone(),
            None => {
                tracing::debug!(
                    seed_token = %tokens[seed_idx],
                    "find_intersection: seed token NOT in index — 0 results"
                );
                return Vec::new();
            }
        };

        // Intersect with each remaining token. Each posting is sorted, so
        // `retain` + binary_search is O(result · log posting). Cheaper than the
        // old HashSet rebuild and allocation-free.
        for (i, h) in hashes.iter().enumerate() {
            if i == seed_idx {
                continue;
            }
            match self.posting.get(h) {
                Some(p) => {
                    let posting = p.value();
                    result.retain(|fh| posting.binary_search(fh).is_ok());
                }
                None => return Vec::new(),
            }
            if result.is_empty() {
                break;
            }
        }
        result
    }

    /// Number of distinct keywords in the index (for stats).
    pub fn keyword_count(&self) -> usize {
        self.posting.len()
    }

    /// Diagnostic: (number of keyword keys, total FileHash entries across all
    /// posting sets). The second number is the real memory cost — empty/stale
    /// postings inflate it until `compact()` runs. Full scan; off hot path.
    pub fn posting_stats(&self) -> (u64, u64) {
        let mut total: u64 = 0;
        for e in self.posting.iter() {
            total += e.value().len() as u64;
        }
        (self.posting.len() as u64, total)
    }

    /// Reclaim memory after churn. `remove_file` shrinks postings in place but
    /// leaves emptied Vecs behind to avoid hot-path contention; this leaves
    /// their (now-empty) slots and over-large capacity in place to avoid lock
    /// contention on the hot path. This sweep — called periodically from the
    /// cleanup task, NOT on the hot path — drops empty postings and shrinks the
    /// surviving sets back to their actual size. Returns the number of empty
    /// keyword entries removed.
    pub fn compact(&self) -> usize {
        // First shrink the surviving sets (retain can't shrink in place).
        for mut entry in self.posting.iter_mut() {
            entry.value_mut().shrink_to_fit();
        }
        // Then drop keywords whose posting set is now empty.
        let before = self.posting.len();
        self.posting.retain(|_, set| !set.is_empty());
        before - self.posting.len()
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
