//! Keyword inverted index.
//!
//! Maps lowercase tokens to file hashes for SEARCHREQUEST lookup.

use crate::state::file_id::FileId;
use crate::state::posting_codec;
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
    "the", "and", "for", "with", "from", "this", "that", "web", "www", "com", "net", "org",
];

/// Word-boundary characters used by the tokenizer.
fn is_separator(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '_' | '-'
                | '.'
                | ','
                | ';'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '!'
                | '?'
                | '@'
                | '#'
                | '$'
                | '%'
                | '^'
                | '&'
                | '*'
                | '+'
                | '='
                | '/'
                | '\\'
                | '|'
                | '<'
                | '>'
                | '"'
                | '\''
                | '`'
                | '~'
        )
}

/// Tokenize a filename into indexable keywords. Returns owned Strings; callers
/// that just want to iterate without keeping the Vec should use
/// [`tokenize_into`] for a callback-based variant.
///
/// Performance: filenames in eD2k traffic are predominantly ASCII (Roman
/// alphabet + digits + punctuation). For ASCII-only filenames we avoid
/// Unicode case mapping (saves ~3% CPU at scale per v0.9.37 profile).
/// Turn one search term from the client's expression tree into index keys.
///
/// Clients do not agree on who splits a query. eMule usually builds a tree of
/// one term per word — `AND(linux, ubuntu)` — but some paths send the whole
/// string as a single `NODE_STRING`, and then the term arrives here as
/// `"linux ubuntu"`, space included.
///
/// That term was previously lower-cased and looked up verbatim. No such key can
/// exist: the indexer splits filenames on separators, so the index holds
/// `linux` and `ubuntu` and never the pair. The symptom is exact — searching
/// either word works, searching both returns nothing.
///
/// Running the term through the SAME tokenizer the indexer uses is the whole
/// fix, and it must be the same function rather than a second splitter beside
/// it: two would eventually disagree about a separator or about
/// `MIN_KEYWORD_LEN`, and produce a fresh class of silent misses.
///
/// Wildcards survive untouched. `*` is not a keyword and the caller filters it,
/// but it must reach the caller to do so — the tokenizer would drop it as
/// shorter than `MIN_KEYWORD_LEN`.
pub fn tokenize_search_term(term: &str) -> Vec<String> {
    let trimmed = term.trim();
    if trimmed == "*" || trimmed == "**" {
        return vec![trimmed.to_string()];
    }
    let toks = tokenize(trimmed);
    if toks.is_empty() {
        // Nothing survived: a term shorter than MIN_KEYWORD_LEN, or one made
        // entirely of separators. Keep the lower-cased original so a
        // single-character search still reaches the index rather than silently
        // becoming a full scan — eMule does send "HD" and "OS".
        let lc = trimmed.to_lowercase();
        if lc.is_empty() {
            return Vec::new();
        }
        return vec![lc];
    }
    toks
}

pub fn tokenize(filename: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(8);
    tokenize_into(filename, |t| out.push(t.to_string()));
    out
}

/// Visit each indexable lowercase token in `filename`. The token is borrowed
/// from a working buffer and remains valid only for the duration of the
/// callback. This avoids the per-token `String` allocation that
/// `tokenize` does — used by [`KeywordIndex::add_file`] and `remove_file`.
/// Latin letters U+00C0..U+024F folded to their ASCII base, one char per code
/// point; `\0` means "leave alone".
///
/// Generated from Unicode canonical decompositions rather than typed by hand.
/// Multi-letter expansions (æ→ae, ß→ss, þ→th, œ→oe) are folded to their FIRST
/// letter here: a one-to-one table keeps the lookup a single index, and the
/// difference only matters for words that are already rare in filenames.
const FOLD_LATIN: &str = concat!(
    "aaaaaaaceeeeiiiidnooooo\0ouuuuytsaaaaaaac",
    "eeeeiiiidnooooo\0ouuuuytyaaaaaaccccccccdd",
    "ddeeeeeeeeeegggggggghhhhiiiiiiiiii\0\0jjkk",
    "kllllll\0\0llnnnnnn\0\0\0oooooooorrrrrrssssss",
    "ssttttttuuuuuuuuuuuuwwyyyzzzzzz\0\0\0\0\0\0\0\0\0",
    "\0\0\0\0\0\0\0e\0\0f\0\0\0\0\0\0\0\0\0\0\0\0\0oo\0\0\0\0\0\0\0\0\0\0\0\0\0u",
    "u\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0aaiioouuuuu",
    "uuuuu\0aaaa\0\0\0\0ggkkoooo\0\0j\0\0\0gg\0\0nnaa\0\0\0\0",
    "aaaaeeeeiiiioooorrrruuuusstt\0\0hh\0\0\0\0\0\0aa",
    "eeooooooooyy\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
);

/// Fold one character towards ASCII for indexing and lookup.
///
/// ⚠ TWO SEPARATE DECISIONS LIVE HERE, and they are not equally justified.
///
///   PRECOMPOSED ACCENTS (NFC) — `café` → `cafe`. This is a COMPATIBILITY fix.
///   Public servers fold these, measured: a query carrying an NFC accent
///   returned 153 results against a reference server where the files are spelled
///   with the plain letter, and 0 here. A client typing what the user typed got
///   results from a real server and an empty list from this one.
///
///   COMBINING MARKS (NFD) — `e`+U+0301 → `e`. This goes BEYOND the reference.
///   The same measurement showed public servers do NOT fold NFD: the same word
///   in decomposed form returned 0 there too. Both encodings are genuinely on
///   the network, so handling it makes this server better rather than merely
///   equal — but it is an improvement, not a compatibility fix, and if it ever
///   causes trouble it can be dropped without reopening the first decision.
///
/// Mojibake is out of scope. Nothing can repair a name whose bytes were already
/// decoded with the wrong encoding by whoever published it.
fn fold_char(c: char) -> Option<char> {
    let cp = c as u32;
    // Combining diacritical marks: drop entirely (the NFD half).
    if (0x0300..=0x036F).contains(&cp) {
        return None;
    }
    if (0x00C0..0x0250).contains(&cp) {
        let b = FOLD_LATIN.as_bytes()[(cp - 0x00C0) as usize];
        if b != 0 {
            return Some(b as char);
        }
    }
    Some(c)
}

/// Fold and lowercase a whole string for comparison, keeping separators.
///
/// `fold_token` is for one token; this is for a filename or a query term that
/// may contain spaces, and it exists so the search post-filter can compare on
/// the same footing as the index. Both must use it or a folded lookup is undone
/// by an unfolded comparison.
pub fn fold_for_match(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match fold_char(c) {
            None => {}
            Some(f) => {
                for lc in f.to_lowercase() {
                    out.push(lc);
                }
            }
        }
    }
    out
}

/// Lowercase and fold a token. Allocates only when something actually changes.
fn fold_token(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match fold_char(c) {
            None => {}
            Some(f) => {
                for lc in f.to_lowercase() {
                    out.push(lc);
                }
            }
        }
    }
    out
}

/// Minimum length of a SUB-token. Deliberately higher than `MIN_KEYWORD_LEN`.
///
/// Whole words keep the 2-character minimum — eMule sends "HD" and "OS" and
/// users mean them. Sub-tokens are different: they come from splitting a word
/// at letter/digit boundaries, and at two characters that produces `01`, `08`,
/// `e0` and the like out of every episode tag on the network, each with a
/// posting list the size of the TV corpus. Three is the smallest length at
/// which `S01E08` still yields `s01` and `e08`, which is what this is for.
const SUBTOKEN_MIN_LEN: usize = 3;

/// A word split into more runs than this is not sub-tokenised at all.
///
/// Real compound tokens have few runs — `s01e08` has four, `kxv7171wjq`
/// three, a double episode `s01e08e09` six. A word with many runs is almost
/// always an identifier: a hash, a release id, a CRC tag. Splitting those only
/// adds single-file postings nobody will query, so past this many runs the word
/// is left as the one whole token it already is.
const SUBTOKEN_MAX_RUNS: usize = 6;

/// Letter or digit — the only two classes a run boundary separates. Anything
/// else has already been cut by `is_separator` before a word reaches here.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RunClass {
    Letter,
    Digit,
    Other,
}

fn run_class(c: char) -> RunClass {
    if c.is_numeric() {
        RunClass::Digit
    } else if c.is_alphabetic() {
        RunClass::Letter
    } else {
        RunClass::Other
    }
}

/// Visit the sub-tokens of one already-lowercased, already-folded word.
///
/// The rule is RUNS PLUS ADJACENT PAIRS:
///
/// ```text
///   s01e08      runs s|01|e|08        pairs s01, 01e, e08     -> s01, 01e, e08
///   1080p       runs 1080|p           pair  = the word        -> 1080
///   kxv7171wjq  runs kxv|7171|wjq     pairs kxv7171, 7171wjq  -> all five
/// ```
///
/// ⚠ PLAIN RUN SPLITTING IS NOT ENOUGH. `S01E08` splits into `s`, `01`, `e`,
///   `08`, and every one of those falls under any sane minimum — so the token
///   that motivated this whole change, `s01`, would never exist. The pairs are
///   what produce it. This was only visible by checking the rule against the
///   example that motivated it (issue #14).
///
/// ⚠ THIS IS NOT A SUPERSET OF LUGDUNUM. A query that begins in the middle of a
///   run — `1x05` against a file named `01x05` — is reached by Lugdunum's
///   substring filter and by nothing here: the runs are `01`, `x`, `05`, the
///   pairs `01x`, `x05`, and `1x05` is neither. Clients that care send both
///   spellings (aMuTorrent emits `1x05` and `01x05` for exactly this reason),
///   so the gap is absorbed on their side — but that is a property of today's
///   client population, not a guarantee. If a client stops sending both, this
///   gap becomes visible immediately.
///
/// Whole words are NOT emitted here; the caller already has them. A pair equal
/// to the whole word is skipped for the same reason.
fn visit_subtokens<F: FnMut(&str)>(word: &str, visit: &mut F) {
    // A hex string is an identifier — a CRC tag, an md5, a release hash — and
    // the run cap alone does not catch it: `deadbeef1234cafe5678` has only four
    // runs, each long enough to index, and every one would be a single-file
    // posting that nobody will ever search for. Eight characters is a CRC32,
    // the shortest of these that turns up in filenames.
    if word.len() >= 8 && word.bytes().all(|b| b.is_ascii_hexdigit()) {
        return;
    }
    // Find run boundaries as byte offsets. Words are short; a small fixed array
    // avoids an allocation on the hot publish path.
    let mut bounds: [usize; SUBTOKEN_MAX_RUNS + 2] = [0; SUBTOKEN_MAX_RUNS + 2];
    let mut n_runs = 0usize;
    let mut prev: Option<RunClass> = None;
    for (i, c) in word.char_indices() {
        let cls = run_class(c);
        if cls == RunClass::Other {
            // Should not happen after is_separator, but a stray symbol makes the
            // run structure meaningless; leave the word whole.
            return;
        }
        if prev != Some(cls) {
            if n_runs >= SUBTOKEN_MAX_RUNS {
                return; // an identifier, not a compound — see SUBTOKEN_MAX_RUNS
            }
            bounds[n_runs] = i;
            n_runs += 1;
            prev = Some(cls);
        }
    }
    if n_runs < 2 {
        return; // a single run IS the word
    }
    bounds[n_runs] = word.len();

    let emit = |s: &str, visit: &mut F| {
        if s.chars().count() >= SUBTOKEN_MIN_LEN
            && s.len() < word.len()
            && !COMMON_WORDS_SKIP.contains(&s)
        {
            visit(s);
        }
    };
    // Runs.
    for r in 0..n_runs {
        emit(&word[bounds[r]..bounds[r + 1]], visit);
    }
    // Adjacent pairs.
    for r in 0..n_runs - 1 {
        emit(&word[bounds[r]..bounds[r + 2]], visit);
    }
}

/// Everything the INDEX stores for a filename: whole tokens, plus sub-tokens
/// when enabled.
///
/// ⚠ INDEXING ONLY. Query terms go through `tokenize_search_term`, which stays
///   whole-token. That asymmetry is the point: a query for `s01` is ONE whole
///   token that now finds the sub-token `s01` in `s01e08`. Sub-tokenising the
///   query as well would turn every search for `s01e08` into an intersection of
///   four postings, three of them enormous, to arrive at the same answer.
///
/// ⚠ `add_file` AND `remove_file` MUST BOTH CALL THIS, WITH THE SAME FLAG. A
///   token added and not removed is a stale id in a posting forever; nothing
///   ever compacts it out. That is also why `subtokens` is fixed when the index
///   is built and not hot-reloadable.
fn index_tokens_into<F: FnMut(&str)>(filename: &str, subtokens: bool, mut visit: F) {
    tokenize_into(filename, |tok| {
        visit(tok);
        if subtokens {
            visit_subtokens(tok, &mut visit);
        }
    });
}

fn tokenize_into<F: FnMut(&str)>(filename: &str, mut visit: F) {
    // Fast ASCII path: lowercase once into a single buffer, then split.
    // Falls back to per-token Unicode lowercase if non-ASCII is present.
    if filename.is_ascii() {
        let mut buf: String = String::with_capacity(filename.len());
        buf.push_str(filename);
        // Safe because we just verified ASCII; make_ascii_lowercase is in-place.
        buf.make_ascii_lowercase();
        for tok in buf.split(is_separator) {
            if tok.len() < MIN_KEYWORD_LEN {
                continue;
            }
            if COMMON_WORDS_SKIP.contains(&tok) {
                continue;
            }
            visit(tok);
        }
    } else {
        // Mixed / non-ASCII: do Unicode-aware lowercase per token.
        for raw in filename.split(is_separator) {
            if raw.len() < MIN_KEYWORD_LEN {
                continue;
            }
            // Fold before lowercasing, and note that folding can EMPTY a token:
            // a word written entirely in combining marks leaves nothing behind.
            let lc = fold_token(raw);
            if lc.is_empty() || COMMON_WORDS_SKIP.contains(&lc.as_str()) {
                continue;
            }
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
    /// Emit letter/digit sub-tokens alongside whole words (see
    /// `visit_subtokens`). Fixed at construction: `add_file` and `remove_file`
    /// must tokenise identically for the life of the index, or postings leak.
    subtokens: bool,
}

/// Shrink a DashMap only when it has at least 2x more slots than entries.
///
/// Unconditional shrinking would rebuild the table on every cycle for a map that
/// is merely full, which costs far more than the slack it reclaims.
fn shrink_if_slack<K, V>(map: &DashMap<K, V>)
where
    K: std::hash::Hash + Eq,
{
    let len = map.len();
    // An empty map still holds its allocation; that is exactly the case worth
    // reclaiming, and `len * 2` would be 0 and never trigger.
    if map.capacity() > std::cmp::max(len * 2, 64) {
        map.shrink_to_fit();
    }
}

impl KeywordIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// An index that also stores sub-tokens. See `index_tokens_into`.
    pub fn with_subtokens(subtokens: bool) -> Self {
        Self {
            subtokens,
            ..Self::default()
        }
    }

    pub fn subtokens_enabled(&self) -> bool {
        self.subtokens
    }

    /// Does any file carry this token? Cheap: two map probes, no posting is
    /// decoded.
    ///
    /// Errs towards "yes". A cold posting whose ids are all pending removal
    /// still reports true until the next compaction, and a token whose hash
    /// collides with a real one reports true forever. Both only mean the word
    /// is treated as known and behaves exactly as before — never that a
    /// genuinely present word is dropped from a query.
    pub fn contains_token(&self, token: &str) -> bool {
        let th = token_hash(token);
        if let Some(v) = self.hot.get(&th) {
            if !v.is_empty() {
                return true;
            }
        }
        self.cold.contains_key(&th)
    }

    /// Index a file by filename. Idempotent — re-adding the same id under a token
    /// is a no-op (it is already in the decoded list).
    pub fn add_file(&self, id: FileId, filename: &str) {
        index_tokens_into(filename, self.subtokens, |token| {
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
        // Same tokeniser, same flag as add_file — see index_tokens_into.
        index_tokens_into(filename, self.subtokens, |token| {
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
                Some(
                    out.into_iter()
                        .filter(|id| p.binary_search(id).is_err())
                        .collect(),
                )
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
                        std::cmp::Ordering::Less => {
                            out.push(cv[i]);
                            i += 1;
                        }
                        std::cmp::Ordering::Greater => {
                            out.push(hv[j]);
                            j += 1;
                        }
                        std::cmp::Ordering::Equal => {
                            out.push(cv[i]);
                            i += 1;
                            j += 1;
                        }
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
    /// Candidates for a grouped query: intersect the groups, union within each.
    ///
    /// `[[a], [b, c]]` means "holds a, AND holds b or c". Every non-boolean
    /// query produces single-term groups and reduces to the plain intersection.
    ///
    /// ⚠ A GROUP THAT MATCHES NOTHING EMPTIES THE RESULT — it must, since the
    ///   file has to satisfy every group. But an OR group is satisfied by ANY
    ///   one member, so a branch naming a token no file contains must not empty
    ///   it. `(S01E05 OR 1x05 OR 1x5)` contains four such branches for any given
    ///   file, and treating them as required is the bug this replaces.
    pub fn find_grouped(&self, groups: &[Vec<String>]) -> Vec<FileId> {
        if groups.is_empty() {
            return Vec::new();
        }
        // Single-term groups go through the streaming intersection, which avoids
        // materialising a huge posting list for a common word. Peel them off so
        // the ordinary query keeps that path unchanged.
        let singles: Vec<String> = groups
            .iter()
            .filter(|g| g.len() == 1)
            .map(|g| g[0].clone())
            .collect();
        let multis: Vec<&Vec<String>> = groups.iter().filter(|g| g.len() > 1).collect();

        if multis.is_empty() {
            return self.find_intersection(&singles);
        }

        let mut result = if singles.is_empty() {
            let mut seed = self.union_of(multis[0]);
            seed.sort_unstable();
            seed.dedup();
            seed
        } else {
            self.find_intersection(&singles)
        };
        if result.is_empty() {
            return result;
        }

        let start = usize::from(singles.is_empty());
        for g in &multis[start..] {
            let mut u = self.union_of(g);
            u.sort_unstable();
            u.dedup();
            if u.is_empty() {
                return Vec::new();
            }
            result.retain(|id| u.binary_search(id).is_ok());
            if result.is_empty() {
                return result;
            }
        }
        result
    }

    /// Every file holding at least one of these tokens. Unsorted, may repeat.
    fn union_of(&self, tokens: &[String]) -> Vec<FileId> {
        let mut out = Vec::new();
        for t in tokens {
            if let Some(v) = self.materialize(token_hash(t)) {
                out.extend_from_slice(&v);
            }
        }
        out
    }

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
                if n == 0 {
                    usize::MAX
                } else {
                    n
                }
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
    /// Slot capacity of the hot tier's table. Diagnostics and tests — capacity
    /// is not otherwise observable, and it is what decides how much of the
    /// keyword index is reserved but unused.
    pub fn hot_capacity(&self) -> usize {
        self.hot.capacity()
    }

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
                    std::cmp::Ordering::Greater => {
                        merged.push(hv[j]);
                        j += 1;
                    }
                    std::cmp::Ordering::Equal => {
                        merged.push(cold_ids[i]);
                        i += 1;
                        j += 1;
                    }
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

        // Give back table capacity the maps are no longer using.
        //
        // `hot` and `pending_removals` are drained to (near) empty every cycle,
        // but their tables keep whatever capacity the busiest cycle ever needed —
        // a burst that touched 200k keywords leaves 200k slots reserved
        // permanently, holding nothing. `cold` grows for real, so it is only
        // shrunk when it has genuinely over-reserved.
        //
        // Gated on a 2x ratio rather than run unconditionally: `shrink_to_fit`
        // rebuilds every shard's table, which is far too expensive to do each
        // cycle on a map that is simply full. With the gate, a steadily growing
        // `cold` is left alone and only real slack is reclaimed.
        //
        // Safe here and nowhere else: compact() runs on the blocking pool, off
        // the runtime, so a rebuild does not stall packet handling.
        shrink_if_slack(&self.hot);
        shrink_if_slack(&self.pending_removals);
        shrink_if_slack(&self.cold);

        before - self.cold.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::file_id::FileId;

    #[test]
    fn a_multi_word_term_is_split_like_a_filename() {
        // Issue #10: searching "linux ubuntu" returned nothing while either word
        // alone worked. Some clients send the whole query as ONE term, and it
        // was looked up verbatim — but no index key contains a space, because
        // the indexer splits on separators. The lookup could only miss.
        assert_eq!(
            tokenize_search_term("linux ubuntu"),
            vec!["linux", "ubuntu"]
        );
        // Whatever the indexer would produce for the same text, the search must
        // ask for. This is the property that matters, not the exact list.
        assert_eq!(
            tokenize_search_term("Linux Ubuntu"),
            tokenize("Linux Ubuntu")
        );
        assert_eq!(
            tokenize_search_term("Ubuntu-24.04_desktop"),
            tokenize("Ubuntu-24.04_desktop")
        );
    }

    #[test]
    fn a_single_word_term_is_unchanged() {
        assert_eq!(tokenize_search_term("linux"), vec!["linux"]);
        assert_eq!(tokenize_search_term("UBUNTU"), vec!["ubuntu"]);
    }

    #[test]
    fn wildcards_reach_the_caller_intact() {
        // The caller filters these; the tokenizer would drop them as shorter
        // than MIN_KEYWORD_LEN, turning a "*" search into a term-less one by
        // accident rather than by decision.
        assert_eq!(tokenize_search_term("*"), vec!["*"]);
        assert_eq!(tokenize_search_term("**"), vec!["**"]);
    }

    #[test]
    fn short_terms_still_reach_the_index() {
        // eMule sends these. The indexer skips them, so they will not match, but
        // they must arrive as a term rather than vanish — a term-less query
        // triggers the capped full scan, which is a different and much more
        // expensive answer.
        assert_eq!(tokenize_search_term("HD"), vec!["hd"]);
        assert_eq!(tokenize_search_term("x"), vec!["x"]);
    }

    #[test]
    fn a_blank_term_yields_nothing() {
        // An empty result means "no keyword constraint from this term", which
        // the caller handles; it must not become an empty-string key.
        assert!(tokenize_search_term("   ").is_empty());
        assert!(tokenize_search_term("").is_empty());
    }

    #[test]
    fn splitting_makes_the_intersection_work() {
        // End to end: index a file, then search it by two of its words as one
        // term. This is the user-visible behaviour issue #10 reported.
        let kw = KeywordIndex::new();
        kw.add_file(FileId(1), "Linux Ubuntu 24.04 desktop amd64.iso");
        kw.add_file(FileId(2), "Linux Mint 21 cinnamon.iso");

        let toks = tokenize_search_term("linux ubuntu");
        assert_eq!(kw.find_intersection(&toks), vec![FileId(1)]);

        // ...and each word alone still behaves as it did.
        assert_eq!(
            kw.find_intersection(&tokenize_search_term("linux")).len(),
            2
        );
        assert_eq!(
            kw.find_intersection(&tokenize_search_term("ubuntu")),
            vec![FileId(1)]
        );
    }

    #[test]
    fn compact_returns_unused_table_capacity() {
        // hot/pending are drained every cycle but keep the capacity of the
        // busiest burst forever. After a big burst is compacted away, the slots
        // must come back.
        let kw = KeywordIndex::new();
        // Each file gets a token unique to it plus one shared by all, so the
        // burst creates ~5000 distinct keywords.
        for i in 0..5000u32 {
            kw.add_file(FileId(i), &format!("filexyz{i} commontoken"));
        }
        let hot_cap_peak = kw.hot_capacity();
        assert!(hot_cap_peak > 1000, "burst should have grown the hot table");

        kw.compact();
        assert!(
            kw.hot_capacity() < hot_cap_peak,
            "hot table kept {} slots after being drained (peak {hot_cap_peak})",
            kw.hot_capacity()
        );

        // The postings themselves survived: capacity is the only thing given
        // back. A unique token resolves to exactly its file...
        assert_eq!(
            kw.find_intersection(&["filexyz4242".to_string()]),
            vec![FileId(4242)],
            "posting data must survive the shrink"
        );
        // ...and the token every file shares still lists them all.
        assert_eq!(
            kw.find_intersection(&["commontoken".to_string()]).len(),
            5000
        );
    }

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
        assert_eq!(
            r,
            vec![FileId(2), FileId(6)],
            "remove must preserve sort order"
        );
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
        assert_eq!(
            idx.find_intersection(&["linux".to_string()]),
            vec![a, b],
            "re-added file was wrongly deleted at compact"
        );
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
        assert_eq!(
            idx.find_intersection(&["linux".to_string()]),
            vec![a, b, d, c]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );

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
        assert_eq!(
            idx.find_intersection(&["linux".to_string(), "debian".to_string()]),
            vec![a]
        );
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
    #[test]
    fn an_accented_query_finds_a_plain_name() {
        // The compatibility gap: a client sends what the user typed, a public
        // server folds the accent and returns 153 results, this one returned 0.
        // Indexing and lookup share `tokenize_into`, so folding either side
        // folds both — which is the only way the two cannot drift apart.
        let idx = KeywordIndex::new();
        idx.add_file(FileId(1), "Le Chateau dans le Ciel");
        assert_eq!(
            idx.find_intersection(&tokenize_search_term("château")),
            vec![FileId(1)],
            "an accented query must reach a name spelled without the accent"
        );
        assert_eq!(
            idx.find_intersection(&tokenize_search_term("CHÂTEAU")),
            vec![FileId(1)]
        );
    }

    #[test]
    fn the_two_unicode_encodings_of_one_word_agree() {
        // Beyond the reference implementation, deliberately: public servers do
        // NOT fold the decomposed form, measured. Both encodings are on the
        // network, so handling it makes this server better rather than equal.
        let idx = KeywordIndex::new();
        idx.add_file(FileId(1), "cafe society");
        let nfc = "caf\u{e9}"; // é as one code point
        let nfd = "cafe\u{301}"; // e + combining acute
        assert_eq!(
            idx.find_intersection(&tokenize_search_term(nfc)),
            vec![FileId(1)]
        );
        assert_eq!(
            idx.find_intersection(&tokenize_search_term(nfd)),
            vec![FileId(1)]
        );
    }

    #[test]
    fn folding_leaves_other_scripts_alone() {
        // Cyrillic, Greek and CJK carry no Latin-1 accents, and public servers
        // do not fold their diacritics either. Touching them would change
        // matching for the majority of this server's non-ASCII traffic to no
        // purpose.
        let idx = KeywordIndex::new();
        idx.add_file(FileId(1), "детское видео");
        idx.add_file(FileId(2), "日本語 のファイル");
        assert_eq!(
            idx.find_intersection(&tokenize_search_term("детское")),
            vec![FileId(1)]
        );
        assert_eq!(
            idx.find_intersection(&tokenize_search_term("日本語")),
            vec![FileId(2)]
        );
    }

    #[test]
    fn a_multi_word_term_is_still_an_intersection() {
        // The regression that took the server from 3% CPU to 92%: a client
        // sending the whole query as one node had its words turned into
        // alternatives, so the candidate set became the union of three common
        // words across a 1.6M-file index instead of their intersection.
        //
        // Results stayed correct — `evaluate` still applied the real condition —
        // which is exactly why nothing looked wrong except the load.
        let idx = KeywordIndex::new();
        idx.add_file(FileId(1), "ubuntu linux bible");
        idx.add_file(FileId(2), "ubuntu server guide");
        idx.add_file(FileId(3), "linux kernel internals");

        // One group per word: all three required.
        let anded = vec![
            vec!["ubuntu".to_string()],
            vec!["linux".to_string()],
            vec!["bible".to_string()],
        ];
        assert_eq!(idx.find_grouped(&anded), vec![FileId(1)]);

        // The same three words in ONE group would be alternatives, which is
        // both the wrong answer and the expensive one.
        let ored = vec![vec![
            "ubuntu".to_string(),
            "linux".to_string(),
            "bible".to_string(),
        ]];
        let mut got = idx.find_grouped(&ored);
        got.sort();
        assert_eq!(
            got,
            vec![FileId(1), FileId(2), FileId(3)],
            "a single group unions — which is why a multi-word term must not \
             become one"
        );
    }

    #[test]
    fn an_or_group_does_not_demand_every_branch() {
        // The television search that returned nothing: one file holds exactly
        // one of the five episode spellings, and the intersection demanded all
        // five.
        let idx = KeywordIndex::new();
        idx.add_file(FileId(1), "Rick and Morty S01E05 1080p");
        idx.add_file(FileId(2), "Rick and Morty S01E06 1080p");

        let groups = vec![
            vec!["morty".to_string()],
            vec![
                "s01e05".to_string(),
                "1x05".to_string(),
                "01x05".to_string(),
                "1x5".to_string(),
            ],
        ];
        assert_eq!(idx.find_grouped(&groups), vec![FileId(1)]);

        // A branch naming a token no file holds must not empty the result — it
        // is an alternative, not a requirement. This is the discriminating case
        // from the report.
        let with_ghost = vec![
            vec!["morty".to_string()],
            vec!["nonexistent_token_xyzzy".to_string(), "s01e06".to_string()],
        ];
        assert_eq!(idx.find_grouped(&with_ghost), vec![FileId(2)]);
    }

    #[test]
    fn every_group_still_has_to_be_satisfied() {
        // Unioning within a group must not turn into unioning across them: AND
        // is still AND.
        let idx = KeywordIndex::new();
        idx.add_file(FileId(1), "alpha bravo");
        idx.add_file(FileId(2), "alpha charlie");
        let groups = vec![
            vec!["alpha".to_string()],
            vec!["bravo".to_string(), "delta".to_string()],
        ];
        assert_eq!(idx.find_grouped(&groups), vec![FileId(1)]);

        // A group nothing satisfies empties the result.
        let impossible = vec![
            vec!["alpha".to_string()],
            vec!["delta".to_string(), "echo".to_string()],
        ];
        assert!(idx.find_grouped(&impossible).is_empty());
    }

    #[test]
    fn a_query_with_no_plain_terms_still_works() {
        // `(a OR b)` alone: no single-term group to seed from, so the seed has
        // to come from the first union.
        let idx = KeywordIndex::new();
        idx.add_file(FileId(1), "alpha bravo");
        idx.add_file(FileId(2), "charlie delta");
        let groups = vec![vec!["bravo".to_string(), "charlie".to_string()]];
        let mut got = idx.find_grouped(&groups);
        got.sort();
        assert_eq!(got, vec![FileId(1), FileId(2)]);
    }

    // ─── sub-tokens (issue #14 follow-up) ─────────────────────────────────

    fn subs(word: &str) -> Vec<String> {
        let mut out = Vec::new();
        visit_subtokens(word, &mut |t: &str| out.push(t.to_string()));
        out
    }

    #[test]
    fn subtokens_of_an_episode_tag_include_the_season() {
        // The case that motivated the whole change. Plain run splitting gives
        // s|01|e|08 and every piece falls under the minimum — s01 would never
        // exist. The PAIRS are what produce it.
        assert_eq!(subs("s01e08"), vec!["s01", "01e", "e08"]);
    }

    #[test]
    fn subtokens_of_a_resolution_tag() {
        // The pair "1080p" is the word itself and is not emitted twice.
        assert_eq!(subs("1080p"), vec!["1080"]);
    }

    #[test]
    fn subtokens_of_a_three_run_word() {
        assert_eq!(
            subs("kxv7171wjq"),
            vec!["kxv", "7171", "wjq", "kxv7171", "7171wjq"]
        );
    }

    #[test]
    fn a_single_run_word_has_no_subtokens() {
        assert!(subs("ubuntu").is_empty());
        assert!(subs("2026").is_empty());
    }

    #[test]
    fn two_character_pieces_are_not_subtokens() {
        // SUBTOKEN_MIN_LEN is 3 on purpose: "01", "08", "e0" out of every
        // episode tag would each carry a posting the size of the TV corpus.
        for t in subs("s01e08") {
            assert!(t.len() >= 3, "{t} is below SUBTOKEN_MIN_LEN");
        }
        assert!(subs("x5").is_empty());
    }

    #[test]
    fn an_identifier_with_many_runs_is_left_whole() {
        // Release ids that alternate letters and digits many times: past
        // SUBTOKEN_MAX_RUNS the word stays whole.
        assert!(subs("a1b2c3d4e5").is_empty());
        // ...while a double-episode tag, six runs, is still split.
        assert!(!subs("s01e08e09").is_empty());
    }

    #[test]
    fn a_hex_identifier_is_left_whole_even_with_few_runs() {
        // The run cap does NOT catch this one: four long runs. Found by this test
        // failing against the first version of the rule, whose comment claimed
        // hashes were covered. They were not.
        assert!(subs("deadbeef1234cafe5678").is_empty());
        assert!(subs("3a7f2b9c").is_empty()); // CRC32
        assert!(subs("d41d8cd98f00b204e9800998ecf8427e").is_empty()); // md5
                                                                      // Not hex: 's' and 'p' are outside a-f, so these still split.
        assert!(!subs("s01e08").is_empty());
        assert!(!subs("1080p").is_empty());
    }

    #[test]
    fn the_mid_run_gap_is_real_and_documented() {
        // NOT a superset of Lugdunum: 1x05 begins in the middle of the run 01 in
        // 01x05, so no run or pair produces it. Pinned so that nobody "fixes"
        // the comment without also fixing the behaviour.
        let got = subs("01x05");
        assert!(!got.contains(&"1x05".to_string()));
        assert_eq!(got, vec!["01x", "x05"]);
    }

    #[test]
    fn subtokens_make_parts_of_a_word_findable() {
        let idx = KeywordIndex::with_subtokens(true);
        idx.add_file(FileId(1), "Some Show S01E08 1080p.mkv");
        idx.add_file(FileId(2), "Some Show S02E01 720p.mkv");

        assert_eq!(idx.find_intersection(&["s01".into()]), vec![FileId(1)]);
        assert_eq!(idx.find_intersection(&["e08".into()]), vec![FileId(1)]);
        assert_eq!(idx.find_intersection(&["1080".into()]), vec![FileId(1)]);
        assert_eq!(idx.find_intersection(&["720".into()]), vec![FileId(2)]);
        // Whole words still work exactly as before.
        assert_eq!(idx.find_intersection(&["s01e08".into()]), vec![FileId(1)]);
        let mut both = idx.find_intersection(&["show".into()]);
        both.sort();
        assert_eq!(both, vec![FileId(1), FileId(2)]);
        // And combine with them: "<title> s01" is the query this is for.
        assert_eq!(
            idx.find_intersection(&["show".into(), "s01".into()]),
            vec![FileId(1)]
        );
    }

    #[test]
    fn without_the_flag_nothing_changes() {
        let idx = KeywordIndex::new();
        idx.add_file(FileId(1), "Some Show S01E08 1080p.mkv");
        assert!(idx.find_intersection(&["s01".into()]).is_empty());
        assert!(idx.find_intersection(&["1080".into()]).is_empty());
        assert_eq!(idx.find_intersection(&["s01e08".into()]), vec![FileId(1)]);
    }

    #[test]
    fn remove_file_removes_every_subtoken_it_added() {
        // The invariant that makes the flag startup-only. A token added and not
        // removed is a stale id in a posting forever — nothing compacts it out.
        let idx = KeywordIndex::with_subtokens(true);
        let name = "Some Show S01E08 kxv7171wjq 1080p.mkv";
        idx.add_file(FileId(7), name);
        let mut added = Vec::new();
        index_tokens_into(name, true, |t| added.push(t.to_string()));
        assert!(added.len() > 6, "sub-tokens should have been emitted");
        for t in &added {
            assert_eq!(idx.find_intersection(&[t.clone()]), vec![FileId(7)], "{t}");
        }

        idx.remove_file(FileId(7), name);
        for t in &added {
            assert!(
                idx.find_intersection(&[t.clone()]).is_empty(),
                "{t} still points at a removed file"
            );
        }
        // And through a compaction, where the cold tier is involved.
        idx.add_file(FileId(8), name);
        idx.compact();
        idx.remove_file(FileId(8), name);
        idx.compact();
        for t in &added {
            assert!(
                idx.find_intersection(&[t.clone()]).is_empty(),
                "{t} survived compaction after removal"
            );
        }
    }

    #[test]
    fn query_terms_are_not_sub_tokenised() {
        // Indexing only. A query for s01e08 stays one whole token; splitting it
        // would intersect four postings, three enormous, for the same answer.
        assert_eq!(tokenize_search_term("S01E08"), vec!["s01e08"]);
        assert_eq!(tokenize_search_term("1080p"), vec!["1080p"]);
    }
}
