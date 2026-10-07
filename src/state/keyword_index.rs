//! Keyword inverted index.
//!
//! Maps lowercase tokens to file hashes for SEARCHREQUEST lookup.

use crate::state::cold_store::{self, ColdStore};
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
    // ASCII fast path: fold_char leaves every ASCII character as it is, and an
    // ASCII character's lowercase is its ASCII lowercase, so this is the same
    // result without the per-character walk. Most names are plain ASCII, and
    // a search folds every candidate's name.
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
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
    cold: ColdStore,
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
    /// Serialises `compact()` (see there).
    compact_lock: std::sync::Mutex<()>,
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

/// merge(cold − pending, hot), all three ascending and deduped. `hot` and
/// `pending` are disjoint (see the invariant on `pending_removals`), so a
/// delete-then-re-add ends up present.
fn merge_tiers(cold: &[FileId], hot: &[FileId], pend: &[FileId]) -> Vec<FileId> {
    let mut merged = Vec::with_capacity(cold.len() + hot.len());
    // Cold ids are tested for deletion in ascending order, so the deletion
    // list is walked once alongside them. It used to be binary-searched for
    // every cold id — a third of all compaction time on a live server.
    let mut k = 0usize;
    let mut deleted = |id: FileId| -> bool {
        while k < pend.len() && pend[k].0 < id.0 {
            k += 1;
        }
        k < pend.len() && pend[k] == id
    };
    let (mut i, mut j) = (0usize, 0usize);
    while i < cold.len() && j < hot.len() {
        match cold[i].0.cmp(&hot[j].0) {
            std::cmp::Ordering::Less => {
                if !deleted(cold[i]) {
                    merged.push(cold[i]);
                }
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                merged.push(hot[j]);
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                merged.push(cold[i]);
                i += 1;
                j += 1;
            }
        }
    }
    for &id in &cold[i..] {
        if !deleted(id) {
            merged.push(id);
        }
    }
    merged.extend_from_slice(&hot[j..]);
    merged
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
        self.cold.contains_key(th)
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
            if self.cold.contains_key(th) {
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
        // Through the same walk as the capped lookup, which reads pending while
        // it still holds the cold and hot guards. Reading pending after
        // releasing them could pair an old cold blob with a pending set that a
        // compaction had already trimmed, and return an id it had just removed.
        self.merge_tiers_locked(th, usize::MAX)
    }

    /// Posting length across both tiers WITHOUT fully decoding cold — good enough
    /// for rarest-seed selection. Overcounts by at most the cross-tier duplicates,
    /// which is fine for a heuristic.
    fn approx_len(&self, th: TokenHash) -> usize {
        let cold = self
            .cold
            .get(th)
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

    /// `find_grouped`, but a query of ONE plain word returns only its first
    /// `cap` ids (ascending) instead of the whole posting.
    ///
    /// The search paths examine candidates in id order and stop after
    /// `search_rank_scan` of them, so for a single common word ("mp3", "avi")
    /// every id past that point was decoded and allocated for nothing — a
    /// posting of millions per query. Here the cold blob is walked with a
    /// cursor and merged with the hot tier only up to `cap`. Callers pass a
    /// cap with headroom over their scan budget, so what they examine is
    /// unchanged. Any other query shape is answered by `find_grouped` in full.
    pub fn find_grouped_capped(&self, groups: &[Vec<String>], cap: usize) -> Vec<FileId> {
        if let [g] = groups {
            if let [t] = g.as_slice() {
                return self.materialize_prefix(token_hash(t), cap);
            }
        }
        self.find_grouped(groups)
    }

    /// The first `cap` ids of merge(cold − pending, hot), ascending, deduped.
    /// The same result as a prefix of `materialize`, without decoding the rest.
    fn materialize_prefix(&self, th: TokenHash, cap: usize) -> Vec<FileId> {
        self.merge_tiers_locked(th, cap).unwrap_or_default()
    }

    /// merge(cold − pending, hot) up to `cap` ids, with all three guards held
    /// for the whole walk. `None` iff the keyword is in neither cold nor hot.
    fn merge_tiers_locked(&self, th: TokenHash, cap: usize) -> Option<Vec<FileId>> {
        // Lock order cold → hot → pending, as everywhere.
        let cold = self.cold.get(th);
        let hot = self.hot.get(&th);
        if cold.is_none() && hot.is_none() {
            return None;
        }
        let pend = self.pending_removals.get(&th);
        let hv: &[FileId] = hot.as_ref().map_or(&[], |h| h.value().as_slice());
        let pv: &[FileId] = pend.as_ref().map_or(&[], |p| p.value().as_slice());
        let mut cur = cold.as_ref().and_then(|c| posting_codec::PostingCursor::new(c.value()));
        let hint = cur.as_ref().map_or(0, |c| c.len()) + hv.len();
        let mut out = Vec::with_capacity(cap.min(hint));
        let mut j = 0usize;
        while out.len() < cap {
            let c = cur.as_ref().and_then(|c| c.peek());
            let h = hv.get(j).copied();
            let next = match (c, h) {
                (None, None) => break,
                (Some(a), Some(b)) if b.0 < a.0 => {
                    j += 1;
                    b
                }
                (Some(a), b) => {
                    if b == Some(a) {
                        j += 1; // in both tiers: once
                    } else if pv.binary_search(&a).is_ok() {
                        // In the blob but deleted, and not re-added (hot and
                        // pending are disjoint): skip.
                        cur.as_mut().unwrap().bump();
                        continue;
                    }
                    cur.as_mut().unwrap().bump();
                    a
                }
                (None, Some(b)) => {
                    j += 1;
                    b
                }
            };
            out.push(next);
        }
        Some(out)
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
            let cold_ref = self.cold.get(*h);
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
        self.cold
            .for_each_blob(|b| total += posting_codec::decoded_len(b).unwrap_or(0) as u64);
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
        let idvec_hdr = std::mem::size_of::<Vec<FileId>>() as u64;
        let id_sz = std::mem::size_of::<FileId>() as u64;
        let key_sz = std::mem::size_of::<TokenHash>() as u64;

        // data = compressed cold blobs (exact-sized) + raw hot Vecs (un-merged tier)
        let (cold_data, cold_index) = self.cold.bytes();
        let mut data = cold_data;
        for e in self.hot.iter() {
            data += e.value().capacity() as u64 * id_sz;
        }
        for e in self.pending_removals.iter() {
            data += e.value().capacity() as u64 * id_sz;
        }
        // headers = one Vec header per cold key + one per hot key
        // (the cold tier's sorted key and offset arrays count here: 8 bytes a
        // keyword, all it spends per keyword besides the blob itself)
        let headers = cold_index
            + (self.hot.len() + self.pending_removals.len()) as u64 * idvec_hdr;
        // slots = the deferred maps' table capacity (the cold tier has none)
        let slots = (self.hot.capacity() + self.pending_removals.capacity()) as u64
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
        // One compactor at a time: the cold blob is decoded, merged and encoded
        // WITHOUT its lock held (below), which is only sound if nobody else
        // rewrites it meanwhile. compact() is the only writer of `cold`.
        let _one = self.compact_lock.lock().unwrap_or_else(|e| e.into_inner());

        // Drain BOTH deferred tiers into the compressed cold blobs in bulk: the hot
        // additions and the pending removals. Each affected keyword costs exactly
        // one decode + one merge/filter + one encode per cycle, instead of one per
        // individual add/remove on the hot path — that is what keeps publish and
        // disconnect traffic off the codec.
        let mut keys: Vec<TokenHash> = self.hot.iter().map(|e| *e.key()).collect();
        keys.extend(self.pending_removals.iter().map(|e| *e.key()));
        keys.sort_unstable();
        keys.dedup();

        // One cold shard at a time: its keys come out of the sort grouped.
        keys.sort_unstable_by_key(|&th| (cold_store::shard_of(th), th));
        let mut dropped = 0usize;
        // (A manual split rather than slice::chunk_by, which needs Rust 1.77;
        // the crate's minimum is 1.75.)
        let mut start = 0usize;
        while start < keys.len() {
            let shard = cold_store::shard_of(keys[start]);
            let end = keys[start..]
                .iter()
                .position(|&k| cold_store::shard_of(k) != shard)
                .map_or(keys.len(), |n| start + n);
            dropped += self.compact_shard(&keys[start..end]);
            start = end;
        }

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

        dropped
    }

    /// Fold the deferred sets of `keys` (all in one cold shard, sorted) into
    /// that shard. Returns the keywords removed.
    fn compact_shard(&self, keys: &[TokenHash]) -> usize {
        // SNAPSHOT the deferred sets; do not take them out yet. They are
        // subtracted only after the new cold blobs are in place, so a search
        // running meanwhile always sees each id in at least one tier.
        //
        // It used to remove them first and write cold last: between the two a
        // search for the keyword missed every file added since the last cycle
        // and returned every one removed since.
        struct Snap {
            th: TokenHash,
            hv: Vec<FileId>,
            pend: Vec<FileId>,
        }
        let mut snaps: Vec<Snap> = Vec::with_capacity(keys.len());
        let mut updates: Vec<(TokenHash, Option<Vec<u8>>)> = Vec::with_capacity(keys.len());
        for &th in keys {
            let hv: Vec<FileId> = self.hot.get(&th).map(|v| v.clone()).unwrap_or_default();
            let pend: Vec<FileId> = self
                .pending_removals
                .get(&th)
                .map(|v| v.clone())
                .unwrap_or_default();
            if hv.is_empty() && pend.is_empty() {
                continue;
            }
            // Decode under a short read lock; merge and encode with none.
            let cold_ids = self
                .cold
                .get(th)
                .and_then(|c| posting_codec::decode(c.value()))
                .unwrap_or_default();
            let merged = merge_tiers(&cold_ids, &hv, &pend);
            // A keyword whose posting became empty is removed here, rather than
            // by a pass over the whole cold tier afterwards.
            let blob = (!merged.is_empty()).then(|| posting_codec::encode(&merged));
            updates.push((th, blob));
            snaps.push(Snap { th, hv, pend });
        }
        if updates.is_empty() {
            return 0;
        }

        // The new shard is built while searches keep reading the old one, and
        // swapped in under the shard's write lock. The snapshots are subtracted
        // while that lock is still held, so a reader (which takes cold before
        // hot) never sees hot already trimmed and cold not yet replaced.
        // Lock order cold → hot → pending, as every reader.
        self.cold.rebuild(cold_store::shard_of(keys[0]), &updates, || {
            for Snap { th, hv, pend } in &snaps {
                if !pend.is_empty() {
                    if let Some(mut p) = self.pending_removals.get_mut(th) {
                        // Deletions marked meanwhile stay pending for next cycle.
                        p.retain(|id| pend.binary_search(id).is_err());
                    }
                }
                if hv.is_empty() {
                    continue;
                }
                // The hot guard is held until the gone ids are in pending
                // (hot → pending, the order add_file also respects): released
                // earlier, an add_file of the same id in between would put it
                // back in hot before it lands in pending, and the two tiers
                // would no longer be disjoint.
                let mut hot_guard = self.hot.get_mut(th);
                let gone: Vec<FileId> = match hot_guard.as_mut() {
                    Some(h) => {
                        // An id from the snapshot no longer in hot was removed
                        // while we merged; it is in the new blob now. remove_file
                        // marks a deletion for cold only when the keyword already
                        // had a cold blob, so for a new keyword nothing else
                        // would ever take it out: mark it here.
                        let gone = hv
                            .iter()
                            .filter(|id| h.binary_search(id).is_err())
                            .copied()
                            .collect();
                        // Ids added meanwhile stay in hot for the next cycle.
                        h.retain(|id| hv.binary_search(id).is_err());
                        gone
                    }
                    None => hv.clone(),
                };
                if !gone.is_empty() {
                    let mut p = self.pending_removals.entry(*th).or_default();
                    for id in gone {
                        if let Err(pos) = p.binary_search(&id) {
                            p.insert(pos, id);
                        }
                    }
                }
                drop(hot_guard);
            }
        })
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
    fn merge_tiers_matches_the_binary_search_version() {
        fn reference(cold: &[FileId], hot: &[FileId], pend: &[FileId]) -> Vec<FileId> {
            let mut all: Vec<FileId> = cold
                .iter()
                .filter(|id| pend.binary_search(id).is_err() || hot.binary_search(id).is_ok())
                .copied()
                .chain(hot.iter().copied())
                .collect();
            all.sort_unstable();
            all.dedup();
            all
        }
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut rnd = |n: u32| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as u32
        };
        for _ in 0..500 {
            let span = 1 + rnd(400);
            let mut pick = |p: u32| -> Vec<FileId> {
                (0..span).filter(|_| rnd(100) < p).map(FileId).collect()
            };
            let cold = pick(50);
            let hot = pick(20);
            // pending is disjoint from hot, as the index keeps it.
            let pend: Vec<FileId> = pick(30)
                .into_iter()
                .filter(|id| hot.binary_search(id).is_err())
                .collect();
            assert_eq!(merge_tiers(&cold, &hot, &pend), reference(&cold, &hot, &pend));
        }
    }

    #[test]
    fn the_ascii_fast_path_folds_like_the_general_one() {
        let general = |s: &str| -> String {
            let mut out = String::new();
            for c in s.chars() {
                if let Some(f) = fold_char(c) {
                    out.extend(f.to_lowercase());
                }
            }
            out
        };
        let all_ascii: String = (0u8..128).map(char::from).collect();
        assert_eq!(fold_for_match(&all_ascii), general(&all_ascii));
        for s in ["Ubuntu-24.04_Desktop.ISO", "", "MiXeD CaSe 123 !@#"] {
            assert_eq!(fold_for_match(s), general(s));
        }
        // Non-ASCII still takes the general path.
        assert_eq!(fold_for_match("Château"), "chateau");
    }

    #[test]
    fn a_search_during_compact_never_misses_a_live_file() {
        // compact() used to take the hot and pending sets out before writing the
        // new cold blob; a search in between missed every file added since the
        // last cycle. Each round here publishes new files (even ids) and
        // compacts, while a reader checks that everything published so far is
        // found, and a writer churns odd ids in and out.
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        use std::sync::Arc;
        let idx = Arc::new(KeywordIndex::new());
        // A large cold posting makes each decode + encode take a while.
        for i in 0..100_000u32 {
            idx.add_file(FileId(i * 2), "alpha.bin");
        }
        idx.compact();
        let published = Arc::new(AtomicU32::new(100_000));
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let (idx, stop, published) =
                (Arc::clone(&idx), Arc::clone(&stop), Arc::clone(&published));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let n = published.load(Ordering::Acquire);
                    let r = idx.find_intersection(&["alpha".to_string()]);
                    let even = r.iter().filter(|id| id.0 % 2 == 0 && id.0 / 2 < n).count();
                    assert_eq!(even as u32, n, "a live file went missing mid-compact");
                    assert!(r.windows(2).all(|w| w[0] < w[1]), "sorted, no duplicates");
                }
            })
        };
        let writer = {
            let (idx, stop) = (Arc::clone(&idx), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut k = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    let id = FileId((k % 5000) * 2 + 1);
                    if k % 3 == 0 {
                        idx.add_file(id, "alpha.bin");
                    } else {
                        idx.remove_file(id, "alpha.bin");
                    }
                    k += 1;
                }
            })
        };
        for _ in 0..100 {
            let n = published.load(Ordering::Relaxed);
            for i in n..n + 100 {
                idx.add_file(FileId(i * 2), "alpha.bin");
            }
            published.store(n + 100, Ordering::Release);
            idx.compact();
        }
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        reader.join().unwrap();

        // Settled: one more compact changes nothing visible and leaves no
        // deferred work behind.
        let before = idx.find_intersection(&["alpha".to_string()]);
        idx.compact();
        assert_eq!(idx.find_intersection(&["alpha".to_string()]), before);
        let (_, hot, pend) = idx.tier_sizes();
        assert_eq!((hot, pend), (0, 0));
    }

    #[test]
    fn a_capped_single_word_lookup_is_a_prefix_of_the_full_one() {
        // Cold ids, hot additions interleaved with them, an id in both tiers
        // and deleted ids: the capped walk must agree with the full lookup.
        let idx = KeywordIndex::new();
        for i in 0..500u32 {
            idx.add_file(FileId(i * 4), "delta.bin");
        }
        idx.compact();
        for i in 0..200u32 {
            idx.add_file(FileId(i * 6 + 1), "delta.bin"); // hot only
        }
        idx.add_file(FileId(40), "delta.bin"); // already cold
        for i in 0..50u32 {
            idx.remove_file(FileId(i * 8), "delta.bin"); // pending
        }
        idx.remove_file(FileId(7), "delta.bin"); // hot removal
        let groups = vec![vec!["delta".to_string()]];
        let full = idx.find_grouped(&groups);
        for cap in [0usize, 1, 5, 37, 100, 300, full.len(), full.len() + 10] {
            let got = idx.find_grouped_capped(&groups, cap);
            assert_eq!(got, full[..cap.min(full.len())].to_vec(), "cap {cap}");
        }
        // Not a single word: the full answer.
        let two = vec![vec!["delta".to_string()], vec!["bin".to_string()]];
        assert_eq!(idx.find_grouped_capped(&two, 3), idx.find_grouped(&two));
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
