//! Mandatory content filter (SPEC.md §7.6).
//!
//! Three layers, each independently sufficient to drop a file. Run on every
//! OFFERFILES record before any indexing decision. The filter cannot be
//! disabled in this build — `ContentFilter::new` always returns an active
//! filter.

mod age_pattern;
pub mod layer2_terms;
mod jargon;
pub mod ipfilter;
pub mod geoip;

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Layer 1 — jargon list, loaded at runtime (not shipped in source)
    L1Jargon,
    /// Layer 2 — age + sexual context co-occurrence
    L2AgePattern,
    /// Layer 3 — hash blocklist match
    L3HashBlock,
    /// Operator-supplied extra terms (additive only — never overrides L1/L2)
    L4Extra,
    /// Layer 5 — "poisoned index" hash list. Blocks like any other layer, but
    /// carries NO accusation against the publisher.
    ///
    /// eD2k indexes are routinely poisoned: one hash is advertised under a dozen
    /// unrelated names (a 700 MB file claiming to be at once a Beatles
    /// compilation, Pulp Fiction and an Office installer). Such a file is junk
    /// and should not be indexed — but the client offering it is an ordinary
    /// user who downloaded a decoy, not a publisher of illegal material, and
    /// must not be counted toward a CSAM ban.
    ///
    /// Keeping these hashes in the CSAM list conflated the two: every decoy
    /// pushed real users toward `publisher_attempt_disconnect_threshold`, and it
    /// polluted a list whose whole value is that every entry means one specific
    /// thing — the list is shared with other operators, with its provenance
    /// stated.
    L5Poison,
}

impl Layer {
    /// Whether a block at this layer counts against the publisher: toward
    /// `csam_attempts` (session disconnect) and toward the distinct-file ban
    /// threshold.
    ///
    /// This is the ONLY place the distinction lives. Every caller that
    /// increments a publisher counter must ask here rather than testing the
    /// layer itself, so a future layer cannot silently inherit the wrong
    /// treatment by being added to a match arm somewhere.
    pub fn counts_against_publisher(&self) -> bool {
        !matches!(self, Layer::L5Poison)
    }

    /// Short stable key for `block_stats` counters and log fields.
    pub fn stat_key(&self) -> &'static str {
        match self {
            Layer::L1Jargon => "csam_L1_jargon",
            Layer::L2AgePattern => "csam_L2_age",
            Layer::L3HashBlock => "csam_L3_hash",
            Layer::L4Extra => "csam_L4_extra",
            Layer::L5Poison => "poison_L5_hash",
        }
    }
}

#[derive(Debug, Clone)]
pub enum FilterResult {
    /// File passed all checks; safe to index.
    Allow,
    /// File matched a content filter at the given layer; do not index.
    ///
    /// The second field says WHAT matched: the offending term for L1/L4, a
    /// rendered age token ("age 12 (yo)") for L2, or "hash" for L3. Carrying the
    /// reason is what makes a block reviewable — with only the layer, a reviewer
    /// has to re-derive the cause from the filename and can get it wrong (an L3
    /// masquerade under an innocent name looks exactly like a term false
    /// positive). It also lets a review group thousands of blocks by their few
    /// dozen causes.
    Block(Layer, String),
}

impl FilterResult {
    pub fn is_blocked(&self) -> bool {
        matches!(self, FilterResult::Block(..))
    }
}

pub struct ContentFilter {
    /// Hash blocklist (Layer 3). Always-on; an empty list at startup is OK
    /// for development builds, refused for `public=true` deployments
    /// (enforced in `main.rs`, not here). Wrapped in ArcSwap so the blocklist
    /// file can be hot-reloaded (mtime watcher in main.rs) without a restart.
    hash_blocklist: arc_swap::ArcSwap<HashSet<[u8; 16]>>,

    /// Operator-extension term list (Layer 4). Additive; cannot override L1/L2.
    /// Wrapped in ArcSwap so the operator can hot-reload the terms file
    /// (e.g. /etc/ed2k-server/csam_terms_extra.txt) without restarting — the
    /// mtime watcher in main.rs calls `reload_extra_terms`.
    extra_terms: arc_swap::ArcSwap<Vec<String>>,

    /// Layer 1 jargon terms, loaded at runtime from an operator-supplied file
    /// (the list is NOT shipped in source — see jargon.rs). Empty = L1 inactive,
    /// which is fine; L2-L4 still run. Hot-reloadable like L4. The matching
    /// logic (substring for long terms, word-bounded for short) lives in
    /// `jargon::matches_terms`; this only holds the (pre-lowercased) list.
    jargon_terms: arc_swap::ArcSwap<Vec<String>>,

    /// Layer 2's vocabulary, hot-swappable like the term files.
    ///
    /// It used to be compiled in, which meant every addition — and they arrive
    /// almost daily from review windows — needed a rebuild and a restart. A
    /// restart drops every connected client, so the server was never observed at
    /// a long uptime.
    ///
    /// Defaults to exactly what was compiled in, so an installation with no file
    /// behaves identically. See `layer2_terms::Layer2Terms`.
    layer2_terms: arc_swap::ArcSwap<layer2_terms::Layer2Terms>,

    /// Filter-only hash list (Layer 5, config key `hash_filter`). Blocked, but
    /// never held against the publisher — see `Layer::L5Poison`. Separate from
    /// `hash_blocklist` on purpose: the two lists mean different things and are
    /// curated, exported and shared differently. Hot-reloadable like the ban
    /// list.
    hash_filter_set: arc_swap::ArcSwap<HashSet<[u8; 16]>>,

    /// Hash whitelist - verified false positives (Layer 3 override).
    /// Any hash here bypasses the hash layers (3 and 5), but NOT the term and
    /// age layers (1, 2, 4).
    ///
    /// Hot-reloadable like the blocklist. It used to load once at startup on the
    /// reasoning that false-positive overrides change rarely — but the whole
    /// point of this list is to un-block something that is being wrongly blocked
    /// RIGHT NOW, and making that wait for a restart is backwards. It is the one
    /// list where the delay is measured in a user's inability to publish a legal
    /// file.
    hash_whitelist: arc_swap::ArcSwap<HashSet<[u8; 16]>>,
}

impl ContentFilter {
    /// Construct a filter. Hardcoded layers are always active; only the
    /// supplementary lists are configurable.
    pub fn new() -> Self {
        Self {
            hash_blocklist: arc_swap::ArcSwap::from_pointee(HashSet::new()),
            extra_terms: arc_swap::ArcSwap::from_pointee(Vec::new()),
            jargon_terms: arc_swap::ArcSwap::from_pointee(Vec::new()),
            layer2_terms: arc_swap::ArcSwap::from_pointee(
                layer2_terms::Layer2Terms::default(),
            ),
            hash_filter_set: arc_swap::ArcSwap::from_pointee(HashSet::new()),
            hash_whitelist: arc_swap::ArcSwap::from_pointee(HashSet::new()),
        }
    }

    /// Heap bytes held by the content filter (for /api/memsize): the CSAM hash
    /// blocklist/whitelist sets and the term lists.
    pub fn size_bytes(&self) -> u64 {
        let hsz = std::mem::size_of::<[u8; 16]>() as u64 + 1; // + hashbrown ctrl byte
        let bl = self.hash_blocklist.load();
        let mut n = bl.capacity() as u64 * hsz;
        n += self.hash_filter_set.load().capacity() as u64 * hsz;
        n += self.hash_whitelist.load().capacity() as u64 * hsz;
        for list in [self.extra_terms.load(), self.jargon_terms.load()] {
            n += list.capacity() as u64 * std::mem::size_of::<String>() as u64;
            for t in list.iter() {
                n += t.capacity() as u64;
            }
        }
        n
    }

    pub fn with_hash_blocklist(self, hashes: impl IntoIterator<Item = [u8; 16]>) -> Self {
        // Builder: merge into the current (normally empty) blocklist.
        let mut set: HashSet<[u8; 16]> = (*self.hash_blocklist.load_full()).clone();
        set.extend(hashes);
        self.hash_blocklist.store(std::sync::Arc::new(set));
        self
    }

    /// Hot-swap the Layer 3 hash blocklist at runtime (no restart). Atomic:
    /// readers in `check()` see either the old or new set. Called by the
    /// blocklist-file mtime watcher in main.rs.
    pub fn reload_hash_blocklist(&self, hashes: impl IntoIterator<Item = [u8; 16]>) {
        let set: HashSet<[u8; 16]> = hashes.into_iter().collect();
        self.hash_blocklist.store(std::sync::Arc::new(set));
    }

    /// Builder: merge into the Layer 5 filter-only hash list.
    pub fn with_hash_filter(self, hashes: impl IntoIterator<Item = [u8; 16]>) -> Self {
        let mut set: HashSet<[u8; 16]> = (*self.hash_filter_set.load_full()).clone();
        set.extend(hashes);
        self.hash_filter_set.store(std::sync::Arc::new(set));
        self
    }

    /// Hot-swap Layer 2's vocabulary.
    ///
    /// Callers must have PARSED successfully first: a failed read or a malformed
    /// file must keep the current lists, exactly as the hash lists do. Handing a
    /// half-parsed value here would silently disable whole categories.
    pub fn reload_layer2_terms(&self, terms: layer2_terms::Layer2Terms) {
        self.layer2_terms.store(std::sync::Arc::new(terms));
    }

    /// Entry count, for the startup log and the web panel.
    pub fn layer2_terms_size(&self) -> usize {
        self.layer2_terms.load().len()
    }

    /// Builder: replace Layer 2's vocabulary before the filter is shared.
    pub fn with_layer2_terms(self, terms: layer2_terms::Layer2Terms) -> Self {
        self.layer2_terms.store(std::sync::Arc::new(terms));
        self
    }

    /// Hot-swap the Layer 5 filter-only list at runtime, like the ban list.
    pub fn reload_hash_filter(&self, hashes: impl IntoIterator<Item = [u8; 16]>) {
        let set: HashSet<[u8; 16]> = hashes.into_iter().collect();
        self.hash_filter_set.store(std::sync::Arc::new(set));
    }

    /// Is this hash on either hash list (and not whitelisted)?
    ///
    /// Cheap enough for the serving path: two `ArcSwap` loads and two hash-set
    /// probes, no filename work at all.
    ///
    /// Exists because the hash lists must take effect on SEARCH RESULTS, not
    /// only on publication. Adding a hash stops the file being re-indexed, but
    /// copies already in the index keep being served until something evicts
    /// them — which for a live file means never, since its sources keep
    /// refreshing it. Before this the only way to make a takedown or a decoy
    /// actually disappear was to restart the server and lose every connected
    /// user.
    ///
    /// Applied at the point of serving rather than by sweeping the index: it is
    /// instant, it costs nothing when the lists are empty, and it is reversible
    /// — removing a hash from the list brings the file back without anyone
    /// having to re-publish it.
    pub fn hash_is_listed(&self, file_hash: &[u8; 16]) -> bool {
        if self.hash_whitelist.load().contains(file_hash) {
            return false;
        }
        self.hash_blocklist.load().contains(file_hash)
            || self.hash_filter_set.load().contains(file_hash)
    }

    /// Same decision for a caller that has only a hash.
    ///
    /// `name` is resolved from the index by the caller; when the file is not in
    /// the index there is no name to test and only the hash lists apply, which
    /// is correct — a hash-only query for an unknown file cannot be answered
    /// from a filename that does not exist.
    pub fn is_withheld_opt(&self, file_hash: &[u8; 16], filename: Option<&str>) -> bool {
        match filename {
            Some(n) => self.is_withheld(file_hash, n),
            None => self.hash_is_listed(file_hash),
        }
    }

    /// Should this record be withheld from search results and source lists?
    ///
    /// Runs the FULL filter, not just the hash lists, and that is the point.
    ///
    /// A file enters the index when nothing matches it. If a term is added
    /// later — and terms are added constantly, from exactly the review data this
    /// server produces — the copy already indexed keeps being served. It is
    /// caught again on every re-publish, so it appears in the review export
    /// faithfully, while remaining in the index and in every search result. The
    /// only thing that removed it was an operator pasting its hash into
    /// `hash_banlist.txt` by hand.
    ///
    /// That made the term lists retroactive on paper and prospective in
    /// practice: adding a marker stopped NEW copies and left old ones serving
    /// indefinitely, since a live file's sources keep refreshing it and eviction
    /// never comes.
    ///
    /// Cost is one `to_lowercase` plus the term scan per served record. Real
    /// filenames are short, the scan exits on the first match, and the serving
    /// paths already cap how many records they touch (200 results, 30 UDP
    /// sources), so this is bounded work on a bounded set — unlike the publish
    /// path, which runs the same check on every offered file anyway.
    pub fn is_withheld(&self, file_hash: &[u8; 16], filename: &str) -> bool {
        !matches!(self.check(file_hash, filename), FilterResult::Allow)
    }

    /// Number of filter-only hashes loaded (for startup logging / web panel).
    pub fn hash_filter_size(&self) -> usize {
        self.hash_filter_set.load().len()
    }

    pub fn with_hash_whitelist(self, hashes: impl IntoIterator<Item = [u8; 16]>) -> Self {
        let mut set: HashSet<[u8; 16]> = (*self.hash_whitelist.load_full()).clone();
        set.extend(hashes);
        self.hash_whitelist.store(std::sync::Arc::new(set));
        self
    }

    pub fn with_extra_terms(self, terms: impl IntoIterator<Item = String>) -> Self {
        // Builder: append to whatever is currently stored (normally empty at
        // construction). Normalization is shared with the hot-reload path.
        let mut v: Vec<String> = (*self.extra_terms.load_full()).clone();
        v.extend(Self::normalize_terms(terms));
        self.extra_terms.store(Arc::new(v));
        self
    }

    /// Normalize operator terms: trim, lowercase, drop empties. Shared by the
    /// builder and the hot-reload path so both apply identical rules.
    fn normalize_terms(terms: impl IntoIterator<Item = String>) -> Vec<String> {
        terms
            .into_iter()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect()
    }

    /// Hot-swap the Layer 4 term list at runtime (no restart). Atomic: readers
    /// in `check()` see either the old or the new list, never a partial one.
    /// Called by the extra-terms-file mtime watcher in main.rs.
    pub fn reload_extra_terms(&self, terms: impl IntoIterator<Item = String>) {
        self.extra_terms
            .store(Arc::new(Self::normalize_terms(terms)));
    }

    /// Builder: load the Layer 1 jargon list (normalized like L4). Replaces the
    /// formerly hardcoded list; an empty list leaves L1 inactive.
    pub fn with_jargon_terms(self, terms: impl IntoIterator<Item = String>) -> Self {
        let mut v: Vec<String> = (*self.jargon_terms.load_full()).clone();
        v.extend(Self::normalize_terms(terms));
        self.jargon_terms.store(Arc::new(v));
        self
    }

    /// Hot-swap the Layer 1 jargon list at runtime (no restart), like L4.
    pub fn reload_jargon_terms(&self, terms: impl IntoIterator<Item = String>) {
        self.jargon_terms
            .store(Arc::new(Self::normalize_terms(terms)));
    }

    /// Number of Layer 1 jargon terms loaded (for startup logging).
    pub fn jargon_terms_count(&self) -> usize {
        self.jargon_terms.load().len()
    }

    /// Number of hashes in blocklist (for startup logging).
    /// Whitelisted hashes (verified false positives, Layer 3 override).
    pub fn whitelist_size(&self) -> usize {
        self.hash_whitelist.load().len()
    }

    /// Hot-swap the false-positive whitelist at runtime.
    ///
    /// Unlike the block/poison lists, an EMPTY reload is meaningful here and is
    /// applied as-is: removing every entry is how an operator retracts an
    /// override they no longer believe in. The caller is responsible for not
    /// calling this with an empty set because a file failed to read — see the
    /// watcher in main.rs, which keeps the current list on any read error.
    pub fn reload_hash_whitelist(&self, hashes: impl IntoIterator<Item = [u8; 16]>) {
        let set: HashSet<[u8; 16]> = hashes.into_iter().collect();
        self.hash_whitelist.store(std::sync::Arc::new(set));
    }

    pub fn blocklist_size(&self) -> usize {
        self.hash_blocklist.load().len()
    }

    /// Number of extra operator-supplied terms (for startup logging).
    pub fn extra_terms_count(&self) -> usize {
        self.extra_terms.load().len()
    }

    /// Check a candidate file. Layer order is fastest-rejection-first.
    /// Undo UTF-8 that was decoded as Latin-1 and re-encoded, once or twice.
    ///
    /// Filenames travel through clients that guess at encodings, and the damage
    /// is reversible because it is a pure byte transformation: text encoded
    /// UTF-8, read as Latin-1, encoded UTF-8 again. Each round doubles the
    /// leading bytes of every non-ASCII character, so `幼女` arrives as
    /// `Ã¥Â¹Â¼Ã¥Â¥Â³` and no CJK term can match it — the bytes are no longer
    /// that character. 494 names in one review window carried this damage.
    ///
    /// STRICT decoding, deliberately. A lossy variant was tried and rejected: by
    /// dropping bytes it cannot read it turns ordinary names into different
    /// ordinary names — "España" into "Espaa", a Japanese title into ".avi" —
    /// and scanning those for terms means scanning something the user never
    /// wrote.
    ///
    /// LIMIT: names whose mojibake is itself lossy, where a client substituted
    /// U+FFFD before re-encoding, are NOT recovered — their byte sequence is not
    /// valid UTF-8 at any depth. Those need their hash listed instead.
    ///
    /// Returns None when nothing changes, so the caller skips the extra scan for
    /// the overwhelming majority of names.
    fn undo_mojibake(name: &str) -> Option<String> {
        fn one_round(s: &str) -> Option<String> {
            if !s.chars().any(|c| c as u32 >= 0x80) {
                return None; // pure ASCII cannot be mojibake
            }
            // Every char must have come from a single byte for the Latin-1
            // round-trip to be the explanation.
            let bytes: Option<Vec<u8>> = s
                .chars()
                .map(|c| if (c as u32) < 0x100 { Some(c as u8) } else { None })
                .collect();
            let decoded = String::from_utf8(bytes?).ok()?;
            (decoded != s).then_some(decoded)
        }

        let first = one_round(name)?;
        // Two rounds are common — the damage often happens once on the way in
        // and once on the way out. Stop there: a third round on legitimate text
        // starts producing plausible-looking garbage.
        Some(one_round(&first).unwrap_or(first))
    }

    pub fn check(&self, file_hash: &[u8; 16], filename: &str) -> FilterResult {
        // Whitelist first, and it now overrides EVERY layer rather than only the
        // hash lists.
        //
        // The old rule bypassed hash matches only, on the theory that a
        // false-positive override should not switch off content matching. Three
        // days of live review showed that gets it backwards: the entries that
        // most need overriding are caught by TERM, not by hash — song titles
        // that happen to be a jargon word ("Motorhead - Jailbait", an Ennio
        // Morricone track), and Song-dynasty paediatric treatises whose title
        // contains a CJK marker. Whitelisting those changed nothing, because
        // L1/L4 re-blocked them on the very next publish, which made the list
        // useless for the one class of mistake that actually occurs.
        //
        // An operator putting a hash here has looked at the file and ruled it
        // legal. That ruling now stands against every layer.
        if self.hash_whitelist.load().contains(file_hash) {
            return FilterResult::Allow;
        }

        // Hash checks — O(1), fastest rejection.
        if self.hash_blocklist.load().contains(file_hash) {
            return FilterResult::Block(Layer::L3HashBlock, "hash".to_string());
        }

        // Layer 5 — poisoned index. Deliberately BEFORE the term layers: the
        // operator has already ruled on this hash, and a decoy usually carries a
        // spam name stuffed with porn tags that L1/L4 would fire on. Letting a
        // term layer win would re-attach the CSAM accusation the poison list
        // exists to detach, and would count an ordinary downloader toward a ban.
        if self.hash_filter_set.load().contains(file_hash) {
            return FilterResult::Block(Layer::L5Poison, "poison".to_string());
        }

        // Normalize for term matching.
        let lowered = filename.to_lowercase();

        // Layer 1: jargon (list loaded at runtime; empty = inactive)
        // One snapshot of the Layer 2 vocabulary for the whole call. Taking it
        // once matters: a reload between the mojibake pass and the main pass
        // would otherwise let a name be tested against two different
        // vocabularies, and the reason string would name a term that is no
        // longer there.
        let l2 = self.layer2_terms.load();

        // Mojibake pass: if the name is recoverable text, test the recovered form
        // too. Only the non-ASCII terms can gain anything — the ASCII part of a
        // mangled name is untouched and the scans below already cover it — but
        // those are exactly the terms this damage hides.
        if let Some(recovered) = Self::undo_mojibake(filename) {
            let rec_lower = recovered.to_lowercase();
            let jt = self.jargon_terms.load();
            if let Some(term) = jargon::matches_terms(&rec_lower, &jt) {
                return FilterResult::Block(Layer::L1Jargon, format!("{term} (mojibake)"));
            }
            let ex = self.extra_terms.load();
            if let Some(term) = jargon::matches_terms(&rec_lower, &ex) {
                return FilterResult::Block(Layer::L4Extra, format!("{term} (mojibake)"));
            }
            if let Some(reason) = age_pattern::matches_layer2(&recovered, &rec_lower, &l2) {
                return FilterResult::Block(Layer::L2AgePattern, format!("{reason} (mojibake)"));
            }
        }

        // Bind the guard first: the returned &str borrows from it, and a guard
        // created inline inside the `if let` condition is a temporary whose
        // lifetime rules changed between editions. An explicit binding is correct
        // under every edition.
        let jargon_terms = self.jargon_terms.load();
        if let Some(term) = jargon::matches_terms(&lowered, &jargon_terms) {
            return FilterResult::Block(Layer::L1Jargon, term.to_string());
        }

        // Layer 2: age pattern + sexual context
        if let Some(reason) = age_pattern::matches_layer2(filename, &lowered, &l2) {
            return FilterResult::Block(Layer::L2AgePattern, reason);
        }

        // DISABLED: animal + act co-occurrence.
        //
        // The idea was to catch bestiality written in plain English, since the
        // operator zoo terms are fixed strings that a sample defeated by putting
        // the animal and the act several words apart. It was validated against
        // 26 hand-written titles with zero false positives and shipped.
        //
        // The first live window then produced 234 matches of which **8% were
        // right**. The hand-written sample simply did not contain what the index
        // actually holds:
        //
        //   * "Raging Stallion" is a large gay porn studio — 48 files;
        //   * "horse hung", "donkey dick", "hung like a horse" are metaphors for
        //     size, and every one of them sits beside a sexual term — 30 files;
        //   * "Bad Dragon" makes animal-shaped dildos — 9 files;
        //   * "Jesse Pony" and "Dark Stallion" are performer names — 15 files.
        //
        // None of these can be excluded by narrowing the lists further: the
        // animal words ARE the studio names and the metaphors, and the acts are
        // ordinary porn vocabulary. A guard list would have to enumerate every
        // studio and performer using an animal name, which is unbounded.
        //
        // Kept as dead code rather than deleted, because the ONE case it caught
        // that nothing else did — "Zoo Party ... A Big White Horse", "Sonia
        // Fucking With Grey Stallion" — is real, and a future version keyed on
        // something stronger than word co-occurrence (a phrase like "fucked by a
        // horse", or animal + act with no human name in the title) could work.
        // The measurement above is why the naive form does not.
        #[allow(dead_code)]
        {
            let _ = age_pattern::matches_zoo_cooccurrence(&lowered, &l2);
        }

        // Layer 4 (operator extras) — snapshot the hot-swappable list.
        //
        // Uses the SAME matcher as Layer 1. It used to call `str::contains`
        // directly, so none of the length-based boundary rules applied to it:
        // that is how a six-character L4 term came to fire inside "fibrosis" and
        // block medical papers. Sharing the matcher is what keeps the two lists
        // from drifting apart again.
        let extra = self.extra_terms.load();
        if let Some(term) = jargon::matches_terms(&lowered, &extra) {
            return FilterResult::Block(Layer::L4Extra, term.to_string());
        }

        FilterResult::Allow
    }

    /// Load a hash list file. Format: one hex MD4 per line, optional
    /// `;`-comment after the hash. Lines starting with # are skipped.
    pub fn load_hash_file(path: &Path) -> std::io::Result<Vec<[u8; 16]>> {
        // Read bytes and decode leniently instead of `read_to_string`.
        //
        // This file legitimately carries eD2k FILENAMES in its `;` comments (that
        // is how a reviewer knows what a hash refers to), and eD2k filenames are
        // arbitrary bytes — any encoding, or none. A strict UTF-8 read fails on the
        // first bad byte and returns Err for the WHOLE file, which silently
        // disables Layer 3 entirely: observed live as
        // "blocklist load failed ... stream did not contain valid UTF-8" with
        // entries = 0 while thousands of hashes sat in the file.
        //
        // Lossy decoding replaces bad sequences with U+FFFD. The payload we parse
        // is ASCII hex, so it is unaffected; only comment text can be mangled, and
        // a mangled comment is infinitely better than a disabled blocklist.
        let bytes = std::fs::read(path)?;
        let content = String::from_utf8_lossy(&bytes);
        let mut hashes = Vec::new();
        for (lineno, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Strip ; comment
            let hex_part = trimmed.split(';').next().unwrap_or("").trim();
            match hex::decode(hex_part) {
                Ok(bytes) if bytes.len() == 16 => {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&bytes);
                    hashes.push(arr);
                }
                Ok(_) => warn!(
                    "{}:{}: hash must be 16 bytes (32 hex chars), skipping",
                    path.display(),
                    lineno + 1
                ),
                Err(e) => warn!(
                    "{}:{}: invalid hex: {}, skipping",
                    path.display(),
                    lineno + 1,
                    e
                ),
            }
        }
        Ok(hashes)
    }

    /// Load operator-supplied extra term file (one substring per line).
    pub fn load_terms_file(path: &Path) -> std::io::Result<Vec<String>> {
        // Same reasoning as load_hash_file: term lists carry non-ASCII terms and
        // operator comments, so one bad byte must not discard the whole file.
        let bytes = std::fs::read(path)?;
        let content = String::from_utf8_lossy(&bytes);
        Ok(content
            .lines()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .map(|s| s.to_string())
            .collect())
    }
}

impl Default for ContentFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zh() -> [u8; 16] {
        [0u8; 16]
    }

    #[test]
    fn allows_legitimate_files() {
        let f = ContentFilter::new();
        assert!(matches!(
            f.check(&zh(), "Linux Mint 22 Cinnamon (64-bit).iso"),
            FilterResult::Allow
        ));
        assert!(matches!(
            f.check(&zh(), "[Quality Assurance] Inception (2010) 1080p.mkv"),
            FilterResult::Allow
        ));
        assert!(matches!(
            f.check(&zh(), "tax_return_2024_final_v2.pdf"),
            FilterResult::Allow
        ));
        assert!(matches!(
            f.check(&zh(), "Война и мир — Лев Толстой.epub"),
            FilterResult::Allow
        ));
    }

    #[test]
    fn allows_borderline_legitimate() {
        let f = ContentFilter::new();
        // Movies with ages in title - not blocked because no sexual context
        assert!(matches!(
            f.check(&zh(), "12 Years a Slave (2013).mkv"),
            FilterResult::Allow
        ));
        assert!(matches!(
            f.check(&zh(), "Big Hero 6.mp4"),
            FilterResult::Allow
        ));
        // Adult content with adult age - not in our scope
        assert!(matches!(
            f.check(&zh(), "30yo brunette compilation.mp4"),
            FilterResult::Allow
        ));
    }

    #[test]
    fn blocks_layer2_age_plus_context() {
        let f = ContentFilter::new();
        // Sanitized example from real-world capture pattern
        let result = f.check(&zh(), "[movie] 8yo girl xxx.mp4");
        assert!(matches!(result, FilterResult::Block(Layer::L2AgePattern, _)));
    }

    #[test]
    fn poison_list_blocks_without_accusing_the_publisher() {
        let junk: [u8; 16] = [0xAB; 16];
        let f = ContentFilter::new().with_hash_filter([junk]);
        match f.check(&junk, "Genesis - Complete Discography.rar") {
            FilterResult::Block(layer, reason) => {
                assert_eq!(layer, Layer::L5Poison);
                assert_eq!(reason, "poison");
                // The whole point of the layer.
                assert!(!layer.counts_against_publisher());
            }
            FilterResult::Allow => panic!("poisoned hash must be blocked"),
        }
        // Every other layer DOES count.
        assert!(Layer::L1Jargon.counts_against_publisher());
        assert!(Layer::L2AgePattern.counts_against_publisher());
        assert!(Layer::L3HashBlock.counts_against_publisher());
        assert!(Layer::L4Extra.counts_against_publisher());
    }

    #[test]
    fn poison_wins_over_the_term_layers() {
        // A decoy normally carries a spam name full of porn tags. If a term layer
        // got there first, the block would be reported as CSAM and would count
        // toward the publisher ban — exactly what the poison list exists to stop.
        let junk: [u8; 16] = [0xCD; 16];
        let f = ContentFilter::new()
            .with_hash_filter([junk])
            .with_extra_terms(["preteen".to_string()]);
        assert!(matches!(
            f.check(&junk, "Pulp Fiction preteen xxx sex.avi"),
            FilterResult::Block(Layer::L5Poison, _)
        ));
        // Same name, a hash that is NOT poisoned → the term layer still fires.
        assert!(matches!(
            f.check(&zh(), "Pulp Fiction preteen xxx sex.avi"),
            FilterResult::Block(Layer::L4Extra, _)
        ));
    }

    #[test]
    fn csam_blocklist_outranks_poison() {
        // If a hash is on both lists the serious classification must win, so the
        // publisher is still counted.
        let h: [u8; 16] = [0xEF; 16];
        let f = ContentFilter::new()
            .with_hash_blocklist([h])
            .with_hash_filter([h]);
        assert!(matches!(
            f.check(&h, "whatever.mp4"),
            FilterResult::Block(Layer::L3HashBlock, _)
        ));
    }

    #[test]
    fn mojibake_names_are_tested_in_recovered_form() {
        // "幼女" round-tripped through Latin-1 twice. As delivered no CJK term
        // can match it — the bytes are no longer that character.
        let f = ContentFilter::new().with_extra_terms(["幼女".to_string()]);
        let mangled = "Ã¥Â¹Â¼Ã¥Â¥Â³ test.avi";
        assert!(mangled.find('幼').is_none(), "the marker really is not there");
        match f.check(&zh(), mangled) {
            FilterResult::Block(Layer::L4Extra, reason) => {
                assert!(reason.contains("mojibake"), "reason should say how it matched");
            }
            other => panic!("recovered form must match: {other:?}"),
        }
    }

    #[test]
    fn ordinary_names_survive_the_mojibake_pass() {
        // The pass must not invent matches out of legitimate text. A lossy
        // decoder was tried and rejected for exactly this: it turns "España"
        // into "Espaa" and a Japanese title into ".avi", then scans the result.
        let f = ContentFilter::new().with_extra_terms(["幼女".to_string(), "brosis".to_string()]);
        for name in [
            "España vs Argentina 2026.ts",
            "El.joven.Sheldon.1x11.números.avi",
            "普通の日本語ファイル.avi",
            "Marc Dorcel - Girls At Work N°1.avi",
            "plain ascii movie.avi",
        ] {
            assert!(
                matches!(f.check(&zh(), name), FilterResult::Allow),
                "{name} must pass"
            );
        }
    }

    #[test]
    fn whitelist_overrides_term_and_age_layers_too() {
        // The live case: three days of review showed the overrides that matter
        // are term matches, and bypassing only the hash lists left them blocked.
        let h: [u8; 16] = [0x33; 16];
        let f = ContentFilter::new()
            .with_extra_terms(["jailbait".to_string()])
            .with_hash_whitelist([h]);
        assert!(matches!(
            f.check(&h, "Motorhead - Jailbait.mp3"),
            FilterResult::Allow
        ));
        // Age patterns too — an operator's ruling stands against every layer.
        assert!(matches!(
            f.check(&h, "some 12yo sex video.avi"),
            FilterResult::Allow
        ));
        // A DIFFERENT hash with the same name is still blocked: the override is
        // per-file, not per-name.
        assert!(f.check(&zh(), "Motorhead - Jailbait.mp3").is_blocked());
    }

    #[test]
    fn whitelist_overrides_the_poison_list_too() {
        let h: [u8; 16] = [0x11; 16];
        let f = ContentFilter::new()
            .with_hash_filter([h])
            .with_hash_whitelist([h]);
        assert!(matches!(f.check(&h, "clean name.mkv"), FilterResult::Allow));
    }

    #[test]
    fn layer4_term_does_not_fire_inside_an_english_word() {
        // Live regression: a six-character L4 term is a suffix of "fibrosis", and
        // L4 used to bypass the length rules entirely by calling str::contains.
        let f = ContentFilter::new().with_extra_terms(["brosis".to_string()]);
        assert!(matches!(
            f.check(&zh(), "Cystic fibrosis transmembrane conductance regulator.pdf"),
            FilterResult::Allow
        ));
        assert!(matches!(
            f.check(&zh(), "pulmonary fibrosis review 2024.pdf"),
            FilterResult::Allow
        ));
        // ...and still catches the real thing, including underscore-joined forms.
        assert!(f.check(&zh(), "italian_brosis_2.avi").is_blocked());
        assert!(f.check(&zh(), "brosis_001.mp4").is_blocked());
        assert!(f.check(&zh(), "2022 Periscope Brosis bj.mp4").is_blocked());
    }

    #[test]
    fn hash_blocklist_blocks() {
        let bad: [u8; 16] = [0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let f = ContentFilter::new().with_hash_blocklist([bad]);
        assert!(matches!(
            f.check(&bad, "anything.mp4"),
            FilterResult::Block(Layer::L3HashBlock, _)
        ));
        // Different hash same name → allowed
        assert!(matches!(
            f.check(&zh(), "anything.mp4"),
            FilterResult::Allow
        ));
    }

    #[test]
    fn whitelist_hot_reload_applies_and_retracts() {
        let bad: [u8; 16] = [0x77; 16];
        let f = ContentFilter::new().with_hash_blocklist([bad]);
        assert!(f.check(&bad, "anything.mp4").is_blocked());

        // Adding an override takes effect without a restart.
        f.reload_hash_whitelist([bad]);
        assert_eq!(f.whitelist_size(), 1);
        assert!(matches!(f.check(&bad, "anything.mp4"), FilterResult::Allow));

        // Retracting it must also take effect. An EMPTY reload is meaningful and
        // is applied as written — it is how an operator withdraws an override
        // they no longer believe in. (A failed file READ is a different case and
        // keeps the current list; that is the watcher's job, not this method's.)
        f.reload_hash_whitelist([]);
        assert_eq!(f.whitelist_size(), 0);
        assert!(f.check(&bad, "anything.mp4").is_blocked());
    }

    #[test]
    fn hash_whitelist_overrides_blocklist() {
        let bad: [u8; 16] = [0x42; 16];
        let f = ContentFilter::new()
            .with_hash_blocklist([bad])
            .with_hash_whitelist([bad]);
        assert!(matches!(
            f.check(&bad, "false_positive.mp4"),
            FilterResult::Allow
        ));
    }

    #[test]
    fn whitelist_overrides_the_jargon_layer_too() {
        // INVERTED in 0.9.71. This used to assert that the whitelist bypassed
        // the hash check ONLY, and that jargon still won. Live review killed
        // that rule: the overrides that matter are term matches, so a
        // whitelisted file was re-blocked on its next publish and the list did
        // nothing for the one class of mistake that actually happens.
        let h: [u8; 16] = [0x42; 16];
        let f = ContentFilter::new()
            .with_hash_whitelist([h])
            .with_jargon_terms(["longmarker".to_string()]);
        assert!(matches!(
            f.check(&h, "something longmarker anything.mp4"),
            FilterResult::Allow
        ));
        // The term itself is unaffected — any OTHER file with that name is still
        // blocked. The override is per-hash, not per-name.
        assert!(matches!(
            f.check(&zh(), "something longmarker anything.mp4"),
            FilterResult::Block(Layer::L1Jargon, _)
        ));
    }

    #[test]
    fn extra_terms_addable() {
        let f = ContentFilter::new().with_extra_terms(["specifictoken".to_string()]);
        assert!(matches!(
            f.check(&zh(), "file specifictoken anything.mp4"),
            FilterResult::Block(Layer::L4Extra, _)
        ));
    }

    #[test]
    fn extra_terms_hot_reload() {
        let f = ContentFilter::new();
        // Not blocked before the term exists.
        assert!(!f.check(&zh(), "holiday clip.mp4").is_blocked());
        // Hot-swap a term in at runtime (no rebuild).
        f.reload_extra_terms(["holiday".to_string()]);
        assert!(matches!(
            f.check(&zh(), "holiday clip.mp4"),
            FilterResult::Block(Layer::L4Extra, _)
        ));
        // Reloading with an empty list clears L4 (terms removed from file).
        f.reload_extra_terms(Vec::<String>::new());
        assert!(!f.check(&zh(), "holiday clip.mp4").is_blocked());
    }
}
