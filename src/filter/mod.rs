//! Mandatory content filter (SPEC.md §7.6).
//!
//! Three layers, each independently sufficient to drop a file. Run on every
//! OFFERFILES record before any indexing decision. The filter cannot be
//! disabled in this build — `ContentFilter::new` always returns an active
//! filter.

mod age_pattern;
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
        // Bind the guard first: the returned &str borrows from it, and a guard
        // created inline inside the `if let` condition is a temporary whose
        // lifetime rules changed between editions. An explicit binding is correct
        // under every edition.
        let jargon_terms = self.jargon_terms.load();
        if let Some(term) = jargon::matches_terms(&lowered, &jargon_terms) {
            return FilterResult::Block(Layer::L1Jargon, term.to_string());
        }

        // Layer 2: age pattern + sexual context
        if let Some(reason) = age_pattern::matches_layer2(filename, &lowered) {
            return FilterResult::Block(Layer::L2AgePattern, reason);
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
