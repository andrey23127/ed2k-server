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
}

#[derive(Debug, Clone)]
pub enum FilterResult {
    /// File passed all checks; safe to index.
    Allow,
    /// File matched a content filter at the given layer; do not index.
    Block(Layer),
}

impl FilterResult {
    pub fn is_blocked(&self) -> bool {
        matches!(self, FilterResult::Block(_))
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
    /// `jargon::matches_layer1`; this only holds the (pre-lowercased) list.
    jargon_terms: arc_swap::ArcSwap<Vec<String>>,

    /// Hash whitelist - verified false positives (Layer 3 override).
    /// Any hash here bypasses Layer 3 (but NOT layers 1, 2, or 4).
    hash_whitelist: HashSet<[u8; 16]>,
}

impl ContentFilter {
    /// Construct a filter. Hardcoded layers are always active; only the
    /// supplementary lists are configurable.
    pub fn new() -> Self {
        Self {
            hash_blocklist: arc_swap::ArcSwap::from_pointee(HashSet::new()),
            extra_terms: arc_swap::ArcSwap::from_pointee(Vec::new()),
            jargon_terms: arc_swap::ArcSwap::from_pointee(Vec::new()),
            hash_whitelist: HashSet::new(),
        }
    }

    /// Heap bytes held by the content filter (for /api/memsize): the CSAM hash
    /// blocklist/whitelist sets and the term lists.
    pub fn size_bytes(&self) -> u64 {
        let hsz = std::mem::size_of::<[u8; 16]>() as u64 + 1; // + hashbrown ctrl byte
        let bl = self.hash_blocklist.load();
        let mut n = bl.capacity() as u64 * hsz;
        n += self.hash_whitelist.capacity() as u64 * hsz;
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

    pub fn with_hash_whitelist(mut self, hashes: impl IntoIterator<Item = [u8; 16]>) -> Self {
        self.hash_whitelist.extend(hashes);
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
    pub fn blocklist_size(&self) -> usize {
        self.hash_blocklist.load().len()
    }

    /// Number of extra operator-supplied terms (for startup logging).
    pub fn extra_terms_count(&self) -> usize {
        self.extra_terms.load().len()
    }

    /// Check a candidate file. Layer order is fastest-rejection-first.
    pub fn check(&self, file_hash: &[u8; 16], filename: &str) -> FilterResult {
        // Hash check first — O(1), fastest rejection. Whitelist takes priority.
        if !self.hash_whitelist.contains(file_hash)
            && self.hash_blocklist.load().contains(file_hash)
        {
            return FilterResult::Block(Layer::L3HashBlock);
        }

        // Normalize for term matching.
        let lowered = filename.to_lowercase();

        // Layer 1: jargon (list loaded at runtime; empty = inactive)
        if jargon::matches_layer1(&lowered, &self.jargon_terms.load()) {
            return FilterResult::Block(Layer::L1Jargon);
        }

        // Layer 2: age pattern + sexual context
        if age_pattern::matches_layer2(filename, &lowered) {
            return FilterResult::Block(Layer::L2AgePattern);
        }

        // Layer 4 (operator extras) — snapshot the hot-swappable list.
        let extra = self.extra_terms.load();
        if extra.iter().any(|t| lowered.contains(t)) {
            return FilterResult::Block(Layer::L4Extra);
        }

        FilterResult::Allow
    }

    /// Load a hash list file. Format: one hex MD4 per line, optional
    /// `;`-comment after the hash. Lines starting with # are skipped.
    pub fn load_hash_file(path: &Path) -> std::io::Result<Vec<[u8; 16]>> {
        let content = std::fs::read_to_string(path)?;
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
        let content = std::fs::read_to_string(path)?;
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
        assert!(matches!(result, FilterResult::Block(Layer::L2AgePattern)));
    }

    #[test]
    fn hash_blocklist_blocks() {
        let bad: [u8; 16] = [0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let f = ContentFilter::new().with_hash_blocklist([bad]);
        assert!(matches!(
            f.check(&bad, "anything.mp4"),
            FilterResult::Block(Layer::L3HashBlock)
        ));
        // Different hash same name → allowed
        assert!(matches!(
            f.check(&zh(), "anything.mp4"),
            FilterResult::Allow
        ));
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
    fn whitelist_does_not_override_term_layers() {
        // Hash whitelist gives bypass for hash check ONLY; jargon still wins.
        let h: [u8; 16] = [0x42; 16];
        // L1 list is now loaded; install a synthetic term to exercise the layer.
        let f = ContentFilter::new()
            .with_hash_whitelist([h])
            .with_jargon_terms(["longmarker".to_string()]);
        let result = f.check(&h, "something longmarker anything.mp4");
        assert!(matches!(result, FilterResult::Block(Layer::L1Jargon)));
    }

    #[test]
    fn extra_terms_addable() {
        let f = ContentFilter::new().with_extra_terms(["specifictoken".to_string()]);
        assert!(matches!(
            f.check(&zh(), "file specifictoken anything.mp4"),
            FilterResult::Block(Layer::L4Extra)
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
            FilterResult::Block(Layer::L4Extra)
        ));
        // Reloading with an empty list clears L4 (terms removed from file).
        f.reload_extra_terms(Vec::<String>::new());
        assert!(!f.check(&zh(), "holiday clip.mp4").is_blocked());
    }
}
