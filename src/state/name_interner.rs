//! Name interner (Stage 2; single-store rework in Stage 4): deduplicate
//! file-name strings.
//!
//! WHY: every file stored its name as an owned `String` — a separate heap
//! allocation per file (24-byte header + the bytes). At Lugdunum scale (30M+
//! files) that is ~2.6 GB, and release names repeat heavily across distinct
//! hashes (the same `ubuntu-24.04.iso` is published by many peers as different
//! file versions, re-encodes, fakes, etc.), so most of those allocations hold
//! identical bytes.
//!
//! HOW: names are interned to `Arc<str>`. Identical names resolve to the SAME
//! `Arc`, so the bytes live once and every record holding that name keeps only
//! a 16-byte (ptr+len) shared handle. Reference counting is the `Arc`'s own:
//! when the last record referencing a name is dropped, the `Arc` strong count
//! falls to the interner's single retained copy, and a periodic sweep drops
//! interner entries whose only remaining holder is the table itself — releasing
//! the bytes. Strategy A (memory IS reclaimed), without a hand-rolled arena/GC.
//!
//! SINGLE-STORE (Stage 4): the dedup table is `DashMap<Arc<str>, ()>`, not the
//! earlier `DashMap<Box<str>, Arc<str>>`. The old layout stored every name's
//! bytes TWICE — once in the `Box<str>` key, once in the `Arc<str>` value. Now
//! the canonical `Arc<str>` IS the key (the table retains the single +1 strong
//! count through it) and the value is zero-sized, so the bytes exist exactly
//! once. Lookups still take a `&str`: `Arc<str>: Borrow<str>`, and `Arc`'s
//! `Hash`/`Eq` delegate to the pointed-to `str`, so two equal-byte arcs collide
//! in the map and dedup correctly.
//!
//! CONCURRENCY: the table is a `DashMap`, so interning is sharded and lock-free
//! on the common path (publish). Lookups never touch it once a record holds its
//! `Arc<str>` directly.

use dashmap::DashMap;
use std::sync::Arc;

/// Deduplicating string interner for file names.
///
/// The canonical `Arc<str>` is the map KEY; the table's ownership of that key is
/// the +1 strong count `sweep_unused` looks for (`strong_count == 1` == only the
/// table holds it). The value is `()` — the name bytes are stored once, in the
/// key.
#[derive(Default)]
pub struct NameInterner {
    table: DashMap<Arc<str>, ()>,
}

impl NameInterner {
    pub fn new() -> Self {
        Self { table: DashMap::new() }
    }

    /// Intern a name: return the shared `Arc<str>` for these bytes, allocating
    /// and recording it only if previously unseen. Two files with the same name
    /// get the same `Arc` — the bytes are stored once.
    pub fn intern(&self, name: &str) -> Arc<str> {
        // Fast path: already interned — clone the canonical key Arc. The lookup
        // is by `&str` (Arc<str>: Borrow<str>), so no allocation here.
        if let Some(e) = self.table.get(name) {
            return e.key().clone();
        }
        // Slow path: create the canonical Arc and publish it as the key. The
        // entry API arbitrates a race between two publishers interning the same
        // new name — the loser drops its Arc and adopts the winner's.
        let arc: Arc<str> = Arc::from(name);
        use dashmap::mapref::entry::Entry;
        match self.table.entry(arc.clone()) {
            Entry::Occupied(e) => e.key().clone(), // someone won; our `arc` drops
            Entry::Vacant(e) => {
                e.insert(());
                arc
            }
        }
    }

    /// Drop interner entries that no record references any more. A name is unused
    /// when its only strong holder is the interner table itself
    /// (`strong_count == 1`). Returns the number of names freed.
    ///
    /// Called off the hot path (the periodic cleanup task). Safe under
    /// concurrency: if a publisher interns the same name between the count check
    /// and the removal, `remove_if` re-checks under the shard lock, so a name
    /// that just gained a user is not dropped.
    ///
    /// NOTE: candidate keys are collected as freshly copied bytes (`Box<str>`),
    /// NOT as `Arc` clones — cloning the key would itself bump `strong_count`
    /// above 1 and defeat the unused check. The byte copies are temporary and
    /// off the hot path.
    pub fn sweep_unused(&self) -> usize {
        let mut freed = 0usize;
        let candidates: Vec<Box<str>> = self
            .table
            .iter()
            .filter(|e| Arc::strong_count(e.key()) == 1)
            .map(|e| Box::<str>::from(&**e.key()))
            .collect();
        for key in candidates {
            // Re-check under the shard lock: only remove if STILL unreferenced.
            let removed = self
                .table
                .remove_if(&*key, |arc, _| Arc::strong_count(arc) == 1)
                .is_some();
            if removed {
                freed += 1;
            }
        }
        freed
    }

    /// Number of distinct interned names currently held.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Total slot capacity of the dedup table (for /api/memsize).
    pub fn capacity(&self) -> usize {
        self.table.capacity()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_names_share_one_allocation() {
        let it = NameInterner::new();
        let a = it.intern("ubuntu-24.04.iso");
        let b = it.intern("ubuntu-24.04.iso");
        // Same backing allocation: the pointers are equal.
        assert!(Arc::ptr_eq(&a, &b), "identical names must share one Arc");
        assert_eq!(it.len(), 1, "only one distinct name stored");
    }

    #[test]
    fn distinct_names_are_separate() {
        let it = NameInterner::new();
        let a = it.intern("a.iso");
        let b = it.intern("b.iso");
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(it.len(), 2);
    }

    #[test]
    fn sweep_frees_only_unreferenced_names() {
        let it = NameInterner::new();
        let keep = it.intern("keep.iso"); // we hold this one
        let _ = it.intern("drop.iso"); // dropped immediately — only the table holds it
        assert_eq!(it.len(), 2);

        let freed = it.sweep_unused();
        assert_eq!(freed, 1, "the unreferenced name is freed");
        assert_eq!(it.len(), 1, "the still-held name remains");
        // The retained handle is still valid.
        assert_eq!(&*keep, "keep.iso");
    }

    #[test]
    fn sweep_keeps_name_with_live_holder() {
        let it = NameInterner::new();
        let held = it.intern("x.iso");
        assert_eq!(it.sweep_unused(), 0, "a referenced name must not be freed");
        assert_eq!(it.len(), 1);
        drop(held);
        assert_eq!(it.sweep_unused(), 1, "after the holder drops it is freed");
    }

    #[test]
    fn reintern_after_sweep_reallocates() {
        let it = NameInterner::new();
        let _ = it.intern("temp.iso");
        assert_eq!(it.sweep_unused(), 1);
        // Re-interning the same name works (fresh allocation).
        let a = it.intern("temp.iso");
        assert_eq!(&*a, "temp.iso");
        assert_eq!(it.len(), 1);
    }
}
