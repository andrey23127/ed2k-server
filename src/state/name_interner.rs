//! Name storage for file records.
//!
//! HISTORY — this used to be a deduplicating interner, and no longer is.
//!
//! The premise was that eD2k filenames repeat often enough that storing each
//! distinct name once would pay for the table doing it. A synthetic benchmark
//! agreed (it modelled 70% distinct names). Production did not: at 1.17M live
//! files there were 1.14M distinct names — a **2.8% dedup rate**, and falling as
//! the index grew. Real filenames are tag-stuffed, re-tagged and re-cased by
//! every publisher, so near enough all of them are unique.
//!
//! The accounting at that point:
//!
//! | | |
//! |---|---|
//! | saved by dedup | 1.8 MB |
//! | `Arc` control blocks | 17.4 MB |
//! | dedup table slots | 29.3 MB |
//! | **net** | **−45 MB** |
//!
//! So the table was removed. `intern` now just allocates; the `Arc` stays,
//! because callers clone names out from under a shard read lock and an `Arc`
//! clone there is a pointer bump rather than a byte copy. That keeps the control
//! block (17.4 MB) and returns the slots (29.3 MB) — about −0.9 GB at the 33M
//! target, against a 1.8 MB loss of real dedup.
//!
//! The type is kept, rather than replacing `Arc<str>` with `Box<str>` at every
//! call site, on purpose: the remaining 16 bytes per name are the price of not
//! touching a dozen signatures and the locking assumptions behind them. If that
//! becomes worth doing, it should be its own change with its own testing.

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

    /// Return an `Arc<str>` for these bytes.
    ///
    /// ⚠ NO LONGER DEDUPLICATES — and that is the point. See the module header:
    /// live measurement put the dedup rate at 2.8%, saving 1.8 MB while the
    /// table that produced it cost 29 MB in slots. The table was a net loss of
    /// ~45 MB at 1.17M files, scaling to about −0.9 GB at the 33M target.
    ///
    /// The `Arc` itself stays. It is what every caller holds and what makes
    /// cloning a name out from under a shard lock cheap; only the dedup TABLE is
    /// gone. Identical names now get separate allocations, which costs the 1.8 MB
    /// the dedup was saving and returns the 29 MB it was spending.
    ///
    /// Kept as a method rather than inlining `Arc::from` at the call sites so
    /// the decision stays in one documented place, and so restoring dedup — if a
    /// future workload ever justifies it — is a change to this function alone.
    pub fn intern(&self, name: &str) -> Arc<str> {
        Arc::from(name)
    }

    /// No-op retained for the periodic cleanup's call site. Always returns 0.
    ///
    /// With no table there is nothing to sweep: a name is freed by its last
    /// `Arc` holder, i.e. when the record referencing it is evicted. That is
    /// strictly better than the old scheme, where a name lingered until the next
    /// sweep noticed `strong_count == 1`.
    ///
    /// Left in place (rather than deleting the call) because the cleanup logs
    /// `dropped_names` and an operator comparing logs across versions should see
    /// it go to zero, not see the field vanish.
    pub fn sweep_unused(&self) -> usize {
        0
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
    fn intern_returns_usable_names() {
        let it = NameInterner::new();
        let a = it.intern("ubuntu-24.04.iso");
        let b = it.intern("ubuntu-24.04.iso");
        assert_eq!(&*a, "ubuntu-24.04.iso");
        assert_eq!(&*a, &*b);
    }

    #[test]
    fn identical_names_no_longer_share_an_allocation() {
        // Deliberate: the dedup table was measured at 2.8% hit rate, saving
        // 1.8 MB while costing 29 MB in slots. Separate allocations are the
        // cheaper answer for this workload. If a future workload brings names
        // back into alignment, restoring dedup is a change to `intern` alone.
        let it = NameInterner::new();
        let a = it.intern("same.iso");
        let b = it.intern("same.iso");
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn a_name_is_freed_by_its_last_holder() {
        // Without a table, nothing keeps a name alive once its record is gone —
        // strictly better than waiting for a sweep to notice.
        let it = NameInterner::new();
        let a = it.intern("gone.iso");
        assert_eq!(Arc::strong_count(&a), 1, "only the caller holds it");
        drop(a);
        assert_eq!(it.len(), 0, "nothing is retained");
    }

    #[test]
    fn sweep_is_a_no_op() {
        let it = NameInterner::new();
        let _keep = it.intern("keep.iso");
        assert_eq!(it.sweep_unused(), 0);
        assert!(it.is_empty());
    }

    #[test]
    fn unicode_names_survive_round_trip() {
        let it = NameInterner::new();
        let n = it.intern("Фильм — 中文 — café.mkv");
        assert_eq!(&*n, "Фильм — 中文 — café.mkv");
    }
}
