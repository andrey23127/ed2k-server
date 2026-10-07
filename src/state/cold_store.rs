//! The keyword index's cold tier: token hash -> compressed posting blob.
//!
//! It used to be a `DashMap<u32, Box<[u8]>>`: one heap allocation per keyword
//! plus a hash-table slot of key + fat pointer + control byte, sized to a
//! power of two. Measured with loadgen that was ~37 bytes of overhead per file
//! (table slots and blob headers) before the blob data itself, plus the
//! allocator's size-class rounding on millions of tiny blobs.
//!
//! Here each of `SHARDS` shards holds three flat arrays:
//!
//! * `keys`  — the token hashes, sorted ascending (4 bytes per keyword);
//! * `ends`  — where each keyword's blob ends in `arena` (4 bytes per keyword;
//!   a blob starts where the previous one ends);
//! * `arena` — every blob of the shard back to back.
//!
//! 8 bytes per keyword in place of ~45, and no per-blob allocation.
//!
//! The arrays are never edited in place. `rebuild` writes a new shard from the
//! old one plus a sorted batch of replacements, under the shard's READ lock
//! (searches keep running), and swaps it in under the write lock. Only
//! `KeywordIndex::compact` writes, one compaction at a time, which is what
//! makes building outside the write lock sound.
//!
//! Lookup is a binary search in one shard's `keys`. A shard is chosen by the
//! low bits of the hash (FNV-1a, well mixed there).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{RwLock, RwLockReadGuard};

use super::keyword_index::TokenHash;

/// Number of shards. A rebuild copies one shard; 1024 keeps that copy small
/// (about 1 MB at 30M files) and spreads read locks.
const SHARDS: usize = 1024;

#[derive(Default)]
struct Shard {
    keys: Vec<TokenHash>,
    ends: Vec<u32>,
    arena: Vec<u8>,
}

impl Shard {
    fn find(&self, th: TokenHash) -> Option<usize> {
        self.keys.binary_search(&th).ok()
    }

    fn span(&self, i: usize) -> (usize, usize) {
        let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
        (start, self.ends[i] as usize)
    }

    fn blob(&self, i: usize) -> &[u8] {
        let (s, e) = self.span(i);
        &self.arena[s..e]
    }
}

/// A borrowed blob. Holds the shard's read lock until dropped, like the
/// `DashMap` reference it replaces.
pub struct ColdRef<'a> {
    guard: RwLockReadGuard<'a, Shard>,
    start: usize,
    end: usize,
}

impl ColdRef<'_> {
    pub fn value(&self) -> &[u8] {
        &self.guard.arena[self.start..self.end]
    }
}

pub struct ColdStore {
    shards: Box<[RwLock<Shard>]>,
    keys: AtomicUsize,
}

impl Default for ColdStore {
    fn default() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| RwLock::new(Shard::default())).collect(),
            keys: AtomicUsize::new(0),
        }
    }
}

/// The shard a token hash lives in.
pub fn shard_of(th: TokenHash) -> usize {
    th as usize % SHARDS
}

impl ColdStore {
    fn read(&self, shard: usize) -> RwLockReadGuard<'_, Shard> {
        self.shards[shard].read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self, th: TokenHash) -> Option<ColdRef<'_>> {
        let guard = self.read(shard_of(th));
        let i = guard.find(th)?;
        let (start, end) = guard.span(i);
        Some(ColdRef { guard, start, end })
    }

    pub fn contains_key(&self, th: TokenHash) -> bool {
        self.read(shard_of(th)).find(th).is_some()
    }

    /// Number of keywords.
    pub fn len(&self) -> usize {
        self.keys.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Visit every blob. Takes one shard's read lock at a time.
    pub fn for_each_blob(&self, mut f: impl FnMut(&[u8])) {
        for s in 0..SHARDS {
            let g = self.read(s);
            for i in 0..g.keys.len() {
                f(g.blob(i));
            }
        }
    }

    /// (blob bytes, index bytes): the arena, and the two per-keyword arrays,
    /// both by capacity.
    pub fn bytes(&self) -> (u64, u64) {
        let (mut data, mut index) = (0u64, 0u64);
        for s in 0..SHARDS {
            let g = self.read(s);
            data += g.arena.capacity() as u64;
            index += (g.keys.capacity() * 4 + g.ends.capacity() * 4) as u64;
        }
        (data, index)
    }

    /// Replace a shard's contents with the old shard plus `updates`, then call
    /// `installed` while the new shard is in place and its write lock is
    /// still held. Returns the number of keywords removed.
    ///
    /// `updates` must all belong to `shard`, be sorted by key and unique.
    /// `Some(blob)` sets a keyword's blob (adding it if new); `None` removes
    /// the keyword. Callers must be serialised (see the module notes).
    pub fn rebuild(
        &self,
        shard: usize,
        updates: &[(TokenHash, Option<Vec<u8>>)],
        installed: impl FnOnce(),
    ) -> usize {
        debug_assert!(updates.windows(2).all(|w| w[0].0 < w[1].0));
        debug_assert!(updates.iter().all(|u| shard_of(u.0) == shard));

        // Build from the old shard. Readers continue meanwhile.
        let (new, removed, added) = {
            let old = self.read(shard);
            let removed_bytes: usize = updates
                .iter()
                .filter_map(|(k, _)| old.find(*k).map(|i| old.span(i)))
                .map(|(s, e)| e - s)
                .sum();
            let added_bytes: usize = updates
                .iter()
                .filter_map(|(_, b)| b.as_ref().map(|b| b.len()))
                .sum();
            let arena_len = old.arena.len() - removed_bytes + added_bytes;
            let max_keys = old.keys.len() + updates.len();
            let mut new = Shard {
                keys: Vec::with_capacity(max_keys),
                ends: Vec::with_capacity(max_keys),
                arena: Vec::with_capacity(arena_len),
            };
            let push = |new: &mut Shard, k: TokenHash, blob: &[u8]| {
                new.arena.extend_from_slice(blob);
                new.keys.push(k);
                new.ends.push(new.arena.len() as u32);
            };
            let (mut removed, mut added) = (0usize, 0usize);
            let (mut i, mut j) = (0usize, 0usize);
            while i < old.keys.len() || j < updates.len() {
                let take_old = match (old.keys.get(i), updates.get(j)) {
                    (Some(&k), Some((u, _))) if k < *u => true,
                    (Some(_), Some(_)) => false,
                    (Some(_), None) => true,
                    (None, _) => false,
                };
                if take_old {
                    push(&mut new, old.keys[i], old.blob(i));
                    i += 1;
                    continue;
                }
                let (k, blob) = &updates[j];
                let existed = old.keys.get(i) == Some(k);
                if existed {
                    i += 1;
                }
                match blob {
                    Some(b) => {
                        push(&mut new, *k, b);
                        if !existed {
                            added += 1;
                        }
                    }
                    None => {
                        if existed {
                            removed += 1;
                        }
                    }
                }
                j += 1;
            }
            new.keys.shrink_to_fit();
            new.ends.shrink_to_fit();
            (new, removed, added)
        };

        let mut w = self.shards[shard].write().unwrap_or_else(|e| e.into_inner());
        *w = new;
        self.keys.fetch_add(added, Ordering::Relaxed);
        self.keys.fetch_sub(removed, Ordering::Relaxed);
        installed();
        drop(w);
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys_in(shard: usize, n: u32) -> Vec<TokenHash> {
        (0..n).map(|i| shard as u32 + i * SHARDS as u32).collect()
    }

    #[test]
    fn rebuild_adds_replaces_and_removes() {
        let c = ColdStore::default();
        let k = keys_in(7, 5);
        let ups: Vec<_> = k.iter().map(|&x| (x, Some(vec![x as u8; (x % 5) as usize + 1]))).collect();
        assert_eq!(c.rebuild(7, &ups, || {}), 0);
        assert_eq!(c.len(), 5);
        for &x in &k {
            assert_eq!(c.get(x).unwrap().value(), &vec![x as u8; (x % 5) as usize + 1][..]);
        }
        // Replace the middle one, remove the first, add a new one.
        let mid = k[2];
        let absent = k[4] + 5 * SHARDS as u32;
        let new_key = k[4] + SHARDS as u32;
        let ups = vec![(k[0], None), (mid, Some(vec![9, 9, 9])), (new_key, Some(vec![1]))];
        assert_eq!(c.rebuild(7, &ups, || {}), 1);
        assert_eq!(c.len(), 5);
        assert!(c.get(k[0]).is_none());
        assert_eq!(c.get(mid).unwrap().value(), &[9, 9, 9]);
        assert_eq!(c.get(new_key).unwrap().value(), &[1]);
        assert_eq!(c.get(k[1]).unwrap().value(), &vec![k[1] as u8; (k[1] % 5) as usize + 1][..]);
        assert!(c.contains_key(k[4]));
        assert!(!c.contains_key(absent));
        // Removing a key that is not there changes nothing.
        assert_eq!(c.rebuild(7, &[(k[0], None)], || {}), 0);
        assert_eq!(c.len(), 5);
        let mut n = 0;
        c.for_each_blob(|_| n += 1);
        assert_eq!(n, 5);
    }

    #[test]
    fn the_install_hook_runs_with_the_new_shard_in_place() {
        let c = ColdStore::default();
        let k = keys_in(3, 1)[0];
        c.rebuild(3, &[(k, Some(vec![5]))], || {});
        let seen = std::cell::Cell::new(false);
        c.rebuild(3, &[(k, Some(vec![6]))], || {
            // The write lock is held here, so only the shard's own data can be
            // inspected through the store's internals.
            let g = c.shards[3].try_read();
            assert!(g.is_err(), "write lock must still be held");
            seen.set(true);
        });
        assert!(seen.get());
        assert_eq!(c.get(k).unwrap().value(), &[6]);
    }
}
