//! SmartSources cache (SPEC.md §6.2.6).
//!
//! GETSOURCES is the hot path on a busy eD2k server — for popular files,
//! hundreds of clients ask for the same hash within seconds. Rebuilding the
//! source list and re-encoding the FOUNDSOURCES payload for every one of
//! those identical requests is wasted work.
//!
//! This cache stores the *already-encoded* FOUNDSOURCES payload bytes for a
//! file hash, for a short TTL (a few seconds). Within that window every
//! GETSOURCES for the same hash is answered from the cache with a single
//! HashMap lookup and a clone — no source-list iteration, no re-encoding.
//!
//! The TTL is deliberately short: source lists change as clients come and
//! go, and a few seconds of staleness is harmless (clients re-query often).
//! Short TTL also bounds memory — entries for files nobody is asking about
//! expire and get swept.
//!
//! Design notes for the small-VPS target:
//!   * Pure in-memory, no disk.
//!   * Bounded size — when the map exceeds MAX_ENTRIES we sweep expired
//!     entries; if still over, we clear it (cheap, correctness-preserving).
//!   * One Mutex around a HashMap. GETSOURCES handlers are short; contention
//!     is not a concern at the hundreds-of-clients scale.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a cached FOUNDSOURCES payload stays fresh by default. 120 s,
/// from the live ages of expired misses at 15 s: about half of all misses
/// came 30 s to 2 min after the entry was built (630k of 1.23M in three
/// hours), against 37k within 30 s. A source list two minutes old is still
/// good for clients that re-ask every ~20 minutes.
/// `limits.getsources_cache_secs` sets it live.
pub const DEFAULT_TTL_SECS: u64 = 120;

/// How long past its TTL an expired entry is remembered (its key and age
/// only, the payload is freed), so a late request lands in the expired-age
/// histogram instead of reading as a plain miss.
pub const STALE_KEEP_SECS: u64 = 1200;

/// Cap on remembered expired entries: a key and a u32 each, about 25 bytes,
/// so 10 MB at most. Not counted against `MAX_ENTRIES`.
const STALE_MAX: usize = 400_000;

/// Cap on cached file entries. It was 4096, and the map was CLEARED when
/// full of fresh entries: at several hundred GETSOURCES a second, 4096
/// distinct hashes arrive within a few seconds, so the cache was wiped about
/// as fast as it filled and few entries lived long enough to be hit. Now
/// the cap is 65536 (a few MB to a few tens of MB of payloads) and, when it
/// is full of fresh entries, a new one is simply not stored. 200k leaves room
/// for a TTL of a few minutes (live: at 9k clients, 59k entries within the
/// first hours).
const MAX_ENTRIES: usize = 200_000;

struct CacheEntry {
    /// Fully-encoded FOUNDSOURCES payload (everything after proto+opcode).
    payload: Vec<u8>,
    /// Who each record in `payload` belongs to, in record order: the first 8
    /// bytes of the source's user hash. The payload is shared by every
    /// requester of the file, so it is built with ALL sources and the asker's
    /// own record is dropped when it is served (see `get_with`).
    owners: Vec<u64>,
    /// When this entry was inserted.
    inserted: Instant,
}

/// Thread-safe SmartSources cache, keyed by file hash.
pub struct SmartSourcesCache {
    /// Keyed by file hash and reply kind: `false` the classic FOUNDSOURCES,
    /// `true` FOUNDSOURCES_OBFU (crypt options and hashes per source).
    map: Mutex<HashMap<([u8; 16], bool), CacheEntry>>,
    /// Served-from-cache count (fresh entry found).
    hits: AtomicU64,
    /// Cache-miss count (no entry, or entry expired). Equivalent to a rebuild.
    misses: AtomicU64,
    /// Of the misses: an entry was there but had expired.
    expired: AtomicU64,
    /// New entries not stored because the map was full of fresh ones.
    skipped: AtomicU64,
    /// Age of the entry at an expired miss: under 30 s, 30-60 s, 1-2 min,
    /// 2-5 min, over 5 min. Tells how much a longer TTL would catch.
    expired_age: [AtomicU64; 5],
    ttl_secs: AtomicU64,
    /// Expired entries swept from `map`: key → insert time, in seconds
    /// since `base`.
    stale: Mutex<HashMap<([u8; 16], bool), u32>>,
    base: Instant,
}

impl SmartSourcesCache {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            expired_age: Default::default(),
            ttl_secs: AtomicU64::new(DEFAULT_TTL_SECS),
            stale: Mutex::new(HashMap::new()),
            // An hour back, so an entry stamped just before (a test's)
            // still has a time after it.
            base: Instant::now()
                .checked_sub(Duration::from_secs(3600))
                .unwrap_or_else(Instant::now),
        }
    }

    /// Look up a cached FOUNDSOURCES payload for `hash`.
    /// Returns the payload bytes if a fresh entry exists, else None.
    pub fn get(&self, hash: &[u8; 16]) -> Option<Vec<u8>> {
        let map = self.map.lock().unwrap();
        let entry = match map.get(&(*hash, false)) {
            Some(e) => e,
            None => {
                self.note_miss(&(*hash, false));
                return None;
            }
        };
        if entry.inserted.elapsed() < self.ttl() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.payload.clone())
        } else {
            self.note_expired(entry.inserted.elapsed());
            None
        }
    }

    /// Like `get`, but hands the fresh payload and its owner list to `f` under
    /// the lock and returns what `f` builds — so a requester-specific answer is
    /// cut from the shared payload without cloning it first.
    pub fn get_with<R>(&self, hash: &[u8; 16], f: impl FnOnce(&[u8], &[u64]) -> R) -> Option<R> {
        self.get_kind_with(hash, false, f)
    }

    /// `get_with` for one reply kind (`obfu`: FOUNDSOURCES_OBFU).
    pub fn get_kind_with<R>(
        &self,
        hash: &[u8; 16],
        obfu: bool,
        f: impl FnOnce(&[u8], &[u64]) -> R,
    ) -> Option<R> {
        let map = self.map.lock().unwrap();
        let entry = match map.get(&(*hash, obfu)) {
            Some(e) => e,
            None => {
                self.note_miss(&(*hash, obfu));
                return None;
            }
        };
        if entry.inserted.elapsed() < self.ttl() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(f(&entry.payload, &entry.owners))
        } else {
            // Expired — counts as a miss (the caller will rebuild). We leave it
            // for the next insert() to sweep; keeping the lock simple avoids
            // upgrade churn.
            self.note_expired(entry.inserted.elapsed());
            None
        }
    }

    /// Cache statistics: (hits, misses). Used by the admin Status page to show
    /// the real GETSOURCES cache hit rate.
    /// Heap bytes held by the cache (for /api/memsize): map slots plus each
    /// entry's encoded payload buffer (by capacity).
    pub fn size_bytes(&self) -> u64 {
        let m = self.map.lock().unwrap();
        let slots = (m.capacity()
            * (std::mem::size_of::<([u8; 16], bool)>() + std::mem::size_of::<CacheEntry>() + 1))
            as u64;
        let payloads: u64 = m
            .values()
            .map(|e| (e.payload.capacity() + e.owners.capacity() * 8) as u64)
            .sum();
        let st = self.stale.lock().unwrap().capacity()
            * (std::mem::size_of::<([u8; 16], bool)>() + std::mem::size_of::<u32>() + 1);
        slots + payloads + st as u64
    }

    /// Number of cached entries (diagnostics).
    pub fn entry_count(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_secs.load(Ordering::Relaxed).max(1))
    }

    /// Set the TTL (live config, `limits.getsources_cache_secs`).
    pub fn set_ttl_secs(&self, secs: u64) {
        let secs = secs.clamp(1, 600);
        // A new TTL starts the statistics over, so the hit rate and the ages
        // on the Status tab describe the TTL in force, not a mix.
        if self.ttl_secs.swap(secs, Ordering::Relaxed) != secs {
            self.hits.store(0, Ordering::Relaxed);
            self.misses.store(0, Ordering::Relaxed);
            self.expired.store(0, Ordering::Relaxed);
            self.skipped.store(0, Ordering::Relaxed);
            for a in &self.expired_age {
                a.store(0, Ordering::Relaxed);
            }
        }
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs.load(Ordering::Relaxed)
    }

    /// No entry in the map: an expired one remembered by the sweep, or none.
    fn note_miss(&self, key: &([u8; 16], bool)) {
        let at = self.stale.lock().unwrap().get(key).copied();
        match at {
            Some(t) => {
                let now = self.base.elapsed().as_secs();
                self.note_expired(Duration::from_secs(now.saturating_sub(u64::from(t))));
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Bucketed by how long the entry had been expired, not by its age: at a
    /// TTL of 300 s every expired entry is over 5 minutes old, and a
    /// histogram of ages put them all in one bucket.
    fn note_expired(&self, age: Duration) {
        self.misses.fetch_add(1, Ordering::Relaxed);
        self.expired.fetch_add(1, Ordering::Relaxed);
        let past = age.saturating_sub(self.ttl()).as_secs();
        let b = match past {
            0..=59 => 0,
            60..=119 => 1,
            120..=299 => 2,
            300..=599 => 3,
            _ => 4,
        };
        self.expired_age[b].fetch_add(1, Ordering::Relaxed);
    }

    /// Expired misses by how long past the TTL the entry was: under 1 min,
    /// 1-2 min, 2-5 min, 5-10 min, 10-20 min. A request later than that is a
    /// plain miss.
    pub fn expired_ages(&self) -> [u64; 5] {
        [0, 1, 2, 3, 4].map(|i| self.expired_age[i].load(Ordering::Relaxed))
    }

    /// (expired misses, inserts skipped for a full map).
    pub fn detail(&self) -> (u64, u64) {
        (
            self.expired.load(Ordering::Relaxed),
            self.skipped.load(Ordering::Relaxed),
        )
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    /// Store a freshly-built FOUNDSOURCES payload for `hash`, with the owner
    /// of each record (see `CacheEntry::owners`).
    pub fn put(&self, hash: [u8; 16], payload: Vec<u8>, owners: Vec<u64>) {
        self.put_kind(hash, false, payload, owners)
    }

    /// `put` for one reply kind (`obfu`: FOUNDSOURCES_OBFU).
    pub fn put_kind(&self, hash: [u8; 16], obfu: bool, payload: Vec<u8>, owners: Vec<u64>) {
        let key = (hash, obfu);
        let mut map = self.map.lock().unwrap();
        self.stale.lock().unwrap().remove(&key);

        // Bound memory: if the map is getting large, sweep expired entries
        // first; if that's not enough, clear it entirely. Clearing is safe —
        // it just means the next requests rebuild and re-cache.
        if map.len() >= MAX_ENTRIES && !map.contains_key(&key) {
            let now = Instant::now();
            let ttl = self.ttl();
            map.retain(|_, e| now.duration_since(e.inserted) < ttl);
            if map.len() >= MAX_ENTRIES {
                // Full of fresh entries: keep them, skip this one.
                self.skipped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        map.insert(
            key,
            CacheEntry {
                payload,
                owners,
                inserted: Instant::now(),
            },
        );
    }

    /// Expire entries. Run by the periodic sweep: without it expired entries
    /// stayed until the map reached its cap (195k of them at 15 s, holding
    /// their payloads), and the entry count said nothing about what the cache
    /// was actually serving.
    ///
    /// An expired entry leaves the map, payload and all, but its key and
    /// insert time are remembered for `STALE_KEEP_SECS` past the TTL, so a
    /// request in that window still lands in the histogram. Dropped outright,
    /// every request later than one sweep read as a plain miss.
    pub fn sweep_expired(&self) -> usize {
        let ttl = self.ttl();
        let now = Instant::now();
        let mut map = self.map.lock().unwrap();
        let mut stale = self.stale.lock().unwrap();
        let before = map.len();
        map.retain(|k, e| {
            let fresh = now.duration_since(e.inserted) < ttl;
            if !fresh && stale.len() < STALE_MAX {
                let t = e.inserted.saturating_duration_since(self.base).as_secs();
                stale.insert(*k, u32::try_from(t).unwrap_or(u32::MAX));
            }
            fresh
        });
        let live = map.len();
        if map.capacity() > live * 4 + 1024 {
            map.shrink_to(live * 2);
        }
        let keep = (ttl.as_secs() + STALE_KEEP_SECS) as u32;
        let now_s = u32::try_from(self.base.elapsed().as_secs()).unwrap_or(u32::MAX);
        stale.retain(|_, t| now_s.saturating_sub(*t) < keep);
        let n = stale.len();
        if stale.capacity() > n * 4 + 1024 {
            stale.shrink_to(n * 2);
        }
        before - live
    }

    /// Invalidate the cached entry for a file — call when its source list
    /// changes in a way that matters (e.g. a new source was added). This is
    /// optional: the short TTL means stale entries self-heal anyway, so
    /// callers may skip invalidation on the hot path and just let TTL handle it.
    pub fn invalidate(&self, hash: &[u8; 16]) {
        let mut map = self.map.lock().unwrap();
        map.remove(&(*hash, false));
        map.remove(&(*hash, true));
        let mut stale = self.stale.lock().unwrap();
        stale.remove(&(*hash, false));
        stale.remove(&(*hash, true));
    }

    /// Number of fresh entries, the ones that can be served. Intended for
    /// stats/metrics, not correctness.
    pub fn len(&self) -> usize {
        let ttl = self.ttl();
        self.map
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.inserted.elapsed() < ttl)
            .count()
    }
}

impl Default for SmartSourcesCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_then_miss_after_ttl() {
        let cache = SmartSourcesCache::new();
        let hash = [7u8; 16];
        let payload = vec![1, 2, 3, 4, 5];

        cache.put(hash, payload.clone(), Vec::new());

        // Immediate get is a hit with identical bytes.
        assert_eq!(cache.get(&hash), Some(payload));

        // A different hash is a miss.
        assert_eq!(cache.get(&[9u8; 16]), None);
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache = SmartSourcesCache::new();
        let hash = [3u8; 16];
        cache.put(hash, vec![0xAA, 0xBB], Vec::new());
        assert!(cache.get(&hash).is_some());

        cache.invalidate(&hash);
        assert!(cache.get(&hash).is_none());
    }

    #[test]
    fn expired_entry_is_a_miss() {
        // We can't easily fast-forward Instant, so this test validates the
        // logic path by constructing an entry with an old timestamp directly.
        let cache = SmartSourcesCache::new();
        let hash = [5u8; 16];
        {
            let mut map = cache.map.lock().unwrap();
            map.insert(
                (hash, false),
                CacheEntry {
                    payload: vec![1, 2, 3],
                    owners: Vec::new(),
                    inserted: Instant::now() - Duration::from_secs(DEFAULT_TTL_SECS + 60),
                },
            );
        }
        // Entry exists but is well past TTL → get() returns None.
        assert_eq!(cache.get(&hash), None);
    }

    #[test]
    fn sweep_remembers_an_expired_entry_by_its_age_alone() {
        let cache = SmartSourcesCache::new();
        let at = |secs: u64| CacheEntry {
            payload: vec![9; 64],
            owners: vec![1, 2],
            inserted: Instant::now() - Duration::from_secs(secs),
        };
        {
            let mut map = cache.map.lock().unwrap();
            map.insert(([1; 16], false), at(10));
            map.insert(([2; 16], false), at(DEFAULT_TTL_SECS + 200));
        }
        assert_eq!(cache.sweep_expired(), 1);
        assert_eq!(cache.len(), 1, "len counts what can be served");
        assert_eq!(cache.map.lock().unwrap().len(), 1, "the expired one left the map");
        // A request for it lands 2-5 min past the TTL.
        assert_eq!(cache.get(&[2; 16]), None);
        assert_eq!(cache.expired_ages()[2], 1);
        assert_eq!(cache.detail().0, 1);
        // A fresh insert forgets it.
        cache.put([2; 16], vec![1], Vec::new());
        assert!(cache.stale.lock().unwrap().is_empty());
        // Unknown hash: a plain miss.
        assert_eq!(cache.get(&[3; 16]), None);
        assert_eq!(cache.detail().0, 1);
    }

    #[test]
    fn put_overwrites_with_fresh_timestamp() {
        let cache = SmartSourcesCache::new();
        let hash = [1u8; 16];
        cache.put(hash, vec![0x01], Vec::new());
        cache.put(hash, vec![0x02, 0x03], Vec::new());
        // Latest put wins.
        assert_eq!(cache.get(&hash), Some(vec![0x02, 0x03]));
    }

    #[test]
    fn stats_count_hits_and_misses() {
        let cache = SmartSourcesCache::new();
        let hash = [4u8; 16];
        assert_eq!(cache.get(&hash), None); // miss (no entry)
        cache.put(hash, vec![1, 2, 3], Vec::new());
        assert!(cache.get(&hash).is_some()); // hit
        let (hits, misses) = cache.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
    }

    /// A cache full of fresh entries keeps them: the new one is skipped, not
    /// the whole map cleared (which emptied it every few seconds under load).
    #[test]
    fn a_full_cache_keeps_its_entries() {
        let cache = SmartSourcesCache::new();
        for i in 0..MAX_ENTRIES as u32 {
            let mut h = [0u8; 16];
            h[..4].copy_from_slice(&i.to_le_bytes());
            cache.put(h, vec![1], Vec::new());
        }
        cache.put([0xFF; 16], vec![2], Vec::new());
        assert_eq!(cache.len(), MAX_ENTRIES);
        assert_eq!(cache.detail().1, 1);
        assert!(cache.get(&[0u8; 16]).is_some(), "an old entry survived");
        assert!(cache.get(&[0xFF; 16]).is_none());
    }
}