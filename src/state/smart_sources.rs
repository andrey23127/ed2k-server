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

/// How long a cached FOUNDSOURCES payload stays fresh.
const CACHE_TTL: Duration = Duration::from_secs(5);

/// Soft cap on the number of cached file entries. Beyond this we sweep /
/// clear. At ~22 bytes-per-source * 200 sources that's a few MB worst case.
const MAX_ENTRIES: usize = 4096;

struct CacheEntry {
    /// Fully-encoded FOUNDSOURCES payload (everything after proto+opcode).
    payload: Vec<u8>,
    /// When this entry was inserted.
    inserted: Instant,
}

/// Thread-safe SmartSources cache, keyed by file hash.
pub struct SmartSourcesCache {
    map: Mutex<HashMap<[u8; 16], CacheEntry>>,
    /// Served-from-cache count (fresh entry found).
    hits: AtomicU64,
    /// Cache-miss count (no entry, or entry expired). Equivalent to a rebuild.
    misses: AtomicU64,
}

impl SmartSourcesCache {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Look up a cached FOUNDSOURCES payload for `hash`.
    /// Returns the payload bytes if a fresh entry exists, else None.
    pub fn get(&self, hash: &[u8; 16]) -> Option<Vec<u8>> {
        let map = self.map.lock().unwrap();
        let entry = match map.get(hash) {
            Some(e) => e,
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        if entry.inserted.elapsed() < CACHE_TTL {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.payload.clone())
        } else {
            // Expired — counts as a miss (the caller will rebuild). We leave it
            // for the next insert() to sweep; keeping the lock simple avoids
            // upgrade churn.
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Cache statistics: (hits, misses). Used by the admin Status page to show
    /// the real GETSOURCES cache hit rate.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    /// Store a freshly-built FOUNDSOURCES payload for `hash`.
    pub fn put(&self, hash: [u8; 16], payload: Vec<u8>) {
        let mut map = self.map.lock().unwrap();

        // Bound memory: if the map is getting large, sweep expired entries
        // first; if that's not enough, clear it entirely. Clearing is safe —
        // it just means the next requests rebuild and re-cache.
        if map.len() >= MAX_ENTRIES {
            let now = Instant::now();
            map.retain(|_, e| now.duration_since(e.inserted) < CACHE_TTL);
            if map.len() >= MAX_ENTRIES {
                map.clear();
            }
        }

        map.insert(
            hash,
            CacheEntry {
                payload,
                inserted: Instant::now(),
            },
        );
    }

    /// Invalidate the cached entry for a file — call when its source list
    /// changes in a way that matters (e.g. a new source was added). This is
    /// optional: the short TTL means stale entries self-heal anyway, so
    /// callers may skip invalidation on the hot path and just let TTL handle it.
    pub fn invalidate(&self, hash: &[u8; 16]) {
        let mut map = self.map.lock().unwrap();
        map.remove(hash);
    }

    /// Number of currently-cached entries (including not-yet-swept expired
    /// ones). Intended for stats/metrics, not correctness.
    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
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

        cache.put(hash, payload.clone());

        // Immediate get is a hit with identical bytes.
        assert_eq!(cache.get(&hash), Some(payload));

        // A different hash is a miss.
        assert_eq!(cache.get(&[9u8; 16]), None);
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache = SmartSourcesCache::new();
        let hash = [3u8; 16];
        cache.put(hash, vec![0xAA, 0xBB]);
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
                hash,
                CacheEntry {
                    payload: vec![1, 2, 3],
                    inserted: Instant::now() - Duration::from_secs(60),
                },
            );
        }
        // Entry exists but is well past TTL → get() returns None.
        assert_eq!(cache.get(&hash), None);
    }

    #[test]
    fn put_overwrites_with_fresh_timestamp() {
        let cache = SmartSourcesCache::new();
        let hash = [1u8; 16];
        cache.put(hash, vec![0x01]);
        cache.put(hash, vec![0x02, 0x03]);
        // Latest put wins.
        assert_eq!(cache.get(&hash), Some(vec![0x02, 0x03]));
    }

    #[test]
    fn stats_count_hits_and_misses() {
        let cache = SmartSourcesCache::new();
        let hash = [4u8; 16];
        assert_eq!(cache.get(&hash), None); // miss (no entry)
        cache.put(hash, vec![1, 2, 3]);
        assert!(cache.get(&hash).is_some()); // hit
        let (hits, misses) = cache.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
    }
}
