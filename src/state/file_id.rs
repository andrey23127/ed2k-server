//! File-id slab: the foundation for "lever A" (FileHash[16] → u32 id).
//!
//! WHY: at Lugdunum scale (30M files, 50k users) storing the full 16-byte MD4
//! hash inside every keyword posting and every user_files entry costs ~3.5 GB.
//! Replacing those references with a 4-byte `FileId` saves the bulk of it. The
//! 16-byte hash then lives in exactly ONE place (the slab record), and a
//! `hash → id` map provides the publish-time lookup.
//!
//! THIS MODULE IS STEP 1 (foundation only): it introduces the `FileId` type,
//! the slab store, and the bidirectional hash↔id mapping. It does NOT yet
//! rewire keyword_index / user_files / files to use ids — that is a later step.
//! Built and tested in isolation so the core search paths are untouched until
//! the migration is done deliberately, one path at a time.
//!
//! Concurrency: `alloc` takes a short write lock (publish path, off the hot
//! search path); lookups take read locks. Ids are never reused within a run
//! (a removed file's slot is tombstoned), so a stale `FileId` held by a posting
//! resolves to `None` rather than to the wrong file — this is the safety
//! property that makes a later lazy-cleanup migration sound.

use crate::state::{FileHash, Source};
use smallvec::{smallvec, SmallVec};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

/// Source storage for a file. Stage 4 (memory): inlined as `SmallVec<[Source; 1]>`
/// instead of `Vec<Source>`. Production averages ~1.02 sources/file, so the one
/// common source now lives INSIDE the FileRecord with no separate heap block —
/// removing roughly one tiny (24-byte) allocation per file (≈33M at full scale),
/// which was the dominant allocator-overhead and fragmentation contributor.
/// Files with several sources (rare; max observed 37) spill to the heap exactly
/// like `Vec`. Costs +8 bytes inline per record — far outweighed by eliminating
/// the per-file allocation. All call sites use only Deref/iter/push/retain/
/// first/len/is_empty, which `SmallVec` provides identically to `Vec`.
pub type SourceVec = SmallVec<[Source; 1]>;

/// Compact 4-byte file identifier. Wraps u32 so it can't be confused with a
/// client id or any other u32. 30M files fits comfortably in u32 (4.2B max).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId(pub u32);

/// The authoritative per-file record. This is what a `FileId` resolves to.
/// Mirrors the data currently in `FileEntry`; during migration the live
/// `FileEntry` stays the source of truth and this slab is populated alongside.
#[derive(Debug, Clone)]
pub struct FileRecord {
    pub hash: FileHash,
    pub size: u64,
    pub name: Arc<str>,
    pub sources: SourceVec,
    /// Seconds since the slab epoch (Stage 3d: packed from 16-byte Instant to
    /// 4 bytes). Currently write-only; reserved for age-based eviction.
    pub last_seen: u32,
    /// Tombstone: when a file is evicted we mark the slot dead rather than
    /// reusing the id, so dangling FileIds in postings resolve to None.
    pub alive: bool,
}

impl FileRecord {
    /// Number of sources that hold a complete copy, for the FT_COMPLETE_SOURCES
    /// (0x30) search-result tag. We count every source: most clients share
    /// downloads-in-progress, and a file's lifetime source set is the useful
    /// signal for the downloader. (Moved here from the former FileEntry.)
    pub fn complete_source_count(&self) -> u32 {
        self.sources.len() as u32
    }
}

/// Slab-allocated file store with an intrusive per-shard hash index.
///
/// - `records[id]` → FileRecord (dense Vec, indexed by id)
/// - hash → id resolves by walking the bucket chain in the hash's shard; the
///   16-byte hash lives once in the record (no separate hash→id map).
/// Number of slab shards. FileId encodes the shard in its top bits, the local
/// index in the low bits, so reads/writes to different shards never contend —
/// recovering DashMap-like parallelism while keeping a dense packed Vec per
/// shard (the memory win of Variant A). 64 shards keeps per-shard lock
/// contention low at 50k concurrent clients.
const SLAB_SHARDS: u32 = 64;
/// Low bits for the per-shard index. 26 bits = 67M records per shard, far more
/// than any real deployment needs; 64 * 67M is well beyond u32 file counts.
const SLAB_INDEX_BITS: u32 = 26;
const SLAB_INDEX_MASK: u32 = (1u32 << SLAB_INDEX_BITS) - 1;

#[inline]
fn id_shard(id: FileId) -> usize {
    (id.0 >> SLAB_INDEX_BITS) as usize
}
#[inline]
fn id_index(id: FileId) -> usize {
    (id.0 & SLAB_INDEX_MASK) as usize
}
#[inline]
fn make_id(shard: u32, index: u32) -> FileId {
    FileId((shard << SLAB_INDEX_BITS) | (index & SLAB_INDEX_MASK))
}

// ---- Intrusive hash index (Stage 4, "lever C", Lugdunum-style) ----
//
// Instead of a separate `DashMap<FileHash, FileId>` (which stores a DUPLICATE
// 16-byte hash per file plus hashbrown control/load-factor overhead, ~30 B/file
// = ~1 GB at 33M), the slab itself is the hash table: the 16-byte hash already
// lives once in `FileRecord.hash`, and records are chained per bucket via a
// parallel `next: Vec<u32>` (within-shard record indices, NIL-terminated). This
// mirrors Lugdunum's `S_file.f_next_in_hash` intrusive chaining — index, not a
// second copy of the hash. A file is placed in the shard determined BY ITS HASH
// (not round-robin), so its bucket chain is shard-local and one shard RwLock
// covers both the record and its chain — preserving the existing per-shard
// concurrency (O(1) insert under a shard write lock, no global lock, no array
// shift).
//
// `id_of` / `get_or_insert` / `insert_sourceless` / `tombstone` all operate
// directly on the chain under a single shard lock; there is no `hash_to_id`
// DashMap any more. Removing it reclaims the duplicate 16-byte hash and the
// DashMap overhead (~30 B/file) and, because each op now takes exactly one
// shard lock, eliminates the old DashMap↔slab lock-ordering window.

/// Empty-slot / chain-terminator sentinel for `next` and `buckets`.
const NIL: u32 = u32::MAX;

/// 64-bit view of a file hash, used to pick a shard and a bucket. The MD4 file
/// hash is already uniformly distributed, so we read 8 of its bytes directly
/// rather than re-hashing.
#[inline]
fn hash_u64(hash: &FileHash) -> u64 {
    u64::from_le_bytes(hash[0..8].try_into().unwrap())
}

/// Which shard a hash belongs to. SLAB_SHARDS is a power of two, so this is the
/// low bits of the hash; the bucket index (below) uses higher bits, keeping the
/// two selectors independent.
#[inline]
fn shard_of_hash(hash: &FileHash) -> u32 {
    (hash_u64(hash) & (SLAB_SHARDS as u64 - 1)) as u32
}

/// Bucket index within a shard for a hash, given the shard's current mask. Uses
/// bits above those consumed by the shard selector (SLAB_SHARDS == 2^6).
#[inline]
fn bucket_of(h: u64, mask: u32) -> usize {
    (((h >> 6) as u32) & mask) as usize
}

/// One shard: a dense Vec of records plus an intrusive per-bucket chain, all
/// under a single RwLock. `next[i]` is the next record index in the same bucket
/// as record `i` (NIL-terminated); `buckets[b]` is the head record index of
/// bucket `b` (NIL if empty). `records` and `next` are kept the same length.
struct SlabShard {
    records: Vec<FileRecord>,
    /// Intrusive chain link: same length as `records`. `next[i]` = next record
    /// index in i's bucket, or NIL. Tombstoned slots are unlinked (NIL) and not
    /// referenced by any bucket head.
    next: Vec<u32>,
    /// Bucket heads (record indices, NIL = empty). Power-of-two length.
    buckets: Vec<u32>,
    /// `buckets.len() - 1`, for masking a hash to a bucket index.
    bucket_mask: u32,
    /// Quarantined tombstoned slot indices awaiting reuse: (index, freed_at_secs).
    /// FIFO by free-time (front = oldest). A slot is only reused once it has aged
    /// past the quarantine window, so no in-flight search can still hold it.
    free: std::collections::VecDeque<(u32, u32)>,
}

/// Initial bucket count per shard (power of two). Shards start empty and grow by
/// doubling as records accumulate, so this is just a small floor.
const SLAB_SHARD_INIT_BUCKETS: usize = 64;

impl SlabShard {
    fn new() -> Self {
        SlabShard {
            records: Vec::new(),
            next: Vec::new(),
            buckets: vec![NIL; SLAB_SHARD_INIT_BUCKETS],
            bucket_mask: (SLAB_SHARD_INIT_BUCKETS - 1) as u32,
            free: std::collections::VecDeque::new(),
        }
    }

    /// Link an existing record (already in `records`/`next`) into its bucket.
    /// Caller holds the shard write lock.
    #[inline]
    fn link(&mut self, index: u32) {
        let h = hash_u64(&self.records[index as usize].hash);
        let b = bucket_of(h, self.bucket_mask);
        self.next[index as usize] = self.buckets[b];
        self.buckets[b] = index;
    }

    /// Unlink `index` from its bucket chain (used on tombstone). O(chain length).
    /// `hash` is the record's hash (read before the record is cleared).
    fn unlink(&mut self, index: u32, hash: &FileHash) {
        let b = bucket_of(hash_u64(hash), self.bucket_mask);
        let mut cur = self.buckets[b];
        let mut prev = NIL;
        while cur != NIL {
            if cur == index {
                if prev == NIL {
                    self.buckets[b] = self.next[cur as usize];
                } else {
                    self.next[prev as usize] = self.next[cur as usize];
                }
                self.next[cur as usize] = NIL;
                return;
            }
            prev = cur;
            cur = self.next[cur as usize];
        }
    }

    /// Double the bucket array and re-chain all live records. Amortized O(1) per
    /// insert (log-many doublings). Tombstoned slots are skipped and left NIL.
    fn grow_buckets(&mut self) {
        let new_len = (self.buckets.len() * 2).max(SLAB_SHARD_INIT_BUCKETS);
        self.buckets = vec![NIL; new_len];
        self.bucket_mask = (new_len - 1) as u32;
        for i in 0..self.records.len() {
            if self.records[i].alive {
                let h = hash_u64(&self.records[i].hash);
                let b = bucket_of(h, self.bucket_mask);
                self.next[i] = self.buckets[b];
                self.buckets[b] = i as u32;
            } else {
                self.next[i] = NIL;
            }
        }
    }

    /// Find the within-shard index of a live record with this hash by walking
    /// its bucket chain. Caller holds the shard read (or write) lock. The 16-byte
    /// hash compare distinguishes records that share a bucket. O(chain length).
    fn find(&self, hash: &FileHash) -> Option<u32> {
        let b = bucket_of(hash_u64(hash), self.bucket_mask);
        let mut cur = self.buckets[b];
        while cur != NIL {
            let r = &self.records[cur as usize];
            if r.alive && &r.hash == hash {
                return Some(cur);
            }
            cur = self.next[cur as usize];
        }
        None
    }

    /// Append a record and link it into its bucket, returning its within-shard
    /// index. Caller holds the shard write lock and must have confirmed the hash
    /// is new (via `find`). Grows the bucket array first when load would exceed
    /// ~1; grow_buckets re-links everything incl. the new record, so we only
    /// `link` separately when we did NOT grow (else we'd double-link).
    fn push_and_link(&mut self, rec: FileRecord) -> u32 {
        let index = self.records.len() as u32;
        self.records.push(rec);
        self.next.push(NIL);
        if self.records.len() > self.buckets.len() {
            self.grow_buckets();
        } else {
            self.link(index);
        }
        index
    }

    /// Insert a record, reusing a quarantined tombstone slot when one is old
    /// enough, else appending a fresh slot. `now` is current secs-from-epoch;
    /// `quarantine` is the min age (secs) a freed slot must reach before reuse.
    ///
    /// The free list is FIFO by free-time (now_secs is monotonic, every push is
    /// at the back), so the front entry is the oldest — checking it alone tells
    /// us whether ANY slot is reusable. The quarantine guarantees no in-flight
    /// search (which resolves a FileId within microseconds) can still be holding
    /// a slot we reuse, so id reuse is safe without generation counters.
    fn insert_record(&mut self, rec: FileRecord, now: u32, quarantine: u32) -> u32 {
        if let Some(&(idx, freed_at)) = self.free.front() {
            if now.wrapping_sub(freed_at) >= quarantine {
                self.free.pop_front();
                let i = idx as usize;
                self.records[i] = rec; // overwrite the dead record in place
                self.next[i] = NIL; // already unlinked at tombstone; be explicit
                self.link(idx); // link into the NEW hash's bucket
                return idx;
            }
        }
        self.push_and_link(rec)
    }
}

/// Slab-allocated file store, sharded for concurrency.
///
/// - `shards[s].records[i]` → FileRecord (dense Vec per shard)
/// - each shard is also an intrusive hash table (records chained per bucket via
///   `shards[s].next` / `shards[s].buckets`); a file lives in the shard chosen
///   by its hash, so one shard lock covers both its record and its chain. The
///   16-byte hash is stored once (in the record) — there is no separate hash→id
///   map. This is the Lugdunum-style intrusive index that replaced the former
///   `DashMap<FileHash, FileId>` (Stage 4 "lever C": removes the duplicate hash
///   and the DashMap overhead, and the old cross-structure lock ordering).
pub struct FileSlab {
    shards: Vec<std::sync::RwLock<SlabShard>>,
    /// Live file count, maintained by get_or_insert/insert_sourceless/tombstone
    /// for O(1) reporting (was derived from the DashMap len before lever C).
    live: AtomicU32,
    /// Monotonic time base. `last_seen` on each record is stored as u32 seconds
    /// since this instant (Stage 3d: 16-byte Instant → 4-byte u32, ~0.4 GB at
    /// 33M files). u32 seconds covers ~136 years of uptime — never overflows in
    /// practice. Kept (not dropped) so a future age-based eviction can use it.
    epoch: Instant,
    /// How long (secs) a tombstoned slot is quarantined before it may be reused.
    /// Bounds dead-slot accumulation (slot_count plateaus near peak-live instead
    /// of growing with total-ever-published) while staying far longer than any
    /// in-flight search, so id reuse needs no generation counters. 60s in prod;
    /// overridable to 0 in tests.
    quarantine_secs: u32,
}

/// Default slot quarantine window (seconds). Far exceeds a search's id-resolve
/// time (µs); a freed slot reused after this can have no live reference.
const SLOT_QUARANTINE_SECS: u32 = 60;

impl Default for FileSlab {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSlab {
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(SLAB_SHARDS as usize);
        for _ in 0..SLAB_SHARDS {
            shards.push(std::sync::RwLock::new(SlabShard::new()));
        }
        Self {
            shards,
            live: AtomicU32::new(0),
            epoch: Instant::now(),
            quarantine_secs: SLOT_QUARANTINE_SECS,
        }
    }

    /// Test seam: override the slot quarantine window (e.g. 0 for immediate
    /// reuse) so reuse can be exercised without waiting real seconds.
    #[cfg(test)]
    fn set_quarantine_secs(&mut self, secs: u32) {
        self.quarantine_secs = secs;
    }

    /// Current time as u32 seconds since the slab epoch — the value stored in
    /// `FileRecord.last_seen`. Saturates at u32::MAX (≈136 years).
    #[inline]
    pub fn now_secs(&self) -> u32 {
        self.epoch.elapsed().as_secs().min(u32::MAX as u64) as u32
    }

    /// Look up the id for a hash, if present. Walks the bucket chain in the
    /// hash's shard (intrusive index — no separate hash→id map). One shard read
    /// lock; chains stay ~1 long at load factor ~1.
    pub fn id_of(&self, hash: &FileHash) -> Option<FileId> {
        let shard_no = shard_of_hash(hash);
        let sh = self.shards[shard_no as usize].read().unwrap();
        sh.find(hash).map(|idx| make_id(shard_no, idx))
    }

    /// Resolve an id back to its hash, if the slot is alive. The reverse of
    /// `id_of`; used by paths that hold a FileId (keyword/user_files) and need
    /// the 16-byte hash to reach the live record.
    pub fn hash_of(&self, id: FileId) -> Option<FileHash> {
        let shard = self.shards.get(id_shard(id))?;
        let recs = shard.read().unwrap();
        recs.records.get(id_index(id)).filter(|r| r.alive).map(|r| r.hash)
    }

    /// Insert a new file or return the existing id. Returns (id, was_new).
    ///
    /// The whole search-then-insert runs under one shard WRITE lock, so the
    /// operation is atomic: two threads publishing the same new hash serialize on
    /// the lock — the first inserts, the second's `find` sees it and returns the
    /// existing id. No separate map, no entry-API race dance, and exactly one
    /// lock taken (this is what removes the old DashMap↔slab lock-ordering).
    pub fn get_or_insert(
        &self,
        hash: FileHash,
        size: u64,
        name: Arc<str>,
        first_source: Source,
    ) -> (FileId, bool) {
        let now = self.now_secs();
        let shard_no = shard_of_hash(&hash);
        let mut sh = self.shards[shard_no as usize].write().unwrap();
        if let Some(idx) = sh.find(&hash) {
            return (make_id(shard_no, idx), false);
        }
        let index = sh.insert_record(
            FileRecord {
                hash,
                size,
                name,
                sources: smallvec![first_source],
                last_seen: now,
                alive: true,
            },
            now,
            self.quarantine_secs,
        );
        drop(sh);
        self.live.fetch_add(1, Ordering::Relaxed);
        (make_id(shard_no, index), true)
    }

    /// Insert a file with NO sources. Returns the id (existing if the hash is
    /// already known). Same single-write-lock discipline as `get_or_insert`.
    pub fn insert_sourceless(&self, hash: FileHash, size: u64, name: Arc<str>) -> FileId {
        let now = self.now_secs();
        let shard_no = shard_of_hash(&hash);
        let mut sh = self.shards[shard_no as usize].write().unwrap();
        if let Some(idx) = sh.find(&hash) {
            return make_id(shard_no, idx);
        }
        let index = sh.insert_record(
            FileRecord {
                hash,
                size,
                name,
                sources: SourceVec::new(),
                last_seen: now,
                alive: true,
            },
            now,
            self.quarantine_secs,
        );
        drop(sh);
        self.live.fetch_add(1, Ordering::Relaxed);
        make_id(shard_no, index)
    }

    /// Resolve an id to a clone of its record, if alive.
    pub fn get(&self, id: FileId) -> Option<FileRecord> {
        let shard = self.shards.get(id_shard(id))?;
        let recs = shard.read().unwrap();
        recs.records.get(id_index(id)).filter(|r| r.alive).cloned()
    }

    /// Tombstone a file by id: marks the slot dead and drops the hash mapping.
    /// Tombstone a file by id: unlinks it from its bucket chain, marks the slot
    /// dead, frees its heavy fields, and queues the slot for quarantined reuse.
    /// Returns true if it was alive. The slot is NOT reused until it ages past
    /// the quarantine window, so any in-flight search holding this id has long
    /// finished — stale ids resolve to None (slot dead / unlinked) until then.
    pub fn tombstone(&self, id: FileId) -> bool {
        let shard = match self.shards.get(id_shard(id)) {
            Some(s) => s,
            None => return false,
        };
        let now = self.now_secs();
        let idx = id_index(id);
        let mut sh = shard.write().unwrap();
        // Read hash + liveness first (immutable borrow ends before we mutate the
        // chain), so the unlink and the field-clear don't fight the borrow check.
        let hash = match sh.records.get(idx) {
            Some(r) if r.alive => r.hash,
            _ => return false,
        };
        // Unlink from its bucket chain (touches buckets/next only), then mark the
        // slot dead and free the heavy fields. Stale ids resolve to None via the
        // alive flag / chain absence until the slot is reused.
        sh.unlink(idx as u32, &hash);
        {
            let r = &mut sh.records[idx];
            r.alive = false;
            r.name = Arc::from("");
            r.sources = SourceVec::new();
        }
        // Queue for reuse once quarantined (FIFO by free-time; now is monotonic).
        sh.free.push_back((idx as u32, now));
        drop(sh);
        self.live.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// Tombstone by hash (convenience for callers that hold a hash, not an id).
    pub fn tombstone_by_hash(&self, hash: &FileHash) -> bool {
        if let Some(id) = self.id_of(hash) {
            self.tombstone(id)
        } else {
            false
        }
    }

    /// Number of live files.
    pub fn live_count(&self) -> usize {
        self.live.load(Ordering::Relaxed) as usize
    }

    /// Total slab slots including tombstones (for diagnostics).
    pub fn slot_count(&self) -> usize {
        let mut n = 0;
        for s in &self.shards {
            n += s.read().unwrap().records.len();
        }
        n
    }

    /// Byte-level breakdown of what the slab holds, for /api/memsize.
    ///
    /// Reports CAPACITY, not length: `Vec` never shrinks on removal, so the
    /// records/next/buckets arrays stay sized to the daily high-water mark. That
    /// gap (capacity vs. live) is exactly what we want to see. Returns
    /// (records_bytes, next_bytes, buckets_bytes, heap_sources_bytes).
    ///
    /// `heap_sources_bytes` counts only sources that SPILLED to the heap: a
    /// SmallVec<[Source;1]> stores the first source inline (already inside the
    /// FileRecord), so only files with 2+ sources allocate.
    pub fn size_report(&self) -> (u64, u64, u64, u64) {
        let rec_sz = std::mem::size_of::<FileRecord>() as u64;
        let src_sz = std::mem::size_of::<Source>() as u64;
        let (mut records, mut next, mut buckets, mut spilled) = (0u64, 0u64, 0u64, 0u64);
        for s in &self.shards {
            let sh = s.read().unwrap();
            records += sh.records.capacity() as u64 * rec_sz;
            next    += sh.next.capacity() as u64 * 4;      // Vec<u32>
            buckets += sh.buckets.capacity() as u64 * 4;   // Vec<u32>
            for r in sh.records.iter() {
                // spilled_capacity() is 0 while the SmallVec is inline
                if r.sources.spilled() {
                    spilled += r.sources.capacity() as u64 * src_sz;
                }
            }
        }
        (records, next, buckets, spilled)
    }

    /// Dead slots currently quarantined awaiting reuse (diagnostics). With the
    /// quarantine free-list, slot_count plateaus near (live high-water) and this
    /// holds the transient surplus; if it grows without bound, churn outpaces the
    /// quarantine window.
    pub fn free_pending_count(&self) -> usize {
        let mut n = 0;
        for s in &self.shards {
            n += s.read().unwrap().free.len();
        }
        n
    }

    // ---- Variant-A accessors: these let the slab replace the `files` DashMap
    // entirely (Stage 3c). Each takes a single shard lock, so operations on
    // different files run concurrently, preserving the sharded parallelism.

    /// Resolve a hash directly to a clone of its live record. Replaces
    /// `files.get(&hash)`. One intrusive chain walk + one shard read lock.
    pub fn get_by_hash(&self, hash: &FileHash) -> Option<FileRecord> {
        let id = self.id_of(hash)?;
        self.get(id)
    }

    /// Add or refresh a source on an existing file (by hash). Returns true if
    /// the file existed (and was updated). Mirrors the and_modify arm of the old
    /// `files.entry(hash).and_modify(...)`: dedups by user_hash, refreshes the
    /// completeness flag, bumps last_seen. Used by add_file_with_source for the
    /// "already known file" path.
    pub fn add_or_refresh_source(&self, hash: &FileHash, src: Source) -> bool {
        let id = match self.id_of(hash) { Some(i) => i, None => return false };
        let shard = match self.shards.get(id_shard(id)) { Some(s) => s, None => return false };
        let mut sh = shard.write().unwrap();
        if let Some(r) = sh.records.get_mut(id_index(id)) {
            if !r.alive { return false; }
            r.last_seen = self.now_secs();
            if let Some(existing) = r.sources.iter_mut().find(|s| s.user_hash == src.user_hash) {
                existing.set_complete(src.complete());
            } else {
                r.sources.push(src);
            }
            return true;
        }
        false
    }

    /// Remove every source published by `user_hash` from the file `id`. Returns
    /// true if the file is now sourceless (an orphan the caller should evict).
    /// Replaces the per-file body of `remove_sources_of`.
    pub fn remove_user_source(&self, id: FileId, user_hash: &FileHash) -> bool {
        let shard = match self.shards.get(id_shard(id)) { Some(s) => s, None => return false };
        let mut sh = shard.write().unwrap();
        if let Some(r) = sh.records.get_mut(id_index(id)) {
            if !r.alive { return false; }
            r.sources.retain(|s| &s.user_hash != user_hash);
            return r.sources.is_empty();
        }
        false
    }

    /// Iterate every LIVE record, calling `f(id, &record)`. Replaces
    /// `files.iter()`. Locks one shard at a time (read), so writers to other
    /// shards proceed; within a shard, writers wait — same granularity as the
    /// old per-bucket DashMap iteration. `f` must not call back into the slab
    /// for the same shard (would deadlock); callers collect what they need.
    pub fn for_each_live<F: FnMut(FileId, &FileRecord)>(&self, mut f: F) {
        for (s_no, shard) in self.shards.iter().enumerate() {
            let sh = shard.read().unwrap();
            for (i, r) in sh.records.iter().enumerate() {
                if r.alive {
                    f(make_id(s_no as u32, i as u32), r);
                }
            }
        }
    }

    /// Lightweight stats pass for memory_report: returns (sources_len,
    /// name_len) per live record without cloning the record itself.
    pub fn iter_records_for_report(&self) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for shard in &self.shards {
            let sh = shard.read().unwrap();
            for r in &sh.records {
                if r.alive {
                    out.push((r.sources.len(), r.name.len()));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn src() -> Source {
        Source::new([1u8; 16], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4662, true)
    }

    #[test]
    fn insert_and_resolve() {
        let slab = FileSlab::new();
        let (id, new) = slab.get_or_insert([10u8; 16], 100, "a.bin".into(), src());
        assert!(new);
        // id resolves back to the same record (value of id is opaque now that
        // it encodes a shard; we test the round-trip, not a literal).
        let rec = slab.get(id).unwrap();
        assert_eq!(rec.hash, [10u8; 16]);
        assert_eq!(&*rec.name, "a.bin");
        assert_eq!(slab.id_of(&[10u8; 16]), Some(id));
        assert_eq!(slab.hash_of(id), Some([10u8; 16]));
    }

    #[test]
    fn dedup_returns_existing_id() {
        let slab = FileSlab::new();
        let (id1, n1) = slab.get_or_insert([10u8; 16], 100, "a.bin".into(), src());
        let (id2, n2) = slab.get_or_insert([10u8; 16], 100, "a.bin".into(), src());
        assert!(n1 && !n2);
        assert_eq!(id1, id2, "same hash must map to same id");
        assert_eq!(slab.live_count(), 1);
    }

    #[test]
    fn ids_are_unique_and_resolve() {
        let slab = FileSlab::new();
        let mut ids = Vec::new();
        for i in 0..100u8 {
            let (id, _) = slab.get_or_insert([i; 16], 1, "f".into(), src());
            ids.push(id);
        }
        // All ids distinct.
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "ids must be unique across shards");
        // Each id resolves to the right hash.
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(slab.hash_of(*id), Some([i as u8; 16]));
        }
        assert_eq!(slab.slot_count(), 100);
        assert_eq!(slab.live_count(), 100);
    }

    #[test]
    fn tombstone_makes_id_resolve_none_and_frees_hash() {
        let slab = FileSlab::new();
        let (id, _) = slab.get_or_insert([10u8; 16], 100, "a.bin".into(), src());
        assert!(slab.tombstone(id));
        // Stale id now resolves to None (safety property for lazy cleanup).
        assert!(slab.get(id).is_none());
        assert!(slab.hash_of(id).is_none());
        // Hash mapping is gone, so the same hash re-publishes as a NEW id.
        assert_eq!(slab.id_of(&[10u8; 16]), None);
        let (id2, new) = slab.get_or_insert([10u8; 16], 100, "a.bin".into(), src());
        assert!(new);
        assert_ne!(id2, id, "tombstoned id is not reused");
    }

    #[test]
    fn double_tombstone_is_false() {
        let slab = FileSlab::new();
        let (id, _) = slab.get_or_insert([10u8; 16], 100, "a.bin".into(), src());
        assert!(slab.tombstone(id));
        assert!(!slab.tombstone(id), "second tombstone returns false");
    }

    #[test]
    fn insert_sourceless_and_tombstone_by_hash() {
        let slab = FileSlab::new();
        let id = slab.insert_sourceless([7u8; 16], 50, "restored.bin".into());
        let rec = slab.get(id).unwrap();
        assert!(rec.sources.is_empty(), "restored file has no sources");
        assert_eq!(slab.live_count(), 1);
        // Re-inserting same hash returns existing id (no duplicate).
        let id2 = slab.insert_sourceless([7u8; 16], 50, "restored.bin".into());
        assert_eq!(id, id2);
        assert_eq!(slab.live_count(), 1);
        // Tombstone by hash.
        assert!(slab.tombstone_by_hash(&[7u8; 16]));
        assert_eq!(slab.live_count(), 0);
        // Unknown hash → false.
        assert!(!slab.tombstone_by_hash(&[99u8; 16]));
    }

    #[test]
    fn shard_encoding_roundtrip() {
        // make_id / id_shard / id_index are inverses.
        for shard in [0u32, 1, 7, 63] {
            for index in [0u32, 1, 1000, SLAB_INDEX_MASK] {
                let id = make_id(shard, index);
                assert_eq!(id_shard(id), shard as usize);
                assert_eq!(id_index(id), index as usize);
            }
        }
    }

    // ---- Intrusive-index validation (Stage 4 lever C): `id_of` now resolves
    // via the per-shard bucket chain (no DashMap). These exercise insert, dedup,
    // bucket growth/rehash and tombstone unlink directly through `id_of`.

    #[test]
    fn intrusive_index_resolves_across_ops() {
        let slab = FileSlab::new();
        // Enough distinct hashes to push several shards past their initial 64
        // buckets, exercising grow_buckets()/rehash.
        let mut ids = Vec::new();
        for i in 0..5000u32 {
            let mut h = [0u8; 16];
            h[0..4].copy_from_slice(&i.to_le_bytes());
            let (id, _) = slab.get_or_insert(h, i as u64, "f".into(), src());
            ids.push((h, id));
        }
        // Every present hash resolves to the id it was inserted as.
        for (h, id) in &ids {
            assert_eq!(slab.id_of(h), Some(*id));
            assert_eq!(slab.hash_of(*id), Some(*h));
        }
        // An absent hash resolves to None.
        let missing = [0xFFu8; 16];
        assert_eq!(slab.id_of(&missing), None);
        assert_eq!(slab.live_count(), 5000);
        // Tombstone half: those become unreachable; the rest still resolve.
        for (h, id) in ids.iter().take(2500) {
            assert!(slab.tombstone(*id));
            assert_eq!(slab.id_of(h), None, "tombstoned hash still in chain");
        }
        for (h, id) in ids.iter().skip(2500) {
            assert_eq!(slab.id_of(h), Some(*id), "survivor dropped from chain");
        }
        assert_eq!(slab.live_count(), 2500);
    }

    #[test]
    fn intrusive_unlink_middle_of_chain() {
        let slab = FileSlab::new();
        // All 8 hashes share their first 8 bytes → same shard AND same bucket →
        // one chain of length 8. They differ only in byte 15, so they are
        // distinct files (full-hash compare distinguishes them in the walk).
        let mut ids = Vec::new();
        for k in 0..8u8 {
            let mut h = [0u8; 16];
            h[0] = 5;
            h[15] = k;
            let (id, _) = slab.get_or_insert(h, k as u64, "f".into(), src());
            ids.push((h, id));
        }
        // Tombstone one in the middle of the chain; the rest must stay reachable.
        let (mid_h, mid_id) = ids[3];
        assert!(slab.tombstone(mid_id));
        assert_eq!(slab.id_of(&mid_h), None);
        for (i, (h, id)) in ids.iter().enumerate() {
            if i == 3 {
                continue;
            }
            assert_eq!(slab.id_of(h), Some(*id), "chain corrupted after middle unlink");
        }
    }

    // ---- Quarantine free-list (slot reuse): bounds slab growth under churn.

    fn h_of(i: u32) -> FileHash {
        let mut h = [0u8; 16];
        h[0..4].copy_from_slice(&i.to_le_bytes());
        h
    }

    #[test]
    fn quarantine_holds_slots_until_window() {
        // Default 60s quarantine: a slot freed now cannot be reused now, so a
        // fresh batch must append new slots rather than recycle the dead ones.
        let slab = FileSlab::new();
        for i in 0..50u32 {
            slab.get_or_insert(h_of(i), i as u64, "f".into(), src());
        }
        for i in 0..50u32 {
            assert!(slab.tombstone(slab.id_of(&h_of(i)).unwrap()));
        }
        // Insert a disjoint batch immediately — quarantine has not elapsed.
        for i in 100..150u32 {
            slab.get_or_insert(h_of(i), i as u64, "f".into(), src());
        }
        assert_eq!(slab.live_count(), 50);
        assert_eq!(
            slab.slot_count(),
            100,
            "quarantined slots must NOT be reused before the window"
        );
    }

    #[test]
    fn reused_slots_keep_slot_count_flat() {
        // Quarantine 0: tombstoned slots are immediately reusable, so churning
        // the same hashes keeps slot_count flat (no unbounded tombstone growth).
        let mut slab = FileSlab::new();
        slab.set_quarantine_secs(0);
        for i in 0..50u32 {
            slab.get_or_insert(h_of(i), i as u64, "f".into(), src());
        }
        assert_eq!(slab.slot_count(), 50);
        for i in 0..50u32 {
            assert!(slab.tombstone(slab.id_of(&h_of(i)).unwrap()));
        }
        assert_eq!(slab.live_count(), 0);
        // Re-publish the same hashes: each lands in the shard that holds its freed
        // slot, so every insert recycles — no new slots appended.
        for i in 0..50u32 {
            slab.get_or_insert(h_of(i), i as u64, "f".into(), src());
        }
        assert_eq!(slab.live_count(), 50);
        assert_eq!(
            slab.slot_count(),
            50,
            "reuse must keep slot_count at the live high-water mark"
        );
        // All re-published hashes resolve correctly through the recycled slots.
        for i in 0..50u32 {
            assert!(slab.id_of(&h_of(i)).is_some());
        }
    }
}
