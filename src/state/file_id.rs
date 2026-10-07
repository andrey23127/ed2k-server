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

use crate::state::file_name::FileName;
use crate::state::{FileHash, Source};
use smallvec::{smallvec, SmallVec};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
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
    /// The name; `None` marks a tombstoned slot. When a file is evicted the
    /// slot is marked dead rather than reused at once, so dangling FileIds in
    /// postings resolve to None.
    ///
    /// One thin pointer (see `FileName`), and doubling as the tombstone flag,
    /// is what brings the record from 80 to 64 bytes: the old separate
    /// `alive: bool` and the `last_seen: u32` (written, never read) are gone.
    fname: Option<FileName>,
    pub sources: SourceVec,
}

impl FileRecord {
    pub fn new(hash: FileHash, size: u64, name: &str, sources: SourceVec) -> Self {
        Self { hash, size, fname: Some(FileName::new(name)), sources }
    }

    /// The file name ("" for a tombstoned slot, which no lookup returns).
    #[inline]
    pub fn name(&self) -> &str {
        self.fname.as_deref().unwrap_or("")
    }

    #[inline]
    pub fn alive(&self) -> bool {
        self.fname.is_some()
    }

    /// Heap bytes of the name, before allocator rounding (memory reports).
    pub fn name_heap_bytes(&self) -> usize {
        self.fname.as_ref().map_or(0, |n| n.heap_bytes())
    }

    /// Number of sources that hold a complete copy, for the FT_COMPLETE_SOURCES
    /// (0x30) search-result tag (issue #28).
    ///
    /// Only sources offered as complete count. eMule and aMule offer a part
    /// file with the incomplete marker (0xFCFCFCFC/0xFCFC), and aMule also
    /// uses it for a complete file whose local verify found corrupt parts;
    /// a re-offer updates the flag. A source offered without markers (old
    /// clients, a real HighID id) is stored as complete. Lugdunum counts the
    /// same way: a file only partial downloaders hold shows no complete
    /// source, which is what eMule's "complete sources" column and aMule's
    /// "total (complete)" are for. This server used to count every source.
    pub fn complete_source_count(&self) -> u32 {
        self.sources.iter().filter(|s| s.complete()).count() as u32
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
/// Records per chunk of a shard (64 KB of 64-byte records).
const RECORD_CHUNK: usize = 1024;

/// A growable array stored as fixed-size chunks.
///
/// The slab's records used to be one `Vec` per shard, grown by a quarter at a
/// time. That still left on average ~10% of the largest allocation in the
/// process reserved and unused, and every growth step copied the whole shard:
/// for a moment the old and the new array both existed, so peak memory ran
/// ~25% of a shard above the steady state, at 30M files tens of MB per step.
/// Chunks never move: growth allocates one more chunk, the idle reserve is at
/// most one chunk per shard, and an element's address is stable.
struct ChunkedVec<T> {
    chunks: Vec<Vec<T>>,
    len: usize,
}

impl<T> ChunkedVec<T> {
    fn new() -> Self {
        Self { chunks: Vec::new(), len: 0 }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    fn capacity(&self) -> usize {
        self.chunks.len() * RECORD_CHUNK
    }

    fn push(&mut self, v: T) {
        if self.len == self.capacity() {
            self.chunks.push(Vec::with_capacity(RECORD_CHUNK));
        }
        self.chunks.last_mut().expect("a chunk with room").push(v);
        self.len += 1;
    }

    #[inline]
    fn get(&self, i: usize) -> Option<&T> {
        self.chunks.get(i / RECORD_CHUNK)?.get(i % RECORD_CHUNK)
    }

    #[inline]
    fn get_mut(&mut self, i: usize) -> Option<&mut T> {
        self.chunks.get_mut(i / RECORD_CHUNK)?.get_mut(i % RECORD_CHUNK)
    }

    fn iter(&self) -> impl Iterator<Item = &T> {
        self.chunks.iter().flat_map(|c| c.iter())
    }
}

impl<T> std::ops::Index<usize> for ChunkedVec<T> {
    type Output = T;
    #[inline]
    fn index(&self, i: usize) -> &T {
        &self.chunks[i / RECORD_CHUNK][i % RECORD_CHUNK]
    }
}

impl<T> std::ops::IndexMut<usize> for ChunkedVec<T> {
    #[inline]
    fn index_mut(&mut self, i: usize) -> &mut T {
        &mut self.chunks[i / RECORD_CHUNK][i % RECORD_CHUNK]
    }
}

struct SlabShard {
    records: ChunkedVec<FileRecord>,
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
            records: ChunkedVec::new(),
            next: Vec::new(),
            buckets: vec![NIL; SLAB_SHARD_INIT_BUCKETS],
            bucket_mask: (SLAB_SHARD_INIT_BUCKETS - 1) as u32,
            free: std::collections::VecDeque::new(),
        }
    }

    /// Grow `next` by a fixed fraction instead of letting `Vec` double (the
    /// records grow by chunks, see `ChunkedVec`).
    ///
    /// `Vec`'s doubling is the right default for a short-lived buffer and the
    /// wrong one for a slab that only ever grows and holds the largest single
    /// allocation in the process. Doubling means the capacity spends its life
    /// between 50% and 100% used: at 1.17M records the shards had reserved room
    /// for ~1.9M, with 62 MB standing idle, and the waste scales — at the 33M
    /// target the same pattern reserves gigabytes to hold nothing.
    ///
    /// Growing by a quarter keeps the idle fraction under ~20% instead of up to
    /// 50%. The cost is more frequent reallocation, but this is still amortised
    /// O(1) growth (geometric, just with a smaller ratio), and a slab that fills
    /// over hours cares far more about resident memory than about how often it
    /// memcpys.
    ///
    /// `GROW_MIN` keeps small/new shards from reallocating on nearly every push
    /// while a quarter of a tiny number is still tiny.
    #[inline]
    fn reserve_gently(&mut self) {
        const GROW_NUM: usize = 1;
        const GROW_DEN: usize = 4;
        const GROW_MIN: usize = 1024;
        let len = self.next.len();
        if len < self.next.capacity() {
            return; // room already
        }
        let extra = std::cmp::max(len * GROW_NUM / GROW_DEN, GROW_MIN);
        // reserve_exact, NOT reserve: reserve would apply Vec's own amplification
        // on top of ours and put the doubling right back.
        self.next.reserve_exact(extra);
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
            if self.records[i].alive() {
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
            if r.alive() && &r.hash == hash {
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
        self.reserve_gently();
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
    /// Monotonic time base for the slot quarantine: u32 seconds since this
    /// instant (~136 years of range).
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

    /// Current time as u32 seconds since the slab epoch. Saturates at u32::MAX
    /// (≈136 years).
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
        recs.records
            .get(id_index(id))
            .filter(|r| r.alive())
            .map(|r| r.hash)
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
        name: &str,
        first_source: Source,
    ) -> (FileId, bool) {
        let now = self.now_secs();
        let shard_no = shard_of_hash(&hash);
        let mut sh = self.shards[shard_no as usize].write().unwrap();
        if let Some(idx) = sh.find(&hash) {
            return (make_id(shard_no, idx), false);
        }
        let index = sh.insert_record(
            FileRecord::new(hash, size, name, smallvec![first_source]),
            now,
            self.quarantine_secs,
        );
        drop(sh);
        self.live.fetch_add(1, Ordering::Relaxed);
        (make_id(shard_no, index), true)
    }

    /// Insert a file with NO sources. Returns the id (existing if the hash is
    /// already known). Same single-write-lock discipline as `get_or_insert`.
    pub fn insert_sourceless(&self, hash: FileHash, size: u64, name: &str) -> FileId {
        let now = self.now_secs();
        let shard_no = shard_of_hash(&hash);
        let mut sh = self.shards[shard_no as usize].write().unwrap();
        if let Some(idx) = sh.find(&hash) {
            return make_id(shard_no, idx);
        }
        let index = sh.insert_record(
            FileRecord::new(hash, size, name, SourceVec::new()),
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
        recs.records.get(id_index(id)).filter(|r| r.alive()).cloned()
    }

    /// Tombstone a file by id: marks the slot dead and drops the hash mapping.
    /// Tombstone a file by id: unlinks it from its bucket chain, marks the slot
    /// dead, frees its heavy fields, and queues the slot for quarantined reuse.
    /// Returns true if it was alive. The slot is NOT reused until it ages past
    /// the quarantine window, so any in-flight search holding this id has long
    /// finished — stale ids resolve to None (slot dead / unlinked) until then.
    pub fn tombstone(&self, id: FileId) -> bool {
        self.tombstone_where(id, |_| true).is_some()
    }

    /// Tombstone `id` only if it is alive AND has no sources, checked under the
    /// same write lock that does the tombstoning. Returns the record's name
    /// (for the keyword removal that must follow) when it was tombstoned.
    ///
    /// The eviction paths decide "this file is sourceless" in one lock and
    /// tombstone in another. A publisher adding a source in between used to
    /// lose the file: it was tombstoned with a live source, and since a
    /// re-publish of a known hash does not re-add keywords, it vanished from
    /// search until every source left and came back. Re-checking here closes
    /// that window; a file that regained a source is simply left alone.
    pub fn tombstone_if_sourceless(&self, id: FileId) -> Option<FileName> {
        self.tombstone_where(id, |r| r.sources.is_empty())
    }

    fn tombstone_where(
        &self,
        id: FileId,
        cond: impl FnOnce(&FileRecord) -> bool,
    ) -> Option<FileName> {
        let shard = self.shards.get(id_shard(id))?;
        let now = self.now_secs();
        let idx = id_index(id);
        let mut sh = shard.write().unwrap();
        // Read hash + liveness first (immutable borrow ends before we mutate the
        // chain), so the unlink and the field-clear don't fight the borrow check.
        let hash = match sh.records.get(idx) {
            Some(r) if r.alive() && cond(r) => r.hash,
            _ => return None,
        };
        // Unlink from its bucket chain (touches buckets/next only), then mark the
        // slot dead and free the heavy fields. Stale ids resolve to None via the
        // alive flag / chain absence until the slot is reused.
        sh.unlink(idx as u32, &hash);
        let name = {
            let r = &mut sh.records[idx];
            r.sources = SourceVec::new();
            r.fname.take()
        };
        // Queue for reuse once quarantined (FIFO by free-time; now is monotonic).
        sh.free.push_back((idx as u32, now));
        drop(sh);
        self.live.fetch_sub(1, Ordering::Relaxed);
        name
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
    /// (len, capacity) of one shard's record vector. Diagnostics and tests —
    /// the capacity is not observable any other way, and it is the number that
    /// decides how much of the slab stands idle.
    pub fn shard_len_cap(&self, shard: usize) -> (usize, usize) {
        match self.shards.get(shard) {
            Some(sh) => {
                let g = sh.read().unwrap();
                (g.records.len(), g.records.capacity())
            }
            None => (0, 0),
        }
    }

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
            next += sh.next.capacity() as u64 * 4; // Vec<u32>
            buckets += sh.buckets.capacity() as u64 * 4; // Vec<u32>
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
    /// completeness flag. Used by add_file_with_source for the
    /// "already known file" path.
    /// Like `add_or_refresh_source`, but also reports the name already stored for
    /// this file when the publisher used a DIFFERENT one.
    ///
    /// Returns `Some(stored_name)` only on divergence; `None` when the names match
    /// or the file is unknown.
    ///
    /// Cost is one string comparison inside the shard lock this call already
    /// takes. Nothing is allocated unless the names actually differ, which is
    /// rare.
    ///
    /// The names are compared by content. The interner no longer deduplicates
    /// (it is a plain `Arc::from`), so the pointer test this used to rely on
    /// was never true for a second publish: every re-publish of a known file
    /// under the SAME name was reported as divergence, ran the alias
    /// bookkeeping and could fill an alias entry with copies of one name.
    ///
    /// Divergence is the signal that catches masquerading: one file circulated
    /// under many unrelated names ("MANUALE PHOTOSHOP COMPLETO.PDF" at 690 MB,
    /// also seen as "12Yo Nude - Sexy Dance", "Daemon.Tools.Pro", "Vikings.3x05").
    /// A name filter cannot see that; the pattern only exists across publishers.
    pub fn add_or_refresh_source_named(
        &self,
        hash: &FileHash,
        src: Source,
        published_as: &str,
    ) -> Option<Arc<str>> {
        let id = self.id_of(hash)?;
        let shard = self.shards.get(id_shard(id))?;
        let mut sh = shard.write().unwrap();
        let r = sh.records.get_mut(id_index(id))?;
        if !r.alive() {
            return None;
        }
        if let Some(existing) = r.sources.iter_mut().find(|s| s.user_hash == src.user_hash) {
            existing.set_complete(src.complete());
        } else {
            r.sources.push(src);
        }
        // Same name → nothing to report. The pointer test is a free shortcut.
        if r.name() == published_as {
            None
        } else {
            Some(Arc::from(r.name()))
        }
    }

    pub fn add_or_refresh_source(&self, hash: &FileHash, src: Source) -> bool {
        let id = match self.id_of(hash) {
            Some(i) => i,
            None => return false,
        };
        let shard = match self.shards.get(id_shard(id)) {
            Some(s) => s,
            None => return false,
        };
        let mut sh = shard.write().unwrap();
        if let Some(r) = sh.records.get_mut(id_index(id)) {
            if !r.alive() {
                return false;
            }
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
        let shard = match self.shards.get(id_shard(id)) {
            Some(s) => s,
            None => return false,
        };
        let mut sh = shard.write().unwrap();
        if let Some(r) = sh.records.get_mut(id_index(id)) {
            if !r.alive() {
                return false;
            }
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
    /// Run `f` against a live record IN PLACE, without cloning it.
    ///
    /// `get`/`get_by_hash` clone the whole `FileRecord` — sources SmallVec, an
    /// Arc bump on the name — which is right when the caller keeps the record,
    /// and wasteful when it only wants to test a predicate. Search does the
    /// latter for every candidate and keeps a handful, so cloning first and
    /// filtering second was paying the clone for results that get thrown away.
    ///
    /// The shard read lock is held for the duration of `f`. Keep `f` short and
    /// pure: it must not touch the slab again (same-shard re-entry would
    /// deadlock on a non-reentrant RwLock) and must not await.
    pub fn with_record<R, F: FnOnce(&FileRecord) -> R>(&self, id: FileId, f: F) -> Option<R> {
        let shard = self.shards.get(id_shard(id))?;
        let recs = shard.read().unwrap();
        let r = recs.records.get(id_index(id))?;
        if !r.alive() {
            return None;
        }
        Some(f(r))
    }

    /// Same, resolved by hash. One lock acquisition, not two.
    ///
    /// Callers that already hold a `FileId` should use `with_record`: going
    /// FileId → hash → FileId costs an extra lock and an extra hash-chain walk
    /// for nothing.
    pub fn with_record_by_hash<R, F: FnOnce(FileId, &FileRecord) -> R>(
        &self,
        hash: &FileHash,
        f: F,
    ) -> Option<R> {
        let shard_no = shard_of_hash(hash);
        let sh = self.shards[shard_no as usize].read().unwrap();
        let idx = sh.find(hash)?;
        let r = sh.records.get(idx as usize)?;
        if !r.alive() {
            return None;
        }
        Some(f(make_id(shard_no, idx), r))
    }

    /// Like `for_each_live`, but stops as soon as `f` returns false.
    ///
    /// Exists so a caller can bound its own work: the full walk holds a shard
    /// read lock and is O(live files), which is not something an unauthenticated
    /// request should be able to trigger without a ceiling.
    pub fn for_each_live_while<F: FnMut(FileId, &FileRecord) -> bool>(&self, mut f: F) {
        for (s_no, shard) in self.shards.iter().enumerate() {
            let sh = shard.read().unwrap();
            for (i, r) in sh.records.iter().enumerate() {
                if r.alive() && !f(make_id(s_no as u32, i as u32), r) {
                    return;
                }
            }
        }
    }

    /// Visit every live record. The shard read lock is taken per slice of
    /// `SCAN_CHUNK` slots, not for the whole shard: at 30M files a shard is
    /// ~470k slots, and holding its lock for the whole walk stalled every
    /// publish and GETSOURCES that hashed to it for the duration. Between
    /// slices writers get in; the walk sees each slot once (slots never move,
    /// and slots appended meanwhile are picked up when the walk reaches them).
    pub fn for_each_live<F: FnMut(FileId, &FileRecord)>(&self, mut f: F) {
        const SCAN_CHUNK: usize = 16 * 1024;
        for (s_no, shard) in self.shards.iter().enumerate() {
            let mut start = 0usize;
            loop {
                let sh = shard.read().unwrap();
                let end = sh.records.len().min(start + SCAN_CHUNK);
                if start >= end {
                    break;
                }
                for i in start..end {
                    let r = &sh.records[i];
                    if r.alive() {
                        f(make_id(s_no as u32, i as u32), r);
                    }
                }
                drop(sh);
                start = end;
            }
        }
    }

    /// Calls `f(sources_len, name_len)` for every live record, for the memory
    /// reports. Folds in place: it used to return a Vec of one pair per file —
    /// 30M pairs, ~480 MB allocated for the length of one admin request.
    /// Uses the chunked walk, so writers are not held off for a whole shard.
    pub fn for_each_record_size(&self, mut f: impl FnMut(usize, usize)) {
        self.for_each_live(|_, r| f(r.sources.len(), r.name_heap_bytes()));
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
    fn complete_sources_count_only_complete_copies_and_follow_re_offers() {
        // Issue #28: a part file offered with the incomplete marker is a
        // source, but not a complete one.
        let slab = FileSlab::new();
        let h = [9u8; 16];
        let partial = |uh: u8| Source::new([uh; 16], IpAddr::V4(Ipv4Addr::new(10, 0, 0, uh)), 4662, false);
        let complete = |uh: u8| Source::new([uh; 16], IpAddr::V4(Ipv4Addr::new(10, 0, 0, uh)), 4662, true);
        slab.get_or_insert(h, 100, "f", partial(1));
        let r = slab.get_by_hash(&h).unwrap();
        assert_eq!((r.sources.len(), r.complete_source_count()), (1, 0));
        slab.add_or_refresh_source(&h, complete(2));
        slab.add_or_refresh_source(&h, partial(3));
        let r = slab.get_by_hash(&h).unwrap();
        assert_eq!((r.sources.len(), r.complete_source_count()), (3, 1));
        // The download finishes and the client re-offers: it counts now.
        slab.add_or_refresh_source(&h, complete(1));
        assert_eq!(slab.get_by_hash(&h).unwrap().complete_source_count(), 2);
        // A complete copy re-offered as incomplete (aMule, corrupt parts).
        slab.add_or_refresh_source(&h, partial(2));
        let r = slab.get_by_hash(&h).unwrap();
        assert_eq!((r.sources.len(), r.complete_source_count()), (3, 1));
    }

    #[test]
    fn tombstone_if_sourceless_spares_a_file_that_regained_a_source() {
        let slab = FileSlab::new();
        let h = [5u8; 16];
        let (id, _) = slab.get_or_insert(h, 100, "a.avi", src());
        // The eviction path saw it go sourceless...
        assert!(slab.remove_user_source(id, &[1u8; 16]));
        // ...but another publisher added a source before the tombstone.
        let other = Source::new([2u8; 16], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)), 4662, true);
        assert!(slab.add_or_refresh_source(&h, other));
        assert!(slab.tombstone_if_sourceless(id).is_none());
        assert_eq!(slab.get(id).map(|r| r.sources.len()), Some(1));

        // Once really sourceless it goes, and hands back the name.
        assert!(slab.remove_user_source(id, &[2u8; 16]));
        assert_eq!(slab.tombstone_if_sourceless(id).as_deref(), Some("a.avi"));
        assert!(slab.get(id).is_none());
        assert!(slab.tombstone_if_sourceless(id).is_none(), "only once");
    }

    #[test]
    fn chunked_scan_visits_every_live_record_once() {
        let slab = FileSlab::new();
        let mut want = std::collections::HashSet::new();
        for i in 0..100_000u32 {
            let mut h = [0u8; 16];
            h[0..4].copy_from_slice(&i.to_le_bytes());
            let (id, _) = slab.get_or_insert(h, 100, "f", src());
            if i % 7 == 0 {
                slab.tombstone(id);
            } else {
                want.insert(id);
            }
        }
        let mut seen = std::collections::HashSet::new();
        slab.for_each_live(|id, r| {
            assert!(r.alive());
            assert!(seen.insert(id), "visited twice");
        });
        assert_eq!(seen, want);
    }

    #[test]
    fn a_record_is_64_bytes() {
        // 16 hash + 8 size + 8 name (thin, doubles as the tombstone flag) +
        // 32 inline source. Was 80 with Arc<str>, alive and last_seen.
        assert_eq!(std::mem::size_of::<FileRecord>(), 64);
    }

    #[test]
    fn shard_capacity_does_not_double() {
        // The slab is the largest allocation in the process and only grows, so
        // Vec's doubling leaves up to half of it idle. This checks the growth
        // stays proportional rather than exponential.
        let slab = FileSlab::new();
        for i in 0..40000u32 {
            let mut h = [0u8; 16];
            h[0..4].copy_from_slice(&i.to_le_bytes());
            slab.get_or_insert(h, 100, "f", src());
        }
        let (len, cap) = slab.shard_len_cap(0);
        assert!(len > 0, "shard 0 must have received records");
        // Doubling would allow up to 2.0; the gentle growth keeps it near 1.25.
        // The bound is loose enough not to be brittle, tight enough to catch a
        // regression back to Vec's default.
        assert!(
            cap as f64 <= len as f64 * 1.5 + 2048.0,
            "capacity {cap} is too far above len {len} — is the growth doubling again?"
        );
        assert!(cap >= len, "capacity must cover len");
    }

    #[test]
    fn with_record_sees_the_same_data_as_get_without_cloning() {
        let slab = FileSlab::new();
        let h = [7u8; 16];
        let (id, _) = slab.get_or_insert(h, 4242, "name.avi", src());

        let via_get = slab.get(id).expect("live record");
        let via_with = slab
            .with_record(id, |r| (r.hash, r.size, r.sources.len()))
            .expect("live record");
        assert_eq!(
            via_with,
            (via_get.hash, via_get.size, via_get.sources.len())
        );

        // By hash, one lock instead of two, and it hands back the id.
        let (rid, size) = slab
            .with_record_by_hash(&h, |id, r| (id, r.size))
            .expect("live record");
        assert_eq!(rid, id);
        assert_eq!(size, 4242);

        // Tombstoned records are invisible to both, like get().
        slab.tombstone(id);
        assert!(slab.with_record(id, |_| ()).is_none());
        assert!(slab.with_record_by_hash(&h, |_, _| ()).is_none());
    }

    #[test]
    fn for_each_live_while_stops_when_asked() {
        let slab = FileSlab::new();
        for i in 0..20u8 {
            let mut h = [0u8; 16];
            h[0] = i;
            slab.get_or_insert(h, 100, "f", src());
        }
        let mut seen = 0;
        slab.for_each_live_while(|_id, _r| {
            seen += 1;
            seen < 5
        });
        assert_eq!(seen, 5, "the walk must stop the moment the closure says so");

        // Returning true always is equivalent to for_each_live.
        let mut all = 0;
        slab.for_each_live_while(|_, _| {
            all += 1;
            true
        });
        assert_eq!(all, 20);
    }

    #[test]
    fn insert_and_resolve() {
        let slab = FileSlab::new();
        let (id, new) = slab.get_or_insert([10u8; 16], 100, "a.bin", src());
        assert!(new);
        // id resolves back to the same record (value of id is opaque now that
        // it encodes a shard; we test the round-trip, not a literal).
        let rec = slab.get(id).unwrap();
        assert_eq!(rec.hash, [10u8; 16]);
        assert_eq!(rec.name(), "a.bin");
        assert_eq!(slab.id_of(&[10u8; 16]), Some(id));
        assert_eq!(slab.hash_of(id), Some([10u8; 16]));
    }

    #[test]
    fn dedup_returns_existing_id() {
        let slab = FileSlab::new();
        let (id1, n1) = slab.get_or_insert([10u8; 16], 100, "a.bin", src());
        let (id2, n2) = slab.get_or_insert([10u8; 16], 100, "a.bin", src());
        assert!(n1 && !n2);
        assert_eq!(id1, id2, "same hash must map to same id");
        assert_eq!(slab.live_count(), 1);
    }

    #[test]
    fn ids_are_unique_and_resolve() {
        let slab = FileSlab::new();
        let mut ids = Vec::new();
        for i in 0..100u8 {
            let (id, _) = slab.get_or_insert([i; 16], 1, "f", src());
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
        let (id, _) = slab.get_or_insert([10u8; 16], 100, "a.bin", src());
        assert!(slab.tombstone(id));
        // Stale id now resolves to None (safety property for lazy cleanup).
        assert!(slab.get(id).is_none());
        assert!(slab.hash_of(id).is_none());
        // Hash mapping is gone, so the same hash re-publishes as a NEW id.
        assert_eq!(slab.id_of(&[10u8; 16]), None);
        let (id2, new) = slab.get_or_insert([10u8; 16], 100, "a.bin", src());
        assert!(new);
        assert_ne!(id2, id, "tombstoned id is not reused");
    }

    #[test]
    fn double_tombstone_is_false() {
        let slab = FileSlab::new();
        let (id, _) = slab.get_or_insert([10u8; 16], 100, "a.bin", src());
        assert!(slab.tombstone(id));
        assert!(!slab.tombstone(id), "second tombstone returns false");
    }

    #[test]
    fn insert_sourceless_and_tombstone_by_hash() {
        let slab = FileSlab::new();
        let id = slab.insert_sourceless([7u8; 16], 50, "restored.bin");
        let rec = slab.get(id).unwrap();
        assert!(rec.sources.is_empty(), "restored file has no sources");
        assert_eq!(slab.live_count(), 1);
        // Re-inserting same hash returns existing id (no duplicate).
        let id2 = slab.insert_sourceless([7u8; 16], 50, "restored.bin");
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
            let (id, _) = slab.get_or_insert(h, i as u64, "f", src());
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
            let (id, _) = slab.get_or_insert(h, k as u64, "f", src());
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
            assert_eq!(
                slab.id_of(h),
                Some(*id),
                "chain corrupted after middle unlink"
            );
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
            slab.get_or_insert(h_of(i), i as u64, "f", src());
        }
        for i in 0..50u32 {
            assert!(slab.tombstone(slab.id_of(&h_of(i)).unwrap()));
        }
        // Insert a disjoint batch immediately — quarantine has not elapsed.
        for i in 100..150u32 {
            slab.get_or_insert(h_of(i), i as u64, "f", src());
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
            slab.get_or_insert(h_of(i), i as u64, "f", src());
        }
        assert_eq!(slab.slot_count(), 50);
        for i in 0..50u32 {
            assert!(slab.tombstone(slab.id_of(&h_of(i)).unwrap()));
        }
        assert_eq!(slab.live_count(), 0);
        // Re-publish the same hashes: each lands in the shard that holds its freed
        // slot, so every insert recycles — no new slots appended.
        for i in 0..50u32 {
            slab.get_or_insert(h_of(i), i as u64, "f", src());
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
