//! Name history (`[name_db]`): every name each file hash has been offered
//! under, by how many independent publishers, since when, and what the
//! content filter said about each name. Kept on disk in SQLite so it builds
//! up over months instead of starting from zero at every restart.
//!
//! Why: this server sees one name, sometimes the only copy, of a file the
//! rest of the network knows under many. A hash list built from single names
//! can be poisoned (a legal film published once under an abuse name), and a
//! whitelist built the same way can hold a hash that other publishers name
//! otherwise. The history is the evidence those decisions need.
//!
//! Cost, by design (measured, see the 0.9.88 changelog):
//!
//! * The offer path only puts an event into a bounded queue (`try_send`):
//!   it never waits on the disk; a full queue drops the event and counts it.
//! * One writer thread looks each event up (a read) and keeps only what is
//!   NEW: a name not stored yet, a publisher a stored name does not have, a
//!   verdict where a stored name had none. Re-offers of known files, nearly
//!   all of the traffic once the history has filled, cost one index read and
//!   nothing in memory or on disk.
//! * The changes are written in ONE transaction, sorted by hash, once
//!   `max_pending` of them have gathered or `flush_secs` have passed. In a
//!   B-tree with random keys a write costs about one page per changed row
//!   unless many changes share a page, so large, rare writes are what keeps
//!   the disk quiet: 100 000 changes cost ~2.6 KB each, 20 000 ~6.4 KB.
//! * One table. A name's publishers live in its own row (a small blob), not
//!   in a second keyed table; names are keyed by a 64-bit digest, so the
//!   unique index does not hold the name text twice. No last-seen time: it
//!   would rewrite every known name every day.
//! * SQLite with WAL, `synchronous = NORMAL`, a page cache of `cache_mb`,
//!   no mmap.
//!
//! What is kept per publisher is a salted 32-bit digest of the user hash and
//! one of the /24 (IPv4) or /48 (IPv6) it came from, never an address: enough
//! to count independent publishers, not to find anyone. At most
//! `publishers_per_name` per name and `names_per_hash` names per hash.
//!
//! The file holds the names the filter blocked as well. It is created with
//! mode 0600; keep it off any shared or published path.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::filter::{FilterResult, Layer};

/// The filter's verdict on one name, as stored (`names.layer`).
pub fn layer_code(l: Option<Layer>) -> u8 {
    match l {
        None => 0,
        Some(Layer::L1Jargon) => 1,
        Some(Layer::L2AgePattern) => 2,
        Some(Layer::L3HashBlock) => 3,
        Some(Layer::L4Extra) => 4,
        Some(Layer::L5Poison) => 5,
    }
}

pub fn layer_name(code: u8) -> &'static str {
    match code {
        0 => "clean",
        1 => "L1",
        2 => "L2",
        3 => "L3",
        4 => "L4",
        5 => "L5",
        _ => "?",
    }
}

/// One offered record.
pub struct NameEvent {
    pub hash: [u8; 16],
    pub size: u64,
    pub name: String,
    /// `layer_code` of what the term layers say about the NAME (L1, L2, L4
    /// or 0), with every hash list set aside.
    pub layer: u8,
    /// What matched, when something did.
    pub rule: Option<String>,
    /// The hash lists the hash was on at the offer (`LISTED_*` bits).
    pub listed: u8,
    pub user_hash: [u8; 16],
    /// The publisher's network: /24 for IPv4, /48 for IPv6, folded.
    pub net: u64,
}

/// The network part of an address, for counting independent publishers.
pub fn net_of(ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(v4) => u64::from(u32::from(v4) >> 8),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let mut b = [0u8; 8];
            b[..6].copy_from_slice(&o[..6]);
            (1u64 << 63) | u64::from_be_bytes(b) >> 16
        }
    }
}

/// `names.listed` bits: the hash was on this list when the name was offered.
pub const LISTED_WHITELIST: u8 = 1;
pub const LISTED_BANLIST: u8 = 2;
pub const LISTED_HASH_FILTER: u8 = 4;

/// The verdict to store for one offer: what the term layers say about the
/// NAME, and which hash lists the hash was on.
///
/// The two are kept apart because the lists are what this history is meant
/// to rebuild. `check` stops at the first hash list that holds the hash, so
/// a banlisted file's names were all stored as "L3 hash": evidence that
/// only repeated the list. Now the name is judged on its own, and the lists
/// go in `listed`.
///
/// Costs a second check only for a hash on a list: otherwise `result` (the
/// publish decision) already is the term verdict.
pub fn verdict(
    filter: &crate::filter::ContentFilter,
    hash: &[u8; 16],
    name: &str,
    result: &FilterResult,
) -> (u8, Option<String>, u8) {
    let mut listed = 0;
    if filter.is_whitelisted(hash) {
        listed |= LISTED_WHITELIST;
    }
    if filter.is_banlisted(hash) {
        listed |= LISTED_BANLIST;
    }
    if filter.is_hash_filtered(hash) {
        listed |= LISTED_HASH_FILTER;
    }
    let terms = if listed == 0 {
        result.clone()
    } else {
        filter.check_terms(name)
    };
    match terms {
        FilterResult::Block(l, r) => (layer_code(Some(l)), Some(r), listed),
        FilterResult::Allow => (0, None, listed),
    }
}

/// A stored layer from before 0.9.89: the hash list stopped the check, so
/// what the name says is unknown until it is checked again.
pub fn layer_is_legacy(layer: u8) -> bool {
    layer == 3 || layer == 5
}

#[derive(Default)]
pub struct NameDbStats {
    /// Offers looked up since the last write, and those that changed
    /// something.
    pub seen: AtomicU64,
    pub dropped: AtomicU64,
    pub flushes: AtomicU64,
    pub last_flush_unix: AtomicU64,
    pub last_flush_ms: AtomicU64,
    pub last_flush_changes: AtomicU64,
    pub files: AtomicU64,
    pub names: AtomicU64,
    pub publishers: AtomicU64,
    pub capped: AtomicU64,
    pub errors: AtomicU64,
    pub pending: AtomicU64,
}

pub struct NameDb {
    tx: SyncSender<Msg>,
    pub stats: Arc<NameDbStats>,
    pub path: PathBuf,
    done: Arc<(Mutex<bool>, std::sync::Condvar)>,
}

enum Msg {
    Event(NameEvent),
    /// Write what is pending now (shutdown).
    Flush,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub flush_secs: u64,
    pub max_pending: usize,
    pub queue: usize,
    pub cache_mb: u32,
    pub names_per_hash: u32,
    pub publishers_per_name: u32,
}

impl NameDb {
    /// Open (or create) the database and start the writer thread.
    pub fn open(path: &Path, s: Settings) -> rusqlite::Result<NameDb> {
        let conn = open_rw(path, s.cache_mb)?;
        let salt = salt(&conn)?;
        let stats = Arc::new(NameDbStats::default());
        load_counts(&conn, &stats);
        let (tx, rx) = std::sync::mpsc::sync_channel(s.queue.max(1024));
        let done = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let w = Writer {
            conn,
            salt,
            s,
            stats: Arc::clone(&stats),
            pending: HashMap::new(),
            new_per_hash: HashMap::new(),
            done: Arc::clone(&done),
        };
        std::thread::Builder::new()
            .name("name-db".into())
            .spawn(move || w.run(rx))
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(NameDb { tx, stats, path: path.to_path_buf(), done })
    }

    /// From the offer path: never blocks.
    pub fn note(&self, e: NameEvent) {
        if self.tx.try_send(Msg::Event(e)).is_err() {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Write everything pending and wait for it, at most `wait`. For a clean
    /// shutdown, and for tests.
    pub fn flush_and_wait(&self, wait: Duration) {
        {
            let mut d = self.done.0.lock().unwrap_or_else(|e| e.into_inner());
            *d = false;
        }
        match self.tx.send(Msg::Flush) {
            Ok(()) => {}
            Err(_) => return,
        }
        let (lock, cv) = &*self.done;
        let g = lock.lock().unwrap_or_else(|e| e.into_inner());
        let _ = cv.wait_timeout_while(g, wait, |d| !*d);
    }

    /// The database and its WAL on disk, in bytes.
    pub fn disk_bytes(&self) -> u64 {
        let mut n = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let mut wal = self.path.as_os_str().to_owned();
        wal.push("-wal");
        n += std::fs::metadata(PathBuf::from(wal)).map(|m| m.len()).unwrap_or(0);
        n
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS names(
    id INTEGER PRIMARY KEY,
    hash BLOB NOT NULL,
    nkey INTEGER NOT NULL,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    layer INTEGER NOT NULL,
    rule TEXT,
    whitelisted INTEGER NOT NULL DEFAULT 0,
    listed INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    npubs INTEGER NOT NULL DEFAULT 0,
    nnets INTEGER NOT NULL DEFAULT 0,
    pubs BLOB NOT NULL DEFAULT x'',
    UNIQUE(hash, nkey)
);
CREATE INDEX IF NOT EXISTS names_flagged ON names(hash) WHERE layer <> 0;
CREATE VIEW IF NOT EXISTS files AS
    SELECT hash, max(size) AS size, min(first_seen) AS first_seen,
           count(*) AS names, sum(layer <> 0) AS flagged_names
    FROM names GROUP BY hash;
";

fn open_rw(path: &Path, cache_mb: u32) -> rusqlite::Result<rusqlite::Connection> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let _ = std::fs::create_dir_all(dir);
    }
    let fresh = !path.exists();
    let conn = rusqlite::Connection::open(path)?;
    if fresh {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "temp_store", "FILE")?;
    conn.pragma_update(None, "mmap_size", 0)?;
    conn.pragma_update(None, "cache_size", -(i64::from(cache_mb.max(2)) * 1024))?;
    // A large write leaves a large WAL; truncate it back after the checkpoint.
    conn.pragma_update(None, "journal_size_limit", 64i64 << 20)?;
    conn.execute_batch(SCHEMA)?;
    migrate(&conn)?;
    Ok(conn)
}

/// Bring a database from an earlier version up to date. Cheap by design:
/// adding a column with a default rewrites nothing in SQLite. Rows written
/// before keep `layer` 3 or 5 where a hash list stopped the check; they are
/// put right when the name is offered again, or all at once by
/// `ed2k-server --namedb-recheck`.
fn migrate(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let has_listed: bool = conn
        .prepare("SELECT 1 FROM pragma_table_info('names') WHERE name = 'listed'")?
        .exists([])?;
    if !has_listed {
        conn.execute_batch("ALTER TABLE names ADD COLUMN listed INTEGER NOT NULL DEFAULT 0;")?;
        tracing::info!("name history: added names.listed (0.9.89); run --namedb-recheck once");
    }
    Ok(())
}

/// Read-only access for the admin page (another connection; WAL lets it read
/// while the writer writes).
pub fn open_ro(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "cache_size", -2048)?;
    conn.pragma_update(None, "mmap_size", 0)?;
    Ok(conn)
}

fn salt(conn: &rusqlite::Connection) -> rusqlite::Result<[u8; 16]> {
    let got: Option<Vec<u8>> = conn
        .query_row("SELECT v FROM meta WHERE k = 'salt'", [], |r| r.get(0))
        .ok();
    if let Some(v) = got.filter(|v| v.len() == 16) {
        let mut s = [0u8; 16];
        s.copy_from_slice(&v);
        return Ok(s);
    }
    let mut s = [0u8; 16];
    let _ = getrandom::getrandom(&mut s);
    conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES('salt', ?1)", [s.to_vec()])?;
    Ok(s)
}

fn load_counts(conn: &rusqlite::Connection, st: &NameDbStats) {
    for (k, a) in [("files", &st.files), ("names", &st.names), ("publishers", &st.publishers)] {
        let v: i64 = conn
            .query_row("SELECT v FROM meta WHERE k = ?1", [k], |r| r.get(0))
            .unwrap_or(0);
        a.store(v.max(0) as u64, Ordering::Relaxed);
    }
}

fn digest(parts: &[&[u8]]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The key of a name (stable across restarts and machines).
pub fn name_key(name: &str) -> i64 {
    let d = digest(&[name.as_bytes()]);
    i64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

fn u32_of(d: [u8; 16]) -> u32 {
    u32::from_le_bytes([d[0], d[1], d[2], d[3]])
}

/// A name's publishers: (publisher, network) pairs of salted 32-bit digests.
fn pubs_decode(b: &[u8]) -> Vec<(u32, u32)> {
    b.chunks_exact(8)
        .map(|c| {
            (
                u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
            )
        })
        .collect()
}

fn pubs_encode(p: &[(u32, u32)]) -> Vec<u8> {
    let mut b = Vec::with_capacity(p.len() * 8);
    for (u, n) in p {
        b.extend_from_slice(&u.to_le_bytes());
        b.extend_from_slice(&n.to_le_bytes());
    }
    b
}

fn distinct_nets(p: &[(u32, u32)]) -> usize {
    let mut n: Vec<u32> = p.iter().map(|x| x.1).collect();
    n.sort_unstable();
    n.dedup();
    n.len()
}

/// Longest name stored, in bytes.
const MAX_NAME: usize = 1024;

/// What a write has to do for one (hash, name).
enum Change {
    New {
        size: u64,
        layer: u8,
        rule: Option<String>,
        listed: u8,
        pubs: Vec<(u32, u32)>,
        at: i64,
    },
    Update {
        id: i64,
        /// Everything the row should hold after the write.
        pubs: Vec<(u32, u32)>,
        added_pubs: u32,
        /// A term verdict for a row that had none: clean, or a pre-0.9.89
        /// row whose check a hash list stopped.
        verdict: Option<(u8, Option<String>)>,
        /// Lists to add to the row's `listed` (bits it lacked).
        listed: u8,
    },
}

struct Writer {
    conn: rusqlite::Connection,
    salt: [u8; 16],
    s: Settings,
    stats: Arc<NameDbStats>,
    pending: HashMap<([u8; 16], i64), (String, Change)>,
    /// Names of a hash waiting to be inserted, for the per-hash cap.
    new_per_hash: HashMap<[u8; 16], u32>,
    done: Arc<(Mutex<bool>, std::sync::Condvar)>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Writer {
    fn run(mut self, rx: Receiver<Msg>) {
        let every = Duration::from_secs(self.s.flush_secs.max(10));
        let mut next = Instant::now() + every;
        loop {
            let wait = next.saturating_duration_since(Instant::now());
            match rx.recv_timeout(wait) {
                Ok(Msg::Event(e)) => {
                    if let Err(err) = self.add(e) {
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(error = %err, "name history: lookup failed");
                    }
                    if self.pending.len() >= self.s.max_pending {
                        self.flush();
                        next = Instant::now() + every;
                    }
                }
                Ok(Msg::Flush) => {
                    self.flush();
                    next = Instant::now() + every;
                    let (lock, cv) = &*self.done;
                    *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
                    cv.notify_all();
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.flush();
                    next = Instant::now() + every;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.flush();
                    return;
                }
            }
        }
    }

    fn add(&mut self, mut e: NameEvent) -> rusqlite::Result<()> {
        use rusqlite::OptionalExtension;
        self.stats.seen.fetch_add(1, Ordering::Relaxed);
        if e.name.len() > MAX_NAME {
            let mut end = MAX_NAME;
            while !e.name.is_char_boundary(end) {
                end -= 1;
            }
            e.name.truncate(end);
        }
        let publisher = (
            u32_of(digest(&[&self.salt, &e.user_hash])),
            u32_of(digest(&[&self.salt, &e.net.to_le_bytes()])),
        );
        let cap = self.s.publishers_per_name as usize;
        let nkey = name_key(&e.name);
        let key = (e.hash, nkey);

        // Already waiting: fold in.
        if let Some((_, ch)) = self.pending.get_mut(&key) {
            match ch {
                Change::New { layer, rule, listed, pubs, .. } => {
                    if *layer == 0 && e.layer != 0 {
                        *layer = e.layer;
                        *rule = e.rule;
                    }
                    *listed |= e.listed;
                    if pubs.len() < cap && !pubs.iter().any(|p| p.0 == publisher.0) {
                        pubs.push(publisher);
                    }
                }
                Change::Update { pubs, added_pubs, verdict, listed, .. } => {
                    if pubs.len() < cap && !pubs.iter().any(|p| p.0 == publisher.0) {
                        pubs.push(publisher);
                        *added_pubs += 1;
                    }
                    // Applied only to a row still clean or legacy (the
                    // UPDATE checks).
                    if e.layer != 0 && verdict.as_ref().map_or(true, |v| v.0 == 0) {
                        *verdict = Some((e.layer, e.rule));
                    }
                    *listed |= e.listed;
                }
            }
            return Ok(());
        }

        // Stored? A read; most offers end here.
        let row: Option<(i64, u8, u8, Vec<u8>)> = self
            .conn
            .prepare_cached("SELECT id, layer, listed, pubs FROM names WHERE hash = ?1 AND nkey = ?2")?
            .query_row(rusqlite::params![&e.hash[..], nkey], |r| {
                Ok((r.get(0)?, r.get::<_, i64>(1)? as u8, r.get::<_, i64>(2)? as u8, r.get(3)?))
            })
            .optional()?;
        match row {
            Some((id, layer, listed, blob)) => {
                let mut pubs = pubs_decode(&blob);
                let mut added = 0;
                if pubs.len() < cap && !pubs.iter().any(|p| p.0 == publisher.0) {
                    pubs.push(publisher);
                    added = 1;
                }
                // A clean row takes a verdict; a legacy one takes whatever
                // the name says now, clean included.
                let verdict = ((layer == 0 && e.layer != 0) || layer_is_legacy(layer))
                    .then(|| (e.layer, e.rule.take()));
                let new_bits = e.listed & !listed;
                if added == 0 && verdict.is_none() && new_bits == 0 {
                    return Ok(());
                }
                self.pending.insert(
                    key,
                    (
                        String::new(),
                        Change::Update { id, pubs, added_pubs: added, verdict, listed: new_bits },
                    ),
                );
            }
            None => {
                let waiting = self.new_per_hash.get(&e.hash).copied().unwrap_or(0);
                let stored: i64 = self
                    .conn
                    .prepare_cached("SELECT count(*) FROM names WHERE hash = ?1")?
                    .query_row([&e.hash[..]], |r| r.get(0))?;
                if stored + i64::from(waiting) >= i64::from(self.s.names_per_hash) {
                    self.stats.capped.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                *self.new_per_hash.entry(e.hash).or_insert(0) += 1;
                let name = std::mem::take(&mut e.name);
                self.pending.insert(
                    key,
                    (
                        name,
                        Change::New {
                            size: e.size,
                            layer: e.layer,
                            rule: e.rule.take(),
                            listed: e.listed,
                            pubs: vec![publisher],
                            at: now_unix(),
                        },
                    ),
                );
            }
        }
        self.stats.pending.store(self.pending.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    fn flush(&mut self) {
        let n = self.pending.len();
        self.new_per_hash.clear();
        if n == 0 {
            self.stats.seen.store(0, Ordering::Relaxed);
            return;
        }
        let started = Instant::now();
        let mut batch: Vec<(([u8; 16], i64), (String, Change))> = self.pending.drain().collect();
        // Sorted by key: neighbouring rows share pages.
        batch.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        match self.write(batch) {
            Ok((files, names, pubs)) => {
                self.stats.files.fetch_add(files, Ordering::Relaxed);
                self.stats.names.fetch_add(names, Ordering::Relaxed);
                self.stats.publishers.fetch_add(pubs, Ordering::Relaxed);
            }
            Err(e) => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(error = %e, changes = n, "name history: write failed, batch dropped");
            }
        }
        self.stats.flushes.fetch_add(1, Ordering::Relaxed);
        self.stats.last_flush_unix.store(now_unix() as u64, Ordering::Relaxed);
        self.stats.last_flush_ms.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
        self.stats.last_flush_changes.store(n as u64, Ordering::Relaxed);
        self.stats.pending.store(0, Ordering::Relaxed);
        self.stats.seen.store(0, Ordering::Relaxed);
    }

    /// One transaction. Returns new (files, names, publishers).
    fn write(
        &mut self,
        batch: Vec<(([u8; 16], i64), (String, Change))>,
    ) -> rusqlite::Result<(u64, u64, u64)> {
        use rusqlite::params;
        let (mut nf, mut nn, mut np) = (0u64, 0u64, 0u64);
        let tx = self.conn.transaction()?;
        {
            let mut has_hash = tx.prepare_cached("SELECT 1 FROM names WHERE hash = ?1 LIMIT 1")?;
            let mut ins = tx.prepare_cached(
                "INSERT OR IGNORE INTO names(hash, nkey, name, size, layer, rule, whitelisted,
                 listed, first_seen, npubs, nnets, pubs)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?;
            let mut upd_pubs =
                tx.prepare_cached("UPDATE names SET npubs = ?2, nnets = ?3, pubs = ?4 WHERE id = ?1")?;
            let mut upd_verdict = tx.prepare_cached(
                "UPDATE names SET layer = ?2, rule = ?3 WHERE id = ?1 AND layer IN (0, 3, 5)",
            )?;
            let mut upd_listed = tx.prepare_cached(
                "UPDATE names SET listed = listed | ?2, whitelisted = whitelisted | (?2 & 1)
                 WHERE id = ?1",
            )?;
            for ((hash, nkey), (name, ch)) in batch {
                match ch {
                    Change::New { size, layer, rule, listed, pubs, at } => {
                        let known = has_hash.exists([&hash[..]])?;
                        let done = ins.execute(params![
                            &hash[..],
                            nkey,
                            name,
                            size as i64,
                            i64::from(layer),
                            rule,
                            i64::from(listed & LISTED_WHITELIST),
                            i64::from(listed),
                            at,
                            pubs.len() as i64,
                            distinct_nets(&pubs) as i64,
                            pubs_encode(&pubs)
                        ])?;
                        if done == 1 {
                            nn += 1;
                            np += pubs.len() as u64;
                            if !known {
                                nf += 1;
                            }
                        }
                    }
                    Change::Update { id, pubs, added_pubs, verdict, listed } => {
                        if added_pubs > 0 {
                            upd_pubs.execute(params![
                                id,
                                pubs.len() as i64,
                                distinct_nets(&pubs) as i64,
                                pubs_encode(&pubs)
                            ])?;
                            np += u64::from(added_pubs);
                        }
                        if let Some((layer, rule)) = verdict {
                            upd_verdict.execute(params![id, i64::from(layer), rule])?;
                        }
                        if listed != 0 {
                            upd_listed.execute(params![id, i64::from(listed)])?;
                        }
                    }
                }
            }
        }
        let st = &self.stats;
        for (k, add, base) in [
            ("files", nf, st.files.load(Ordering::Relaxed)),
            ("names", nn, st.names.load(Ordering::Relaxed)),
            ("publishers", np, st.publishers.load(Ordering::Relaxed)),
        ] {
            tx.execute(
                "INSERT OR REPLACE INTO meta(k, v) VALUES(?1, ?2)",
                params![k, (base + add) as i64],
            )?;
        }
        tx.commit()?;
        Ok((nf, nn, np))
    }
}

/// One stored name, for the admin lookup.
#[derive(Debug, serde::Serialize)]
pub struct NameRow {
    /// Only for a clean name that carries no signal; empty otherwise.
    pub name: String,
    pub layer: &'static str,
    pub rule: Option<String>,
    pub whitelisted: bool,
    /// The hash lists the hash was on when this name was offered:
    /// "whitelist", "banlist", "hash_filter".
    pub listed: Vec<&'static str>,
    pub size: u64,
    pub first_seen: i64,
    pub publishers: i64,
    pub networks: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct HashReport {
    pub hash: String,
    pub known: bool,
    pub first_seen: i64,
    pub names: usize,
    pub flagged_names: usize,
    /// Distinct publishers and networks over all names, and behind the
    /// flagged and the clean names.
    pub publishers: usize,
    pub networks: usize,
    pub flagged_networks: usize,
    pub clean_networks: usize,
    pub rows: Vec<NameRow>,
}

/// Everything stored for one hash. `show` decides which clean names may be
/// printed; a flagged name never is.
pub fn report(
    conn: &rusqlite::Connection,
    hash: &[u8; 16],
    show: impl Fn(&str) -> bool,
) -> rusqlite::Result<HashReport> {
    let mut st = conn.prepare(
        "SELECT name, layer, rule, whitelisted, size, first_seen, npubs, nnets, pubs, listed
         FROM names WHERE hash = ?1 ORDER BY layer DESC, npubs DESC, first_seen",
    )?;
    let mut rep = HashReport {
        hash: hex::encode(hash),
        known: false,
        first_seen: 0,
        names: 0,
        flagged_names: 0,
        publishers: 0,
        networks: 0,
        flagged_networks: 0,
        clean_networks: 0,
        rows: Vec::new(),
    };
    let (mut all_p, mut all_n, mut fl_n, mut cl_n) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let rows = st.query_map([&hash[..]], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, i64>(7)?,
            r.get::<_, Vec<u8>>(8)?,
            r.get::<_, i64>(9)?,
        ))
    })?;
    for row in rows {
        let (name, layer, rule, wl, size, first, npubs, nnets, blob, listed) = row?;
        let listed = listed as u8 | if layer == 3 { LISTED_BANLIST } else if layer == 5 { LISTED_HASH_FILTER } else { 0 };
        rep.known = true;
        rep.names += 1;
        if layer != 0 {
            rep.flagged_names += 1;
        }
        if rep.first_seen == 0 || first < rep.first_seen {
            rep.first_seen = first;
        }
        for (u, n) in pubs_decode(&blob) {
            all_p.push(u);
            all_n.push(n);
            if layer != 0 { fl_n.push(n) } else { cl_n.push(n) }
        }
        let visible = layer == 0 && show(&name);
        rep.rows.push(NameRow {
            name: if visible { name } else { String::new() },
            layer: layer_name(layer as u8),
            rule,
            whitelisted: wl != 0,
            listed: [
                (LISTED_WHITELIST, "whitelist"),
                (LISTED_BANLIST, "banlist"),
                (LISTED_HASH_FILTER, "hash_filter"),
            ]
            .into_iter()
            .filter(|(b, _)| listed & b != 0)
            .map(|(_, n)| n)
            .collect(),
            size: size as u64,
            first_seen: first,
            publishers: npubs,
            networks: nnets,
        });
    }
    let distinct = |mut v: Vec<u32>| {
        v.sort_unstable();
        v.dedup();
        v.len()
    };
    rep.publishers = distinct(all_p);
    rep.networks = distinct(all_n);
    rep.flagged_networks = distinct(fl_n);
    rep.clean_networks = distinct(cl_n);
    Ok(rep)
}

/// What `recheck` did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecheckReport {
    pub rows: u64,
    /// Rows rewritten (verdict, rule or lists changed).
    pub changed: u64,
    /// Pre-0.9.89 rows whose check a hash list had stopped, now judged by
    /// their name.
    pub legacy: u64,
    /// Of those, the ones the term layers block.
    pub legacy_flagged: u64,
    /// Rows that were clean and are flagged now (terms added since).
    pub now_flagged: u64,
    /// Rows that were flagged by a term and are clean now (terms removed).
    pub now_clean: u64,
}

/// Judge every stored name again with `filter`'s term layers, hash lists
/// set aside, and record in `listed` the lists the old `layer` 3/5 and
/// `whitelisted` stood for.
///
/// For a database from before 0.9.89, once, and after a dictionary change
/// when the history should reflect it. Works on the live file while the
/// server runs: it writes in transactions of `batch` rows, each short, and
/// waits for the server's own writes. `progress` gets the rows done so far.
pub fn recheck(
    path: &Path,
    filter: &crate::filter::ContentFilter,
    batch: usize,
    mut progress: impl FnMut(u64),
) -> rusqlite::Result<RecheckReport> {
    use rusqlite::params;
    let mut conn = open_rw(path, 16)?;
    conn.busy_timeout(Duration::from_secs(120))?;
    let mut rep = RecheckReport::default();
    let mut last_id: i64 = 0;
    loop {
        let rows: Vec<(i64, String, u8, Option<String>, u8, i64)> = conn
            .prepare_cached(
                "SELECT id, name, layer, rule, listed, whitelisted FROM names
                 WHERE id > ?1 ORDER BY id LIMIT ?2",
            )?
            .query_map(params![last_id, batch.max(1) as i64], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get::<_, i64>(2)? as u8,
                    r.get(3)?,
                    r.get::<_, i64>(4)? as u8,
                    r.get(5)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let Some(last) = rows.last() else { break };
        last_id = last.0;
        let tx = conn.transaction()?;
        {
            let mut upd = tx.prepare_cached(
                "UPDATE names SET layer = ?2, rule = ?3, listed = ?4, whitelisted = ?5 WHERE id = ?1",
            )?;
            for (id, name, layer, rule, listed, wl) in rows {
                rep.rows += 1;
                let mut bits = listed;
                if wl != 0 {
                    bits |= LISTED_WHITELIST;
                }
                if layer == 3 {
                    bits |= LISTED_BANLIST;
                }
                if layer == 5 {
                    bits |= LISTED_HASH_FILTER;
                }
                let (nl, nr) = match filter.check_terms(&name) {
                    FilterResult::Block(l, r) => (layer_code(Some(l)), Some(r)),
                    FilterResult::Allow => (0, None),
                };
                if layer_is_legacy(layer) {
                    rep.legacy += 1;
                    if nl != 0 {
                        rep.legacy_flagged += 1;
                    }
                } else if layer == 0 && nl != 0 {
                    rep.now_flagged += 1;
                } else if layer != 0 && nl == 0 {
                    rep.now_clean += 1;
                }
                if nl != layer || nr != rule || bits != listed {
                    rep.changed += 1;
                    upd.execute(params![
                        id,
                        i64::from(nl),
                        nr,
                        i64::from(bits),
                        i64::from(bits & LISTED_WHITELIST)
                    ])?;
                }
            }
        }
        tx.commit()?;
        progress(rep.rows);
    }
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings {
            flush_secs: 3600,
            max_pending: 1_000_000,
            queue: 10_000,
            cache_mb: 4,
            names_per_hash: 3,
            publishers_per_name: 4,
        }
    }

    fn ev(hash: u8, name: &str, layer: u8, user: u8, net: u64) -> NameEvent {
        NameEvent {
            hash: [hash; 16],
            size: 700 << 20,
            name: name.into(),
            layer,
            rule: (layer != 0).then(|| "rule".to_string()),
            listed: 0,
            user_hash: [user; 16],
            net,
        }
    }

    #[test]
    fn names_publishers_and_networks_are_counted_once_and_capped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("names.db");
        let db = NameDb::open(&path, settings()).unwrap();
        // One clean name from three publishers on two networks, the same
        // offer repeated; one flagged name from one publisher.
        for _ in 0..5 {
            db.note(ev(1, "Film.2001.avi", 0, 1, 10));
        }
        db.note(ev(1, "Film.2001.avi", 0, 2, 10));
        db.note(ev(1, "Film.2001.avi", 0, 3, 11));
        db.note(ev(1, "bad name", 4, 9, 99));
        // A fourth and fifth name for the hash: over the cap of 3.
        db.note(ev(1, "other", 0, 4, 12));
        db.note(ev(1, "one more", 0, 5, 13));
        db.flush_and_wait(Duration::from_secs(10));
        assert_eq!(db.stats.files.load(Ordering::Relaxed), 1);
        assert_eq!(db.stats.names.load(Ordering::Relaxed), 3);
        assert_eq!(db.stats.capped.load(Ordering::Relaxed), 1);
        assert_eq!(db.stats.publishers.load(Ordering::Relaxed), 5);

        let ro = open_ro(&path).unwrap();
        let rep = report(&ro, &[1; 16], |_| true).unwrap();
        assert!(rep.known);
        assert_eq!((rep.names, rep.flagged_names), (3, 1));
        let film = rep.rows.iter().find(|r| r.name == "Film.2001.avi").unwrap();
        assert_eq!((film.publishers, film.networks), (3, 2));
        assert_eq!((rep.flagged_networks, rep.clean_networks), (1, 3));
        // A flagged name is never printed.
        let bad = rep.rows.iter().find(|r| r.layer == "L4").unwrap();
        assert!(bad.name.is_empty());
        drop(ro);

        // Known publishers add nothing; a new one on a stored name does, up
        // to the cap; a later verdict on a clean name is kept.
        db.note(ev(1, "Film.2001.avi", 0, 1, 10));
        db.note(ev(1, "Film.2001.avi", 0, 6, 14));
        db.note(ev(1, "Film.2001.avi", 0, 7, 15));
        db.note(ev(1, "other", 2, 4, 12));
        db.flush_and_wait(Duration::from_secs(10));
        assert_eq!(db.stats.publishers.load(Ordering::Relaxed), 6);
        let ro = open_ro(&path).unwrap();
        let rep = report(&ro, &[1; 16], |_| true).unwrap();
        assert_eq!(rep.flagged_names, 2);
        let film = rep.rows.iter().find(|r| r.name == "Film.2001.avi").unwrap();
        assert_eq!(film.publishers, 4);
        drop(ro);

        // Reopened: the counts and the salt carry over.
        drop(db);
        let db2 = NameDb::open(&path, settings()).unwrap();
        assert_eq!(db2.stats.names.load(Ordering::Relaxed), 3);
        db2.note(ev(1, "bad name", 4, 9, 99));
        db2.flush_and_wait(Duration::from_secs(10));
        assert_eq!(db2.stats.publishers.load(Ordering::Relaxed), 6);
    }

    #[test]
    fn networks_fold_addresses_to_their_prefix() {
        let a: IpAddr = "10.1.2.3".parse().unwrap();
        let b: IpAddr = "10.1.2.200".parse().unwrap();
        let c: IpAddr = "10.1.3.1".parse().unwrap();
        assert_eq!(net_of(a), net_of(b));
        assert_ne!(net_of(a), net_of(c));
        let x: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let y: IpAddr = "2001:db8:1:ffff::1".parse().unwrap();
        assert_eq!(net_of(x), net_of(y));
        assert_ne!(net_of(x), net_of(a));
    }

    #[test]
    fn a_listed_hash_keeps_the_names_verdict_and_records_the_list() {
        use crate::filter::ContentFilter;
        let f = ContentFilter::new()
            .with_extra_terms(vec!["badterm".into()])
            .with_hash_blocklist(vec![[7; 16]])
            .with_hash_filter(vec![[8; 16]])
            .with_hash_whitelist(vec![[9; 16]]);
        let v = |h: u8, name: &str| {
            let r = f.check(&[h; 16], name);
            verdict(&f, &[h; 16], name, &r)
        };
        // Banlisted: the publish decision is L3, the name speaks for itself.
        assert!(matches!(f.check(&[7; 16], "x badterm.avi"), FilterResult::Block(Layer::L3HashBlock, _)));
        let (l, r, listed) = v(7, "x badterm.avi");
        assert_eq!((l, listed), (4, LISTED_BANLIST));
        assert!(r.is_some());
        assert_eq!(v(7, "Holiday.avi"), (0, None, LISTED_BANLIST));
        assert_eq!(v(8, "Holiday.avi"), (0, None, LISTED_HASH_FILTER));
        assert_eq!(v(9, "x badterm.avi").0, 4);
        assert_eq!(v(9, "x badterm.avi").2, LISTED_WHITELIST);
        // On no list: the publish decision is the verdict.
        assert_eq!(v(1, "x badterm.avi").2, 0);
        assert_eq!(v(1, "x badterm.avi").0, 4);
    }

    #[test]
    fn an_old_database_is_migrated_and_rechecked() {
        use crate::filter::ContentFilter;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        // A 0.9.88 database: no `listed`, rows stopped at L3 / L5.
        {
            let c = rusqlite::Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE meta(k TEXT PRIMARY KEY, v) WITHOUT ROWID;
                 CREATE TABLE names(id INTEGER PRIMARY KEY, hash BLOB NOT NULL, nkey INTEGER NOT NULL,
                   name TEXT NOT NULL, size INTEGER NOT NULL, layer INTEGER NOT NULL, rule TEXT,
                   whitelisted INTEGER NOT NULL DEFAULT 0, first_seen INTEGER NOT NULL,
                   npubs INTEGER NOT NULL DEFAULT 0, nnets INTEGER NOT NULL DEFAULT 0,
                   pubs BLOB NOT NULL DEFAULT x'', UNIQUE(hash, nkey));",
            )
            .unwrap();
            let ins = |id: i64, h: u8, name: &str, layer: i64, rule: Option<&str>, wl: i64| {
                c.execute(
                    "INSERT INTO names(id, hash, nkey, name, size, layer, rule, whitelisted, first_seen)
                     VALUES(?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, 0)",
                    rusqlite::params![id, vec![h; 16], name_key(name), name, layer, rule, wl],
                )
                .unwrap();
            };
            ins(1, 7, "x badterm.avi", 3, Some("hash"), 0); // banlisted, bad name
            ins(2, 7, "Holiday.avi", 3, Some("hash"), 0); // banlisted, clean name
            ins(3, 8, "Decoy.avi", 5, Some("poison"), 0);
            ins(4, 9, "x badterm.avi", 4, Some("badterm"), 1); // whitelisted
            ins(5, 1, "newterm clip.avi", 0, None, 0); // a term added since
            ins(6, 2, "oldterm clip.avi", 4, Some("oldterm"), 0); // a term removed since
        }
        // Opening it as 0.9.89 adds the column and changes nothing else.
        drop(NameDb::open(&path, settings()).unwrap());
        let f = ContentFilter::new().with_extra_terms(vec!["badterm".into(), "newterm".into()]);
        let mut seen = 0;
        let rep = recheck(&path, &f, 2, |n| seen = n).unwrap();
        assert_eq!(seen, 6);
        assert_eq!(
            rep,
            RecheckReport { rows: 6, changed: 6, legacy: 3, legacy_flagged: 1, now_flagged: 1, now_clean: 1 }
        );
        let c = rusqlite::Connection::open(&path).unwrap();
        let row = |id: i64| -> (i64, i64, i64) {
            c.query_row("SELECT layer, listed, whitelisted FROM names WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap()
        };
        assert_eq!(row(1), (4, i64::from(LISTED_BANLIST), 0));
        assert_eq!(row(2), (0, i64::from(LISTED_BANLIST), 0));
        assert_eq!(row(3), (0, i64::from(LISTED_HASH_FILTER), 0));
        assert_eq!(row(4), (4, i64::from(LISTED_WHITELIST), 1));
        assert_eq!(row(5).0, 4);
        assert_eq!(row(6).0, 0);
        // A second run finds nothing to do.
        let again = recheck(&path, &f, 100, |_| {}).unwrap();
        assert_eq!(again.changed, 0);
    }

    #[test]
    fn a_reoffer_puts_a_legacy_row_right_and_adds_lists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("names.db");
        let db = NameDb::open(&path, settings()).unwrap();
        db.note(ev(3, "Clip.avi", 0, 1, 10));
        db.flush_and_wait(Duration::from_secs(10));
        // Make it look like a pre-0.9.89 row stopped at L3.
        {
            let c = rusqlite::Connection::open(&path).unwrap();
            c.execute("UPDATE names SET layer = 3, rule = 'hash'", []).unwrap();
        }
        let mut e = ev(3, "Clip.avi", 0, 1, 10);
        e.listed = LISTED_BANLIST;
        db.note(e);
        db.flush_and_wait(Duration::from_secs(10));
        let c = rusqlite::Connection::open(&path).unwrap();
        let (layer, listed): (i64, i64) = c
            .query_row("SELECT layer, listed FROM names", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!((layer, listed), (0, i64::from(LISTED_BANLIST)));
    }
}
