//! Shared work admission (issue #25).
//!
//! Everything a remote peer can make this server do — open a socket, run a
//! login, probe its port, search the index, relay a callback, schedule a
//! retry, send a UDP query — passes through ONE component held by
//! `ServerState`. Each kind of work has a hard ceiling that does not depend on
//! how the load is spread across addresses, listeners or address families.
//!
//! The ceilings are restart-only: shrinking a semaphore under live permits is
//! not worth its complexity, and admission must be predictable more than it
//! must be hot-reloadable. None of them accepts 0 as "unlimited"; a config with
//! a zero ceiling is refused.
//!
//! What saturation does, by path:
//! * new TCP socket, pending login — closed before any task is spawned;
//! * logged-in clients — an atomic reservation, so concurrent logins cannot
//!   overshoot `limits.max_clients`;
//! * HighID probes (initial and background share one ceiling) — the login is
//!   given LowID, the conservative answer;
//! * hole-punch retries — skipped; a retry already pending for the same
//!   (requester, target) pair is not scheduled twice;
//! * callback and hole-punch requests — a per-session token bucket; over it,
//!   a callback gets the protocol's own failure reply, a hole-punch is ignored;
//! * search — a small fixed number of jobs off the runtime, a bounded TCP wait
//!   queue, UDP never waits (see `search_lane`);
//! * UDP — a server-wide bucket, then a per-source one (see `udp`).

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{AdmissionConfig, Config};

/// Milliseconds since the UNIX epoch, for "time since last rejection".
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A fixed-size pool of permits for one kind of concurrent work.
pub struct Pool {
    sem: Arc<Semaphore>,
    cap: u32,
    rejected: AtomicU64,
    /// Shared with the owning `Admission`, to stamp the latest rejection.
    last_rejection: Arc<AtomicU64>,
}

impl Pool {
    fn new(cap: u32, last_rejection: Arc<AtomicU64>) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(cap as usize)),
            cap,
            rejected: AtomicU64::new(0),
            last_rejection,
        }
    }

    /// Take a permit now or not at all. For hostile or unauthenticated work.
    pub fn try_take(&self) -> Option<OwnedSemaphorePermit> {
        match Arc::clone(&self.sem).try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                self.note_rejected();
                None
            }
        }
    }

    /// Wait for a permit, in arrival order, at most `wait`. For work from an
    /// established session that may queue briefly.
    pub async fn take_within(&self, wait: Duration) -> Option<OwnedSemaphorePermit> {
        match tokio::time::timeout(wait, Arc::clone(&self.sem).acquire_owned()).await {
            Ok(Ok(p)) => Some(p),
            _ => {
                self.note_rejected();
                None
            }
        }
    }

    fn note_rejected(&self) {
        self.rejected.fetch_add(1, Relaxed);
        self.last_rejection.store(now_ms(), Relaxed);
    }

    pub fn cap(&self) -> u32 {
        self.cap
    }

    pub fn in_use(&self) -> u32 {
        self.cap.saturating_sub(self.sem.available_permits() as u32)
    }

    pub fn rejected(&self) -> u64 {
        self.rejected.load(Relaxed)
    }

    pub fn is_full(&self) -> bool {
        self.sem.available_permits() == 0
    }
}

/// Logged-in client reservations against `limits.max_clients`.
///
/// The old check counted the client map and inserted much later, after the
/// HighID probe had awaited; concurrent logins all saw room. A reservation is
/// taken with one compare-and-swap before the login does any work, held by
/// the connection task for its lifetime, and returned when the task ends.
pub struct ClientSlots {
    held: Arc<AtomicU32>,
    rejected: AtomicU64,
}

/// One reserved logged-in client. Returns its slot on drop.
#[derive(Debug)]
pub struct ClientSlot(Arc<AtomicU32>);

impl Drop for ClientSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

/// A session's logged-in slot, shared by every copy of its `ClientHandle`, so
/// whoever replaces the session (a same-hash re-login) can release it at once
/// instead of leaving it held until the old socket is found dead.
pub type SharedSlot = Arc<std::sync::Mutex<Option<ClientSlot>>>;

/// Release a session's slot, if it still holds one. Idempotent.
pub fn release_slot(slot: &SharedSlot) {
    let taken = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(taken);
}

impl ClientSlots {
    fn new() -> Self {
        Self {
            held: Arc::new(AtomicU32::new(0)),
            rejected: AtomicU64::new(0),
        }
    }

    /// Reserve a slot if fewer than `max` are held. `max == 0` = no cap
    /// (`limits.max_clients` keeps its documented meaning).
    pub fn try_reserve(&self, max: u32) -> Option<ClientSlot> {
        let mut cur = self.held.load(Relaxed);
        loop {
            if max != 0 && cur >= max {
                self.rejected.fetch_add(1, Relaxed);
                return None;
            }
            match self
                .held
                .compare_exchange_weak(cur, cur + 1, Relaxed, Relaxed)
            {
                Ok(_) => return Some(ClientSlot(Arc::clone(&self.held))),
                Err(seen) => cur = seen,
            }
        }
    }

    /// Reserve regardless of the cap: a client replacing its own session is
    /// always let in, and its stale task still holds the old slot until it
    /// ends.
    pub fn force_reserve(&self) -> ClientSlot {
        self.held.fetch_add(1, Relaxed);
        ClientSlot(Arc::clone(&self.held))
    }

    pub fn held(&self) -> u32 {
        self.held.load(Relaxed)
    }

    pub fn rejected(&self) -> u64 {
        self.rejected.load(Relaxed)
    }
}

/// Integer token bucket. Levels are kept in micro-credits so refill is exact
/// at any rate; `Instant` is monotonic.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate_per_s: u64,
    burst_micro: u64,
    level_micro: u64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_s: u32, burst: u32, now: Instant) -> Self {
        let burst_micro = burst as u64 * 1_000_000;
        Self {
            rate_per_s: rate_per_s as u64,
            burst_micro,
            level_micro: burst_micro,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let us = now.saturating_duration_since(self.last).as_micros() as u64;
        if us > 0 {
            self.level_micro = self
                .level_micro
                .saturating_add(us.saturating_mul(self.rate_per_s))
                .min(self.burst_micro);
            // Advance by exactly the microseconds credited, so the
            // sub-microsecond remainder is not lost on every call.
            self.last += Duration::from_micros(us);
        }
    }

    /// Take `cost` credits if available.
    pub fn take(&mut self, cost: u32, now: Instant) -> bool {
        self.refill(now);
        let need = cost as u64 * 1_000_000;
        if self.level_micro >= need {
            self.level_micro -= need;
            true
        } else {
            false
        }
    }

    /// Give back credits taken by a `take` whose work was then not done
    /// (a later check refused it).
    pub fn refund(&mut self, cost: u32) {
        self.level_micro = self
            .level_micro
            .saturating_add(cost as u64 * 1_000_000)
            .min(self.burst_micro);
    }

    /// True when the bucket has been idle long enough to be full again, so
    /// dropping it loses nothing.
    pub fn is_full_at(&self, now: Instant) -> bool {
        let mut b = self.clone();
        b.refill(now);
        b.level_micro >= b.burst_micro
    }
}

/// What happened to a frame pushed to a client's bounded channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    Queued,
    /// The channel was full; the frame was dropped.
    Full,
    /// The client's connection task is gone.
    Closed,
}

/// Which path pushed a frame. Fixed cardinality, for the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushKind {
    Callback = 0,
    Holepunch = 1,
    Keepalive = 2,
}

const PUSH_KINDS: usize = 3;

#[derive(Default)]
pub struct PushStats {
    full: [AtomicU64; PUSH_KINDS],
    closed: [AtomicU64; PUSH_KINDS],
}

impl PushStats {
    pub fn note(&self, kind: PushKind, outcome: PushOutcome) {
        match outcome {
            PushOutcome::Queued => {}
            PushOutcome::Full => {
                self.full[kind as usize].fetch_add(1, Relaxed);
            }
            PushOutcome::Closed => {
                self.closed[kind as usize].fetch_add(1, Relaxed);
            }
        }
    }

    /// (full, closed) for one kind.
    pub fn get(&self, kind: PushKind) -> (u64, u64) {
        (
            self.full[kind as usize].load(Relaxed),
            self.closed[kind as usize].load(Relaxed),
        )
    }
}

/// A pending hole-punch retry for one (requester, target) pair. Removes its
/// key on drop, however the retry task ends.
pub struct RetryKey {
    map: Arc<DashMap<([u8; 16], u32), ()>>,
    key: ([u8; 16], u32),
}

impl Drop for RetryKey {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

/// An admitted socket that has not logged in yet: its share of the global
/// pending-login pool and of its source's. Both are returned on drop.
pub struct PendingLogin {
    _permit: OwnedSemaphorePermit,
    _source: Option<SourceShare>,
}

struct SourceShare {
    map: Arc<DashMap<IpAddr, u32>>,
    key: IpAddr,
}

impl Drop for SourceShare {
    fn drop(&mut self) {
        if let Some(mut n) = self.map.get_mut(&self.key) {
            *n = n.saturating_sub(1);
        }
        self.map.remove_if(&self.key, |_, n| *n == 0);
    }
}

/// See `Admission::udp_search_admit`.
pub enum UdpSearchTicket {
    Ready(OwnedSemaphorePermit),
    Queued(OwnedSemaphorePermit),
}

/// Why a hole-punch retry was not scheduled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrySkip {
    /// One is already pending for this pair.
    Coalesced,
    /// The retry pool is full.
    Busy,
}

/// Per-session allowance for requests that make the server push frames to
/// ANOTHER client (callback, hole-punch). Owned by the connection task.
pub struct RelayBudget(TokenBucket);

impl RelayBudget {
    pub fn new(cfg: &AdmissionConfig) -> Self {
        Self(TokenBucket::new(
            cfg.session_relay_per_second,
            cfg.session_relay_burst,
            Instant::now(),
        ))
    }

    pub fn allow(&mut self) -> bool {
        self.0.take(1, Instant::now())
    }
}

/// Pools whose sustained saturation means the server is not ready.
const CRITICAL: [&str; 3] = ["open_tcp", "pending_login", "search_jobs"];

pub struct Admission {
    pub cfg: AdmissionConfig,
    /// Every accepted TCP socket, from accept until its task ends.
    pub open_tcp: Pool,
    /// Accepted sockets that have not completed a login yet.
    pub pending_login: Pool,
    /// The same, per source key: one source cannot hold the whole pool.
    pending_per_source: Arc<DashMap<IpAddr, u32>>,
    pub pending_source_rejected: AtomicU64,
    /// Outbound HighID probes, initial and background together.
    pub probes: Pool,
    /// Detached hole-punch retry tasks.
    pub retries: Pool,
    /// Searches running, off the runtime (see `run_search`).
    pub search_jobs: Pool,
    /// TCP searches waiting for a search job.
    pub search_queue: Pool,
    /// UDP searches waiting for a search job (from a task, never the
    /// receive loop). Kept separate from the TCP queue, and small, so UDP
    /// cannot crowd out established sessions.
    pub udp_search_queue: Pool,
    /// UDP searches dropped: their queue was full, or they waited too long.
    pub udp_search_shed: AtomicU64,
    /// TCP searches answered empty: queue full, or waited too long.
    pub tcp_search_shed: AtomicU64,
    /// Longest and most recent wait for a search job, in ms.
    pub search_wait_max_ms: AtomicU64,
    pub search_wait_last_ms: AtomicU64,
    retry_pairs: Arc<DashMap<([u8; 16], u32), ()>>,
    pub retries_coalesced: AtomicU64,
    pub clients: ClientSlots,
    pub push: PushStats,
    /// Callback / hole-punch requests over a session's relay budget.
    pub relay_rejected: AtomicU64,
    /// Logins given LowID because the probe ceiling was full.
    pub probe_shed_lowid: AtomicU64,
    /// Every UDP listener, both families.
    pub udp: UdpBudget,
    /// For each critical pool, when it was first seen full in the current
    /// run of full samples (ms since epoch), or 0. See `sample`.
    saturated_since: [AtomicU64; CRITICAL.len()],
    last_rejection: Arc<AtomicU64>,
}

impl Admission {
    pub fn new(cfg: &Config) -> Self {
        let a = cfg.admission.clone();
        let last = Arc::new(AtomicU64::new(0));
        Self {
            open_tcp: Pool::new(a.effective_open_tcp(cfg), Arc::clone(&last)),
            pending_login: Pool::new(a.max_pending_logins, Arc::clone(&last)),
            pending_per_source: Arc::new(DashMap::new()),
            pending_source_rejected: AtomicU64::new(0),
            probes: Pool::new(a.effective_probes(), Arc::clone(&last)),
            retries: Pool::new(a.max_retry_tasks, Arc::clone(&last)),
            search_jobs: Pool::new(a.max_search_jobs, Arc::clone(&last)),
            search_queue: Pool::new(a.max_queued_tcp_searches, Arc::clone(&last)),
            udp_search_queue: Pool::new(a.max_queued_udp_searches, Arc::clone(&last)),
            udp_search_shed: AtomicU64::new(0),
            tcp_search_shed: AtomicU64::new(0),
            search_wait_max_ms: AtomicU64::new(0),
            search_wait_last_ms: AtomicU64::new(0),
            retry_pairs: Arc::new(DashMap::new()),
            retries_coalesced: AtomicU64::new(0),
            clients: ClientSlots::new(),
            push: PushStats::default(),
            relay_rejected: AtomicU64::new(0),
            probe_shed_lowid: AtomicU64::new(0),
            udp: UdpBudget::new(&a),
            saturated_since: Default::default(),
            last_rejection: last,
            cfg: a,
        }
    }

    /// Admit a new socket into setup/login: at most
    /// `max_pending_logins_per_source` per source key (loopback exempt), then
    /// the global pool. Err names the pool that was full.
    pub fn try_pending(&self, ip: IpAddr) -> Result<PendingLogin, &'static str> {
        let source = if ip.is_loopback() {
            None
        } else {
            let key = SourceKey::of(ip, self.cfg.ipv6_source_prefix_bits).as_ip();
            let mut n = self.pending_per_source.entry(key).or_insert(0);
            if *n >= self.cfg.max_pending_logins_per_source {
                drop(n);
                self.pending_per_source.remove_if(&key, |_, n| *n == 0);
                self.pending_source_rejected.fetch_add(1, Relaxed);
                self.last_rejection.store(now_ms(), Relaxed);
                return Err("admission_pending_per_source");
            }
            *n += 1;
            Some(SourceShare {
                map: Arc::clone(&self.pending_per_source),
                key,
            })
        };
        match self.pending_login.try_take() {
            Some(p) => Ok(PendingLogin {
                _permit: p,
                _source: source,
            }),
            None => Err("admission_pending_login"), // `source` drops: share returned
        }
    }

    /// Admission for a hole-punch retry: the pair must not already have one
    /// pending, and the pool must have room. Both guards must be held by the
    /// retry task for its whole life.
    pub fn try_retry(
        &self,
        requester: [u8; 16],
        target_id: u32,
    ) -> Result<(RetryKey, OwnedSemaphorePermit), RetrySkip> {
        let key = (requester, target_id);
        // Claim the pair first; a concurrent duplicate sees it taken.
        if self.retry_pairs.insert(key, ()).is_some() {
            self.retries_coalesced.fetch_add(1, Relaxed);
            return Err(RetrySkip::Coalesced);
        }
        let guard = RetryKey {
            map: Arc::clone(&self.retry_pairs),
            key,
        };
        match self.retries.try_take() {
            Some(p) => Ok((guard, p)),
            None => Err(RetrySkip::Busy), // guard drops: pair released
        }
    }

    /// A search job for an established TCP session: wait in arrival order for
    /// at most `tcp_search_wait_ms`, behind at most `max_queued_tcp_searches`
    /// others. None = answer the search empty.
    pub async fn tcp_search_permit(&self) -> Option<OwnedSemaphorePermit> {
        // Fast path: a free job, no queueing.
        if let Ok(p) = Arc::clone(&self.search_jobs.sem).try_acquire_owned() {
            self.note_search_wait(0);
            return Some(p);
        }
        let Some(_queued) = self.search_queue.try_take() else {
            self.tcp_search_shed.fetch_add(1, Relaxed);
            return None;
        };
        let t0 = Instant::now();
        let got = self
            .search_jobs
            .take_within(Duration::from_millis(self.cfg.tcp_search_wait_ms))
            .await;
        self.note_search_wait(t0.elapsed().as_millis() as u64);
        if got.is_none() {
            self.tcp_search_shed.fetch_add(1, Relaxed);
        }
        got
    }

    /// A search job for UDP. Returns at once: either a job now, or a place in
    /// the small UDP queue to wait from a task (`udp_search_wait`), or None —
    /// the query is dropped, which for UDP looks like a lost datagram.
    pub fn udp_search_admit(&self) -> Option<UdpSearchTicket> {
        if let Ok(p) = Arc::clone(&self.search_jobs.sem).try_acquire_owned() {
            return Some(UdpSearchTicket::Ready(p));
        }
        match self.udp_search_queue.try_take() {
            Some(q) => Some(UdpSearchTicket::Queued(q)),
            None => {
                self.udp_search_shed.fetch_add(1, Relaxed);
                None
            }
        }
    }

    /// Turn a ticket into a job permit, waiting at most `udp_search_wait_ms`.
    pub async fn udp_search_wait(&self, ticket: UdpSearchTicket) -> Option<OwnedSemaphorePermit> {
        match ticket {
            UdpSearchTicket::Ready(p) => Some(p),
            UdpSearchTicket::Queued(_queued) => {
                let got = self
                    .search_jobs
                    .take_within(Duration::from_millis(self.cfg.udp_search_wait_ms))
                    .await;
                if got.is_none() {
                    self.udp_search_shed.fetch_add(1, Relaxed);
                }
                got
            }
        }
    }

    fn note_search_wait(&self, ms: u64) {
        self.search_wait_last_ms.store(ms, Relaxed);
        self.search_wait_max_ms.fetch_max(ms, Relaxed);
    }

    pub fn note_relay_rejected(&self) {
        self.relay_rejected.fetch_add(1, Relaxed);
        self.last_rejection.store(now_ms(), Relaxed);
    }

    pub fn note_probe_shed(&self) {
        self.probe_shed_lowid.fetch_add(1, Relaxed);
    }

    fn critical_pool(&self, i: usize) -> &Pool {
        match i {
            0 => &self.open_tcp,
            1 => &self.pending_login,
            _ => &self.search_jobs,
        }
    }

    /// Record which critical pools are full now. Called once a second; a
    /// pool counts as saturated from the first full sample of an unbroken
    /// run of full samples.
    pub fn sample(&self) {
        let now = now_ms();
        for i in 0..CRITICAL.len() {
            let since = &self.saturated_since[i];
            if self.critical_pool(i).is_full() {
                let _ = since.compare_exchange(0, now, Relaxed, Relaxed);
            } else {
                since.store(0, Relaxed);
            }
        }
    }

    /// Ready unless a critical pool has stayed full for
    /// `readiness_window_secs`. Returns the pools that have.
    pub fn readiness(&self) -> (bool, Vec<&'static str>) {
        let now = now_ms();
        let window = self.cfg.readiness_window_secs.saturating_mul(1000);
        let stuck: Vec<&'static str> = (0..CRITICAL.len())
            .filter(|&i| {
                let t = self.saturated_since[i].load(Relaxed);
                t != 0 && now.saturating_sub(t) >= window
            })
            .map(|i| CRITICAL[i])
            .collect();
        (stuck.is_empty(), stuck)
    }

    /// Every admission gauge and counter, fixed cardinality, no addresses.
    pub fn metrics(&self) -> serde_json::Value {
        let pool = |p: &Pool| serde_json::json!({ "in_use": p.in_use(), "cap": p.cap(), "rejected": p.rejected() });
        let push = |k: PushKind| {
            let (full, closed) = self.push.get(k);
            serde_json::json!({ "full": full, "closed": closed })
        };
        let (ready, saturated) = self.readiness();
        serde_json::json!({
            "ready": ready,
            "saturated": saturated,
            "ms_since_last_rejection": self.ms_since_last_rejection(),
            "open_tcp": pool(&self.open_tcp),
            "pending_login": pool(&self.pending_login),
            "pending_source_rejected": self.pending_source_rejected.load(Relaxed),
            "probes": pool(&self.probes),
            "probe_shed_lowid": self.probe_shed_lowid.load(Relaxed),
            "retries": pool(&self.retries),
            "retries_coalesced": self.retries_coalesced.load(Relaxed),
            "clients": { "held": self.clients.held(), "rejected": self.clients.rejected() },
            "relay_rejected": self.relay_rejected.load(Relaxed),
            "search_jobs": pool(&self.search_jobs),
            "search_queue": pool(&self.search_queue),
            "udp_search_queue": pool(&self.udp_search_queue),
            "tcp_search_shed": self.tcp_search_shed.load(Relaxed),
            "udp_search_shed": self.udp_search_shed.load(Relaxed),
            "search_wait_ms": {
                "max": self.search_wait_max_ms.load(Relaxed),
                "last": self.search_wait_last_ms.load(Relaxed),
            },
            "push": {
                "callback": push(PushKind::Callback),
                "holepunch": push(PushKind::Holepunch),
                "keepalive": push(PushKind::Keepalive),
            },
            "udp": {
                "enforce": self.udp.enforce,
                "admitted": self.udp.admitted.load(Relaxed),
                "refused_global": self.udp.refused_global.load(Relaxed),
                "refused_source": self.udp.refused_source.load(Relaxed),
                "refused_table_full": self.udp.refused_table_full.load(Relaxed),
                "source_entries": self.udp.entries(),
                "source_entries_cap": self.udp.cap(),
            },
        })
    }

    /// Milliseconds since the last rejection on any path; None if never.
    pub fn ms_since_last_rejection(&self) -> Option<u64> {
        match self.last_rejection.load(Relaxed) {
            0 => None,
            t => Some(now_ms().saturating_sub(t)),
        }
    }

    /// UDP admission for one packet: see `UdpBudget::admit`. A refusal
    /// stamps the last-rejection time even in observe mode.
    pub fn udp_admit(&self, ip: IpAddr, cost: u32) -> bool {
        let before = self.udp.admitted.load(Relaxed);
        let serve = self.udp.admit(ip, cost);
        if self.udp.admitted.load(Relaxed) == before {
            self.last_rejection.store(now_ms(), Relaxed);
        }
        serve
    }
}

/// UDP credit costs. A plain status query is the unit. Chosen from the work
/// each packet triggers; tune with the counters, not by guessing.
pub mod udp_cost {
    /// Every datagram, charged on arrival before anything is parsed.
    pub const ARRIVAL: u32 = 1;
    /// An obfuscated datagram that misses the decode cache: up to nine
    /// MD5+RC4 attempts.
    pub const OBF_COLD: u32 = 4;
    /// A search (on top of ARRIVAL): an index scan and up to ten replies.
    pub const SEARCH: u32 = 9;
    /// Per file hash in a source request (on top of ARRIVAL).
    pub const PER_SOURCE_HASH: u32 = 1;
    /// A server list request or response (gossip merge).
    pub const SERVER_LIST: u32 = 20;
}

/// Why a UDP packet was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpRefusal {
    Global,
    Source,
    /// The per-source table is at `max_rate_state_entries`.
    TableFull,
}

/// Server-wide, then per-source, UDP budgets — one instance for every UDP
/// listener and both address families.
pub struct UdpBudget {
    global: std::sync::Mutex<TokenBucket>,
    sources: DashMap<SourceKey, TokenBucket>,
    /// Entries in `sources`, reserved before insertion so the cap holds under
    /// concurrent inserts.
    entries: AtomicU32,
    cap: u32,
    src_rate: u32,
    src_burst: u32,
    v6_bits: u8,
    pub enforce: bool,
    pub admitted: AtomicU64,
    pub refused_global: AtomicU64,
    pub refused_source: AtomicU64,
    pub refused_table_full: AtomicU64,
}

impl UdpBudget {
    pub fn new(cfg: &AdmissionConfig) -> Self {
        Self {
            global: std::sync::Mutex::new(TokenBucket::new(
                cfg.udp_global_credits_per_second,
                cfg.udp_global_burst_credits,
                Instant::now(),
            )),
            sources: DashMap::new(),
            entries: AtomicU32::new(0),
            cap: cfg.max_rate_state_entries,
            src_rate: cfg.udp_source_credits_per_second,
            src_burst: cfg.udp_source_burst_credits,
            v6_bits: cfg.ipv6_source_prefix_bits,
            enforce: cfg.udp_rate_enforce,
            admitted: AtomicU64::new(0),
            refused_global: AtomicU64::new(0),
            refused_source: AtomicU64::new(0),
            refused_table_full: AtomicU64::new(0),
        }
    }

    /// Charge `cost` credits to the server-wide budget and then to `ip`'s.
    ///
    /// The global check comes first, so rotating or spoofed source addresses
    /// cannot get past the server-wide bound, and no per-source state is
    /// allocated for a packet the server is refusing anyway. Credits taken
    /// from the global budget are refunded if the source then refuses.
    ///
    /// Returns whether to serve the packet. In observe mode
    /// (`udp_rate_enforce = false`) every refusal is counted but the answer is
    /// always true.
    pub fn admit(&self, ip: IpAddr, cost: u32) -> bool {
        match self.check(ip, cost, Instant::now()) {
            Ok(()) => {
                self.admitted.fetch_add(1, Relaxed);
                true
            }
            Err(r) => {
                match r {
                    UdpRefusal::Global => &self.refused_global,
                    UdpRefusal::Source => &self.refused_source,
                    UdpRefusal::TableFull => &self.refused_table_full,
                }
                .fetch_add(1, Relaxed);
                !self.enforce
            }
        }
    }

    fn check(&self, ip: IpAddr, cost: u32, now: Instant) -> Result<(), UdpRefusal> {
        {
            let mut g = self.global.lock().unwrap_or_else(|e| e.into_inner());
            if !g.take(cost, now) {
                return Err(UdpRefusal::Global);
            }
        }
        let refund = |this: &Self| {
            let mut g = this.global.lock().unwrap_or_else(|e| e.into_inner());
            g.refund(cost);
        };
        let key = SourceKey::of(ip, self.v6_bits);
        let ok = match self.sources.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut e) => e.get_mut().take(cost, now),
            dashmap::mapref::entry::Entry::Vacant(v) => {
                // Reserve the table slot before inserting (the entry lock is
                // held, so no one else can insert this key meanwhile).
                let mut cur = self.entries.load(Relaxed);
                loop {
                    if cur >= self.cap {
                        drop(v);
                        refund(self);
                        return Err(UdpRefusal::TableFull);
                    }
                    match self
                        .entries
                        .compare_exchange_weak(cur, cur + 1, Relaxed, Relaxed)
                    {
                        Ok(_) => break,
                        Err(seen) => cur = seen,
                    }
                }
                let mut b = TokenBucket::new(self.src_rate, self.src_burst, now);
                let ok = b.take(cost, now);
                v.insert(b);
                ok
            }
        };
        if ok {
            Ok(())
        } else {
            refund(self);
            Err(UdpRefusal::Source)
        }
    }

    /// Drop per-source entries that have been idle long enough to be full
    /// again — forgetting them loses nothing. Called periodically.
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let before = self.sources.len();
        self.sources.retain(|_, b| {
            let keep = !b.is_full_at(now);
            if !keep {
                self.entries.fetch_sub(1, Relaxed);
            }
            keep
        });
        before.saturating_sub(self.sources.len())
    }

    pub fn entries(&self) -> u32 {
        self.entries.load(Relaxed)
    }

    pub fn cap(&self) -> u32 {
        self.cap
    }
}

/// Run CPU-heavy search work off the async runtime.
///
/// The permit is moved INTO the blocking job and handed back with its result,
/// so capacity is released only when the computation has actually finished —
/// even if the awaiting caller goes away. Callers acquire the permit first
/// (`tcp_search_permit` / `udp_search_permit`), so the blocking pool never
/// holds more than `max_search_jobs` searches.
pub async fn run_search<T, F>(permit: OwnedSemaphorePermit, f: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let r = f();
        drop(permit);
        r
    })
    .await
    .ok()
}

/// The accounting key for a remote address: IPv4 by /32, IPv6 by a prefix
/// (`admission.ipv6_source_prefix_bits`, /64 by default), IPv4-mapped IPv6
/// as the IPv4 it carries. Never the port. Used by every listener and both
/// transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKey {
    V4(std::net::Ipv4Addr),
    V6Prefix { prefix: u128, bits: u8 },
}

impl SourceKey {
    /// The key as an address: IPv4 as is, IPv6 masked to its prefix. For maps
    /// already keyed by `IpAddr` (the TCP per-IP limit).
    pub fn as_ip(&self) -> IpAddr {
        match *self {
            SourceKey::V4(v4) => IpAddr::V4(v4),
            SourceKey::V6Prefix { prefix, .. } => IpAddr::V6(std::net::Ipv6Addr::from(prefix)),
        }
    }

    pub fn of(ip: IpAddr, v6_bits: u8) -> Self {
        match ip {
            IpAddr::V4(v4) => SourceKey::V4(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => SourceKey::V4(v4),
                None => {
                    let bits = v6_bits.clamp(1, 128);
                    let mask = if bits == 128 {
                        u128::MAX
                    } else {
                        !(u128::MAX >> bits)
                    };
                    SourceKey::V6Prefix {
                        prefix: u128::from(v6) & mask,
                        bits,
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::minimal_test_config()
    }

    #[test]
    fn exactly_n_permits_are_admitted_and_n_plus_one_is_rejected() {
        let p = Pool::new(3, Arc::new(AtomicU64::new(0)));
        let held: Vec<_> = (0..3).map(|_| p.try_take().expect("within cap")).collect();
        assert!(p.try_take().is_none());
        assert_eq!((p.in_use(), p.rejected()), (3, 1));
        drop(held);
        assert_eq!(p.in_use(), 0, "permits come back when dropped");
        assert!(p.try_take().is_some());
    }

    #[tokio::test]
    async fn a_bounded_wait_times_out_and_counts() {
        let p = Pool::new(1, Arc::new(AtomicU64::new(0)));
        let _held = p.try_take().unwrap();
        assert!(p.take_within(Duration::from_millis(20)).await.is_none());
        assert_eq!(p.rejected(), 1);
    }

    #[test]
    fn concurrent_reservations_cannot_exceed_max_clients() {
        let slots = Arc::new(ClientSlots::new());
        let got = Arc::new(std::sync::Mutex::new(Vec::new()));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let (s, g) = (Arc::clone(&slots), Arc::clone(&got));
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        if let Some(slot) = s.try_reserve(50) {
                            g.lock().unwrap().push(slot);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(got.lock().unwrap().len(), 50);
        assert_eq!(slots.held(), 50);
        assert_eq!(slots.rejected(), 16 * 100 - 50);
        got.lock().unwrap().clear();
        assert_eq!(slots.held(), 0, "slots return on drop");
    }

    #[test]
    fn max_clients_zero_is_no_cap_and_force_reserve_ignores_the_cap() {
        let s = ClientSlots::new();
        let a: Vec<_> = (0..10).map(|_| s.try_reserve(0).unwrap()).collect();
        assert_eq!(s.held(), 10);
        assert!(s.try_reserve(10).is_none());
        let f = s.force_reserve();
        assert_eq!(s.held(), 11);
        drop((a, f));
        assert_eq!(s.held(), 0);
    }

    #[test]
    fn token_bucket_refills_at_its_rate_and_caps_at_burst() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(10, 5, t0);
        for _ in 0..5 {
            assert!(b.take(1, t0));
        }
        assert!(!b.take(1, t0), "burst spent");
        assert!(
            b.take(1, t0 + Duration::from_millis(100)),
            "one credit per 100 ms"
        );
        assert!(!b.take(1, t0 + Duration::from_millis(150)));
        // A long idle period refills to the burst, not beyond.
        let later = t0 + Duration::from_secs(60);
        assert!(b.is_full_at(later));
        for _ in 0..5 {
            assert!(b.take(1, later));
        }
        assert!(!b.take(1, later));
        b.refund(2);
        assert!(b.take(2, later));
    }

    #[test]
    fn hole_punch_retries_coalesce_per_pair_and_cap_overall() {
        let mut c = cfg();
        c.admission.max_retry_tasks = 2;
        let a = Admission::new(&c);
        let r1 = a.try_retry([1; 16], 7).unwrap();
        assert!(matches!(a.try_retry([1; 16], 7), Err(RetrySkip::Coalesced)));
        let _r2 = a.try_retry([1; 16], 8).unwrap();
        assert!(matches!(a.try_retry([2; 16], 9), Err(RetrySkip::Busy)));
        // A Busy refusal must not leave its pair claimed.
        drop(r1);
        let _r3 = a.try_retry([2; 16], 9).expect("pair released after Busy");
        assert!(matches!(a.try_retry([1; 16], 7), Err(RetrySkip::Busy)));
        assert_eq!(a.retries.in_use(), 2);
    }

    #[test]
    fn source_keys_follow_the_documented_aggregation() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let v4 = Ipv4Addr::new(203, 0, 113, 5);
        assert_eq!(SourceKey::of(IpAddr::V4(v4), 64), SourceKey::V4(v4));
        let mapped: Ipv6Addr = v4.to_ipv6_mapped();
        assert_eq!(SourceKey::of(IpAddr::V6(mapped), 64), SourceKey::V4(v4));
        let a: Ipv6Addr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let c: Ipv6Addr = "2001:db8:1:3::1".parse().unwrap();
        let k = |x| SourceKey::of(IpAddr::V6(x), 64);
        assert_eq!(k(a), k(b), "same /64 shares a budget");
        assert_ne!(k(a), k(c));
        assert_ne!(
            SourceKey::of(IpAddr::V6(a), 128),
            SourceKey::of(IpAddr::V6(b), 128)
        );
    }

    #[tokio::test]
    async fn search_jobs_and_queue_never_exceed_their_bounds() {
        let mut c = cfg();
        c.admission.max_search_jobs = 1;
        c.admission.max_queued_tcp_searches = 1;
        c.admission.tcp_search_wait_ms = 50;
        let a = Arc::new(Admission::new(&c));
        let job = a.tcp_search_permit().await.expect("free job");
        // UDP is never admitted by waiting in the receive loop; with the job
        // busy it can only take a place in its own queue.
        assert!(matches!(
            a.udp_search_admit(),
            Some(UdpSearchTicket::Queued(_))
        ));
        // One TCP search may queue; a second is answered empty at once.
        let a2 = Arc::clone(&a);
        let waiter = tokio::spawn(async move { a2.tcp_search_permit().await.is_some() });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(a.search_queue.in_use(), 1);
        assert!(a.tcp_search_permit().await.is_none(), "queue full");
        // The queued one times out while the job is held.
        assert!(!waiter.await.unwrap());
        assert_eq!(a.tcp_search_shed.load(Relaxed), 2);
        drop(job);
        assert!(a.tcp_search_permit().await.is_some());
    }

    #[tokio::test]
    async fn a_search_permit_is_released_only_when_the_blocking_job_ends() {
        let mut c = cfg();
        c.admission.max_search_jobs = 1;
        let a = Arc::new(Admission::new(&c));
        let p = a.tcp_search_permit().await.unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        // The caller gives up at once; the job keeps running.
        let fut = run_search(p, move || {
            rx.recv().unwrap();
            7
        });
        let h = tokio::spawn(fut);
        tokio::time::sleep(Duration::from_millis(20)).await;
        h.abort();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(a.search_jobs.in_use(), 1, "still computing: permit held");
        tx.send(()).unwrap();
        for _ in 0..100 {
            if a.search_jobs.in_use() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(a.search_jobs.in_use(), 0);
    }

    fn udp_cfg(enforce: bool) -> AdmissionConfig {
        AdmissionConfig {
            udp_global_credits_per_second: 1,
            udp_global_burst_credits: 10,
            udp_source_credits_per_second: 1,
            udp_source_burst_credits: 3,
            max_rate_state_entries: 4,
            udp_rate_enforce: enforce,
            ..AdmissionConfig::default()
        }
    }

    fn v4(n: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, n))
    }

    #[test]
    fn udp_per_source_budget_refuses_and_global_is_refunded() {
        let b = UdpBudget::new(&udp_cfg(true));
        for _ in 0..3 {
            assert!(b.admit(v4(1), 1));
        }
        assert!(!b.admit(v4(1), 1), "source burst spent");
        assert_eq!(b.refused_source.load(Relaxed), 1);
        // The refused packet's global credit came back: 10 - 3 = 7 left.
        for n in 2..=3 {
            for _ in 0..3 {
                assert!(b.admit(v4(n), 1));
            }
        }
        assert!(b.admit(v4(4), 1), "7th global credit");
        assert!(!b.admit(v4(4), 1), "global burst spent");
        assert_eq!(b.refused_global.load(Relaxed), 1);
    }

    #[test]
    fn udp_global_is_checked_before_any_source_state_is_allocated() {
        let mut c = udp_cfg(true);
        c.udp_global_burst_credits = 1;
        let b = UdpBudget::new(&c);
        assert!(b.admit(v4(1), 1));
        assert!(!b.admit(v4(2), 1));
        assert_eq!(b.entries(), 1, "the refused source got no entry");
    }

    #[test]
    fn udp_source_table_never_exceeds_its_cap_under_concurrent_inserts() {
        let mut c = udp_cfg(true);
        c.udp_global_burst_credits = 1_000_000;
        c.udp_global_credits_per_second = 1_000_000;
        c.max_rate_state_entries = 100;
        let b = Arc::new(UdpBudget::new(&c));
        let ts: Vec<_> = (0..8u8)
            .map(|t| {
                let b = Arc::clone(&b);
                std::thread::spawn(move || {
                    for i in 0..200u8 {
                        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, t, i, 1));
                        b.admit(ip, 1);
                    }
                })
            })
            .collect();
        for t in ts {
            t.join().unwrap();
        }
        assert_eq!(b.entries(), 100);
        assert_eq!(b.sources.len(), 100);
        assert_eq!(b.refused_table_full.load(Relaxed), 8 * 200 - 100);
    }

    #[test]
    fn udp_ipv6_addresses_in_one_prefix_share_a_budget() {
        let b = UdpBudget::new(&udp_cfg(true));
        let a: IpAddr = "2001:db8:5:6::1".parse().unwrap();
        let c: IpAddr = "2001:db8:5:6:ffff::2".parse().unwrap();
        assert!(b.admit(a, 2));
        assert!(b.admit(c, 1));
        assert!(!b.admit(c, 1), "same /64: one budget");
        let mapped: IpAddr = "::ffff:198.51.100.9".parse().unwrap();
        assert!(b.admit(mapped, 3));
        assert!(!b.admit(v4(9), 1), "mapped v6 is its IPv4");
    }

    #[test]
    fn udp_observe_mode_counts_but_serves() {
        let b = UdpBudget::new(&udp_cfg(false));
        for _ in 0..3 {
            b.admit(v4(1), 1);
        }
        assert!(b.admit(v4(1), 1), "observe: served");
        assert_eq!(b.refused_source.load(Relaxed), 1, "but counted");
    }

    #[test]
    fn udp_sweep_forgets_idle_sources_and_frees_their_slots() {
        let mut c = udp_cfg(true);
        c.udp_source_credits_per_second = 1_000_000;
        let b = UdpBudget::new(&c);
        b.admit(v4(1), 1);
        b.admit(v4(2), 1);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(b.sweep(), 2);
        assert_eq!(b.entries(), 0);
    }

    #[test]
    fn readiness_turns_false_only_after_sustained_saturation_and_recovers() {
        let mut c = cfg();
        c.admission.max_pending_logins = 1;
        c.admission.readiness_window_secs = 1;
        let a = Admission::new(&c);
        assert!(a.readiness().0);
        let held = a.pending_login.try_take().unwrap();
        a.sample();
        assert!(a.readiness().0, "full, but not for the window yet");
        std::thread::sleep(Duration::from_millis(1100));
        a.sample();
        let (ready, stuck) = a.readiness();
        assert!(!ready);
        assert_eq!(stuck, vec!["pending_login"]);
        drop(held);
        a.sample();
        assert!(a.readiness().0, "recovers once the pool has room");
        assert_eq!(a.metrics()["pending_login"]["in_use"], 0);
    }

    #[tokio::test]
    async fn udp_searches_queue_in_their_own_small_queue_and_time_out() {
        let mut c = cfg();
        c.admission.max_search_jobs = 1;
        c.admission.max_queued_udp_searches = 1;
        c.admission.udp_search_wait_ms = 30;
        let a = Admission::new(&c);
        let job = match a.udp_search_admit() {
            Some(UdpSearchTicket::Ready(p)) => p,
            _ => panic!("a free job is taken at once"),
        };
        let queued = a.udp_search_admit().expect("one place in the UDP queue");
        assert!(a.udp_search_admit().is_none(), "queue full: dropped");
        assert_eq!(a.search_queue.in_use(), 0, "the TCP queue is untouched");
        assert!(a.udp_search_wait(queued).await.is_none(), "timed out");
        assert_eq!(a.udp_search_shed.load(Relaxed), 2);
        assert_eq!(a.udp_search_queue.in_use(), 0);
        drop(job);
        let t = a.udp_search_admit().unwrap();
        assert!(a.udp_search_wait(t).await.is_some());
    }

    #[test]
    fn one_source_cannot_hold_the_whole_pending_pool() {
        let mut c = cfg();
        c.admission.max_pending_logins = 4;
        c.admission.max_pending_logins_per_source = 2;
        let a = Admission::new(&c);
        let ip = v4(1);
        let p1 = a.try_pending(ip).unwrap();
        let _p2 = a.try_pending(ip).unwrap();
        assert_eq!(
            a.try_pending(ip).err(),
            Some("admission_pending_per_source")
        );
        // Another /64 of the same IPv6 /56 is another source; the same /64 is not.
        let x: IpAddr = "2001:db8:0:1::1".parse().unwrap();
        let y: IpAddr = "2001:db8:0:1::2".parse().unwrap();
        let z: IpAddr = "2001:db8:0:2::1".parse().unwrap();
        let _px = a.try_pending(x).unwrap();
        let _py = a.try_pending(y).expect("second socket of the /64");
        assert_eq!(
            a.try_pending(z).err(),
            Some("admission_pending_login"),
            "global full"
        );
        assert_eq!(a.pending_login.in_use(), 4);
        // A global refusal returns the source share it had taken.
        drop(p1);
        let _p3 = a.try_pending(ip).unwrap();
        assert_eq!(a.pending_source_rejected.load(Relaxed), 1);
        // Loopback has no per-source share.
        let mut c2 = cfg();
        c2.admission.max_pending_logins_per_source = 1;
        let b = Admission::new(&c2);
        let lo = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let _l1 = b.try_pending(lo).unwrap();
        assert!(b.try_pending(lo).is_ok());
    }

    #[test]
    fn a_replaced_session_gives_its_slot_back_at_once() {
        let slots = ClientSlots::new();
        let old: SharedSlot = Arc::default();
        *old.lock().unwrap() = Some(slots.try_reserve(1).unwrap());
        let old_copy = Arc::clone(&old); // the handle in the client map
                                         // Same hash logs in again while the old task still runs.
        let new: SharedSlot = Arc::default();
        *new.lock().unwrap() = Some(slots.force_reserve());
        assert_eq!(slots.held(), 2);
        release_slot(&old_copy); // the replacing login releases the old one
        assert_eq!(slots.held(), 1, "one user, one slot");
        release_slot(&old); // the old task ending later is a no-op
        assert_eq!(slots.held(), 1);
        release_slot(&new);
        assert_eq!(slots.held(), 0);
    }

    #[test]
    fn probe_ceiling_defaults_above_pending_logins() {
        let a = AdmissionConfig::default();
        assert_eq!(a.effective_probes(), a.max_pending_logins + 64);
    }
}
