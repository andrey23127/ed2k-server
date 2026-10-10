//! OFFERFILES v1: advertised batch size and pacing (issue #19).
//!
//! Legacy eMule and aMule publish at most 200 files per OP_OFFERFILES and wait
//! about a minute between batches, because a Lugdunum server may black out an
//! IP that publishes faster (its per-IP credit bucket, `slimit_lookup`). A
//! client cannot tell this server from such a one, so it cannot go faster
//! without being told. v1 tells it, and holds it to what it was told.
//!
//! # Wire contract (agreed in #19 and aMule #1699 / PR #1715)
//!
//! A client asks for v1 with a string-named uint32 tag `offerfiles_v` (the
//! highest version it implements, 1) in its OP_LOGINREQUEST; see
//! [`client_requests_v1`]. Only a client that asked is answered, and only its
//! connection is held to the rules below. Every other client is a legacy one,
//! whatever the configuration says: no tag in its SERVERIDENT, no pacing, no
//! batch limit beyond the hard one — exactly as with v1 off. (Revised
//! 10.10.2026, after v1 applied to every login on the live server rejected the
//! first, whole-list OFFERFILES of stock eMule clients.)
//!
//! To a client that asked, a server with v1 enabled sends, in the post-login
//! OP_SERVERIDENT and nowhere else, each exactly once and all as uint32:
//!
//! | tag                          | name kind | meaning                              |
//! |------------------------------|-----------|--------------------------------------|
//! | `ST_SOFTFILES` (0x88)        | numeric   | per-connection indexing budget        |
//! | `ST_HARDFILES` (0x89)        | numeric   | per-packet boundary: a packet must declare fewer records |
//! | `offerfiles_v`               | string    | capability version, exactly 1         |
//! | `offerfiles_batch_max`       | string    | most records in one OP_OFFERFILES     |
//! | `offerfiles_min_interval_ms` | string    | least time between two batches        |
//!
//! The advertisement is all or nothing. The values must satisfy soft > 0,
//! batch_max > 0, interval > 0 and hard > batch_max; a configuration that
//! breaks any of these advertises no `offerfiles_*` tag (an error is logged)
//! and the server behaves as a legacy one. There is deliberately no
//! `offer_burst`: tolerance for frames that TCP delivers together is internal,
//! not an entitlement a client may plan around.
//!
//! The five values are a snapshot taken when the client logs in
//! ([`OfferPolicy`], kept on its `ClientHandle`). Every limit applied to that
//! connection comes from the snapshot, so what was advertised is what is
//! enforced, and a live configuration change reaches new connections only.
//!
//! # Enforcement, for a v1 connection
//!
//! In this order, on each OP_OFFERFILES:
//!
//! 1. declared count >= hard → packet rejected, connection closed (as legacy);
//! 2. declared count > batch_max → not indexed, counted, logged; the session
//!    stays up;
//! 3. the connection's own bucket ([`Gcra`]): a batch that arrives early WAITS
//!    for its tokens, it is never dropped. The connection is not reading while
//!    it waits, so this is ordinary TCP backpressure with nothing queued
//!    beyond the frame already read;
//! 4. the server-wide bucket ([`GlobalOfferPacer`], `limits.offerfiles_global_
//!    records_per_sec`): the same, shared by every v1 connection and served in
//!    arrival order, so that a reconnect wave of fast publishers slows each of
//!    them down instead of saturating the content filter;
//! 5. content filter, soft budget and indexing exactly as for a legacy client.
//!
//! A legacy connection (the client did not ask, v1 is off, or the
//! configuration is invalid) goes through none of 2–4, and reads soft and hard
//! live as before.

use crate::config::LimitsConfig;
use crate::proto::tags::{Tag, TagName, TagValue};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;
// tokio's Instant, so the pacing follows tokio's (pausable) clock in tests and
// matches the `sleep` that serves the wait.
use tokio::time::Instant;

/// The capability version this server implements.
pub const OFFERFILES_VERSION: u32 = 1;
pub const TAG_VERSION: &str = "offerfiles_v";
pub const TAG_BATCH_MAX: &str = "offerfiles_batch_max";
pub const TAG_MIN_INTERVAL_MS: &str = "offerfiles_min_interval_ms";

/// One connection's v1 policy, snapshotted at login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferPolicy {
    pub soft: u32,
    pub hard: u32,
    pub batch_max: u32,
    pub min_interval_ms: u32,
}

impl OfferPolicy {
    /// The policy `limits` describes: `Ok(None)` when v1 is off, `Err` with the
    /// rule broken when it is on but the values cannot be advertised.
    pub fn from_limits(l: &LimitsConfig) -> Result<Option<Self>, String> {
        if !l.offerfiles_v1 {
            return Ok(None);
        }
        let p = OfferPolicy {
            soft: l.soft_limit_files,
            hard: l.hard_limit_files,
            batch_max: l.offerfiles_batch_max,
            min_interval_ms: l.offerfiles_min_interval_ms,
        };
        // 0 means "no limit" for soft and hard elsewhere in this server, but
        // the contract has no way to say "unlimited": a client reads 0 as an
        // invalid advertisement. So v1 needs both limits set.
        if p.soft == 0 {
            return Err("limits.soft_limit_files must be above 0".into());
        }
        if p.batch_max == 0 {
            return Err("limits.offerfiles_batch_max must be above 0".into());
        }
        if p.min_interval_ms == 0 {
            return Err("limits.offerfiles_min_interval_ms must be above 0".into());
        }
        if p.hard <= p.batch_max {
            return Err(format!(
                "limits.hard_limit_files ({}) must be above limits.offerfiles_batch_max ({}): \
                 a full batch would otherwise be a hard-limit disconnect",
                p.hard, p.batch_max
            ));
        }
        Ok(Some(p))
    }

    /// The three string-named tags. ST_SOFTFILES / ST_HARDFILES are written by
    /// the SERVERIDENT builder from the same snapshot.
    pub fn tags(&self) -> [Tag; 3] {
        let t = |name: &str, v: u32| Tag {
            name: TagName::Str(name.to_string()),
            value: TagValue::U32(v),
        };
        [
            t(TAG_VERSION, OFFERFILES_VERSION),
            t(TAG_BATCH_MAX, self.batch_max),
            t(TAG_MIN_INTERVAL_MS, self.min_interval_ms),
        ]
    }

    /// A fresh per-connection bucket for this policy.
    pub fn bucket(&self) -> Gcra {
        Gcra::new(self.batch_max, Duration::from_millis(self.min_interval_ms as u64))
    }
}

/// Did the client ask for OFFERFILES v1 in its OP_LOGINREQUEST?
///
/// The request is a string-named uint32 tag `offerfiles_v` among the login
/// tags, carrying the highest version the client implements (1 today). Any
/// other shape — absent, another type, 0 — is a legacy client.
///
/// Why a request at all: the server cannot otherwise tell a client that will
/// read the advertisement from one that will not, and the v1 rules are not
/// neutral for the second kind. Applied to everyone on the live server they
/// rejected the first OFFERFILES of stock eMule clients, which send their
/// whole list in one packet (thousands of records, under the hard limit but
/// far over batch_max), and put every publisher behind the server-wide
/// ceiling. So the server answers only a client that asked: it advertises,
/// and enforces, for that connection and no other.
pub fn client_requests_v1(tags: &[Tag]) -> bool {
    tags.iter().any(|t| {
        matches!(&t.name, TagName::Str(n) if n == TAG_VERSION)
            && matches!(t.value, TagValue::U32(v) if v >= OFFERFILES_VERSION)
    })
}

/// The policy for a client logging in now, logging a configuration that cannot
/// be advertised (once per distinct bad combination, not once per login).
pub fn policy_for_login(l: &LimitsConfig) -> Option<OfferPolicy> {
    match OfferPolicy::from_limits(l) {
        Ok(p) => p,
        Err(why) => {
            use std::sync::Mutex;
            static LOGGED: Mutex<Option<(u32, u32, u32, u32)>> = Mutex::new(None);
            let key = (
                l.soft_limit_files,
                l.hard_limit_files,
                l.offerfiles_batch_max,
                l.offerfiles_min_interval_ms,
            );
            let mut last = LOGGED.lock().unwrap_or_else(|e| e.into_inner());
            if *last != Some(key) {
                *last = Some(key);
                tracing::error!(
                    "limits.offerfiles_v1 is on but cannot be advertised: {why}. \
                     No offerfiles_* tag is sent; publishing works as on a legacy server."
                );
            }
            None
        }
    }
}

/// A token bucket in file records, written as GCRA (one timestamp, no
/// background refill): `rate` records per `per`, holding at most `rate`.
///
/// It starts full, so the first batch goes at once. A batch of `n` records
/// costs `n * per / rate`; [`Gcra::reserve`] books it and returns how long
/// the caller must wait before processing it. The booking is made up front, so
/// a batch that waits does not let a later one overtake it.
#[derive(Debug, Clone)]
pub struct Gcra {
    rate: u32,
    per: Duration,
    /// Theoretical arrival time: when the bucket would be full again.
    tat: Option<Instant>,
}

impl Gcra {
    pub fn new(rate: u32, per: Duration) -> Self {
        Gcra {
            rate: rate.max(1),
            per,
            tat: None,
        }
    }

    pub fn rate(&self) -> (u32, Duration) {
        (self.rate, self.per)
    }

    /// Book `n` records at `now`; returns the wait before they may be processed.
    pub fn reserve(&mut self, n: u32, now: Instant) -> Duration {
        let cost_ns = (self.per.as_nanos() * n as u128) / self.rate as u128;
        // Capped so a pathological configuration cannot overflow Instant
        // arithmetic: a day is far beyond any interval anyone would set.
        let cost = Duration::from_nanos(cost_ns.min(86_400_000_000_000) as u64);
        let start = match self.tat {
            Some(t) if t > now => t,
            _ => now,
        };
        let tat = start + cost;
        self.tat = Some(tat);
        // Allowed once the bucket has room for n: tat - per <= now.
        match tat.checked_sub(self.per) {
            Some(earliest) if earliest > now => earliest - now,
            _ => Duration::ZERO,
        }
    }
}

/// The server-wide record ceiling for v1 connections.
///
/// One FIFO lock around one [`Gcra`]: a publisher takes the lock, books its
/// batch, and sleeps out its wait while still holding it. `tokio::sync::Mutex`
/// is fair, so waiting publishers are served in arrival order and none can
/// starve; and since each waiter is a connection that has stopped reading, the
/// queue is bounded by the number of v1 connections, each holding the one
/// frame it already read.
pub struct GlobalOfferPacer {
    bucket: tokio::sync::Mutex<Option<Gcra>>,
    /// Publishers waiting for the ceiling right now.
    pub waiting: AtomicU64,
}

impl Default for GlobalOfferPacer {
    fn default() -> Self {
        GlobalOfferPacer {
            bucket: tokio::sync::Mutex::new(None),
            waiting: AtomicU64::new(0),
        }
    }
}

impl GlobalOfferPacer {
    /// Wait until `n` records fit under `records_per_sec` (read live; `0` = no
    /// ceiling). Returns the time waited, queueing included.
    pub async fn acquire(&self, n: u32, records_per_sec: u32) -> Duration {
        if records_per_sec == 0 || n == 0 {
            return Duration::ZERO;
        }
        // Measured from arrival, so time spent queued behind other publishers
        // counts, not only this one's own sleep.
        let arrived = Instant::now();
        self.waiting.fetch_add(1, Relaxed);
        let _queued = DecOnDrop(&self.waiting);
        let mut guard = self.bucket.lock().await;
        let per = Duration::from_secs(1);
        if guard.as_ref().map(|g| g.rate()) != Some((records_per_sec, per)) {
            // First use, or the ceiling was changed live: start over full.
            *guard = Some(Gcra::new(records_per_sec, per));
        }
        let wait = guard
            .as_mut()
            .expect("set above")
            .reserve(n, Instant::now());
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        arrived.elapsed()
    }
}

struct DecOnDrop<'a>(&'a AtomicU64);
impl Drop for DecOnDrop<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

/// Counters for choosing production values (Status tab, /api/stats).
#[derive(Default)]
pub struct OfferV1Stats {
    /// Logins that asked for v1 (tag `offerfiles_v` in OP_LOGINREQUEST).
    pub requested: AtomicU64,
    /// Logins that were sent the v1 advertisement (asked, and v1 is on and
    /// valid).
    pub sessions: AtomicU64,
    /// Batches and records processed on v1 connections.
    pub batches: AtomicU64,
    pub records: AtomicU64,
    /// Batches that waited for their connection's bucket, and for how long.
    pub conn_waits: AtomicU64,
    pub conn_wait_ms: AtomicU64,
    /// Batches that waited for the server-wide ceiling, and for how long.
    pub global_waits: AtomicU64,
    pub global_wait_ms: AtomicU64,
    /// The longest single wait for the ceiling, in ms.
    pub global_wait_max_ms: AtomicU64,
    /// Batches above the negotiated batch_max (not indexed, session kept).
    pub oversized: AtomicU64,
}

impl OfferV1Stats {
    pub fn note_conn_wait(&self, d: Duration) {
        if !d.is_zero() {
            self.conn_waits.fetch_add(1, Relaxed);
            self.conn_wait_ms.fetch_add(d.as_millis() as u64, Relaxed);
        }
    }

    pub fn note_global_wait(&self, d: Duration) {
        // `acquire` reports time since arrival, which is never exactly zero —
        // a batch that went straight through still took a few microseconds to
        // lock and book. Count only what a client could notice.
        if d >= Duration::from_millis(1) {
            let ms = d.as_millis() as u64;
            self.global_waits.fetch_add(1, Relaxed);
            self.global_wait_ms.fetch_add(ms, Relaxed);
            self.global_wait_max_ms.fetch_max(ms, Relaxed);
        }
    }

    pub fn to_json(&self, pacer: &GlobalOfferPacer) -> serde_json::Value {
        serde_json::json!({
            "requested": self.requested.load(Relaxed),
            "sessions": self.sessions.load(Relaxed),
            "batches": self.batches.load(Relaxed),
            "records": self.records.load(Relaxed),
            "conn_waits": self.conn_waits.load(Relaxed),
            "conn_wait_ms": self.conn_wait_ms.load(Relaxed),
            "global_waits": self.global_waits.load(Relaxed),
            "global_wait_ms": self.global_wait_ms.load(Relaxed),
            "global_wait_max_ms": self.global_wait_max_ms.load(Relaxed),
            "global_waiting_now": pacer.waiting.load(Relaxed),
            "oversized": self.oversized.load(Relaxed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(on: bool, soft: u32, hard: u32, batch: u32, ms: u32) -> LimitsConfig {
        let mut l: LimitsConfig = toml::from_str("").unwrap();
        l.offerfiles_v1 = on;
        l.soft_limit_files = soft;
        l.hard_limit_files = hard;
        l.offerfiles_batch_max = batch;
        l.offerfiles_min_interval_ms = ms;
        l
    }

    #[test]
    fn defaults_are_off_and_would_be_valid() {
        let l: LimitsConfig = toml::from_str("").unwrap();
        assert!(!l.offerfiles_v1);
        assert_eq!(OfferPolicy::from_limits(&l), Ok(None));
        let mut on = l.clone();
        on.offerfiles_v1 = true;
        let p = OfferPolicy::from_limits(&on).unwrap().unwrap();
        assert_eq!((p.batch_max, p.min_interval_ms), (200, 500));
    }

    #[test]
    fn every_contract_rule_refuses_the_advertisement() {
        assert!(OfferPolicy::from_limits(&limits(true, 5, 4, 2, 200)).unwrap().is_some());
        for (soft, hard, batch, ms) in [
            (0, 4, 2, 200),   // soft 0
            (5, 4, 0, 200),   // batch 0
            (5, 4, 2, 0),     // interval 0
            (5, 2, 2, 200),   // hard == batch
            (5, 1, 2, 200),   // hard < batch
            (5, 0, 2, 200),   // hard 0 ("no limit" elsewhere) is below batch
        ] {
            assert!(
                OfferPolicy::from_limits(&limits(true, soft, hard, batch, ms)).is_err(),
                "{soft} {hard} {batch} {ms}"
            );
            // And the login path then advertises nothing.
            assert_eq!(policy_for_login(&limits(true, soft, hard, batch, ms)), None);
        }
        // Off never errs, whatever the values.
        assert_eq!(OfferPolicy::from_limits(&limits(false, 0, 0, 0, 0)), Ok(None));
    }

    #[test]
    fn only_an_explicit_uint32_request_counts() {
        let tag = |name: TagName, value: TagValue| Tag { name, value };
        let ask = |v| tag(TagName::Str("offerfiles_v".into()), v);
        assert!(client_requests_v1(&[ask(TagValue::U32(1))]));
        assert!(client_requests_v1(&[ask(TagValue::U32(2))]), "a newer client still gets v1");
        assert!(!client_requests_v1(&[]));
        assert!(!client_requests_v1(&[ask(TagValue::U32(0))]));
        assert!(!client_requests_v1(&[ask(TagValue::U8(1))]), "wrong type");
        assert!(!client_requests_v1(&[ask(TagValue::String("1".into()))]));
        assert!(!client_requests_v1(&[tag(TagName::Str("offerfiles_V".into()), TagValue::U32(1))]));
    }

    #[test]
    fn tags_are_uint32_with_the_agreed_names() {
        let p = OfferPolicy { soft: 5, hard: 4000, batch_max: 200, min_interval_ms: 500 };
        let tags = p.tags();
        let got: Vec<_> = tags
            .iter()
            .map(|t| match (&t.name, &t.value) {
                (TagName::Str(n), TagValue::U32(v)) => (n.as_str(), *v),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            got,
            [("offerfiles_v", 1), ("offerfiles_batch_max", 200), ("offerfiles_min_interval_ms", 500)]
        );
        // On the wire: old-format string-named uint32 (type 0x03, u16 name
        // length, name, u32), which both eMule and aMule skip when unknown.
        let mut buf = bytes::BytesMut::new();
        crate::proto::tags::write_tag(&mut buf, &tags[0]);
        let mut want = vec![0x03, 12, 0];
        want.extend_from_slice(b"offerfiles_v");
        want.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(&buf[..], &want[..]);
    }

    const MS: fn(u64) -> Duration = Duration::from_millis;

    #[test]
    fn first_batch_is_free_then_one_batch_per_interval() {
        let t0 = Instant::now();
        let mut b = Gcra::new(200, MS(500));
        assert_eq!(b.reserve(200, t0), Duration::ZERO);
        // A second full batch at once waits a whole interval...
        assert_eq!(b.reserve(200, t0), MS(500));
        // ...and a third, booked behind it, two.
        assert_eq!(b.reserve(200, t0), MS(1000));
        // Sent on schedule, nothing waits.
        let mut b = Gcra::new(200, MS(500));
        for i in 0..10 {
            assert_eq!(b.reserve(200, t0 + MS(500 * i)), Duration::ZERO, "batch {i}");
        }
    }

    #[test]
    fn smaller_batches_are_charged_by_record_count() {
        let t0 = Instant::now();
        let mut b = Gcra::new(200, MS(500));
        // Four batches of 50 fill exactly one batch worth of tokens.
        for _ in 0..4 {
            assert_eq!(b.reserve(50, t0), Duration::ZERO);
        }
        // The fifth waits for 50 records' refill: 125 ms.
        assert_eq!(b.reserve(50, t0), MS(125));
        // Splitting a batch into single records buys no extra rate.
        let mut b = Gcra::new(200, MS(500));
        let mut last = Duration::ZERO;
        for _ in 0..400 {
            last = b.reserve(1, t0);
        }
        // 400 single records: the second 200 wait exactly as a second batch would.
        assert_eq!(last, MS(500));
    }

    #[test]
    fn idle_time_refills_only_up_to_one_batch() {
        let t0 = Instant::now();
        let mut b = Gcra::new(200, MS(500));
        b.reserve(200, t0);
        // An hour idle does not bank an hour of batches.
        let later = t0 + Duration::from_secs(3600);
        assert_eq!(b.reserve(200, later), Duration::ZERO);
        assert_eq!(b.reserve(200, later), MS(500));
    }

    #[test]
    fn extreme_values_do_not_overflow() {
        let t0 = Instant::now();
        let mut b = Gcra::new(u32::MAX, Duration::from_millis(u32::MAX as u64));
        b.reserve(u32::MAX, t0);
        b.reserve(u32::MAX, t0);
        let mut b = Gcra::new(1, Duration::from_millis(u32::MAX as u64));
        b.reserve(u32::MAX, t0);
        let w = b.reserve(u32::MAX, t0);
        assert!(w <= Duration::from_secs(86_400));
        let mut b = Gcra::new(0, MS(1)); // rate clamped to 1
        assert_eq!(b.reserve(1, t0), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn the_global_ceiling_serves_publishers_in_arrival_order() {
        use std::sync::Arc;
        let pacer = Arc::new(GlobalOfferPacer::default());
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let t0 = tokio::time::Instant::now();
        let mut tasks = Vec::new();
        for i in 0..5u32 {
            let (p, o) = (pacer.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                let w = p.acquire(1000, 1000).await;
                o.lock().unwrap().push((i, t0.elapsed().as_millis()));
                w
            }));
            // Let each one queue before the next arrives.
            tokio::task::yield_now().await;
        }
        let mut waited = Vec::new();
        for t in tasks {
            waited.push(t.await.unwrap());
        }
        let got = order.lock().unwrap().clone();
        // 1000 records/s, 1000 records each: the first at once, then one a second.
        assert_eq!(
            got,
            vec![(0, 0), (1, 1000), (2, 2000), (3, 3000), (4, 4000)]
        );
        // The reported wait includes the queueing: the last one waited 4 s.
        assert_eq!(waited[4], Duration::from_secs(4));
        assert_eq!(pacer.waiting.load(Relaxed), 0);
        // 0 = no ceiling.
        assert_eq!(pacer.acquire(1_000_000, 0).await, Duration::ZERO);
    }
}
