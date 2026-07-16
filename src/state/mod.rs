//! Shared server state.

/// Lever-A foundation (FileId slab). NOT currently wired into ServerState —
/// kept compiled+tested for when lever A is resumed. Dual-write (step 2) was
/// reverted in v0.9.51 after prod data showed snapshot-orphan churn made the
/// slab tombstone-thrash; the snapshot removal in v0.9.51 fixes the root cause,
/// so a future lever A can use plain tombstones. See STATE.md lever A plan.
#[allow(dead_code)]
pub mod file_id;
pub mod keyword_index;
pub mod posting_codec;
pub mod name_interner;
pub mod smart_sources;

use crate::filter::ContentFilter;
use crate::proto::Frame;
use dashmap::DashMap;
use keyword_index::KeywordIndex;
use smart_sources::SmartSourcesCache;
use std::net::{IpAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};

pub type UserHash = [u8; 16];
pub type FileHash = [u8; 16];

/// Capacity of the per-client frame send channel.
/// Keeps a small buffer so the sending task doesn't block on a single slow receiver.
const CLIENT_CHANNEL_CAP: usize = 16;

/// Per-client state held while a TCP session is alive.
#[derive(Debug, Clone)]
pub struct ClientHandle {
    pub user_hash: UserHash,
    pub assigned_id: u32,
    pub ip: IpAddr,
    pub port: u16,
    /// Client's UDP port for LowID↔LowID NAT traversal (§3.12). 0 = unknown.
    /// Populated when a modified client sends OP_LOWID_HOLEPUNCH_REQUEST (which
    /// carries its own UDP port). Stock clients never set this and so can't be
    /// hole-punch targets — that's fine, the feature is opt-in by client mods.
    pub udp_port: u16,
    /// True if this client advertised NAT-traversal capability at login (it sent
    /// CT_EMULE_UDPPORTS, which stock eMule does NOT send to servers — only our
    /// client mod does). Used purely for the web-UI "NAT-T capable clients"
    /// statistic so the operator can watch mod adoption.
    pub natt_capable: bool,
    pub nick: String,
    pub server_flags: u32,
    pub is_high_id: bool,
    pub connected_at: Instant,
    /// ISO-3166-1 alpha-2 country code, "??" if unknown. Set from ip-to-country.csv.
    pub country: String,
    /// Client software name: "eMule", "aMule", "mldonkey", "Shareaza", etc.
    /// Derived from CT_EMULE_VERSION (0xFB) top byte in the login packet.
    pub software: String,
    /// Number of files the client has offered via OFFERFILES. Starts at 0,
    /// incremented by the OFFERFILES handler. Used for the "Files" column.
    pub shared_files: u32,
    /// Counters for §7.6 enforcement
    pub csam_attempts: u32,
    /// Channel to push frames to this client's connection task.
    /// Used by callback and keepalive code. None when channel is closed/dropped.
    pub tx: Option<mpsc::Sender<Frame>>,
    /// Shared "last activity" clock, in milliseconds since `ServerState::epoch`.
    /// The TCP connection task owns the idle timeout, but a NAT-T LowID *source*
    /// is silent on TCP for hours (it only shares — it never searches, asks for
    /// sources, or downloads). Its only regular contact with the server is the
    /// OP_SERVER_NATT_KEEPALIVE UDP packet, which arrives on a DIFFERENT socket
    /// and task. Without a shared clock that UDP keepalive could not reset the
    /// TCP idle timer, so the server would evict a perfectly alive client after
    /// ~15 min — dropping it from "NAT-T capable" and making its shared files
    /// unsearchable even though the TCP link was never broken. Both the UDP
    /// keepalive handler and the TCP task bump this; the TCP task reads it to
    /// decide whether the client is really idle.
    pub last_activity_ms: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ClientHandle {
    /// Wall-clock milliseconds (UNIX epoch). Used for the shared activity clock
    /// so the UDP keepalive handler and the TCP task can compare timestamps
    /// without sharing an `Instant`.
    pub fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Mark the client active right now (any TCP frame or UDP keepalive).
    pub fn touch_activity(&self) {
        self.last_activity_ms
            .store(Self::now_ms(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Milliseconds since the last recorded activity (TCP or UDP).
    pub fn idle_ms(&self) -> u64 {
        Self::now_ms().saturating_sub(
            self.last_activity_ms.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Send a frame to this client without waiting (fire-and-forget).
    /// Silently drops if the channel is full or closed.
    pub fn send_frame(&self, frame: Frame) {
        if let Some(tx) = &self.tx {
            let _ = tx.try_send(frame);
        }
    }

    /// True while the client's connection task is still running. The task holds
    /// the receiver end of `tx`; when it ends (clean disconnect, read error such
    /// as the provider NAT dropping the TCP link, etc.) the receiver is dropped
    /// and the sender reports closed. Used by hole-punch coordination to avoid
    /// directing a requester at a target whose session is already dead but not
    /// yet swept from the client map.
    pub fn is_alive(&self) -> bool {
        match &self.tx {
            Some(tx) => !tx.is_closed(),
            None => false,
        }
    }
}

/// A single source of a file, memory-packed (Stage 1a).
///
/// The previous representation was the tuple `(UserHash, IpAddr, u16, bool)`.
/// `std::net::IpAddr` is an enum (V4/V6 + discriminant) that aligns to ~20
/// bytes, so the tuple cost ~40 bytes each. At Lugdunum scale (tens of millions
/// of source links) that enum overhead alone is ~1 GB.
///
/// This struct stores the IPv4 address as a raw `u32` (the only family eD2k
/// peers use as sources) and folds the completeness flag into the top bit of
/// the port field, giving 16 + 4 + 2 = 22 bytes (24 with alignment). For the
/// rare IPv6 peer we simply store 0 (it can't be an eD2k source IP anyway), the
/// same as the old code which `unwrap`ed V4 octets and treated others as 0.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Source {
    pub user_hash: UserHash,   // 16 bytes — needed for dedup and self-filter
    pub ipv4: u32,             // 4 bytes  — native-endian IPv4 octets, 0 if not V4
    port_complete: u16,        // 2 bytes  — port in low 15 bits, complete in top bit
}

const SRC_COMPLETE_BIT: u16 = 0x8000;

impl Source {
    pub fn new(user_hash: UserHash, ip: IpAddr, port: u16, complete: bool) -> Self {
        let ipv4 = match ip {
            IpAddr::V4(v4) => u32::from_le_bytes(v4.octets()),
            IpAddr::V6(_) => 0,
        };
        // Ports are 16-bit; eD2k never uses port 0 for a real source, and the
        // top bit is free in every realistic port value, so steal it for the
        // completeness flag. (Defensive: mask the port to 15 bits.)
        let pc = (port & 0x7FFF) | if complete { SRC_COMPLETE_BIT } else { 0 };
        Source { user_hash, ipv4, port_complete: pc }
    }

    #[inline]
    pub fn port(&self) -> u16 {
        self.port_complete & 0x7FFF
    }

    #[inline]
    pub fn complete(&self) -> bool {
        self.port_complete & SRC_COMPLETE_BIT != 0
    }

    #[inline]
    pub fn set_complete(&mut self, complete: bool) {
        if complete {
            self.port_complete |= SRC_COMPLETE_BIT;
        } else {
            self.port_complete &= !SRC_COMPLETE_BIT;
        }
    }

    /// IPv4 back as an `IpAddr` for the encode paths that still want one.
    #[inline]
    pub fn ip(&self) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(self.ipv4.to_le_bytes()))
    }
}

pub struct ServerState {
    pub clients: DashMap<UserHash, ClientHandle>,
    /// FileId slab (Stage 3): the single authoritative file store. Holds every
    /// file's hash, size, name, sources and last_seen in sharded packed Vecs
    /// indexed by FileId; `hash_to_id` resolves a hash to its id. This replaced
    /// the former `files: DashMap<FileHash, FileEntry>` — eliminating the
    /// duplicate copy of every file's metadata (the dual-store from Stages 1-2).
    pub file_slab: file_id::FileSlab,
    /// Name interner (Stage 2): dedups file-name strings across FileEntries.
    /// Identical names share one Arc<str> allocation; freed by a periodic sweep
    /// when no FileEntry references them any more.
    pub name_interner: name_interner::NameInterner,
    /// Reverse index: for each user, the set of file hashes for which that user
    /// is registered as a source. Required to keep `remove_sources_of` and the
    /// per-user file count fast (O(K) where K = files of this user) instead of
    /// O(N) where N = total indexed files. Without this, the offerfiles handler
    /// degenerated into ~63% of CPU at 250k+ files in the index (observed in
    /// production v0.9.35), because each newly-published file did an O(N) scan
    /// to count user files for the hard-limit check.
    pub user_files: DashMap<UserHash, std::collections::HashSet<file_id::FileId>>,
    pub keyword_index: KeywordIndex,
    pub smart_sources: SmartSourcesCache,
    pub filter: Arc<ContentFilter>,
    next_low_id: AtomicU32,
    pub total_sessions: AtomicU32,
    /// Live count of LowID clients (is_high_id == false). Kept in sync at
    /// login/logout so the UDP GLOBSERVSTATRES handler doesn't have to do an
    /// O(N) iter every time it answers a 0x96 probe.
    pub lowid_count_cached: AtomicU32,
    /// Known peer servers — populated via gossip on startup, served to clients
    pub server_list: RwLock<Vec<SocketAddrV4>>,
    /// Our latest outgoing random_part sent to each seed via OBF ping.
    /// The seed encrypts its responses (0xA1, 0x97) using this value as the
    /// ServerKey. We need it to decrypt those responses in the UDP handler.
    /// Keyed by seed IPv4 address, updated each time we send an OBF ping.
    pub our_sent_random_parts: DashMap<std::net::Ipv4Addr, u32>,
    /// Per-seed ServerKey for outbound obfuscated UDP. A seed tells us the
    /// key to use when talking to it via the ServerKey field of an obfuscated
    /// GLOBSERVSTATRES. Keyed by the seed's IPv4 address. Empty until the
    /// first obfuscated 0x97 arrives — gossip falls back to plain UDP until then.
    pub seed_server_keys: DashMap<std::net::Ipv4Addr, u32>,
    /// Latest challenge a Lugdunum peer sent us in its 0x96 probe. Lugdunum's
    /// 0x97 handler validates that the echoed challenge matches `entry+0x28`
    /// (the chal it stored when it sent its 0x96). For our obfuscated 0x97
    /// reply to be accepted (and our ServerKey extracted), we must echo the
    /// SAME chal seed sent in its most recent 0x96. handle_servstat fills
    /// this map; gossip Phase 3 reads from it.
    pub incoming_seed_challenges: DashMap<std::net::Ipv4Addr, u32>,
    /// Last external UDP port we observed a given client IP send from (i.e. the
    /// post-NAT source port of a real UDP packet to us, e.g. OP_GLOB_GETSOURCES).
    /// Used to improve LowID↔LowID hole punching: a client behind a NAT announces
    /// its *internal* UDP port at login, but the peer must punch the *external*
    /// (post-NAT) port. For cone-type NATs the external port a client uses toward
    /// us is the same one a peer must target, so substituting this observed port
    /// into OP_LOWID_HOLEPUNCH_INFO makes the punch work where the announced
    /// internal port would fail. Symmetric NATs use a different external port per
    /// destination, so this can't help them — we fall back to the announced port.
    /// Value carries the observation time so stale entries can be ignored.
    pub observed_udp_ports: DashMap<std::net::Ipv4Addr, (u16, Instant)>,
    /// Map of local UDP port → bound UdpSocket. Lets any handler send from a
    /// specific port (e.g. send an obfuscated reply from our :4675 even when
    /// the request came in on our :4665). Lugdunum's FUN_0042c480 looks up
    /// peer ServerKey by (sender_ip, sender_port), and rejects packets whose
    /// source port doesn't match either peer_TCP+12 (obfpingport) or
    /// peer_TCP+14 (portUDPobf). Replying from the wrong port = silent drop.
    pub udp_sockets: DashMap<u16, Arc<tokio::net::UdpSocket>>,
    /// IP filter — blocks connections from ranges in guarding.p2p.
    /// Reloaded in-place on SIGHUP without restart.
    pub ip_filter: tokio::sync::RwLock<crate::filter::ipfilter::IpFilter>,
    /// Country DB from ip-to-country.csv.
    pub country_db: tokio::sync::RwLock<crate::filter::geoip::CountryDb>,
    /// Per-country connection counter. key = ISO-2 code.
    pub country_stats: DashMap<String, u64>,
    /// Per-client-software counter. key = software name string.
    pub client_type_stats: DashMap<String, u64>,
    /// IPs that recently connected as clients, with timestamp of last seen.
    /// Retained for 30 minutes after disconnect to prevent mldonkey clients from
    /// appearing as peer servers via gossip (seeds propagate their registrations).
    pub recent_client_ips: DashMap<std::net::Ipv4Addr, std::time::Instant>,
    /// IPs that have proven they are real eD2k servers by replying to our 0x96
    /// ping with a 0x97 GLOBSERVSTATRES. Used in the periodic cleanup to remove
    /// entries that have been in server_list >10min without ever replying — those
    /// are almost certainly mldonkey/eMule CLIENTS that seeds wrongly propagated
    /// into their server lists.
    pub verified_servers: DashMap<std::net::Ipv4Addr, std::time::Instant>,
    /// Servers verified at a SPECIFIC ip:port (not just IP).
    ///
    /// `verified_servers` is keyed by IP alone, which is fine for "is this a real
    /// server, don't evict it" but WRONG as a gate for handing entries out: once an
    /// IP is verified, *every* port on that IP passes — so a bogus entry like
    /// 45.82.80.155:24996 (a phantom port for a real server, learned from a peer's
    /// list) was advertised to our clients as a genuine server, and aMule happily
    /// added it. There is exactly one server per ip:port, so the list we hand out
    /// must be gated on the pair.
    ///
    /// Filled from the 0x97 ping reply: we probe `tcp_port + 4` and the reply comes
    /// back from that UDP port, so the TCP port is `from.port() - 4` (the UDP =
    /// TCP+4 convention every eD2k client already assumes when it pings a server),
    /// and from a successful obfuscated handshake, where we know the seed's TCP port
    /// because we initiated to it.
    pub verified_sockets: DashMap<SocketAddrV4, std::time::Instant>,
    /// Live sum of every connection's Framed read+write buffer CAPACITY.
    ///
    /// These buffers are per-connection heap that /api/memsize could not see (they
    /// live inside each task's Framed, not in any registry), which is why the
    /// unaccounted remainder tracked the client count. Each connection adds its
    /// current capacity here and subtracts it on close, so the endpoint can report
    /// the real figure instead of us inferring it from a regression.
    pub framed_buffer_bytes: std::sync::atomic::AtomicI64,
    /// When each entry was first added to server_list (for the "give it 10
    /// minutes to verify" grace period).
    pub server_list_added_at: DashMap<std::net::Ipv4Addr, std::time::Instant>,
    /// Per-IP CSAM tracker: counts unique IPs that hit CSAM at least once.
    /// Used to compute "unique users blocked" stat — distinct from total file
    /// blocks (which can be many per user).
    pub csam_unique_ips: DashMap<std::net::Ipv4Addr, u64>,
    /// Distinct file hashes that have been blocked by the CSAM filter since
    /// startup. A client that republishes the same blocked file every
    /// keepalive cycle should not inflate the "blocked files" metric — we
    /// count each hash once. This is the metric the operator actually cares
    /// about: how many unique candidate files we kept out of the index.
    pub csam_blocked_hashes: DashMap<[u8; 16], ()>,
    /// Cache of (key, formula_id) that last successfully decoded an obfuscated
    /// UDP datagram from a given sender. formula_id: 0=Plain, 1=ObfA5, 2=Obf6B.
    /// Massively reduces CPU on the hot path: a busy peer that sends many obf
    /// packets only triggers ONE decode attempt per packet instead of 9.
    pub obf_decode_cache: DashMap<std::net::Ipv4Addr, (u32, u8)>,
    /// Hot-reloadable config snapshot. Updated by `POST /api/config`. Handlers
    /// that need live values (limits, server name/desc, version, this_ip, log)
    /// read `state.live_cfg.load()` instead of using a fixed Arc<Config>.
    /// Non-hot-reloadable fields (ports, seckey, admin port) are kept here too
    /// but changes to those require restart.
    pub live_cfg: arc_swap::ArcSwap<crate::config::Config>,
    /// Per-IP query-rate tracker. Records a sliding 60-second window of UDP
    /// search/sources requests from each client IP. Used by the bot detector.
    pub bot_query_log: DashMap<std::net::Ipv4Addr, BotTracker>,
    /// Aggregated bot detections, for display in the admin UI.
    pub bot_detections: DashMap<std::net::Ipv4Addr, BotDetection>,
    /// Temporarily-banned flood bots. Keyed by IP, value = ban start instant.
    /// Entries older than BOT_BAN_TTL are swept by the 60s cleanup task. We use
    /// a time-boxed in-memory ban (not the static ipfilter) because flood-bot
    /// IPs are dynamic — a permanent rule is pointless, but dropping the active
    /// IP for 24h kills the current flood, and a rotated IP is re-flagged and
    /// re-banned the same way.
    pub banned_bots: DashMap<std::net::Ipv4Addr, std::time::Instant>,
    /// CSAM publishers banned by USER_HASH (not IP). IP is dynamic for most
    /// clients (changes ~every few days), while user_hash only changes on eMule
    /// reinstall — a far more stable identifier. Value = ban start time. Checked
    /// at login; a banned user_hash is refused for publisher_blacklist_seconds.
    pub banned_publishers: DashMap<UserHash, std::time::Instant>,
    /// Per-user set of DISTINCT CSAM file hashes seen from that user_hash, kept
    /// across reconnects. We count UNIQUE files, not block events: republishing
    /// the SAME (possibly false-positive) file never advances the count beyond
    /// 1, so a user with a single rare FP can reconnect forever without ever
    /// being banned. Only N genuinely DIFFERENT blocked files reach the
    /// threshold. Value = (set of file hashes, last_seen for TTL sweep).
    pub csam_files_by_user:
        DashMap<UserHash, (std::collections::HashSet<FileHash>, std::time::Instant)>,
    /// Per-reason counter of blocked connection attempts.
    /// Keys: "ipfilter", "csam", "max_connections_per_ip", "rate_limit", "bot".
    pub block_stats: DashMap<String, u64>,
}

/// Sliding-window query tracker per client IP.
#[derive(Default)]
pub struct BotTracker {
    /// Timestamps of recent search/sources requests (last 60 seconds).
    pub query_times: std::sync::Mutex<std::collections::VecDeque<std::time::Instant>>,
}

/// Aggregated bot-detection record.
#[derive(Clone)]
pub struct BotDetection {
    pub first_seen: std::time::SystemTime,
    pub last_seen: std::time::SystemTime,
    pub query_count: u64,
    /// Rate of queries per minute (sliding 60-second average).
    pub queries_per_minute: f64,
    /// Standard deviation of inter-query intervals (in milliseconds).
    /// Bots often have very low stddev (regular intervals).
    pub interval_stddev_ms: f64,
    /// Country code if known.
    pub country: String,
    /// Why we flagged this IP as a bot.
    pub reason: String,
}

impl ServerState {
    /// How long a flagged flood bot stays banned (its UDP traffic dropped).
    pub const BOT_BAN_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

    /// Test-only constructor: a state with a minimal config and a working
    /// content filter, used by handler unit tests in other modules.
    #[cfg(test)]
    pub fn for_test() -> Self {
        let filter = std::sync::Arc::new(crate::filter::ContentFilter::new());
        let cfg = std::sync::Arc::new(crate::config::Config::minimal_test_config());
        Self::new(filter, cfg)
    }

    /// Test-only: register a connected client with a live (but drained) channel
    /// so send_frame() succeeds. `udp` = the client's announced UDP port (0 =
    /// none). Used by holepunch tests.
    #[cfg(test)]
    pub fn register_test_client(&self, user_hash: UserHash, id: u32, high_id: bool, udp: u16) {
        // send_frame is fire-and-forget (`let _ = tx.try_send`), so even though
        // we don't service the receiver here, the handler under test still
        // exercises the full lookup + build + send path without error. We keep
        // the receiver ALIVE (leak it) so that ClientHandle::is_alive() reports
        // true — otherwise the hole-punch staleness check would treat every test
        // client as a dead session and short-circuit to FAIL.
        let (tx, rx) = mpsc::channel(16);
        std::mem::forget(rx);
        let handle = ClientHandle {
            user_hash,
            assigned_id: id,
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, (id % 250) as u8 + 1)),
            port: 4662,
            udp_port: udp,
            natt_capable: udp != 0,
            nick: "test".into(),
            server_flags: 0,
            is_high_id: high_id,
            connected_at: std::time::Instant::now(),
            country: "??".into(),
            software: "test".into(),
            shared_files: 0,
            csam_attempts: 0,
            tx: Some(tx),
            last_activity_ms: std::sync::Arc::new(
                std::sync::atomic::AtomicU64::new(ClientHandle::now_ms()),
            ),
        };
        self.clients.insert(user_hash, handle);
    }

    /// Temporarily ban an IP (flood-bot). Idempotent: re-banning refreshes the
    /// 24h window. Cheap — one DashMap insert. Called from the bot detector.
    /// The `bot_ban` block_stats counter is bumped only on the not-banned →
    /// banned transition, so it reflects distinct ban events, not refreshes.
    pub fn ban_bot(&self, ip: std::net::Ipv4Addr) {
        let was_new = self
            .banned_bots
            .insert(ip, std::time::Instant::now())
            .is_none();
        if was_new {
            *self.block_stats.entry("bot_ban".to_string()).or_insert(0) += 1;
        }
    }

    /// True if `ip` is currently banned (within BOT_BAN_TTL). Called on the UDP
    /// hot path before any parsing, so it must stay a single cheap lookup.
    /// Expired entries are not removed here (the 60s cleanup task sweeps them);
    /// we just treat them as not-banned.
    pub fn is_bot_banned(&self, ip: &std::net::Ipv4Addr) -> bool {
        self.banned_bots
            .get(ip)
            .map(|since| since.elapsed() < Self::BOT_BAN_TTL)
            .unwrap_or(false)
    }

    /// Record a DISTINCT blocked CSAM file hash for a publisher's user_hash and
    /// return true if the number of distinct blocked files has EXCEEDED
    /// `threshold` (→ caller should ban). `threshold` is the MAX number of
    /// distinct blocked files TOLERATED before a ban (headroom for rare false
    /// positives): with threshold=3, files 1-3 are filtered but allowed, the
    /// ban fires on the 4th distinct blocked file. Counts UNIQUE file hashes, so:
    ///  - republishing the SAME file (e.g. a rare false positive) never advances
    ///    the count past 1 — a single-FP user can reconnect forever, never banned;
    ///  - only `threshold + 1` genuinely DIFFERENT blocked files trigger a ban.
    /// Persists across reconnects (keyed by user_hash). `ttl` bounds memory: a
    /// user idle longer than ttl is swept and starts fresh.
    pub fn record_csam_file_for_user(
        &self,
        user_hash: UserHash,
        file_hash: FileHash,
        threshold: u32,
        ttl: std::time::Duration,
    ) -> bool {
        let now = std::time::Instant::now();
        let mut entry = self
            .csam_files_by_user
            .entry(user_hash)
            .or_insert_with(|| (std::collections::HashSet::new(), now));
        // Restart if the user's record has gone stale (older than ttl).
        if now.duration_since(entry.1) > ttl {
            entry.0.clear();
        }
        entry.0.insert(file_hash);
        entry.1 = now;
        // Ban only once the count EXCEEDS the tolerated threshold (e.g. 4th
        // distinct file when threshold=3). Files at or below threshold are still
        // filtered — they just don't trigger a ban.
        entry.0.len() as u32 > threshold
    }

    /// Ban a CSAM publisher by user_hash. Idempotent; refreshes ban start time.
    pub fn ban_publisher(&self, user_hash: UserHash) {
        let was_new = self
            .banned_publishers
            .insert(user_hash, std::time::Instant::now())
            .is_none();
        if was_new {
            *self.block_stats.entry("publisher_ban".to_string()).or_insert(0) += 1;
        }
    }

    /// Like `ban_publisher`, but returns whether this call newly banned the user
    /// (true) versus refreshing an already-active ban (false). Callers use this
    /// to log the ban exactly once instead of once per blocked file in a batch.
    pub fn ban_publisher_is_new(&self, user_hash: UserHash) -> bool {
        let was_new = self
            .banned_publishers
            .insert(user_hash, std::time::Instant::now())
            .is_none();
        if was_new {
            *self.block_stats.entry("publisher_ban".to_string()).or_insert(0) += 1;
        }
        was_new
    }

    /// True if `user_hash` is a CSAM publisher banned within `ttl` (= configured
    /// publisher_blacklist_seconds). Checked at login to refuse the connection.
    pub fn is_publisher_banned(&self, user_hash: &UserHash, ttl: std::time::Duration) -> bool {
        self.banned_publishers
            .get(user_hash)
            .map(|since| since.elapsed() < ttl)
            .unwrap_or(false)
    }

    pub fn new(filter: Arc<ContentFilter>, cfg: Arc<crate::config::Config>) -> Self {
        Self {
            clients: DashMap::new(),
            user_files: DashMap::new(),
            file_slab: file_id::FileSlab::new(),
            name_interner: name_interner::NameInterner::new(),
            keyword_index: KeywordIndex::new(),
            smart_sources: SmartSourcesCache::new(),
            filter,
            next_low_id: AtomicU32::new(1),
            total_sessions: AtomicU32::new(0),
            lowid_count_cached: AtomicU32::new(0),
            server_list: RwLock::new(Vec::new()),
            seed_server_keys: DashMap::new(),
            incoming_seed_challenges: DashMap::new(),
            observed_udp_ports: DashMap::new(),
            our_sent_random_parts: DashMap::new(),
            udp_sockets: DashMap::new(),
            ip_filter: tokio::sync::RwLock::new(crate::filter::ipfilter::IpFilter::default()),
            country_db: tokio::sync::RwLock::new(crate::filter::geoip::CountryDb::default()),
            country_stats: DashMap::new(),
            client_type_stats: DashMap::new(),
            recent_client_ips: DashMap::new(),
            verified_servers: DashMap::new(),
            verified_sockets: DashMap::new(),
            framed_buffer_bytes: std::sync::atomic::AtomicI64::new(0),
            server_list_added_at: DashMap::new(),
            csam_unique_ips: DashMap::new(),
            csam_blocked_hashes: DashMap::new(),
            obf_decode_cache: DashMap::new(),
            live_cfg: arc_swap::ArcSwap::from(cfg),
            bot_query_log: DashMap::new(),
            bot_detections: DashMap::new(),
            banned_bots: DashMap::new(),
            banned_publishers: DashMap::new(),
            csam_files_by_user: DashMap::new(),
            block_stats: DashMap::new(),
        }
    }

    pub fn allocate_low_id(&self) -> u32 {
        let id = self.next_low_id.fetch_add(1, Ordering::Relaxed);
        if id >= 0x00FF_FFFF {
            self.next_low_id.store(1, Ordering::Relaxed);
            return 1;
        }
        id
    }

    pub fn client_count(&self) -> usize { self.clients.len() }
    pub fn file_count(&self)  -> usize { self.file_slab.live_count() }

    /// Count LowID clients (behind NAT, not reachable directly).
    pub fn lowid_count(&self) -> usize {
        self.lowid_count_cached.load(std::sync::atomic::Ordering::Relaxed) as usize
    }

    /// Create a (Sender, Receiver) pair and store the Sender in the ClientHandle.
    /// Returns the Receiver; the connection task owns it.
    pub fn create_client_channel(handle: &mut ClientHandle) -> mpsc::Receiver<Frame> {
        let (tx, rx) = mpsc::channel(CLIENT_CHANNEL_CAP);
        handle.tx = Some(tx);
        rx
    }

    pub fn add_file_with_source(
        &self,
        hash: FileHash,
        size: u64,
        name: String,
        source: (UserHash, IpAddr, u16, bool),
    ) {
        let publisher_hash = source.0;
        let src = Source::new(source.0, source.1, source.2, source.3);
        // Intern the name once: identical names across files share this Arc.
        let name_arc = self.name_interner.intern(&name);
        // The slab is now the single store. get_or_insert creates the record
        // (with this first source) if the hash is new; otherwise we add/refresh
        // the source on the existing record. Both take one shard lock.
        let (file_id, newly_added) =
            self.file_slab.get_or_insert(hash, size, name_arc.clone(), src);
        if !newly_added {
            self.file_slab.add_or_refresh_source(&hash, src);
        } else {
            self.keyword_index.add_file(file_id, &name_arc);
        }
        // Maintain reverse index user → set of FileIds this user sources.
        // HashSet semantics dedup re-publishes of the same file by the same user.
        self.user_files.entry(publisher_hash).or_default().insert(file_id);
    }

    /// Remove this user as a source from every file they published. If a file
    /// loses its last source, the file is removed from the global index too.
    ///
    /// Performance: O(K) where K is the number of files this user sourced —
    /// typically a few thousand. Before v0.9.36 this was O(N) over the entire
    /// file index (250k+ entries) which dominated CPU usage. The reverse
    /// index `user_files[user_hash]` makes lookup direct.
    pub fn remove_sources_of(&self, user_hash: &UserHash) {
        // Take the set of FileIds for this user — removes it from the
        // map so we don't keep stale entries for departed users.
        let file_ids: Vec<file_id::FileId> = match self.user_files.remove(user_hash) {
            Some((_, set)) => set.into_iter().collect(),
            None => return,
        };
        // (file_id, name) for files that lost their last source — to evict.
        let mut empty: Vec<(file_id::FileId, Arc<str>)> =
            Vec::with_capacity(file_ids.len() / 4);
        for fid in &file_ids {
            // Drop this user's source from the record (one shard lock). Returns
            // true when the file is now sourceless and should be evicted.
            if self.file_slab.remove_user_source(*fid, user_hash) {
                // Fetch the name (for the keyword removal) before tombstoning.
                if let Some(rec) = self.file_slab.get(*fid) {
                    empty.push((*fid, rec.name.clone()));
                }
            }
        }
        for (fid, name) in empty {
            self.keyword_index.remove_file(fid, &name);
            self.file_slab.tombstone(fid);
        }
    }

    /// Remove a set of file hashes from the `user_files` reverse index. The
    /// orphan-cleanup path deletes files directly from `files`/`keyword_index`
    /// without going through `remove_sources_of`, so without this the reverse
    /// index would retain FileHash entries for files that no longer exist —
    /// a slow memory leak (the reverse index never shrinks even as files are
    /// evicted). Drops any user entry that becomes empty afterwards.
    ///
    /// Cost: O(U) over the number of users (~hundreds), scanning each user's
    /// set. Called only from the 10-min orphan-cleanup, off the hot path — NOT
    /// suitable for per-request use.
    /// Diagnostic snapshot of every in-memory structure's element count, so we
    /// can see what actually holds RSS instead of guessing. Cheap-ish (a few
    /// full scans) — intended for the /api/memdebug endpoint, not the hot path.
    /// Benchmark/diagnostic helper (NOT for production): register a synthetic
    /// connected client so the loadgen example can model the memory of ~54k live
    /// `ClientHandle`s — the nick/country/software strings, the push channel, and
    /// the activity atomic — on top of the file index. The receiver is dropped;
    /// the retained `tx` keeps the channel's shared state allocated, so the
    /// per-client heap footprint matches a real connection closely enough.
    #[doc(hidden)]
    pub fn register_synthetic_client(
        &self,
        user_hash: UserHash,
        id: u32,
        ip: IpAddr,
        nick: String,
        country: String,
        software: String,
        udp_port: u16,
    ) {
        let (tx, _rx) = mpsc::channel::<Frame>(16);
        let handle = ClientHandle {
            user_hash,
            assigned_id: id,
            ip,
            port: 4662,
            udp_port,
            natt_capable: udp_port != 0,
            nick,
            server_flags: 0,
            is_high_id: false,
            connected_at: std::time::Instant::now(),
            country,
            software,
            shared_files: 0,
            csam_attempts: 0,
            tx: Some(tx),
            last_activity_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        self.clients.insert(user_hash, handle);
    }

    pub fn memory_report(&self) -> Vec<(String, u64)> {
        // Sum of all source vectors across files (the real per-source cost).
        let mut total_sources: u64 = 0;
        let mut max_sources: u64 = 0;
        let mut name_bytes: u64 = 0;
        for e in self.file_slab.iter_records_for_report() {
            let n = e.0 as u64;
            total_sources += n;
            if n > max_sources { max_sources = n; }
            name_bytes += e.1 as u64;
        }
        // Sum of all user_files set sizes (reverse-index real size).
        let mut uf_entries: u64 = 0;
        for e in self.user_files.iter() {
            uf_entries += e.value().len() as u64;
        }
        // Sum of all keyword posting-set sizes (the real index cost).
        let (kw_keys, kw_postings) = self.keyword_index.posting_stats();
        vec![
            ("files".into(), self.file_slab.live_count() as u64),
            // Total slab slots including tombstones. slab_slots - files = number
            // of tombstoned (removed, never-reclaimed) records still occupying
            // ~60-80 B each. Grows with TOTAL files ever published, not live —
            // the key long-uptime accumulation metric.
            ("slab_slots".into(), self.file_slab.slot_count() as u64),
            // Dead slots quarantined for reuse. slab_slots − files − slab_free
            // ≈ slots freed within the last quarantine window (not yet reusable).
            ("slab_free".into(), self.file_slab.free_pending_count() as u64),
            ("files_name_bytes".into(), name_bytes),
            ("files_sources_total".into(), total_sources),
            ("files_sources_max".into(), max_sources),
            ("clients".into(), self.clients.len() as u64),
            ("user_files_users".into(), self.user_files.len() as u64),
            ("user_files_entries_total".into(), uf_entries),
            ("keyword_keys".into(), kw_keys),
            ("keyword_postings_total".into(), kw_postings),
            ("obf_decode_cache".into(), self.obf_decode_cache.len() as u64),
            ("incoming_seed_challenges".into(), self.incoming_seed_challenges.len() as u64),
            ("banned_bots".into(), self.banned_bots.len() as u64),
            ("banned_publishers".into(), self.banned_publishers.len() as u64),
            ("csam_files_by_user".into(), self.csam_files_by_user.len() as u64),
            ("csam_blocked_hashes".into(), self.csam_blocked_hashes.len() as u64),
            ("csam_unique_ips".into(), self.csam_unique_ips.len() as u64),
            ("server_list".into(),
                self.server_list.try_read().map(|g| g.len() as u64).unwrap_or(0)),
            ("verified_servers".into(), self.verified_servers.len() as u64),
            ("recent_client_ips".into(), self.recent_client_ips.len() as u64),
            ("bot_query_log".into(), self.bot_query_log.len() as u64),
            ("bot_detections".into(), self.bot_detections.len() as u64),
        ]
    }

    /// Byte-level memory breakdown by CAPACITY (not length), for /api/memsize.
    ///
    /// Reports `capacity * element_size` for every container the server holds, so
    /// `capacity - live` is the peak-plateau slack (Vec/HashMap/HashSet/DashMap
    /// never shrink their backing store on removal; a struct sized to the daily
    /// high-water mark keeps that memory even when the live count drops).
    ///
    /// DashMap overhead note: a DashMap is N_SHARDS separate hashbrown tables, each
    /// behind an RwLock. `capacity()` sums the shards' capacities, so slot counts
    /// below already account for the sharding; the per-slot cost is
    /// (key + value + 1 control byte), hashbrown's layout.
    ///
    /// Will not sum exactly to jemalloc `allocated` (size-class rounding, Arc/Box
    /// control blocks, tokio buffers and thread caches live outside), but the
    /// remainder is reported as `unaccounted_bytes` by the endpoint.
    pub fn memsize_report(&self) -> Vec<(String, u64)> {
        use std::mem::size_of;

        // Cost of one DashMap slot: key + value + hashbrown's 1 control byte.
        fn dm_slots(cap: usize, key: usize, val: usize) -> u64 {
            (cap * (key + val + 1)) as u64
        }
        const IPV4: usize = 4;
        const UHASH: usize = 16;
        const INSTANT: usize = 16;

        // ── file index ────────────────────────────────────────────────────────
        let (slab_records, slab_next, slab_buckets, slab_spilled_src) =
            self.file_slab.size_report();
        let (kw_data, kw_headers, kw_slots) = self.keyword_index.size_report();

        // user_files: DashMap<UserHash, HashSet<FileId>> — outer map slots PLUS
        // each per-user HashSet's own hashbrown table.
        let id_sz = size_of::<file_id::FileId>();
        let mut uf_sets_bytes = 0u64;
        for e in self.user_files.iter() {
            uf_sets_bytes += e.value().capacity() as u64 * (id_sz as u64 + 1);
        }
        let uf_map_slots = dm_slots(
            self.user_files.capacity(),
            UHASH,
            size_of::<std::collections::HashSet<file_id::FileId>>(),
        );

        // names: interned bytes + one Arc control block per unique name + map slots
        let mut name_bytes = 0u64;
        for (_src_len, name_len) in self.file_slab.iter_records_for_report() {
            name_bytes += name_len as u64;
        }
        let name_arc_ctrl = self.name_interner.len() as u64 * 16;
        let name_map_slots =
            self.name_interner.capacity() as u64 * (size_of::<Arc<str>>() as u64 + 1);

        // ── clients ───────────────────────────────────────────────────────────
        // ClientHandle carries three Strings (nick/country/software) whose heap
        // buffers live outside the struct, plus an Arc<AtomicU64> and an mpsc Sender.
        let mut client_strings = 0u64;
        for e in self.clients.iter() {
            let c = e.value();
            client_strings +=
                (c.nick.capacity() + c.country.capacity() + c.software.capacity()) as u64;
        }
        let clients_slots = dm_slots(
            self.clients.capacity(),
            UHASH,
            size_of::<ClientHandle>(),
        );

        // ── filters (loaded once, large) ──────────────────────────────────────
        let ipfilter_bytes = self
            .ip_filter
            .try_read()
            .map(|f| f.size_bytes())
            .unwrap_or(0);
        let geoip_bytes = self
            .country_db
            .try_read()
            .map(|d| d.size_bytes())
            .unwrap_or(0);
        let content_filter_bytes = self.filter.size_bytes();

        // ── caches & bookkeeping maps ─────────────────────────────────────────
        let smart_sources_bytes = self.smart_sources.size_bytes();

        let server_list_bytes = {
            let l = self.server_list.try_read();
            match l {
                Ok(v) => (v.capacity() * size_of::<SocketAddrV4>()) as u64,
                Err(_) => 0,
            }
        };

        let mut misc = 0u64;
        misc += dm_slots(self.our_sent_random_parts.capacity(), IPV4, 4);
        misc += dm_slots(self.seed_server_keys.capacity(), IPV4, 4);
        misc += dm_slots(self.incoming_seed_challenges.capacity(), IPV4, 4);
        misc += dm_slots(self.observed_udp_ports.capacity(), IPV4, 2 + INSTANT);
        misc += dm_slots(self.recent_client_ips.capacity(), IPV4, INSTANT);
        misc += dm_slots(self.verified_servers.capacity(), IPV4, INSTANT);
        misc += dm_slots(self.server_list_added_at.capacity(), IPV4, INSTANT);
        misc += dm_slots(self.csam_unique_ips.capacity(), IPV4, 8);
        misc += dm_slots(self.csam_blocked_hashes.capacity(), UHASH, 0);
        misc += dm_slots(self.obf_decode_cache.capacity(), IPV4, 5);
        misc += dm_slots(self.banned_bots.capacity(), IPV4, INSTANT);
        misc += dm_slots(self.banned_publishers.capacity(), UHASH, INSTANT);
        misc += dm_slots(self.bot_query_log.capacity(), IPV4, size_of::<BotTracker>());
        misc += dm_slots(self.bot_detections.capacity(), IPV4, size_of::<BotDetection>());
        misc += dm_slots(self.udp_sockets.capacity(), 2, size_of::<Arc<tokio::net::UdpSocket>>());

        // ── totals ────────────────────────────────────────────────────────────
        let slab_total = slab_records + slab_next + slab_buckets + slab_spilled_src;
        let kw_total = kw_data + kw_headers + kw_slots;
        let names_total = name_bytes + name_arc_ctrl + name_map_slots;
        let uf_total = uf_sets_bytes + uf_map_slots;
        // Real per-connection codec buffers, reported by the connections themselves.
        let framed_bufs = self
            .framed_buffer_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
            .max(0) as u64;
        let clients_total = clients_slots + client_strings + framed_bufs;
        let filters_total = ipfilter_bytes + geoip_bytes + content_filter_bytes;
        let other_total = smart_sources_bytes + server_list_bytes + misc;

        vec![
            // file slab
            ("slab_records_cap".into(), slab_records),
            ("slab_next+buckets_cap".into(), slab_next + slab_buckets),
            ("slab_sources_spilled".into(), slab_spilled_src),
            ("slab_TOTAL".into(), slab_total),
            // keyword index
            ("keyword_posting_data_cap".into(), kw_data),
            ("keyword_vec_headers".into(), kw_headers),
            ("keyword_table_slots_cap".into(), kw_slots),
            ("keyword_TOTAL".into(), kw_total),
            // names
            ("names_bytes".into(), name_bytes),
            ("names_arc_ctrl".into(), name_arc_ctrl),
            ("names_map_slots_cap".into(), name_map_slots),
            ("names_TOTAL".into(), names_total),
            // reverse index
            ("user_files_sets_cap".into(), uf_sets_bytes),
            ("user_files_map_slots_cap".into(), uf_map_slots),
            ("user_files_TOTAL".into(), uf_total),
            // clients
            ("clients_map_slots_cap".into(), clients_slots),
            ("clients_strings".into(), client_strings),
            ("clients_framed_buffers".into(), framed_bufs),
            ("clients_TOTAL".into(), clients_total),
            // filters (static, loaded at startup)
            ("filter_ipfilter".into(), ipfilter_bytes),
            ("filter_geoip".into(), geoip_bytes),
            ("filter_content".into(), content_filter_bytes),
            ("filters_TOTAL".into(), filters_total),
            // caches / bookkeeping
            ("smart_sources_cache".into(), smart_sources_bytes),
            ("server_list".into(), server_list_bytes),
            ("misc_maps".into(), misc),
            ("other_TOTAL".into(), other_total),
            // grand total
            (
                "GRAND_TOTAL_tracked".into(),
                slab_total + kw_total + names_total + uf_total
                    + clients_total + filters_total + other_total,
            ),
        ]
    }

    /// Remove a set of file hashes from the `user_files` reverse index. The
    /// orphan-cleanup path deletes files directly from `files`/`keyword_index`
    /// without going through `remove_sources_of`, so without this the reverse
    /// index would retain FileHash entries for files that no longer exist —
    /// a slow memory leak (the reverse index never shrinks even as files are
    /// evicted). Drops any user entry that becomes empty afterwards.
    ///
    /// Cost: O(U) over the number of users (~hundreds), scanning each user's
    /// set. Called only from the 10-min orphan-cleanup, off the hot path — NOT
    /// suitable for per-request use.
    /// Remove the given FileIds from the `user_files` reverse index.
    ///
    /// Callers (orphan cleanup) hold the FileIds directly. We purge by id
    /// rather than by hash on purpose: by the time cleanup runs, the records
    /// have already been tombstoned, so `id_of(hash)` would resolve to None and
    /// purge nothing — leaving dead ids in `user_files` forever (an RSS leak).
    /// FileId values stay valid after tombstone, so this works regardless.
    pub fn purge_ids_from_user_files(&self, ids: &[file_id::FileId]) {
        if ids.is_empty() {
            return;
        }
        let set: std::collections::HashSet<file_id::FileId> = ids.iter().copied().collect();
        let mut empty_users: Vec<UserHash> = Vec::new();
        for mut entry in self.user_files.iter_mut() {
            let before = entry.value().len();
            if before == 0 {
                empty_users.push(*entry.key());
                continue;
            }
            entry.value_mut().retain(|id| !set.contains(id));
            if entry.value().is_empty() {
                empty_users.push(*entry.key());
            } else if entry.value().len() != before {
                entry.value_mut().shrink_to_fit();
            }
        }
        for u in empty_users {
            // Only remove if still empty (a concurrent re-publish may have
            // re-added an id between the scan and here).
            self.user_files.remove_if(&u, |_, set| set.is_empty());
        }
    }
}

#[cfg(test)]
mod callback_tests {
    use super::*;
    use crate::proto::Frame;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    fn mk_client(id: u32, high: bool) -> ClientHandle {
        ClientHandle {
            user_hash: [id as u8; 16],
            assigned_id: id,
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, id as u8)),
            port: 4662,
            udp_port: 0,
            natt_capable: false,
            nick: format!("client{id}"),
            server_flags: 0,
            is_high_id: high,
            connected_at: Instant::now(),
            country: "??".to_string(),
            software: "test".to_string(),
            shared_files: 0,
            csam_attempts: 0,
            tx: None,
            last_activity_ms: std::sync::Arc::new(
                std::sync::atomic::AtomicU64::new(ClientHandle::now_ms()),
            ),
        }
    }

    #[test]
    fn callback_channel_delivers_frame_to_target() {
        // Two clients: HighID(2) wants the server to call back LowID(1).
        // After create_client_channel, the target's tx is wired up and
        // send_frame delivers a frame the connection task can pull from rx.
        let mut lowid = mk_client(1, false);
        let mut rx = ServerState::create_client_channel(&mut lowid);

        // The HighID client's CALLBACK handler does this:
        let callback_frame = Frame::new(0x35, vec![0xAA, 0xBB, 0xCC, 0xDD, 0x12, 0x34]);
        lowid.send_frame(callback_frame.clone());

        // The connection task for the LowID client would read from rx and
        // forward to the wire. Here we just check the channel actually got it.
        let received = rx.try_recv().expect("LowID's rx should receive the callback frame");
        assert_eq!(received.opcode, 0x35);
        assert_eq!(received.payload, vec![0xAA, 0xBB, 0xCC, 0xDD, 0x12, 0x34]);
    }

    #[test]
    fn callback_silently_drops_when_no_channel() {
        // A handle without a channel (tx == None) must not panic when
        // someone tries to push a frame at it — it just drops silently.
        let handle = mk_client(5, true);
        assert!(handle.tx.is_none());
        handle.send_frame(Frame::new(0x42, vec![1, 2, 3]));
        // No panic = success.
    }
}

#[cfg(test)]
mod user_files_index_tests {
    //! Regression tests for the v0.9.36 reverse-index fix that took
    //! `remove_sources_of` and `layer_count` from O(N=total files) to O(K=files
    //! of this user). At 250k+ indexed files the old O(N) variants dominated
    //! CPU usage (62%+ of one core observed in production profiling).

    use super::*;
    use crate::filter::ContentFilter;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn build_state() -> Arc<ServerState> {
        let filter = Arc::new(ContentFilter::new());
        let cfg = Arc::new(crate::config::Config::minimal_test_config());
        Arc::new(ServerState::new(filter, cfg))
    }

    fn fhash(n: u8) -> FileHash { [n; 16] }
    fn uhash(n: u8) -> UserHash { [n; 16] }

    #[test]
    fn publisher_ban_triggers_above_threshold_not_at() {
        use std::time::Duration;
        let s = build_state();
        let u = uhash(1);
        let ttl = Duration::from_secs(3600);
        // threshold = 3 = MAX tolerated distinct files. Files 1-3 are filtered
        // but must NOT ban (headroom for false positives).
        assert!(!s.record_csam_file_for_user(u, fhash(10), 3, ttl), "1st file");
        assert!(!s.record_csam_file_for_user(u, fhash(11), 3, ttl), "2nd file");
        assert!(!s.record_csam_file_for_user(u, fhash(12), 3, ttl), "3rd file (at threshold)");
        assert!(!s.is_publisher_banned(&u, ttl), "not banned at threshold");
        // The 4th DISTINCT file EXCEEDS the threshold → ban.
        assert!(s.record_csam_file_for_user(u, fhash(13), 3, ttl), "4th distinct file");
        s.ban_publisher(u);
        assert!(s.is_publisher_banned(&u, ttl), "banned above threshold");
    }

    #[test]
    fn repeated_same_file_never_bans() {
        // THE false-positive safety property: a user who keeps republishing the
        // SAME (possibly false-positive) blocked file must NEVER be banned, no
        // matter how many times — because we count DISTINCT file hashes, not
        // block events. This is what protects an innocent user with one rare FP
        // across unlimited reconnects.
        use std::time::Duration;
        let s = build_state();
        let u = uhash(7);
        let ttl = Duration::from_secs(3600);
        let fp_file = fhash(99);
        for _ in 0..50 {
            assert!(
                !s.record_csam_file_for_user(u, fp_file, 3, ttl),
                "republishing the same file must never reach the threshold"
            );
        }
        assert!(!s.is_publisher_banned(&u, ttl), "single distinct file = never banned");
    }

    #[test]
    fn publisher_ban_expires_after_ttl() {
        use std::time::Duration;
        let s = build_state();
        let u = uhash(3);
        s.ban_publisher(u);
        // Zero TTL → already expired; long TTL → active.
        assert!(!s.is_publisher_banned(&u, Duration::from_secs(0)));
        assert!(s.is_publisher_banned(&u, Duration::from_secs(3600)));
    }

    #[test]
    fn user_files_populated_on_add() {
        let s = build_state();
        let u1 = uhash(1);
        let src = (u1, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4662u16, true);
        s.add_file_with_source(fhash(10), 100, "f1.bin".into(), src);
        s.add_file_with_source(fhash(11), 200, "f2.bin".into(), src);
        let count = s.user_files.get(&u1).map(|e| e.len()).unwrap_or(0);
        assert_eq!(count, 2, "user_files should reflect both files");
    }

    #[test]
    fn user_files_dedups_republished_hash() {
        let s = build_state();
        let u1 = uhash(1);
        let src = (u1, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4662u16, true);
        // Same hash published 3 times — common pattern when a client re-OFFERFILES.
        for _ in 0..3 {
            s.add_file_with_source(fhash(10), 100, "f1.bin".into(), src);
        }
        let count = s.user_files.get(&u1).map(|e| e.len()).unwrap_or(0);
        assert_eq!(count, 1, "republishing the same hash must not inflate the user index");
    }

    #[test]
    fn user_files_cleared_on_remove_sources_of() {
        let s = build_state();
        let u1 = uhash(1);
        let src = (u1, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4662u16, true);
        s.add_file_with_source(fhash(10), 100, "f1.bin".into(), src);
        s.add_file_with_source(fhash(11), 200, "f2.bin".into(), src);
        s.remove_sources_of(&u1);
        assert!(s.user_files.get(&u1).is_none(),
                "user_files entry must be deleted when user logs out");
        assert_eq!(s.file_slab.live_count(), 0,
                "files with no remaining sources must be removed from the global index");
    }

    #[test]
    fn purge_clears_reverse_index_on_orphan_eviction() {
        // Simulates the orphan-cleanup path: files removed directly, then the
        // reverse index purged. Without purge, user_files would retain the
        // dead hashes (the leak this fixes).
        let s = build_state();
        let u1 = uhash(1);
        let src = (u1, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4662u16, true);
        s.add_file_with_source(fhash(10), 100, "f1.bin".into(), src);
        s.add_file_with_source(fhash(11), 200, "f2.bin".into(), src);
        // user has 2 hashes in the reverse index
        assert_eq!(s.user_files.get(&u1).map(|e| e.len()).unwrap_or(0), 2);
        // Capture the FileIds BEFORE tombstoning (production holds them too).
        let id10 = s.file_slab.id_of(&fhash(10)).unwrap();
        let id11 = s.file_slab.id_of(&fhash(11)).unwrap();
        // Orphan-cleanup removes the files directly (bypassing remove_sources_of)
        s.file_slab.tombstone_by_hash(&fhash(10));
        s.file_slab.tombstone_by_hash(&fhash(11));
        // Now purge the evicted ids from the reverse index
        s.purge_ids_from_user_files(&[id10, id11]);
        assert!(s.user_files.get(&u1).is_none(),
                "user_files must not retain hashes for orphan-evicted files");
    }

    #[test]
    fn purge_keeps_unrelated_hashes() {
        let s = build_state();
        let u1 = uhash(1);
        let src = (u1, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4662u16, true);
        s.add_file_with_source(fhash(10), 100, "f1.bin".into(), src);
        s.add_file_with_source(fhash(11), 200, "f2.bin".into(), src);
        // Only one hash evicted — the other must survive in the reverse index.
        let id10 = s.file_slab.id_of(&fhash(10)).unwrap();
        s.file_slab.tombstone_by_hash(&fhash(10));
        s.purge_ids_from_user_files(&[id10]);
        let remaining = s.user_files.get(&u1).map(|e| e.len()).unwrap_or(0);
        assert_eq!(remaining, 1, "unrelated hash must remain in reverse index");
    }

    #[test]
    fn shared_file_keeps_alive_after_one_user_leaves() {
        let s = build_state();
        let (u1, u2) = (uhash(1), uhash(2));
        let src1 = (u1, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4662u16, true);
        let src2 = (u2, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 4662u16, true);
        s.add_file_with_source(fhash(20), 500, "shared.bin".into(), src1);
        s.add_file_with_source(fhash(20), 500, "shared.bin".into(), src2);
        assert_eq!(s.file_slab.live_count(), 1);
        s.remove_sources_of(&u1);
        assert_eq!(s.file_slab.live_count(), 1, "file must remain — u2 still sources it");
        let remaining_count = s.user_files.get(&u2).map(|e| e.len()).unwrap_or(0);
        assert_eq!(remaining_count, 1, "u2's user_files entry must still list the file");
    }

    #[test]
    fn remove_sources_of_unknown_user_is_safe() {
        let s = build_state();
        // Removing a user that never published anything must not panic.
        s.remove_sources_of(&uhash(99));
    }
}
