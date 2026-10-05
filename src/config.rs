//! Configuration loader (TOML).
//!
//! See SPEC.md §5 for full semantics. This MVP build supports the subset
//! used by the test stand: server identity, network, limits, content_filter,
//! welcome.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub network: NetworkConfig,
    pub limits: LimitsConfig,
    pub content_filter: ContentFilterConfig,
    #[serde(default)]
    pub welcome: WelcomeConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub updates: UpdatesConfig,
    #[serde(default)]
    pub admission: AdmissionConfig,
}

/// Server-wide work admission (issue #25). Restart-only. No value accepts 0
/// as "unlimited": a zero ceiling is refused at startup.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct AdmissionConfig {
    /// Accepted TCP sockets at once, logged in or not. Checked at accept,
    /// before a task is spawned. Absent = limits.max_clients + 10% +
    /// max_pending_logins (200 000 when max_clients is 0). Keep it below the
    /// process file-descriptor limit.
    #[serde(default)]
    pub max_open_tcp_connections: Option<u32>,
    /// Accepted sockets that have not completed a login (obfuscation
    /// handshake, LOGINREQUEST, HighID probe).
    #[serde(default = "default_adm_pending")]
    pub max_pending_logins: u32,
    /// The same, per source (IPv4 address, IPv6 prefix): one source cannot
    /// hold the whole pending pool. Loopback exempt.
    #[serde(default = "default_adm_pending_per_source")]
    pub max_pending_logins_per_source: u32,
    /// Outbound HighID probes at once, initial and background together. A
    /// login that finds none free is given LowID. Absent = 64 more than
    /// max_pending_logins, so logins (bounded by max_pending_logins) always
    /// find one beside the background checks (at most 64).
    #[serde(default)]
    pub max_probe_jobs: Option<u32>,
    /// Detached hole-punch retry tasks at once.
    #[serde(default = "default_adm_retries")]
    pub max_retry_tasks: u32,
    /// Per-session allowance for callback and hole-punch requests (each makes
    /// the server push a frame to another client): sustained rate and burst.
    #[serde(default = "default_adm_relay_rate")]
    pub session_relay_per_second: u32,
    #[serde(default = "default_adm_relay_burst")]
    pub session_relay_burst: u32,
    /// Searches running at once, off the async runtime.
    #[serde(default = "default_adm_search_jobs")]
    pub max_search_jobs: u32,
    /// TCP searches allowed to wait for a search job; beyond it the search
    /// gets an empty result at once. UDP searches never wait.
    #[serde(default = "default_adm_search_queue")]
    pub max_queued_tcp_searches: u32,
    /// How long a queued TCP search waits before it gets an empty result.
    #[serde(default = "default_adm_search_wait")]
    pub tcp_search_wait_ms: u64,
    /// UDP searches allowed to wait for a search job — from a task, never in
    /// the receive loop — and for how long. Small and separate from the TCP
    /// queue, so UDP cannot crowd out established sessions.
    #[serde(default = "default_adm_udp_search_queue")]
    pub max_queued_udp_searches: u32,
    #[serde(default = "default_adm_udp_search_wait")]
    pub udp_search_wait_ms: u64,
    /// Per-source UDP budgets tracked at once. A new source beyond it is
    /// refused rather than letting the table grow.
    #[serde(default = "default_adm_rate_entries")]
    pub max_rate_state_entries: u32,
    /// IPv6 sources sharing this prefix share one budget (TCP per-IP limit
    /// and UDP). IPv4 is always per address.
    #[serde(default = "default_adm_v6_bits")]
    pub ipv6_source_prefix_bits: u8,
    /// Server-wide UDP budget, in credits (a status query costs 1).
    #[serde(default = "default_adm_udp_global_rate")]
    pub udp_global_credits_per_second: u32,
    #[serde(default = "default_adm_udp_global_burst")]
    pub udp_global_burst_credits: u32,
    /// Per-source UDP budget, in the same credits.
    #[serde(default = "default_adm_udp_source_rate")]
    pub udp_source_credits_per_second: u32,
    #[serde(default = "default_adm_udp_source_burst")]
    pub udp_source_burst_credits: u32,
    /// false (default): UDP budgets are measured and over-budget packets are
    /// COUNTED but still served — to choose values from live traffic first.
    /// true: over-budget packets are dropped.
    #[serde(default)]
    pub udp_rate_enforce: bool,
    /// /api/ready reports not-ready once a critical pool (open sockets,
    /// pending logins, search jobs) has stayed full this long.
    #[serde(default = "default_adm_ready_window")]
    pub readiness_window_secs: u64,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            max_open_tcp_connections: None,
            max_pending_logins: default_adm_pending(),
            max_pending_logins_per_source: default_adm_pending_per_source(),
            max_probe_jobs: None,
            max_retry_tasks: default_adm_retries(),
            session_relay_per_second: default_adm_relay_rate(),
            session_relay_burst: default_adm_relay_burst(),
            max_search_jobs: default_adm_search_jobs(),
            max_queued_tcp_searches: default_adm_search_queue(),
            tcp_search_wait_ms: default_adm_search_wait(),
            max_queued_udp_searches: default_adm_udp_search_queue(),
            udp_search_wait_ms: default_adm_udp_search_wait(),
            max_rate_state_entries: default_adm_rate_entries(),
            ipv6_source_prefix_bits: default_adm_v6_bits(),
            udp_global_credits_per_second: default_adm_udp_global_rate(),
            udp_global_burst_credits: default_adm_udp_global_burst(),
            udp_source_credits_per_second: default_adm_udp_source_rate(),
            udp_source_burst_credits: default_adm_udp_source_burst(),
            udp_rate_enforce: false,
            readiness_window_secs: default_adm_ready_window(),
        }
    }
}

impl AdmissionConfig {
    /// `max_open_tcp_connections`, or its default derived from the limits.
    pub fn effective_open_tcp(&self, cfg: &Config) -> u32 {
        self.max_open_tcp_connections.unwrap_or_else(|| {
            let mc = cfg.limits.max_clients;
            if mc == 0 {
                200_000
            } else {
                mc.saturating_add(mc / 10)
                    .saturating_add(self.max_pending_logins)
            }
        })
    }

    /// `max_probe_jobs`, or its default.
    pub fn effective_probes(&self) -> u32 {
        self.max_probe_jobs
            .unwrap_or_else(|| self.max_pending_logins.saturating_add(64))
    }

    fn validate(&self) -> Result<()> {
        let nonzero: [(&str, u64); 18] = [
            (
                "max_pending_logins_per_source",
                self.max_pending_logins_per_source as u64,
            ),
            (
                "max_queued_udp_searches",
                self.max_queued_udp_searches as u64,
            ),
            ("udp_search_wait_ms", self.udp_search_wait_ms),
            (
                "max_probe_jobs",
                self.max_probe_jobs.map_or(1, |v| v as u64),
            ),
            ("readiness_window_secs", self.readiness_window_secs),
            ("max_pending_logins", self.max_pending_logins as u64),
            ("max_retry_tasks", self.max_retry_tasks as u64),
            (
                "session_relay_per_second",
                self.session_relay_per_second as u64,
            ),
            ("session_relay_burst", self.session_relay_burst as u64),
            ("max_search_jobs", self.max_search_jobs as u64),
            (
                "max_queued_tcp_searches",
                self.max_queued_tcp_searches as u64,
            ),
            ("tcp_search_wait_ms", self.tcp_search_wait_ms),
            ("max_rate_state_entries", self.max_rate_state_entries as u64),
            (
                "udp_global_credits_per_second",
                self.udp_global_credits_per_second as u64,
            ),
            (
                "udp_global_burst_credits",
                self.udp_global_burst_credits as u64,
            ),
            (
                "udp_source_credits_per_second",
                self.udp_source_credits_per_second as u64,
            ),
            (
                "udp_source_burst_credits",
                self.udp_source_burst_credits as u64,
            ),
            (
                "max_open_tcp_connections",
                self.max_open_tcp_connections.map_or(1, |v| v as u64),
            ),
        ];
        for (name, v) in nonzero {
            if v == 0 {
                bail!("admission.{name} must be at least 1: there is no \"unlimited\" for a safety limit");
            }
        }
        if !(16..=128).contains(&self.ipv6_source_prefix_bits) {
            bail!(
                "admission.ipv6_source_prefix_bits = {} must be between 16 and 128",
                self.ipv6_source_prefix_bits
            );
        }
        Ok(())
    }
}

// [admission] defaults are sized for the load the server is designed for —
// 50 000 clients (about 45 000 of them LowID) and 30 000 000 files — and for
// its worst moment: a restart, after which every client reconnects at once.
// A ceiling that is too high costs memory only while it is used; one that is
// too low refuses real users, so every value leans high.
//
// The login storm, measured on a live server: a restart with 9 000 clients
// overflowed 4 096 pending logins (1 157 refused), i.e. it peaked above 0.45
// pending per client. A pending login lives through the obfuscation
// handshake, the login and the HighID probe, which for a LowID client — whose
// port does not answer — lasts the whole login_timeout_ms. At 50 000 clients
// that ratio is ~23 000 at once; 32 768 leaves a margin. Every pending login
// may run one probe, so the probe pool (pending + 64) matches it.
fn default_adm_ready_window() -> u64 {
    30
}
fn default_adm_pending() -> u32 {
    32_768
}
fn default_adm_pending_per_source() -> u32 {
    32
}
fn default_adm_udp_search_queue() -> u32 {
    128
}
fn default_adm_udp_search_wait() -> u64 {
    500
}
fn default_adm_retries() -> u32 {
    1024
}
fn default_adm_relay_rate() -> u32 {
    10
}
fn default_adm_relay_burst() -> u32 {
    200
}
fn default_adm_search_jobs() -> u32 {
    8
}
fn default_adm_search_queue() -> u32 {
    512
}
fn default_adm_search_wait() -> u64 {
    2000
}
fn default_adm_rate_entries() -> u32 {
    524_288
}
fn default_adm_v6_bits() -> u8 {
    64
}
fn default_adm_udp_global_rate() -> u32 {
    200_000
}
fn default_adm_udp_global_burst() -> u32 {
    400_000
}
fn default_adm_udp_source_rate() -> u32 {
    60
}
fn default_adm_udp_source_burst() -> u32 {
    1000
}

/// Update service for the filter data files.
///
/// The whole section is optional and disabled by default: a server that does not
/// want to pull anything should not have to say so.
#[derive(Debug, Deserialize, Clone)]
pub struct UpdatesConfig {
    /// Master switch. Off means the buttons in the admin UI report that updates
    /// are disabled and nothing is ever fetched.
    #[serde(default)]
    pub enabled: bool,

    /// Where downloaded files are installed. This is the directory the running
    /// server already reads its lists from, so an update lands where the mtime
    /// watchers are looking.
    #[serde(default = "default_dest_dir")]
    pub dest_dir: String,

    /// Ed25519 public key, 32 bytes as hex, that data files must be signed with.
    ///
    /// This is the single most important line in the section. It is what stops a
    /// hijacked domain or a compromised update host from pushing an empty
    /// vocabulary (silencing a layer everywhere) or a ban-list entry for a
    /// popular legal release (banning its publishers everywhere, for thirty
    /// days). Verified before anything is written.
    #[serde(default)]
    pub public_key: String,

    /// Require a valid signature. Leaving this on is strongly recommended; it
    /// exists as a switch only because third-party mirrors may not sign, and
    /// turning it off should be a visible, deliberate line in the config rather
    /// than a silent fallback in the code.
    #[serde(default = "default_true")]
    pub require_signature: bool,

    /// The server whose exported peer table the update service loaded. Our
    /// access key is derived against THIS address — it is the number this server
    /// already sent that peer during the obfuscated handshake, so no
    /// registration step is needed. Empty disables credentials.
    #[serde(default)]
    pub key_reference_ip: String,

    /// Header the access key is sent in.
    #[serde(default = "default_key_header")]
    pub key_header: String,

    /// Backup generations kept next to each file as `<name>.1` … `<name>.N`.
    /// Three by default: a bad list is often noticed a day later, by which time
    /// a single slot has already been overwritten by the next update.
    #[serde(default = "default_backups")]
    pub backups: u8,

    /// Per-request timeout, seconds.
    #[serde(default = "default_update_timeout")]
    pub timeout_secs: u64,

    /// Hard ceiling on a single download. The country database is the largest
    /// of these at a few megabytes compressed.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,

    /// Refuse a REPLACE whose entry count falls below this fraction of the file
    /// it would overwrite. Catches the truncated download that parses cleanly
    /// and is simply much shorter. 0 disables.
    #[serde(default = "default_min_keep_ratio")]
    pub min_keep_ratio: f64,

    /// Where to POST the (IP, key) table of peers that completed gossip.
    /// Empty disables the export.
    #[serde(default)]
    pub export_url: String,

    /// Bearer token for the export endpoint.
    #[serde(default)]
    pub export_token: String,

    /// How often to push the peer table, seconds.
    #[serde(default = "default_export_interval")]
    pub export_interval_secs: u64,

    /// Per-file URLs. Two have compiled-in defaults because they carry no access
    /// control; the rest are empty until an update service is running.
    #[serde(default)]
    pub urls: UpdateUrls,
}

/// URL per data file. Field names match `updates::Target::id()`.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct UpdateUrls {
    #[serde(default)]
    pub csam_jargon: String,
    #[serde(default)]
    pub csam_terms_extra: String,
    #[serde(default)]
    pub layer2_terms: String,
    #[serde(default)]
    pub guarding_p2p: String,
    #[serde(default)]
    pub ip_to_country: String,
    #[serde(default)]
    pub hash_banlist: String,
    #[serde(default)]
    pub hash_filter: String,
    #[serde(default)]
    pub whitelist_hashes: String,
    /// MaxMind DB for GeoIP (IPv4 + IPv6), e.g. a zipped ipinfo_lite.mmdb.
    /// No compiled-in default: set it to the file you publish.
    #[serde(default)]
    pub geoip_mmdb: String,
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dest_dir: default_dest_dir(),
            public_key: String::new(),
            require_signature: true,
            key_reference_ip: String::new(),
            key_header: default_key_header(),
            backups: default_backups(),
            timeout_secs: default_update_timeout(),
            max_bytes: default_max_bytes(),
            min_keep_ratio: default_min_keep_ratio(),
            export_url: String::new(),
            export_token: String::new(),
            export_interval_secs: default_export_interval(),
            urls: UpdateUrls::default(),
        }
    }
}

fn default_dest_dir() -> String {
    "/etc/ed2k-server".to_string()
}
fn default_key_header() -> String {
    "X-Server-Key".to_string()
}
// `default_true` already exists above in this module — reused here rather than
// redefined.
fn default_backups() -> u8 {
    3
}
fn default_update_timeout() -> u64 {
    120
}
fn default_max_bytes() -> u64 {
    256 * 1024 * 1024
}
fn default_min_keep_ratio() -> f64 {
    0.5
}
fn default_export_interval() -> u64 {
    3600
}

impl UpdatesConfig {
    /// URL for one target: the configured value, or the compiled-in default for
    /// the two public files when config leaves it empty.
    pub fn url_for(&self, t: crate::updates::Target) -> String {
        use crate::updates::Target as T;
        let configured = match t {
            T::CsamJargon => &self.urls.csam_jargon,
            T::CsamTermsExtra => &self.urls.csam_terms_extra,
            T::Layer2Terms => &self.urls.layer2_terms,
            T::GuardingP2p => &self.urls.guarding_p2p,
            T::IpToCountry => &self.urls.ip_to_country,
            T::HashBanlist => &self.urls.hash_banlist,
            T::HashFilter => &self.urls.hash_filter,
            T::WhitelistHashes => &self.urls.whitelist_hashes,
            T::GeoipMmdb => &self.urls.geoip_mmdb,
        };
        if configured.trim().is_empty() {
            t.default_url().to_string()
        } else {
            configured.trim().to_string()
        }
    }
}

/// Localhost-only admin web UI. Disabled by default for safety.
#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    /// Enable the admin web server. Always binds to 127.0.0.1 only;
    /// access via SSH tunnel: `ssh -L 8080:127.0.0.1:8080 vps`.
    #[serde(default)]
    pub enabled: bool,
    /// Port for the admin UI on 127.0.0.1.
    #[serde(default = "default_admin_port")]
    pub port: u16,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_admin_port(),
        }
    }
}

fn default_admin_port() -> u16 {
    8080
}

/// Persistent storage of the file index across restarts.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct StorageConfig {
    /// Path to IP filter file in guarding.p2p format (eMule-compatible).
    /// Leave empty to disable. Reloaded on SIGHUP without restart.
    #[serde(default)]
    pub ipfilter_path: String,
    /// Path to ip-to-country.csv for client country stats in the admin UI.
    /// Format: start_int,end_int,ISO2,CountryName. Leave empty to disable.
    #[serde(default)]
    pub country_db_path: String,
    /// MaxMind DB file for GeoIP (IPv4 and IPv6, with provider names), tried
    /// before `country_db_path`. Empty = `ipinfo_lite.mmdb` in the same
    /// directory as `country_db_path`; `"off"` = use the CSV only. When the
    /// file is missing or unreadable the CSV is used.
    #[serde(default)]
    pub geoip_mmdb_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub name: String,
    #[serde(default)]
    pub desc: String,
    #[serde(default)]
    pub public: bool,
    /// Version shown in eMule server list as "major.minor"
    #[serde(default = "default_version_major")]
    pub version_major: u8,
    #[serde(default = "default_version_minor")]
    pub version_minor: u8,
    /// Public IP advertised to clients in SERVERIDENT.
    /// If empty, the server sends 0.0.0.0 (clients use the TCP source IP).
    #[serde(default)]
    pub this_ip: String,
    /// Seed servers for server-list gossip on startup.
    /// Format: ["ip:port", ...]
    #[serde(default)]
    pub seed_servers: Vec<String>,
}

impl NetworkConfig {
    /// Main UDP port — ALWAYS `tcp_port + 4`, never configured separately.
    ///
    /// The eD2k protocol fixes the whole UDP block relative to the TCP port, and
    /// every other channel already derived itself that way (`+8` aux, `+12`
    /// server-to-server obf-ping, `+14` portUDPobf). The main port was the lone
    /// exception, settable independently — which only created ways to be wrong:
    /// a mismatched value makes the server advertise ports it does not listen on,
    /// and clients (aMule especially) then talk to a dead socket. Deriving it
    /// removes that entire class of misconfiguration.
    ///
    /// A stale `udp_port = ...` left in an existing config.toml is harmless: the
    /// struct has no `deny_unknown_fields`, so the key is simply ignored.
    pub fn udp_port(&self) -> u16 {
        self.tcp_port.wrapping_add(4)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub tcp_port: u16,
    #[serde(default = "default_listen_ip")]
    pub listen_ip: String,
    /// TCP accept backlog for the IPv4 and IPv6 listeners. `0` = 1024. The
    /// kernel caps it at net.core.somaxconn. Restart.
    #[serde(default = "default_backlog")]
    pub listen_backlog: u32,
    #[serde(default = "default_max_frame")]
    pub max_frame_size: u32,
    /// Ceiling on the decompressed payload of one packed (0xD4) frame.
    /// `max_frame_size` bounds the compressed wire length only, and zlib
    /// expands up to ~1000:1. Must be at least 1; there is no "off". Applies to
    /// new connections.
    #[serde(default = "default_max_decompressed")]
    pub max_decompressed_frame_size: u32,
    // `udp_server_key` was here and was never read: the ServerKey a client
    // gets in OP_GLOBSERVSTATRES is computed per client as
    // IPObfuscate(seckey, client_ip), which is what the protocol requires. The
    // struct has no deny_unknown_fields, so an old config carrying the key
    // still loads and the key is ignored.
    /// Timeout for HighID probe (HighID detection)
    #[serde(default = "default_login_timeout_ms")]
    pub login_timeout_ms: u64,
    /// Enable/accept obfuscated connections from clients
    #[serde(default = "default_true")]
    pub support_crypt: bool,

    /// Give clients that reach the server from a PRIVATE address a chance at
    /// HighID, by probing `server.this_ip` on their port instead.
    ///
    /// For the topology where an operator runs a client on the same network as
    /// the server: the client reaches it through the router's hairpin NAT, the
    /// login socket therefore carries an RFC1918 address, and the server assigns
    /// LowID without probing anything. In that topology the client's real
    /// public address is by definition the server's own.
    ///
    /// ⚠ OFF BY DEFAULT, AND THE DEFAULT IS THE CAUTIOUS ONE. Two things can go
    ///   wrong. A server in a datacentre may see private addresses from a
    ///   management network that has nothing to do with its public address. And
    ///   where the router source-NATs hairpin traffic, ALL local clients arrive
    ///   from the same address and cannot be told apart, so a port-forward may
    ///   lead to a different machine than the one that logged in.
    ///
    ///   The second risk is why this path uses the IDENTITY probe rather than
    ///   the plain one: the peer must answer with the user hash that logged in.
    ///   If that check is ever weakened, this option has to go with it.
    #[serde(default)]
    pub hairpin_lan_clients: bool,

    /// OBSERVE ONLY: after a client gets HighID from the plain TCP probe, also
    /// run the identity probe (OP_HELLO → OP_HELLOANSWER with the user hash that
    /// logged in) in the background, and count what it finds. The verdict is
    /// NOT changed and the login does NOT wait for it.
    ///
    /// Why: HighID is decided by a bare TCP connect. A stock Lugdunum requires a
    /// protocol answer — measured, it reports "No answer from your NNNN port"
    /// and gives LowID to a port that accepts connections but does not speak
    /// eD2k, where this server gives HighID. Such a client is published as a
    /// source nobody can download from. Before tightening the verdict to match,
    /// this counts how many real HighID clients would lose it, and why — so the
    /// change is decided on numbers, not on a guess.
    ///
    /// Cost: one extra outbound connection per HighID login (two if the client
    /// advertised obfuscation and refuses it), bounded by a concurrency cap so a
    /// reconnect storm after a restart cannot turn into a probe storm.
    ///
    /// Does not touch the hairpin path: that runs only when the plain probe has
    /// already FAILED, and this only when it has SUCCEEDED.
    #[serde(default)]
    pub highid_verify_observe: bool,

    /// VERDICT, remembered: when a HighID client's port answers OP_HELLO with
    /// a DIFFERENT user hash (type-marker bytes ignored, see
    /// `same_client_hash`), remember (address, port, login hash) for
    /// `highid_wrong_hash_ttl_secs`, and give that client LowID on its next
    /// logins while the mark lasts.
    ///
    /// That answer proves the forward belongs to another eD2k client: two
    /// machines behind one NAT, both on the default port, the router forwarding
    /// it to one of them. The other one holds a HighID every peer is sent to
    /// the wrong machine by; as LowID it is reached through server callback.
    ///
    /// The check runs in the BACKGROUND and the login is answered at once — a
    /// synchronous check was tried and measured: clients whose login is still
    /// pending mostly do not answer the hello in time, so the login waited and
    /// the check caught little. The price is that the first session after a
    /// mismatch keeps its HighID; such clients reconnect often.
    ///
    /// A marked client is re-checked in the background on every login. If its
    /// port now answers with its own hash (forwarding fixed), the mark is
    /// dropped and the next login gets HighID again. A wrong hash again renews
    /// the mark. No answer leaves it as it is.
    ///
    /// Every outcome other than a different hash keeps HighID exactly as
    /// before: silent close and reset (the peer's IP filter drops us), timeout,
    /// refused, garbage. Supersedes `highid_verify_observe` while on (the same
    /// counters are fed). Hairpin path unaffected.
    #[serde(default)]
    pub highid_downgrade_on_wrong_hash: bool,

    /// How long a wrong-hash mark lasts, seconds. Default 86400 (a day).
    #[serde(default = "default_highid_wrong_hash_ttl_secs")]
    pub highid_wrong_hash_ttl_secs: u64,

    /// Accept client connections over IPv6, on the same TCP port.
    ///
    /// A separate listener rather than a dual-stack socket: the IPv4 path stays
    /// byte-identical, and a host without IPv6 simply logs a warning and serves
    /// IPv4 as before.
    #[serde(default)]
    pub ipv6_enabled: bool,

    /// Address the IPv6 listener binds to. `::` is every interface.
    #[serde(default = "default_listen_ip6")]
    pub listen_ip6: String,

    /// This server's public IPv6, announced to clients that speak the
    /// extension. Empty means the server has none; sources are then still
    /// accepted over IPv6 but the server does not advertise itself.
    #[serde(default)]
    pub this_ip6: String,

    /// Publish IPv6 sources to clients that can parse them.
    ///
    /// Separate from `ipv6_enabled` on purpose: accepting IPv6 clients is a
    /// local decision, while publishing IPv6 sources changes what other peers
    /// receive, and an operator may want the first without the second while
    /// watching how it behaves.
    #[serde(default)]
    pub ipv6_publish_sources: bool,
}

fn default_listen_ip6() -> String {
    "::".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct LimitsConfig {
    /// Max logged-in clients; advertised as ST_MAXUSERS and enforced at login
    /// (a client replacing its own session is always admitted). `0` = no cap.
    /// Live.
    #[serde(default = "default_max_clients")]
    pub max_clients: u32,
    /// Advertised as ST_SOFTFILES. Lugdunum semantics: the indexing budget of
    /// one client, in distinct files indexed for it across all its OFFERFILES.
    /// New files beyond it are not indexed and the client gets one server
    /// message per connection; re-offers of files it already sources and
    /// files the content filter blocks use no budget; the session stays up.
    /// `0` = no limit. Live.
    #[serde(default = "default_soft_limit")]
    pub soft_limit_files: u32,
    /// Advertised as ST_HARDFILES. Lugdunum semantics: a per-packet bound. An
    /// OFFERFILES declaring this many records or more is rejected before it is
    /// read and the connection is closed. Must stay well above the largest
    /// batch a client sends (eMule: 200), or every publisher is disconnected.
    /// `0` = no limit. Live.
    #[serde(default = "default_hard_limit")]
    pub hard_limit_files: u32,
    /// Open TCP connections allowed per client IP, checked at accept. Loopback
    /// exempt, `0` = no cap. Live.
    #[serde(default = "default_per_ip")]
    pub max_clients_per_ip: u32,
    /// Max bytes stored for a file name or nick, cut at a character boundary
    /// AFTER the content filter has seen the whole name. `0` = no cap. Live.
    #[serde(default = "default_max_string")]
    pub max_string_size: u32,
    #[serde(default = "default_ping_delay")]
    pub ping_delay_seconds: u64,

    /// Maximum file records returned for one search, across all pages.
    ///
    /// Lugdunum has no single number here: it picks between `maxSearchCount`
    /// and `maxSearchCountz` on the client's zlib capability bit, then halves
    /// the result for LowID clients, so the same query answers differently for
    /// two clients looking at the same index. Measured against a stock 17.15
    /// (query "1080p"): 309 and 205 for HighID with and without zlib, 153 and
    /// 101 for the same two as LowID — half minus one, consistently.
    ///
    /// We deliberately keep ONE number for everybody. A client has no way to
    /// learn it was served the smaller set, and an operator has no way to say
    /// what their users actually receive.
    #[serde(default = "default_max_search_results")]
    pub max_search_results: u32,

    /// Upper bound on candidate records examined while ranking one search.
    ///
    /// Ranking has to look at more than it returns: to serve the best-sourced
    /// matches it must examine every candidate, where the unranked path could
    /// stop at the first `max_search_results` that matched. On a common word
    /// that is the difference between a couple of hundred records and a posting
    /// list of hundreds of thousands — the cost profile that took this server
    /// from 3% to 92% CPU once already.
    ///
    /// Past this many candidates the ranking is over what was seen rather than
    /// over everything, `search.rank_scan_capped` counts it and a log line says
    /// so. The default is 100x the default result cap, so it only bites on
    /// words common enough that no ordering of them is meaningful anyway.
    #[serde(default = "default_search_rank_scan")]
    pub search_rank_scan: u32,

    /// Also index letter/digit sub-tokens of each word: `S01E08` becomes
    /// findable as `s01` and `e08`, `1080p` as `1080`.
    ///
    /// Why: a stock Lugdunum reaches those files through a substring filter
    /// over candidates seeded by another word, so `<title> s01` finds the
    /// whole season there and nothing here. Indexing the pieces gets most of
    /// that recall with a predictable cost — an intersection, not a filter
    /// whose outcome depends on which word happened to be rarest.
    ///
    /// Cost: measured on 1482 real filenames at +10% distinct keywords and
    /// +12% postings. That sample is small; measure on your own index before
    /// relying on it (compare the Health tab's memory and keyword figures with
    /// this off, then on, after the index has refilled).
    ///
    /// ⚠ READ ONCE AT STARTUP, NOT HOT-RELOADED. `add_file` and `remove_file`
    ///   must split names identically for the life of the index. Flipping this
    ///   while files are indexed would remove fewer tokens than were added and
    ///   leave stale ids in postings permanently. Changing it takes a restart,
    ///   and the index refills from publishes as it always does.
    ///
    /// Off by default: turning it on changes what searches return.
    #[serde(default)]
    pub index_subtokens: bool,

    /// Drop query words that no indexed file contains, instead of returning
    /// nothing because of them.
    ///
    /// One unknown word — a typo, a word in another language, a tag nobody
    /// else used — used to empty the whole search however good the other words
    /// were. Lugdunum does the same; we deliberately do not.
    ///
    /// Safe to have on only because results are ranked. Without ranking, a
    /// query whose distinguishing words were all unknown would come back as the
    /// cap's worth of files matching whatever common word survived, in
    /// publication order — worse than an honest zero. With ranking it is the
    /// best-sourced files for the words that do exist.
    ///
    /// A query where EVERY word is unknown still returns nothing. Applied live.
    #[serde(default = "default_true")]
    pub search_drop_unknown_words: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ContentFilterConfig {
    /// Optional. List of paths to hash-blocklist files. Empty list is
    /// permitted only when `server.public = false`. Enforced in `validate()`.
    #[serde(default)]
    pub hash_banlist: Vec<String>,

    /// Optional path to operator-supplied additional term file.
    #[serde(default)]
    pub extra_terms_file: Option<String>,

    /// Optional path to the Layer 1 jargon list (one term per line, `#` comments).
    /// NOT shipped in source — operators supply it from authoritative sources
    /// (INHOPE/IWF/NCMEC). Absent/empty ⇒ Layer 1 inactive (L2-L4 still run).
    #[serde(default)]
    pub jargon_terms_file: Option<String>,

    /// Optional path to the Layer 2 vocabulary file.
    ///
    /// Layer 2 blocks on an age claim co-occurring with a sexual context, and
    /// its word lists change almost daily as review windows surface new
    /// phrasing. Keeping them in the binary meant a rebuild and a restart for
    /// every addition, and a restart drops every connected client.
    ///
    /// Absent ⇒ the compiled-in vocabulary is used, which is exactly what it was
    /// before this option existed. A file REPLACES the sections it names and
    /// leaves the rest at their defaults. See `config/layer2_terms.txt.example`.
    #[serde(default)]
    pub layer2_terms_file: Option<String>,

    /// Optional path to hash whitelist (verified false-positive overrides).
    #[serde(default)]
    pub whitelist_hashes_file: Option<String>,

    /// Optional. Paths to FILTER-ONLY hash lists (Layer 5): files that must not
    /// be indexed, but whose publisher is not accused of anything.
    ///
    /// A hit here is blocked like any other, yet it does not raise
    /// `csam_attempts` and does not count toward
    /// `publisher_attempt_disconnect_threshold`.
    ///
    /// Two things belong here:
    ///   * decoys — one hash advertised under a dozen unrelated names. Offering
    ///     one makes a client a victim of index poisoning, not a publisher of
    ///     illegal material;
    ///   * takedown requests — a rightsholder complaint means the file should go
    ///     out of the index, and says nothing about the user who happens to
    ///     share it.
    ///
    /// Keeping these out of `hash_banlist` is what lets that list keep meaning
    /// one specific thing: every entry there is something its publisher should
    /// be held responsible for.
    #[serde(default)]
    pub hash_filter: Vec<String>,

    /// Maximum number of DISTINCT blocked CSAM files TOLERATED from one
    /// publisher (by user_hash) before banning — headroom for rare false
    /// positives. Files at or below this count are still filtered; the ban fires
    /// on the next distinct blocked file (e.g. value 3 ⇒ ban on the 4th).
    #[serde(default = "default_csam_disconnect_threshold")]
    pub publisher_attempt_disconnect_threshold: u32,

    /// How long (seconds) a banned publisher's user_hash stays blocked at login.
    /// Ban is by user_hash (stable across dynamic IPs), so a long window (e.g.
    /// 30 days = 2592000) is appropriate.
    ///
    /// This is the PUNISHMENT length. How far back distinct files are counted
    /// toward the threshold is a separate question — see
    /// `publisher_count_window_seconds`.
    #[serde(default = "default_csam_blacklist")]
    pub publisher_blacklist_seconds: u64,

    /// Optional. How far back (seconds) distinct blocked files are counted
    /// toward `publisher_attempt_disconnect_threshold`. Defaults to
    /// `publisher_blacklist_seconds` when absent, so an existing config keeps
    /// behaving exactly as before.
    ///
    /// These were one value, and that conflated two settings that want opposite
    /// answers. The ban should be long — a confirmed publisher has no business
    /// returning tomorrow. The counting window should be SHORT, because it is
    /// what decides who gets banned in the first place.
    ///
    /// At 30 days for both, the rule reads "N distinct blocked files in a month".
    /// Collectors of tag-stuffed Asian adult video accumulate those slowly and
    /// innocently — one poisoning source can put dozens of such names in a single
    /// library — so a low threshold banned real users for a slow drip. At 24 h
    /// the same threshold means "N in a day", which a collector cannot reach by
    /// accident and a publisher clears in one OFFERFILES packet.
    ///
    /// Note this does NOT shorten how long the per-user records are kept: they
    /// live for `publisher_blacklist_seconds` so that `/api/review` and
    /// `/api/publishers` keep their history. Only the COUNT is windowed.
    #[serde(default)]
    pub publisher_count_window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct WelcomeConfig {
    #[serde(default)]
    pub messages: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub connection_trace: bool,
    /// Number of tokio worker threads. Default = 1 (single-threaded, like
    /// Lugdunum's epoll loop). Increase to 2-4 only if the server is genuinely
    /// CPU-bound across multiple cores. Multi-threaded mode adds work-stealing
    /// overhead and DashMap shard contention that costs more CPU than it saves
    /// on a typical eD2k workload (small UDP packets, brief TCP sessions).
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            connection_trace: false,
            worker_threads: default_worker_threads(),
        }
    }
}

fn default_worker_threads() -> usize {
    1
}

fn default_listen_ip() -> String {
    "0.0.0.0".into()
}
fn default_backlog() -> u32 {
    256
}
fn default_max_frame() -> u32 {
    1_000_000
}
fn default_max_decompressed() -> u32 {
    crate::proto::frame::DEFAULT_MAX_DECOMPRESSED
}
fn default_login_timeout_ms() -> u64 {
    2000
}
fn default_highid_wrong_hash_ttl_secs() -> u64 {
    86_400
}
fn default_true() -> bool {
    true
}
fn default_version_major() -> u8 {
    17
}
fn default_version_minor() -> u8 {
    15
}
fn default_max_clients() -> u32 {
    1024
}
fn default_soft_limit() -> u32 {
    1000
}
fn default_hard_limit() -> u32 {
    4000
}
fn default_per_ip() -> u32 {
    10
}
fn default_max_string() -> u32 {
    250
}
fn default_ping_delay() -> u64 {
    300
}
/// Refuse a result cap above this. Well past anything a client displays, and
/// low enough that one search cannot be turned into a multi-megabyte response.
pub const MAX_SEARCH_RESULTS_CEILING: u32 = 5_000;

/// 200 keeps the behaviour every existing deployment already has.
fn default_max_search_results() -> u32 {
    200
}
fn default_search_rank_scan() -> u32 {
    20_000
}
fn default_csam_disconnect_threshold() -> u32 {
    3
}
fn default_csam_blacklist() -> u64 {
    86_400
}
fn default_log_level() -> String {
    "info".into()
}

impl ContentFilterConfig {
    /// How far back distinct blocked files count toward the ban threshold.
    /// Falls back to the ban length when unset, preserving the old behaviour.
    pub fn count_window(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.publisher_count_window_seconds
                .unwrap_or(self.publisher_blacklist_seconds),
        )
    }

    /// How long a ban lasts, and how long per-user records are retained.
    pub fn ban_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.publisher_blacklist_seconds)
    }
}

impl Config {
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Minimal valid Config for unit tests. Not for production.
    #[doc(hidden)]
    pub fn minimal_test_config() -> Self {
        let toml_str = r#"
[server]
name = "test_server"
desc = "test"
this_ip = ""
version_major = 17
version_minor = 15
public = false

[network]
tcp_port = 4661

[limits]
max_clients = 1000
soft_limit_files = 1000
hard_limit_files = 5000
ping_delay_seconds = 600

[content_filter]
hash_banlist = []
hash_filter = []
publisher_count_window_seconds = 86400

[updates]
# Update service for the filter data files. Off by default.
#
# WITHOUT csam_jargon.txt, csam_terms_extra.txt, layer2_terms.txt,
# hash_banlist.txt and hash_filter.txt the content filter has almost nothing to
# work with, and those lists cannot be published in a public repository. This
# section is how a server gets them.
enabled = false

# Where files are installed. Must be the directory the paths above point into,
# or an update will land somewhere nothing is watching.
dest_dir = "/etc/ed2k-server"

# Ed25519 public key (32 bytes, hex) that data files must be signed with.
#
# Read this before leaving it empty. A hijacked domain or a compromised update
# host can push an EMPTY vocabulary — every layer that uses it silently matches
# nothing, on every server that pulled — or one hash of a popular legal release
# into the ban list, which bans its publishers for thirty days everywhere at
# once. The signature is checked before anything is written; it is the only
# defence that does not depend on who controls the domain.
public_key = ""
require_signature = true

# Credential for the access-controlled files. The key is DERIVED, not stored:
# it is IPObfuscate(our seckey, this address) — the same number this server
# already sends that peer during the obfuscated server-to-server handshake, so
# the update service can be given the table without any registration step.
# Set this to the server whose exported peer table the service loaded.
key_reference_ip = ""

backups = 3
min_keep_ratio = 0.5

# Peer table export: (IP, key) of servers that completed gossip with us.
export_url = ""
export_token = ""
export_interval_secs = 3600

[updates.urls]
# The two public files have compiled-in defaults and need no credentials.
guarding_p2p = "https://ed2k.emule-security.org/pub/guarding.p2p"
ip_to_country = "https://ed2k.emule-security.org/pub/ip-to-country.csv.zip"
# GeoIP for IPv4 + IPv6 (MaxMind DB). Public data, no default URL.
geoip_mmdb = ""
# The rest identify material and are fetched with the access key above.
csam_jargon = ""
csam_terms_extra = ""
layer2_terms = ""
hash_banlist = ""
hash_filter = ""
whitelist_hashes = ""
"#;
        toml::from_str(toml_str).expect("minimal_test_config TOML must parse")
    }

    /// Enforce the SPEC.md §1.2 rule: refuse public deployment without
    /// a hash blocklist configured.
    pub fn validate(&self) -> Result<()> {
        if self.server.public && self.content_filter.hash_banlist.is_empty() {
            bail!(
                "server.public = true requires content_filter.hash_banlist \
                 to be configured (see SPEC.md §1.2 / §7.6.3). Refusing to start."
            );
        }
        self.admission.validate()?;
        if self.network.max_decompressed_frame_size == 0 {
            bail!(
                "network.max_decompressed_frame_size must be at least 1: it is the only \
                 bound on what one compressed frame may expand to"
            );
        }
        if self.limits.max_search_results == 0 {
            bail!("limits.max_search_results must be at least 1");
        }
        if self.limits.max_search_results > MAX_SEARCH_RESULTS_CEILING {
            bail!(
                "limits.max_search_results = {} exceeds the ceiling of {}. Every result \
                 carries a filename and a tag set, so a large cap turns one search into \
                 a multi-megabyte response the client never asked for.",
                self.limits.max_search_results,
                MAX_SEARCH_RESULTS_CEILING
            );
        }
        if (self.limits.search_rank_scan as u64) < self.limits.max_search_results as u64 {
            bail!(
                "limits.search_rank_scan ({}) is below limits.max_search_results ({}). \
                 Ranking would then examine fewer candidates than it returns, which \
                 silently reinstates the arbitrary-order cap this setting exists to remove.",
                self.limits.search_rank_scan,
                self.limits.max_search_results
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_network(extra: &str) -> Result<Config> {
        let toml_str = format!(
            "[server]\nname = \"t\"\ndesc = \"t\"\nthis_ip = \"\"\nversion_major = 17\n\
             version_minor = 15\npublic = false\n\n[network]\ntcp_port = 6262\n{extra}\n\n\
             [limits]\nmax_clients = 1\nsoft_limit_files = 1\nhard_limit_files = 1\n\
             ping_delay_seconds = 1\n\n[content_filter]\nhash_banlist = []\nhash_filter = []\n"
        );
        let cfg: Config = toml::from_str(&toml_str)?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn max_decompressed_frame_size_defaults_overrides_and_rejects_zero() {
        let d = with_network("").unwrap();
        assert_eq!(d.network.max_decompressed_frame_size, 8_000_000);
        let o = with_network("max_decompressed_frame_size = 2_000_000").unwrap();
        assert_eq!(o.network.max_decompressed_frame_size, 2_000_000);
        let z = with_network("max_decompressed_frame_size = 0");
        assert!(z.is_err(), "0 would remove the only bound on expansion");
    }

    #[test]
    fn udp_port_is_derived_from_tcp_port() {
        let cfg = Config::minimal_test_config();
        assert_eq!(cfg.network.tcp_port, 4661);
        // Protocol-fixed offset: main UDP is always TCP+4.
        assert_eq!(cfg.network.udp_port(), 4665);
    }

    #[test]
    fn stale_udp_port_key_is_ignored_not_an_error() {
        // Existing deployments still carry `udp_port = ...` in config.toml, and
        // may carry the removed `udp_server_key` too.
        // Parsing must succeed and ignore it, deriving the port from tcp_port
        // instead — otherwise every server would fail to start after upgrading.
        let toml_str = r#"
[server]
name = "t"
desc = "t"
this_ip = ""
version_major = 17
version_minor = 15
public = false

[network]
tcp_port = 6262
udp_port = 9999
udp_server_key = 305419896

[limits]
max_clients = 1
soft_limit_files = 1
hard_limit_files = 1
ping_delay_seconds = 1

[content_filter]
hash_banlist = []
hash_filter = []
publisher_count_window_seconds = 86400

[updates]
# Update service for the filter data files. Off by default.
#
# WITHOUT csam_jargon.txt, csam_terms_extra.txt, layer2_terms.txt,
# hash_banlist.txt and hash_filter.txt the content filter has almost nothing to
# work with, and those lists cannot be published in a public repository. This
# section is how a server gets them.
enabled = false

# Where files are installed. Must be the directory the paths above point into,
# or an update will land somewhere nothing is watching.
dest_dir = "/etc/ed2k-server"

# Ed25519 public key (32 bytes, hex) that data files must be signed with.
#
# Read this before leaving it empty. A hijacked domain or a compromised update
# host can push an EMPTY vocabulary — every layer that uses it silently matches
# nothing, on every server that pulled — or one hash of a popular legal release
# into the ban list, which bans its publishers for thirty days everywhere at
# once. The signature is checked before anything is written; it is the only
# defence that does not depend on who controls the domain.
public_key = ""
require_signature = true

# Credential for the access-controlled files. The key is DERIVED, not stored:
# it is IPObfuscate(our seckey, this address) — the same number this server
# already sends that peer during the obfuscated server-to-server handshake, so
# the update service can be given the table without any registration step.
# Set this to the server whose exported peer table the service loaded.
key_reference_ip = ""

backups = 3
min_keep_ratio = 0.5

# Peer table export: (IP, key) of servers that completed gossip with us.
export_url = ""
export_token = ""
export_interval_secs = 3600

[updates.urls]
# The two public files have compiled-in defaults and need no credentials.
guarding_p2p = "https://ed2k.emule-security.org/pub/guarding.p2p"
ip_to_country = "https://ed2k.emule-security.org/pub/ip-to-country.csv.zip"
# GeoIP for IPv4 + IPv6 (MaxMind DB). Public data, no default URL.
geoip_mmdb = ""
# The rest identify material and are fetched with the access key above.
csam_jargon = ""
csam_terms_extra = ""
layer2_terms = ""
hash_banlist = ""
hash_filter = ""
whitelist_hashes = ""
"#;
        let cfg: Config = toml::from_str(toml_str).expect("stale key must not break parsing");
        assert_eq!(
            cfg.network.udp_port(),
            6266,
            "must derive, not use the stale 9999"
        );
    }
}
