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
#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    /// Path to IP filter file in guarding.p2p format (eMule-compatible).
    /// Leave empty to disable. Reloaded on SIGHUP without restart.
    #[serde(default)]
    pub ipfilter_path: String,
    /// Path to ip-to-country.csv for client country stats in the admin UI.
    /// Format: start_int,end_int,ISO2,CountryName. Leave empty to disable.
    #[serde(default)]
    pub country_db_path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            ipfilter_path: String::new(),
            country_db_path: String::new(),
        }
    }
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
    #[serde(default = "default_backlog")]
    pub listen_backlog: u32,
    #[serde(default = "default_max_frame")]
    pub max_frame_size: u32,
    /// Server key embedded in GLOBSERVSTATRES
    #[serde(default = "default_udp_server_key")]
    pub udp_server_key: u32,

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
}

#[derive(Debug, Deserialize, Clone)]
pub struct LimitsConfig {
    #[serde(default = "default_max_clients")]
    pub max_clients: u32,
    #[serde(default = "default_soft_limit")]
    pub soft_limit_files: u32,
    #[serde(default = "default_hard_limit")]
    pub hard_limit_files: u32,
    #[serde(default = "default_per_ip")]
    pub max_clients_per_ip: u32,
    #[serde(default = "default_max_string")]
    pub max_string_size: u32,
    #[serde(default = "default_ping_delay")]
    pub ping_delay_seconds: u64,
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

fn default_worker_threads() -> usize { 1 }

fn default_listen_ip() -> String {
    "0.0.0.0".into()
}
fn default_backlog() -> u32 {
    256
}
fn default_max_frame() -> u32 {
    1_000_000
}
fn default_udp_server_key() -> u32 { 0x1234_5678 }
fn default_login_timeout_ms() -> u64 { 2000 }
fn default_true() -> bool { true }
fn default_version_major() -> u8 { 17 }
fn default_version_minor() -> u8 { 15 }
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
fn default_max_string() -> u32 { 250 }
fn default_ping_delay() -> u64 { 300 }
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_port_is_derived_from_tcp_port() {
        let cfg = Config::minimal_test_config();
        assert_eq!(cfg.network.tcp_port, 4661);
        // Protocol-fixed offset: main UDP is always TCP+4.
        assert_eq!(cfg.network.udp_port(), 4665);
    }

    #[test]
    fn stale_udp_port_key_is_ignored_not_an_error() {
        // Existing deployments still carry `udp_port = ...` in config.toml.
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
# The rest identify material and are fetched with the access key above.
csam_jargon = ""
csam_terms_extra = ""
layer2_terms = ""
hash_banlist = ""
hash_filter = ""
whitelist_hashes = ""
"#;
        let cfg: Config = toml::from_str(toml_str).expect("stale key must not break parsing");
        assert_eq!(cfg.network.udp_port(), 6266, "must derive, not use the stale 9999");
    }
}
