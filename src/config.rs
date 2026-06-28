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

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub tcp_port: u16,
    #[serde(default = "default_listen_ip")]
    pub listen_ip: String,
    #[serde(default = "default_backlog")]
    pub listen_backlog: u32,
    #[serde(default = "default_max_frame")]
    pub max_frame_size: u32,
    #[serde(default = "default_udp_port")]
    pub udp_port: u16,
    /// Server key embedded in GLOBSERVSTATRES
    #[serde(default = "default_udp_server_key")]
    pub udp_server_key: u32,

    /// Timeout for HighID probe (HighID detection)
    #[serde(default = "default_login_timeout_ms")]
    pub login_timeout_ms: u64,
    /// Enable/accept obfuscated connections from clients
    #[serde(default = "default_true")]
    pub support_crypt: bool,
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
    pub hash_blocklists: Vec<String>,

    /// Optional path to operator-supplied additional term file.
    #[serde(default)]
    pub extra_terms_file: Option<String>,

    /// Optional path to the Layer 1 jargon list (one term per line, `#` comments).
    /// NOT shipped in source — operators supply it from authoritative sources
    /// (INHOPE/IWF/NCMEC). Absent/empty ⇒ Layer 1 inactive (L2-L4 still run).
    #[serde(default)]
    pub jargon_terms_file: Option<String>,

    /// Optional path to hash whitelist (verified false-positive overrides).
    #[serde(default)]
    pub whitelist_hashes_file: Option<String>,

    /// Maximum number of DISTINCT blocked CSAM files TOLERATED from one
    /// publisher (by user_hash) before banning — headroom for rare false
    /// positives. Files at or below this count are still filtered; the ban fires
    /// on the next distinct blocked file (e.g. value 3 ⇒ ban on the 4th).
    #[serde(default = "default_csam_disconnect_threshold")]
    pub publisher_attempt_disconnect_threshold: u32,

    /// How long (seconds) a banned publisher's user_hash stays blocked at login.
    /// Ban is by user_hash (stable across dynamic IPs), so a long window (e.g.
    /// 30 days = 2592000) is appropriate.
    #[serde(default = "default_csam_blacklist")]
    pub publisher_blacklist_seconds: u64,
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
fn default_udp_port() -> u16 { 4665 }
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
udp_port = 4665

[limits]
max_clients = 1000
soft_limit_files = 1000
hard_limit_files = 5000
ping_delay_seconds = 600

[content_filter]
hash_blocklists = []
"#;
        toml::from_str(toml_str).expect("minimal_test_config TOML must parse")
    }

    /// Enforce the SPEC.md §1.2 rule: refuse public deployment without
    /// a hash blocklist configured.
    pub fn validate(&self) -> Result<()> {
        if self.server.public && self.content_filter.hash_blocklists.is_empty() {
            bail!(
                "server.public = true requires content_filter.hash_blocklists \
                 to be configured (see SPEC.md §1.2 / §7.6.3). Refusing to start."
            );
        }
        Ok(())
    }
}
