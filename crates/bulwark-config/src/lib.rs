//! Bulwark configuration model: strongly-typed, serde-(de)serializable config
//! with sensible defaults and YAML persistence.
//!
//! Durations are stored as plain seconds (`*_secs`) so the YAML file and the
//! JSON API stay simple and the web UI can edit them as numbers.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

mod defaults;
use defaults::*;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Current on-disk schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// The root configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "one")]
    pub version: u32,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub upstreams: UpstreamsConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub filtering: FilteringConfig,
    #[serde(default)]
    pub clients: Vec<ClientConfig>,
    #[serde(default)]
    pub query_log: QueryLogConfig,
    #[serde(default)]
    pub stats: StatsConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            server: ServerConfig::default(),
            upstreams: UpstreamsConfig::default(),
            cache: CacheConfig::default(),
            filtering: FilteringConfig::default(),
            clients: Vec::new(),
            query_log: QueryLogConfig::default(),
            stats: StatsConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Addresses to serve plain DNS on (UDP + TCP).
    #[serde(default = "default_dns_bind")]
    pub dns_bind: Vec<SocketAddr>,
    /// Address to serve the web UI + API on.
    #[serde(default = "default_http_bind")]
    pub http_bind: SocketAddr,
    /// Per-client query rate limit (queries/sec); 0 disables.
    #[serde(default)]
    pub ratelimit: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            dns_bind: default_dns_bind(),
            http_bind: default_http_bind(),
            ratelimit: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Spec string, e.g. `1.1.1.1`, `tls://dns.google`, `https://.../dns-query`.
    pub spec: String,
    /// Optional friendly name for the UI.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "btrue")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamsConfig {
    #[serde(default = "default_upstreams")]
    pub servers: Vec<UpstreamConfig>,
    /// Plain-DNS bootstrap servers for resolving DoT/DoH/DoQ hostnames.
    #[serde(default = "default_bootstrap")]
    pub bootstrap: Vec<SocketAddr>,
    /// Per-attempt query timeout (seconds).
    #[serde(default = "five")]
    pub timeout_secs: u64,
    /// Interval between background latency probes (seconds); 0 disables probing.
    #[serde(default = "sixty")]
    pub probe_interval_secs: u64,
}

impl Default for UpstreamsConfig {
    fn default() -> Self {
        Self {
            servers: default_upstreams(),
            bootstrap: default_bootstrap(),
            timeout_secs: 5,
            probe_interval_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "btrue")]
    pub enabled: bool,
    /// Maximum number of cached entries.
    #[serde(default = "default_cache_size")]
    pub size: usize,
    /// Clamp lower bound for TTLs (seconds).
    #[serde(default)]
    pub min_ttl_secs: u32,
    /// Clamp upper bound for TTLs (seconds); 0 means "no upper clamp".
    #[serde(default = "default_max_ttl")]
    pub max_ttl_secs: u32,
    /// Optimistic caching (serve-stale): serve expired entries immediately while
    /// refreshing in the background.
    #[serde(default)]
    pub optimistic: bool,
    /// When optimistic caching is on, the maximum number of seconds **past
    /// expiry** that a stale entry may still be served before a fresh resolve is
    /// required. Bounds staleness (entries are never served unbounded); 0
    /// disables serve-stale even if `optimistic` is true.
    #[serde(default = "default_stale_max_age")]
    pub optimistic_max_age_secs: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            size: default_cache_size(),
            min_ttl_secs: 0,
            max_ttl_secs: default_max_ttl(),
            optimistic: false,
            optimistic_max_age_secs: default_stale_max_age(),
        }
    }
}

/// How blocked queries are answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlockingMode {
    /// Respond with NXDOMAIN.
    #[default]
    NxDomain,
    /// Respond with 0.0.0.0 / :: (null IP).
    NullIp,
    /// Respond with a custom IP (see `custom_block_ipv4`/`ipv6`).
    CustomIp,
    /// Respond with REFUSED.
    Refused,
    /// Respond with NODATA (empty NOERROR).
    NoData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterListConfig {
    pub id: u32,
    pub name: String,
    /// Remote URL to fetch; if absent the list is managed purely in the UI.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default = "btrue")]
    pub enabled: bool,
    /// Cached metadata (updated by the server; persisted for the UI).
    #[serde(default)]
    pub rule_count: usize,
    #[serde(default)]
    pub last_updated: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteringConfig {
    #[serde(default = "btrue")]
    pub enabled: bool,
    #[serde(default)]
    pub blocking_mode: BlockingMode,
    #[serde(default = "default_block_ipv4")]
    pub custom_block_ipv4: std::net::Ipv4Addr,
    #[serde(default = "default_block_ipv6")]
    pub custom_block_ipv6: std::net::Ipv6Addr,
    /// TTL (seconds) for synthesized blocked responses.
    #[serde(default = "ten")]
    pub blocked_ttl_secs: u32,
    #[serde(default)]
    pub lists: Vec<FilterListConfig>,
    /// User-authored custom rules (one rule per line).
    #[serde(default)]
    pub custom_rules: String,
}

impl Default for FilteringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            blocking_mode: BlockingMode::default(),
            custom_block_ipv4: default_block_ipv4(),
            custom_block_ipv6: default_block_ipv6(),
            blocked_ttl_secs: 10,
            lists: Vec::new(),
            custom_rules: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub name: String,
    /// Identifiers: IP addresses or CIDR ranges.
    #[serde(default)]
    pub ids: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether filtering applies to this client.
    #[serde(default = "btrue")]
    pub filtering_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogConfig {
    #[serde(default = "btrue")]
    pub enabled: bool,
    /// Number of recent entries kept in memory for fast browsing.
    #[serde(default = "default_log_size")]
    pub size: usize,
    /// Persist the query log to disk so it survives restarts.
    #[serde(default = "btrue")]
    pub persist: bool,
    /// How many days of query log to retain on disk (independent of `stats`).
    /// 0 keeps only the in-memory `size` window.
    #[serde(default = "default_log_retention_days")]
    pub retention_days: u32,
    /// Whether to anonymize client IPs (drop last octet / suffix).
    #[serde(default)]
    pub anonymize: bool,
}

impl Default for QueryLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            size: default_log_size(),
            persist: true,
            retention_days: default_log_retention_days(),
            anonymize: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsConfig {
    #[serde(default = "btrue")]
    pub enabled: bool,
    /// Persist statistics to disk so they survive restarts.
    #[serde(default = "btrue")]
    pub persist: bool,
    /// How many days of time-bucketed statistics history to keep (independent of
    /// the query-log retention).
    #[serde(default = "default_stats_days")]
    pub retention_days: u32,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            persist: true,
            retention_days: default_stats_days(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Admin username.
    #[serde(default)]
    pub username: String,
    /// Argon2 password hash; `None` until the admin sets a password (setup flow).
    #[serde(default)]
    pub password_hash: Option<String>,
}

impl AuthConfig {
    /// Whether initial setup (creating the admin account) is still required.
    pub fn needs_setup(&self) -> bool {
        self.username.is_empty() || self.password_hash.is_none()
    }
}

// ---------------------------------------------------------------------------

impl Config {
    /// Load config from a YAML file, or return defaults if it doesn't exist.
    pub fn load_or_default(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = serde_yaml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Persist config to a YAML file atomically (write temp + rename).
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let yaml = serde_yaml::to_string(self)?;
        let tmp = path.with_extension("yaml.tmp");
        std::fs::write(&tmp, yaml.as_bytes())?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Validate invariants, returning a helpful error otherwise.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.dns_bind.is_empty() {
            return Err(ConfigError::Invalid(
                "server.dns_bind must not be empty".into(),
            ));
        }
        if self.cache.max_ttl_secs != 0 && self.cache.min_ttl_secs > self.cache.max_ttl_secs {
            return Err(ConfigError::Invalid(format!(
                "cache.min_ttl_secs ({}) exceeds max_ttl_secs ({})",
                self.cache.min_ttl_secs, self.cache.max_ttl_secs
            )));
        }
        // Validate upstream specs early so misconfig is caught on save.
        for u in &self.upstreams.servers {
            if u.spec.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "upstream spec must not be empty".into(),
                ));
            }
        }
        Ok(())
    }

    /// Allocate a filter-list id not already used.
    pub fn next_list_id(&self) -> u32 {
        self.filtering
            .lists
            .iter()
            .map(|l| l.id)
            .max()
            .map_or(1, |m| m + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_roundtrip() {
        let cfg = Config::default();
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let back: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.version, SCHEMA_VERSION);
        assert!(!back.upstreams.servers.is_empty());
        back.validate().unwrap();
    }

    #[test]
    fn partial_config_uses_defaults() {
        let yaml = "version: 1\nfiltering:\n  enabled: false\n";
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(!cfg.filtering.enabled);
        // Unspecified sections fall back to defaults.
        assert!(cfg.cache.enabled);
        assert_eq!(cfg.server.http_bind, default_http_bind());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let mut cfg = Config::default();
        cfg.filtering.custom_rules = "||ads.example.com^".into();
        cfg.save(&path).unwrap();
        let loaded = Config::load_or_default(&path).unwrap();
        assert_eq!(loaded.filtering.custom_rules, "||ads.example.com^");
    }

    #[test]
    fn validate_rejects_bad_ttl() {
        let mut cfg = Config::default();
        cfg.cache.min_ttl_secs = 100;
        cfg.cache.max_ttl_secs = 50;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn missing_file_is_default() {
        let cfg = Config::load_or_default("/nonexistent/path/to/config.yaml").unwrap();
        assert_eq!(cfg.version, SCHEMA_VERSION);
    }
}
