//! Bulwark configuration model: strongly-typed, serde-(de)serializable config
//! with sensible defaults and YAML persistence.
//!
//! Durations are stored as plain seconds (`*_secs`) so the YAML file and the
//! JSON API stay simple and the web UI can edit them as numbers.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize};

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
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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
    pub privacy: PrivacyConfig,
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
            privacy: PrivacyConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ServerConfig {
    /// Addresses to serve plain DNS on (UDP + TCP).
    #[serde(default = "default_dns_bind")]
    #[schema(value_type = Vec<String>)]
    pub dns_bind: Vec<SocketAddr>,
    /// Address to serve the web UI + API on.
    #[serde(default = "default_http_bind")]
    #[schema(value_type = String)]
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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpstreamsConfig {
    /// Freeform upstream list: one spec per line. Lines starting with `#` are
    /// comments and blank lines are ignored — both are preserved verbatim so
    /// you can annotate and toggle entries by commenting them out. e.g.
    /// `https://cloudflare-dns.com/dns-query`, `tls://one.one.one.one`.
    #[serde(default = "default_upstreams", deserialize_with = "de_upstreams")]
    pub servers: String,
    /// Plain-DNS bootstrap servers for resolving DoT/DoH/DoQ hostnames.
    #[serde(default = "default_bootstrap")]
    #[schema(value_type = Vec<String>)]
    pub bootstrap: Vec<SocketAddr>,
    /// Per-attempt query timeout (seconds).
    #[serde(default = "five")]
    pub timeout_secs: u64,
}

impl Default for UpstreamsConfig {
    fn default() -> Self {
        Self {
            servers: default_upstreams(),
            bootstrap: default_bootstrap(),
            timeout_secs: 5,
        }
    }
}

impl UpstreamsConfig {
    /// The active upstream specs: non-blank lines that aren't comments (`#`),
    /// trimmed. Comment and blank lines in [`servers`](Self::servers) are
    /// ignored here but preserved on disk.
    pub fn active_specs(&self) -> impl Iterator<Item = &str> {
        self.servers
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
    }

    /// Tidy the freeform [`servers`](Self::servers) text in place: trim each
    /// line, drop leading/trailing blank lines, and collapse runs of blank
    /// lines so at most one blank line (two consecutive newlines) survives. The
    /// result always ends in a single trailing newline, or is empty.
    pub fn normalize(&mut self) {
        let mut out = String::with_capacity(self.servers.len());
        let mut blanks = 0u32;
        for line in self.servers.lines() {
            let line = line.trim();
            if line.is_empty() {
                blanks += 1;
                if blanks > 1 {
                    continue;
                }
            } else {
                blanks = 0;
            }
            out.push_str(line);
            out.push('\n');
        }
        let trimmed = out.trim_matches('\n');
        self.servers = if trimmed.is_empty() {
            String::new()
        } else {
            format!("{trimmed}\n")
        };
    }
}

/// Deserialize the freeform upstream list leniently: accept a string as-is, and
/// fall back to the default for anything else (e.g. a config written by an older
/// build that stored a structured list). This keeps one stale field from failing
/// the whole config load — only the upstreams reset.
fn de_upstreams<'de, D>(de: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match serde_yaml::Value::deserialize(de)? {
        serde_yaml::Value::String(s) => s,
        _ => default_upstreams(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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
    /// Optimistic caching (serve-stale): the maximum number of seconds **past
    /// expiry** that a stale entry may be served immediately while a fresh
    /// resolve runs in the background. `0` disables serve-stale entirely; any
    /// value `> 0` enables it and bounds how stale an answer can be (entries are
    /// never served unbounded).
    #[serde(default)]
    pub optimistic_max_age_secs: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            size: default_cache_size(),
            min_ttl_secs: 0,
            max_ttl_secs: default_max_ttl(),
            optimistic_max_age_secs: 0,
        }
    }
}

/// How blocked queries are answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FilteringConfig {
    #[serde(default = "btrue")]
    pub enabled: bool,
    #[serde(default)]
    pub blocking_mode: BlockingMode,
    #[serde(default = "default_block_ipv4")]
    #[schema(value_type = String)]
    pub custom_block_ipv4: std::net::Ipv4Addr,
    #[serde(default = "default_block_ipv6")]
    #[schema(value_type = String)]
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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ClientConfig {
    /// Stable, server-assigned identifier. Used as the resource key in the API.
    #[serde(default)]
    pub id: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueryLogConfig {
    #[serde(default = "btrue")]
    pub enabled: bool,
    /// Persist the query log to disk so it survives restarts. When off, the log
    /// is kept in an in-memory database for the lifetime of the process.
    #[serde(default = "btrue")]
    pub persist: bool,
    /// How many days of query log to retain (independent of `stats`). Entries
    /// older than this are pruned periodically. 0 disables time-based pruning
    /// (the log is kept indefinitely).
    #[serde(default = "default_log_retention_days")]
    pub retention_days: u32,
}

impl Default for QueryLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            persist: true,
            retention_days: default_log_retention_days(),
        }
    }
}

/// Privacy-related toggles that span more than one subsystem.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PrivacyConfig {
    /// When set, client IPs are dropped entirely from the query log (the stored
    /// and API-returned `client_ip` is blank) **and** from statistics (the
    /// dashboard's "top clients" panel is empty while on). The IP is still used
    /// to identify the client for filtering before logging/recording — only the
    /// retained/displayed copy is removed.
    #[serde(default)]
    pub anonymize_client_ips: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuthConfig {
    /// Admin username.
    #[serde(default)]
    pub username: String,
    /// Argon2 password hash; `None` until the admin sets a password (setup flow).
    /// Skipped when absent so the redacted (`None`) value the API returns never
    /// rides the wire, and the YAML stays clean before setup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
        let mut cfg: Config = serde_yaml::from_str(&text)?;
        cfg.validate()?;
        // Clients are keyed by a stable `id`. Legacy entries predating the
        // granular client API have none and can't be addressed, so drop them
        // rather than migrate.
        let before = cfg.clients.len();
        cfg.clients.retain(|c| !c.id.is_empty());
        let dropped = before - cfg.clients.len();
        if dropped > 0 {
            tracing::warn!("dropped {dropped} client(s) without an id from config");
        }
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
        // The config holds the admin password hash, so keep it owner-only. Set
        // perms on the temp file before the atomic rename so the final file is
        // never briefly world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
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
        // Require at least one active (non-comment) upstream spec so we never
        // silently end up with nothing to resolve against.
        if self.upstreams.active_specs().next().is_none() {
            return Err(ConfigError::Invalid(
                "at least one upstream must be configured".into(),
            ));
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

    #[test]
    fn active_specs_skips_comments_and_blanks() {
        let cfg = UpstreamsConfig {
            servers: "# Cloudflare\nhttps://cloudflare-dns.com/dns-query\n\n#tls://one.one.one.one\n  1.1.1.1  \n".into(),
            ..Default::default()
        };
        let specs: Vec<&str> = cfg.active_specs().collect();
        assert_eq!(specs, ["https://cloudflare-dns.com/dns-query", "1.1.1.1"]);
    }

    #[test]
    fn freeform_upstreams_preserve_comments_across_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let mut cfg = Config::default();
        cfg.upstreams.servers =
            "# Cloudflare\nhttps://cloudflare-dns.com/dns-query\n#tls://one.one.one.one\n".into();
        cfg.save(&path).unwrap();
        let loaded = Config::load_or_default(&path).unwrap();
        assert_eq!(loaded.upstreams.servers, cfg.upstreams.servers);
    }

    #[test]
    fn normalize_trims_lines_and_collapses_blanks() {
        let mut cfg = UpstreamsConfig {
            servers: "\n\n  # Cloudflare  \n\n\n  https://cloudflare-dns.com/dns-query  \n\n\n\n#tls://one.one.one.one\n\n".into(),
            ..Default::default()
        };
        cfg.normalize();
        assert_eq!(
            cfg.servers,
            "# Cloudflare\n\nhttps://cloudflare-dns.com/dns-query\n\n#tls://one.one.one.one\n"
        );
    }

    #[test]
    fn normalize_empty_stays_empty() {
        let mut cfg = UpstreamsConfig {
            servers: "\n  \n\n".into(),
            ..Default::default()
        };
        cfg.normalize();
        assert_eq!(cfg.servers, "");
    }

    #[test]
    fn all_comments_fails_validation() {
        let mut cfg = Config::default();
        cfg.upstreams.servers = "# everything is off\n#1.1.1.1\n".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn legacy_structured_servers_reset_without_breaking_load() {
        // A config from an older build stored `servers` as a structured list.
        // It must not fail the whole load — only the upstreams reset.
        let yaml = "version: 1\ncache:\n  size: 1234\nupstreams:\n  servers:\n    - spec: 1.1.1.1\n      name: Cloudflare\n      enabled: true\n";
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.cache.size, 1234);
        assert_eq!(cfg.upstreams.servers, default_upstreams());
    }
}
