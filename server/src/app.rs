//! Shared application state and the config → engine build/apply logic.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bulwark_config::Config;
use bulwark_engine::cache::DnsCache;
use bulwark_engine::clients::ClientMatcher;
use bulwark_engine::querylog::QueryLog;
use bulwark_engine::stats::Stats;
use bulwark_engine::{Engine, EngineState};
use bulwark_filter::Compiler;
use bulwark_upstream::{PoolEntry, PoolSettings, UpstreamPool};
use tokio::sync::RwLock;

use crate::auth::Sessions;

/// Filesystem layout under the data directory.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub config: PathBuf,
    pub lists_dir: PathBuf,
    /// Disk-backed query-log database (SQLite via Turso).
    pub querylog_db: PathBuf,
    pub stats: PathBuf,
    /// DNS cache snapshot, restored on startup to warm the cache (see
    /// [`crate::persist::load_cache`]).
    pub cache_snapshot: PathBuf,
}

impl Paths {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            config: data_dir.join("config.yaml"),
            lists_dir: data_dir.join("lists"),
            querylog_db: data_dir.join("querylog.db"),
            stats: data_dir.join("stats.json"),
            cache_snapshot: data_dir.join("cache.snap"),
            data_dir,
        }
    }

    pub fn list_file(&self, id: u32) -> PathBuf {
        self.lists_dir.join(format!("{id}.txt"))
    }
}

/// Application state shared by all HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    pub config: Arc<RwLock<Config>>,
    pub paths: Arc<Paths>,
    pub sessions: Arc<Sessions>,
    /// Disk-backed query-log store, read by the API and written by the
    /// background writer task.
    pub store: Arc<crate::store::QueryStore>,
    /// Serializes config read-modify-write updates. Held across a handler's
    /// clone → mutate → [`apply_config`] sequence so concurrent edits can't lose
    /// each other's writes or allocate the same list id twice.
    pub update_lock: Arc<tokio::sync::Mutex<()>>,
}

impl AppState {
    /// Begin a serialized config update: take the update lock, then clone the
    /// current config to mutate. Hold the returned guard until [`apply_config`]
    /// completes — the whole read-modify-write must happen under it.
    pub async fn begin_update(&self) -> (Config, tokio::sync::OwnedMutexGuard<()>) {
        let guard = self.update_lock.clone().lock_owned().await;
        let cfg = self.config.read().await.clone();
        (cfg, guard)
    }
}

/// Read a filter list's stored text (empty if it doesn't exist yet).
pub fn read_list_text(paths: &Paths, id: u32) -> String {
    std::fs::read_to_string(paths.list_file(id)).unwrap_or_default()
}

/// Compile the filter engine from custom rules + enabled lists on disk.
/// Returns the engine plus per-list rule counts (list_id → rule count).
pub fn compile_filters(
    cfg: &Config,
    paths: &Paths,
) -> (bulwark_filter::FilterEngine, Vec<(u32, usize)>) {
    let mut c = Compiler::new();
    // Custom user rules are list id 0.
    c.add_list(0, "Custom rules", &cfg.filtering.custom_rules);
    for l in &cfg.filtering.lists {
        if l.enabled {
            let text = read_list_text(paths, l.id);
            c.add_list(l.id, &l.name, &text);
        }
    }
    let (engine, stats) = c.build();
    let counts = stats.iter().map(|s| (s.list_id, s.rules)).collect();
    (engine, counts)
}

/// Build the upstream pool from the enabled configured upstreams.
pub async fn build_pool(cfg: &Config) -> anyhow::Result<UpstreamPool> {
    let entries: Vec<PoolEntry> = cfg
        .upstreams
        .active_specs()
        .map(|spec| PoolEntry {
            spec: spec.to_string(),
            name: None,
        })
        .collect();
    let settings = PoolSettings {
        query_timeout: Duration::from_secs(cfg.upstreams.timeout_secs.max(1)),
        bootstrap: cfg.upstreams.bootstrap.clone(),
        ..Default::default()
    };
    let mut pool = UpstreamPool::build(&entries, settings)
        .await
        .context("building upstream pool")?;
    // Each upstream drives its own probe schedule; the tasks stop when this pool
    // is dropped (e.g. replaced on the next config reload).
    pool.start_probing();
    Ok(pool)
}

/// Build a fresh [`EngineState`] from the current config.
pub async fn build_engine_state(cfg: &Config, paths: &Paths) -> anyhow::Result<EngineState> {
    let (filter, _counts) = compile_filters(cfg, paths);
    let pool = Arc::new(build_pool(cfg).await?);
    let clients = Arc::new(ClientMatcher::build(&cfg.clients));
    Ok(EngineState {
        filter: Arc::new(filter),
        pool,
        clients,
        filtering_enabled: cfg.filtering.enabled,
        blocking_mode: cfg.filtering.blocking_mode,
        block_v4: cfg.filtering.custom_block_ipv4,
        block_v6: cfg.filtering.custom_block_ipv6,
        blocked_ttl: cfg.filtering.blocked_ttl_secs,
    })
}

/// Build the engine + cache/log/stats at startup from config.
pub async fn build_engine(cfg: &Config, paths: &Paths) -> anyhow::Result<Arc<Engine>> {
    let state = build_engine_state(cfg, paths).await?;
    let cache = Arc::new(DnsCache::new(
        cfg.cache.size,
        cfg.cache.min_ttl_secs,
        cfg.cache.max_ttl_secs,
        cfg.cache.optimistic_max_age_secs,
    ));
    cache.reconfigure(
        cfg.cache.enabled,
        cfg.cache.size,
        cfg.cache.min_ttl_secs,
        cfg.cache.max_ttl_secs,
        cfg.cache.optimistic_max_age_secs,
    );
    let log = Arc::new(QueryLog::new(
        cfg.query_log.enabled,
        cfg.privacy.anonymize_client_ips,
    ));
    let stats = Arc::new(Stats::new(
        cfg.stats.enabled,
        cfg.stats.retention_days,
        cfg.privacy.anonymize_client_ips,
    ));
    Ok(Engine::new(state, cache, log, stats))
}

/// Validate, persist, and hot-apply a new configuration.
pub async fn apply_config(state: &AppState, mut new_cfg: Config) -> anyhow::Result<()> {
    new_cfg.upstreams.normalize();
    new_cfg.validate().context("config validation")?;

    // Refresh per-list rule counts so the UI reflects reality.
    let (_engine, counts) = compile_filters(&new_cfg, &state.paths);
    for l in new_cfg.filtering.lists.iter_mut() {
        if let Some((_, n)) = counts.iter().find(|(id, _)| *id == l.id) {
            l.rule_count = *n;
        }
    }

    // Build the new engine state first (this can fail on a bad upstream/filter),
    // then persist to disk BEFORE swapping any live state. If the save fails we
    // return the error with the running engine and stored config untouched, so a
    // disk problem can't leave the engine running a config the API reported as
    // failed (and that isn't on disk for the next restart).
    let engine_state = build_engine_state(&new_cfg, &state.paths).await?;
    new_cfg.save(&state.paths.config).context("saving config")?;
    state.engine.swap_state(engine_state);

    // Reconfigure persistent components.
    state.engine.cache().reconfigure(
        new_cfg.cache.enabled,
        new_cfg.cache.size,
        new_cfg.cache.min_ttl_secs,
        new_cfg.cache.max_ttl_secs,
        new_cfg.cache.optimistic_max_age_secs,
    );
    state
        .engine
        .log()
        .reconfigure(
            new_cfg.query_log.enabled,
            new_cfg.privacy.anonymize_client_ips,
        );
    state.engine.stats().reconfigure(
        new_cfg.stats.enabled,
        new_cfg.stats.retention_days,
        new_cfg.privacy.anonymize_client_ips,
    );

    *state.config.write().await = new_cfg;
    Ok(())
}

/// Ensure the data directory and lists subdirectory exist.
pub fn ensure_dirs(paths: &Paths) -> anyhow::Result<()> {
    std::fs::create_dir_all(&paths.data_dir)
        .with_context(|| format!("creating data dir {}", paths.data_dir.display()))?;
    std::fs::create_dir_all(&paths.lists_dir)
        .with_context(|| format!("creating lists dir {}", paths.lists_dir.display()))?;
    // The data dir holds the admin password hash (config), browsing history
    // (query log), and the DNS cache — restrict it to the owner so other local
    // users can't read any of it. 0700 on the dir protects every file within.
    restrict_to_owner(&paths.data_dir);
    restrict_to_owner(&paths.lists_dir);
    Ok(())
}

/// Set `0700` (owner-only) on a directory. No-op on non-Unix; best-effort.
#[cfg(unix)]
fn restrict_to_owner(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn restrict_to_owner(_path: &std::path::Path) {}

/// Resolve an env-or-default socket override, for testing on non-privileged
/// ports without editing config.
pub fn apply_env_overrides(cfg: &mut Config) {
    if let Ok(v) = std::env::var("BULWARK_DNS_BIND") {
        if let Ok(addr) = v.parse() {
            cfg.server.dns_bind = vec![addr];
        }
    }
    if let Ok(v) = std::env::var("BULWARK_HTTP_BIND") {
        if let Ok(addr) = v.parse() {
            cfg.server.http_bind = addr;
        }
    }
}

/// Helper used by the lists API to write list text to disk.
pub fn write_list_text(paths: &Paths, id: u32, text: &str) -> std::io::Result<()> {
    std::fs::write(paths.list_file(id), text)
}
