//! On-disk persistence for statistics (periodic JSON snapshot) and the
//! background plumbing for the disk-backed query-log store (see
//! [`crate::store`]): the writer that batches entries into the database and the
//! periodic retention pruner.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bulwark_engine::querylog::QueryLogEntry;
use bulwark_engine::Engine;
use tokio::sync::mpsc::Receiver;

use crate::store::QueryStore;

/// Bound on the query-log writer channel. Caps how many log entries can queue
/// ahead of the background writer before the DNS hot path sheds them (see
/// [`bulwark_engine::querylog::QueryLog::push`]), so a stalled or slow writer
/// can't grow memory without limit.
pub const QUERYLOG_CHANNEL_CAP: usize = 16_384;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Spawn the background writer that batches new log entries into the store.
pub fn spawn_querylog_writer(
    store: Arc<QueryStore>,
    mut rx: Receiver<QueryLogEntry>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Some(first) = rx.recv().await else {
                break;
            };
            // Drain whatever is queued and write as one transaction.
            let mut batch = vec![first];
            while let Ok(e) = rx.try_recv() {
                batch.push(e);
                if batch.len() >= 512 {
                    break;
                }
            }
            if let Err(e) = store.insert_batch(&batch).await {
                tracing::warn!(error = %e, "query log batch insert failed");
            }
        }
    })
}

/// Periodically delete query-log entries older than the retention window.
pub fn spawn_querylog_pruner(
    store: Arc<QueryStore>,
    config: Arc<tokio::sync::RwLock<bulwark_config::Config>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        tick.tick().await; // skip immediate
        loop {
            tick.tick().await;
            let retention = config.read().await.query_log.retention_days;
            // 0 disables time-based pruning.
            if retention == 0 {
                continue;
            }
            let cutoff = now_ms() - (retention as i64) * 86_400_000;
            match store.delete_older_than(cutoff).await {
                Ok(n) if n > 0 => tracing::debug!(removed = n, "pruned old query-log entries"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "query log prune failed"),
            }
        }
    })
}

/// Load a persisted stats snapshot into the engine, if present.
pub fn load_stats(path: &Path, engine: &Engine) {
    if let Ok(text) = std::fs::read_to_string(path) {
        engine.stats().import(&text);
    }
}

/// Periodically snapshot statistics to disk.
pub fn spawn_stats_snapshotter(
    engine: Arc<Engine>,
    path: PathBuf,
    config: Arc<tokio::sync::RwLock<bulwark_config::Config>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if config.read().await.stats.persist {
                let json = engine.stats().export();
                let tmp = path.with_extension("json.tmp");
                if std::fs::write(&tmp, json.as_bytes()).is_ok() {
                    let _ = std::fs::rename(&tmp, &path);
                }
            }
        }
    })
}

/// Write the current stats snapshot synchronously (used on shutdown).
pub fn snapshot_stats_now(engine: &Engine, path: &Path) {
    let json = engine.stats().export();
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, json.as_bytes()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// How often the DNS cache is snapshotted to disk. The cache rewarms itself on
/// demand (serve-stale + background refresh), so this only bounds how much of a
/// warm cache a hard crash can cost us; a generous interval keeps the periodic
/// full-shard walk cheap.
const CACHE_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(300);

/// Restore a persisted DNS cache snapshot into the engine, if present. Must run
/// after the cache's TTL/stale config is applied so expiry is judged correctly.
pub fn load_cache(path: &Path, engine: &Engine) {
    let Ok(blob) = std::fs::read(path) else {
        return; // no snapshot yet (or unreadable) — start cold.
    };
    let n = engine.cache().import_snapshot(&blob);
    if n > 0 {
        tracing::info!(entries = n, "restored DNS cache from snapshot");
    }
}

/// Write the cache snapshot to `path` atomically (temp file + rename), so a
/// crash mid-write never leaves a torn snapshot — readers see the old file or
/// the complete new one. Skips writing while the cache is disabled so a
/// temporary disable doesn't clobber a good snapshot with an empty one.
fn snapshot_cache_to(engine: &Engine, path: &Path) {
    if !engine.cache().is_enabled() {
        return;
    }
    let blob = engine.cache().export_snapshot();
    let tmp = path.with_extension("snap.tmp");
    if std::fs::write(&tmp, &blob).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Periodically snapshot the DNS cache to disk.
pub fn spawn_cache_snapshotter(engine: Arc<Engine>, path: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CACHE_SNAPSHOT_INTERVAL);
        tick.tick().await; // skip the immediate tick.
        loop {
            tick.tick().await;
            snapshot_cache_to(&engine, &path);
        }
    })
}

/// Write the current cache snapshot synchronously (used on shutdown).
pub fn snapshot_cache_now(engine: &Engine, path: &Path) {
    snapshot_cache_to(engine, path);
}
