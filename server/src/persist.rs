//! On-disk persistence for the query log (append-only JSONL) and statistics
//! (periodic JSON snapshot), each with its own retention.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bulwark_engine::querylog::QueryLogEntry;
use bulwark_engine::Engine;
use tokio::sync::mpsc::UnboundedReceiver;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Load persisted query-log entries newer than `retention_days`, pruning the
/// file to those entries. Returns them oldest-first.
pub fn load_and_prune_querylog(path: &Path, retention_days: u32) -> Vec<QueryLogEntry> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let cutoff = if retention_days == 0 {
        0
    } else {
        now_ms() - (retention_days as i64) * 86_400_000
    };
    let mut kept: Vec<QueryLogEntry> = BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str::<QueryLogEntry>(&line).ok())
        .filter(|e| e.time_ms >= cutoff)
        .collect();

    // Bound memory: keep only the most recent ~200k lines on load.
    const MAX_LOAD: usize = 200_000;
    if kept.len() > MAX_LOAD {
        kept.drain(0..kept.len() - MAX_LOAD);
    }

    // Rewrite the (pruned) file atomically.
    if let Err(e) = rewrite_jsonl(path, &kept) {
        tracing::warn!(error = %e, "failed to prune query log file");
    }
    kept
}

fn rewrite_jsonl(path: &Path, entries: &[QueryLogEntry]) -> std::io::Result<()> {
    let tmp = path.with_extension("jsonl.tmp");
    {
        let mut w = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        for e in entries {
            if let Ok(line) = serde_json::to_string(e) {
                writeln!(w, "{line}")?;
            }
        }
        w.flush()?;
    }
    std::fs::rename(&tmp, path)
}

/// Spawn the background writer that appends new log entries to disk.
pub fn spawn_querylog_writer(
    path: PathBuf,
    mut rx: UnboundedReceiver<QueryLogEntry>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Open in append mode; recreate if missing.
        loop {
            let Some(first) = rx.recv().await else {
                break;
            };
            // Drain whatever is queued and write as a batch.
            let mut batch = vec![first];
            while let Ok(e) = rx.try_recv() {
                batch.push(e);
                if batch.len() >= 512 {
                    break;
                }
            }
            if let Err(e) = append_batch(&path, &batch) {
                tracing::warn!(error = %e, "query log append failed");
            }
        }
    })
}

fn append_batch(path: &Path, batch: &[QueryLogEntry]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let mut buf = String::new();
    for e in batch {
        if let Ok(line) = serde_json::to_string(e) {
            buf.push_str(&line);
            buf.push('\n');
        }
    }
    f.write_all(buf.as_bytes())
}

/// Periodically prune the query-log file to the retention window.
pub fn spawn_querylog_pruner(
    path: PathBuf,
    config: Arc<tokio::sync::RwLock<bulwark_config::Config>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        tick.tick().await; // skip immediate
        loop {
            tick.tick().await;
            let (persist, retention) = {
                let c = config.read().await;
                (c.query_log.persist, c.query_log.retention_days)
            };
            if persist {
                let p = path.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    load_and_prune_querylog(&p, retention);
                })
                .await;
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
