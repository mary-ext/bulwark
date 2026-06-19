//! Disk-backed store for upstream probe telemetry (embedded SQLite via Turso).
//!
//! A sibling of the query-log [`store`](crate::store), kept deliberately
//! separate: it's an opt-in maintenance/diagnostics feature with its own DB
//! file, retention, and enable toggle, so it never touches the query log's hot
//! path or schema. The background probe loop sends [`ProbeEvent`]s to an
//! `mpsc` channel, a background writer batches them into transactions here, and
//! retention prunes the oldest. See [`crate::persist`] for the writer/pruner.
//!
//! Every Turso type stays confined to this module, mirroring [`store`].
//!
//! [`store`]: crate::store

use bulwark_upstream::{ProbeEvent, ProbeOutcome, TransportKind};
use turso::{params::Params, Builder, Connection, Value};

/// The schema. `rtt_ms`, `ewma_ms`, and `detail` are NULL when they don't apply
/// (a failed probe has no RTT; an upstream with no successful probe yet has no
/// EWMA; a clean answer has no detail). `up` is the precomputed liveness flag.
const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS probes (
        id                   INTEGER PRIMARY KEY,
        time_ms              INTEGER NOT NULL,
        upstream             TEXT NOT NULL,
        name                 TEXT NOT NULL,
        kind                 TEXT NOT NULL,
        outcome              TEXT NOT NULL,
        rtt_ms               REAL,
        ewma_ms              REAL,
        up                   INTEGER NOT NULL,
        consecutive_failures INTEGER NOT NULL,
        detail               TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_probes_time ON probes(time_ms);
    CREATE INDEX IF NOT EXISTS idx_probes_upstream ON probes(upstream);
";

// `id` is omitted so SQLite assigns the rowid, which persists on disk: after a
// restart the log keeps growing above existing rows. Plain `INSERT` so a
// (never-expected) id collision surfaces as an error rather than an overwrite.
const INSERT_SQL: &str = "INSERT INTO probes
    (time_ms, upstream, name, kind, outcome, rtt_ms, ewma_ms, up, consecutive_failures, detail)
    VALUES (?,?,?,?,?,?,?,?,?,?)";

/// Resolves every column the reader/writer depends on without returning rows, to
/// detect an incompatible pre-existing schema (see [`QueryStore`]).
///
/// [`QueryStore`]: crate::store::QueryStore
const SCHEMA_PROBE: &str = "SELECT id, time_ms, upstream, name, kind, outcome, rtt_ms, \
    ewma_ms, up, consecutive_failures, detail FROM probes LIMIT 0";

pub struct ProbeStore {
    /// All writes funnel through one connection so there is a single writer.
    write: tokio::sync::Mutex<Connection>,
    /// Reads use their own connection; WAL lets them run concurrently.
    read: Connection,
}

impl ProbeStore {
    /// Open (creating if needed) the store at `path`. Pass `":memory:"` for a
    /// non-persistent log. Like the query store, an unusable on-disk DB (corrupt
    /// or schema-incompatible) is wiped and recreated rather than failing startup
    /// — probe telemetry is pure diagnostics, never a reason to refuse to boot.
    pub async fn open(path: &str) -> turso::Result<Self> {
        match Self::try_open(path).await {
            Ok(store) => Ok(store),
            Err(e) if path != ":memory:" => {
                tracing::warn!(error = %e, path, "probe log DB unusable; recreating from scratch");
                reset_db_files(path);
                Self::try_open(path).await
            }
            Err(e) => Err(e),
        }
    }

    async fn try_open(path: &str) -> turso::Result<Self> {
        let db = Builder::new_local(path).build().await?;
        let write = db.connect()?;
        write.execute_batch(SCHEMA).await?;
        // Probe that a pre-existing table actually has our columns.
        write.query(SCHEMA_PROBE, ()).await?;
        let read = db.connect()?;
        Ok(Self {
            write: tokio::sync::Mutex::new(write),
            read,
        })
    }

    /// Insert a batch of events in one transaction, reusing one prepared
    /// statement. On any failure the whole transaction rolls back, so a bad batch
    /// never leaves the writer connection stuck in an open, failed transaction.
    pub async fn insert_batch(&self, events: &[ProbeEvent]) -> turso::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let conn = self.write.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        match Self::insert_all(&conn, events).await {
            Ok(()) => {
                conn.execute("COMMIT", ()).await?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", ()).await;
                Err(e)
            }
        }
    }

    async fn insert_all(conn: &Connection, events: &[ProbeEvent]) -> turso::Result<()> {
        let mut stmt = conn.prepare(INSERT_SQL).await?;
        for e in events {
            stmt.execute(insert_params(e)).await?;
        }
        Ok(())
    }

    /// Delete every event older than `cutoff_ms`. Returns the number removed.
    pub async fn delete_older_than(&self, cutoff_ms: i64) -> turso::Result<u64> {
        let conn = self.write.lock().await;
        conn.execute(
            "DELETE FROM probes WHERE time_ms < ?1",
            Params::Positional(vec![Value::Integer(cutoff_ms)]),
        )
        .await
    }

    /// The most recent `limit` events, newest first, optionally only those at or
    /// after `since_ms`. The reading half of the export: a caller serializes the
    /// returned events to JSONL (or charts them) however it likes.
    pub async fn recent(&self, since_ms: Option<i64>, limit: usize) -> turso::Result<Vec<ProbeEvent>> {
        let (where_sql, params): (&str, Vec<Value>) = match since_ms {
            Some(ms) => (" WHERE time_ms >= ?1", vec![Value::Integer(ms)]),
            None => ("", Vec::new()),
        };
        let n = params.len() + 1;
        let sql = format!(
            "SELECT time_ms, upstream, name, kind, outcome, rtt_ms, ewma_ms, up, \
             consecutive_failures, detail FROM probes{where_sql} ORDER BY id DESC LIMIT ?{n}"
        );
        let mut params = params;
        params.push(Value::Integer(limit as i64));
        let mut rows = self.read.query(&sql, Params::Positional(params)).await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(row_to_event(&row)?);
        }
        Ok(out)
    }
}

/// Bind a [`ProbeEvent`] to the INSERT statement's positional params.
fn insert_params(e: &ProbeEvent) -> Params {
    Params::Positional(vec![
        Value::Integer(e.time_ms),
        Value::Text(e.upstream.clone()),
        Value::Text(e.name.clone()),
        Value::Text(e.kind.as_str().into()),
        Value::Text(e.outcome.as_str().into()),
        e.rtt_ms.map(Value::Real).unwrap_or(Value::Null),
        e.ewma_ms.map(Value::Real).unwrap_or(Value::Null),
        Value::Integer(e.up as i64),
        Value::Integer(e.consecutive_failures as i64),
        e.detail.clone().map(Value::Text).unwrap_or(Value::Null),
    ])
}

/// Reconstruct a [`ProbeEvent`] from a result row. Column order matches the
/// SELECT in [`ProbeStore::recent`].
fn row_to_event(row: &turso::Row) -> turso::Result<ProbeEvent> {
    Ok(ProbeEvent {
        time_ms: row.get(0)?,
        upstream: row.get(1)?,
        name: row.get(2)?,
        kind: TransportKind::from_label(&row.get::<String>(3)?),
        outcome: ProbeOutcome::from_label(&row.get::<String>(4)?),
        rtt_ms: opt_real(row.get_value(5)?),
        ewma_ms: opt_real(row.get_value(6)?),
        up: row.get::<i64>(7)? != 0,
        consecutive_failures: row.get::<i64>(8)? as u32,
        detail: opt_text(row.get_value(9)?),
    })
}

fn opt_real(v: Value) -> Option<f64> {
    match v {
        Value::Real(r) => Some(r),
        // We only ever write REAL/NULL, but tolerate an INTEGER (e.g. a
        // hand-edited DB) rather than silently dropping it to None.
        Value::Integer(i) => Some(i as f64),
        _ => None,
    }
}

fn opt_text(v: Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s),
        _ => None,
    }
}

/// Remove a SQLite DB file and its WAL/journal sidecars so a corrupt or
/// incompatible probe-log DB can be recreated clean. Best-effort.
fn reset_db_files(path: &str) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(format!("{path}{suffix}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(time_ms: i64, outcome: ProbeOutcome, rtt: Option<f64>) -> ProbeEvent {
        ProbeEvent {
            time_ms,
            upstream: "udp://1.1.1.1:53".into(),
            name: "cloudflare".into(),
            kind: TransportKind::Udp,
            outcome,
            rtt_ms: rtt,
            ewma_ms: rtt,
            up: outcome == ProbeOutcome::Answer,
            consecutive_failures: if outcome == ProbeOutcome::Answer { 0 } else { 1 },
            detail: (outcome != ProbeOutcome::Answer).then(|| "Timeout".to_string()),
        }
    }

    #[tokio::test]
    async fn round_trips_events_newest_first() {
        let store = ProbeStore::open(":memory:").await.unwrap();
        store
            .insert_batch(&[
                event(1, ProbeOutcome::Answer, Some(12.0)),
                event(2, ProbeOutcome::Timeout, None),
                event(3, ProbeOutcome::Answer, Some(15.0)),
            ])
            .await
            .unwrap();

        let all = store.recent(None, 100).await.unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].time_ms, 3, "newest first");
        // A failed probe round-trips with NULL rtt and a populated detail.
        let timeout = all.iter().find(|e| e.outcome == ProbeOutcome::Timeout).unwrap();
        assert!(timeout.rtt_ms.is_none());
        assert!(!timeout.up);
        assert_eq!(timeout.detail.as_deref(), Some("Timeout"));
        // A clean answer keeps its RTT/EWMA and has no detail.
        let answer = &all[0];
        assert_eq!(answer.rtt_ms, Some(15.0));
        assert_eq!(answer.kind, TransportKind::Udp);
        assert!(answer.detail.is_none());
    }

    #[tokio::test]
    async fn since_filter_and_retention() {
        let store = ProbeStore::open(":memory:").await.unwrap();
        store
            .insert_batch(&[
                event(10, ProbeOutcome::Answer, Some(1.0)),
                event(20, ProbeOutcome::Answer, Some(2.0)),
                event(30, ProbeOutcome::Answer, Some(3.0)),
            ])
            .await
            .unwrap();

        // `since` keeps only events at or after the cutoff.
        let recent = store.recent(Some(20), 100).await.unwrap();
        assert_eq!(recent.len(), 2);

        // Retention drops events strictly older than the cutoff.
        let removed = store.delete_older_than(20).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.recent(None, 100).await.unwrap().len(), 2);
    }
}
