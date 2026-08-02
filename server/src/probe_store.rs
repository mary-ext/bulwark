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

use bulwark_upstream::{ProbeErrorKind, ProbeEvent, ProbeOutcome, TransportKind};
use turso::{params::Params, Builder, Connection, Value};

/// The schema. `rtt_ms`, `first_rtt_ms`, `ewma_ms`, `detail`, `error_kind`,
/// `live_ewma_ms`, and `rank` are NULL when they don't apply (a failed probe has
/// no RTT; a probe whose first shot failed has no first RTT either; an upstream
/// with no successful probe yet has no EWMA; a clean answer has no detail/error
/// kind; an upstream with no live traffic has no live EWMA; an unranked one has
/// no rank). `up` and `lead_held` are precomputed boolean flags; `live_queries`/
/// `live_failures` are cumulative real-traffic counters at probe time.
const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS probes (
        id                   INTEGER PRIMARY KEY,
        time_ms              INTEGER NOT NULL,
        upstream             TEXT NOT NULL,
        name                 TEXT NOT NULL,
        kind                 TEXT NOT NULL,
        outcome              TEXT NOT NULL,
        rtt_ms               REAL,
        first_rtt_ms         REAL,
        ewma_ms              REAL,
        up                   INTEGER NOT NULL,
        consecutive_failures INTEGER NOT NULL,
        detail               TEXT,
        error_kind           TEXT,
        live_ewma_ms         REAL,
        live_queries         INTEGER NOT NULL,
        live_failures        INTEGER NOT NULL,
        rank                 INTEGER,
        lead_held            INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_probes_time ON probes(time_ms);
    CREATE INDEX IF NOT EXISTS idx_probes_upstream ON probes(upstream);
";

// `id` is omitted so SQLite assigns the rowid, which persists on disk: after a
// restart the log keeps growing above existing rows. Plain `INSERT` so a
// (never-expected) id collision surfaces as an error rather than an overwrite.
const INSERT_SQL: &str = "INSERT INTO probes
    (time_ms, upstream, name, kind, outcome, rtt_ms, first_rtt_ms, ewma_ms, up, \
     consecutive_failures, detail, error_kind, live_ewma_ms, live_queries, live_failures, rank, \
     lead_held)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

/// The columns the reader/writer depend on, in row order. Shared by the export
/// and `recent` reads and the schema-compatibility probe so they can't drift.
const COLUMNS: &str = "time_ms, upstream, name, kind, outcome, rtt_ms, first_rtt_ms, ewma_ms, up, \
    consecutive_failures, detail, error_kind, live_ewma_ms, live_queries, live_failures, \
    rank, lead_held";

/// Columns added after the table's first release, applied to a pre-existing DB
/// before the compatibility probe runs. Each is `ALTER TABLE … ADD COLUMN`, whose
/// error on an already-current table is expected and ignored — that is what makes
/// this idempotent. Without it, an added column would fail [`SCHEMA_PROBE`] and
/// route [`ProbeStore::open`] to wipe the file; the log's whole value is the
/// months of history that would destroy.
///
/// Only additive, nullable columns belong here. A change the reader can't take
/// (a dropped or retyped column) should still fall through to the recreate path.
const MIGRATIONS: &[&str] = &["ALTER TABLE probes ADD COLUMN first_rtt_ms REAL"];

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
        // Bring an older table up to the current columns. Each statement errors
        // if it has already been applied, which is the idempotency check.
        for sql in MIGRATIONS {
            let _ = write.execute(*sql, ()).await;
        }
        // Probe that the table really resolves every column the reader needs,
        // built from the same list the reads use so the two can't drift.
        let compat = format!("SELECT id, {COLUMNS} FROM probes LIMIT 0");
        write.query(&compat, ()).await?;
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

    /// Remove all events.
    pub async fn clear(&self) -> turso::Result<()> {
        let conn = self.write.lock().await;
        conn.execute("DELETE FROM probes", ()).await?;
        Ok(())
    }

    /// Every event as newline-delimited JSON, oldest first — the natural log-file
    /// order for an export/download. Probe telemetry is low-volume (≈ one row per
    /// upstream per minute), so materializing the whole table as one string is
    /// fine for the deployments this runs on.
    pub async fn export_jsonl(&self) -> turso::Result<String> {
        let sql = format!("SELECT {COLUMNS} FROM probes ORDER BY id ASC");
        let mut rows = self.read.query(&sql, ()).await?;
        let mut out = String::new();
        while let Some(row) = rows.next().await? {
            let event = row_to_event(&row)?;
            if let Ok(line) = serde_json::to_string(&event) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        Ok(out)
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
            "SELECT {COLUMNS} FROM probes{where_sql} ORDER BY id DESC LIMIT ?{n}"
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
        e.first_rtt_ms.map(Value::Real).unwrap_or(Value::Null),
        e.ewma_ms.map(Value::Real).unwrap_or(Value::Null),
        Value::Integer(e.up as i64),
        Value::Integer(e.consecutive_failures as i64),
        e.detail.clone().map(Value::Text).unwrap_or(Value::Null),
        e.error_kind
            .map(|k| Value::Text(k.as_str().into()))
            .unwrap_or(Value::Null),
        e.live_ewma_ms.map(Value::Real).unwrap_or(Value::Null),
        Value::Integer(e.live_queries as i64),
        Value::Integer(e.live_failures as i64),
        e.rank.map(|r| Value::Integer(r as i64)).unwrap_or(Value::Null),
        Value::Integer(e.lead_held as i64),
    ])
}

/// Reconstruct a [`ProbeEvent`] from a result row. Column order matches
/// [`COLUMNS`] (the shared SELECT list).
fn row_to_event(row: &turso::Row) -> turso::Result<ProbeEvent> {
    Ok(ProbeEvent {
        time_ms: row.get(0)?,
        upstream: row.get(1)?,
        name: row.get(2)?,
        kind: TransportKind::from_label(&row.get::<String>(3)?),
        outcome: ProbeOutcome::from_label(&row.get::<String>(4)?),
        rtt_ms: opt_real(row.get_value(5)?),
        first_rtt_ms: opt_real(row.get_value(6)?),
        ewma_ms: opt_real(row.get_value(7)?),
        up: row.get::<i64>(8)? != 0,
        consecutive_failures: row.get::<i64>(9)? as u32,
        detail: opt_text(row.get_value(10)?),
        error_kind: opt_text(row.get_value(11)?).map(|s| ProbeErrorKind::from_label(&s)),
        live_ewma_ms: opt_real(row.get_value(12)?),
        live_queries: row.get::<i64>(13)? as u64,
        live_failures: row.get::<i64>(14)? as u64,
        rank: opt_int(row.get_value(15)?).map(|i| i as u16),
        lead_held: row.get::<i64>(16)? != 0,
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

fn opt_int(v: Value) -> Option<i64> {
    match v {
        Value::Integer(i) => Some(i),
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
        let answered = outcome == ProbeOutcome::Answer;
        ProbeEvent {
            time_ms,
            upstream: "udp://1.1.1.1:53".into(),
            name: "cloudflare".into(),
            kind: TransportKind::Udp,
            outcome,
            rtt_ms: rtt,
            // The first shot pays the handshake the second one skips.
            first_rtt_ms: rtt.map(|r| r + 30.0),
            ewma_ms: rtt,
            up: answered,
            consecutive_failures: if answered { 0 } else { 1 },
            detail: (!answered).then(|| "Timeout".to_string()),
            error_kind: (!answered).then_some(ProbeErrorKind::Timeout),
            live_ewma_ms: Some(30.0),
            live_queries: 42,
            live_failures: 2,
            rank: Some(0),
            lead_held: false,
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
        // A failed probe round-trips with NULL rtt, a populated detail, and a
        // structured error kind.
        let timeout = all.iter().find(|e| e.outcome == ProbeOutcome::Timeout).unwrap();
        assert!(timeout.rtt_ms.is_none());
        assert!(timeout.first_rtt_ms.is_none());
        assert!(!timeout.up);
        assert_eq!(timeout.detail.as_deref(), Some("Timeout"));
        assert_eq!(timeout.error_kind, Some(ProbeErrorKind::Timeout));
        // A clean answer keeps its RTT/EWMA and has no detail/error kind.
        let answer = &all[0];
        assert_eq!(answer.rtt_ms, Some(15.0));
        // Both shots round-trip, so analysis can recover the setup cost.
        assert_eq!(answer.first_rtt_ms, Some(45.0));
        assert_eq!(answer.kind, TransportKind::Udp);
        assert!(answer.detail.is_none());
        assert!(answer.error_kind.is_none());
        // The live-traffic snapshot and selection fields survive the round-trip.
        assert_eq!(answer.live_ewma_ms, Some(30.0));
        assert_eq!(answer.live_queries, 42);
        assert_eq!(answer.live_failures, 2);
        assert_eq!(answer.rank, Some(0));
        assert!(!answer.lead_held);
    }

    #[tokio::test]
    async fn added_column_migrates_without_discarding_history() {
        // A probe DB written before `first_rtt_ms` existed must survive the
        // upgrade. The log's whole value is its months of history, so an added
        // column has to migrate in place rather than fall through to the
        // wipe-and-recreate path that `open` keeps for genuinely unreadable DBs.
        let dir = std::env::temp_dir().join(format!("bulwark-probe-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("probes.db");
        let path_str = path.to_str().unwrap();
        reset_db_files(path_str);

        // Build the pre-migration table by hand, minus the new column.
        let old_schema = SCHEMA.replace("first_rtt_ms         REAL,\n", "");
        assert!(!old_schema.contains("first_rtt_ms"), "old schema lacks the column");
        let db = Builder::new_local(path_str).build().await.unwrap();
        let conn = db.connect().unwrap();
        conn.execute_batch(&old_schema).await.unwrap();
        conn.execute(
            "INSERT INTO probes (time_ms, upstream, name, kind, outcome, rtt_ms, ewma_ms, up, \
             consecutive_failures, live_queries, live_failures, lead_held) \
             VALUES (7, 'udp://1.1.1.1:53', 'cloudflare', 'udp', 'answer', 12.0, 12.0, 1, 0, 5, 0, 0)",
            (),
        )
        .await
        .unwrap();
        drop(conn);
        drop(db);

        // Reopening with the current code migrates rather than recreating.
        let store = ProbeStore::open(path_str).await.unwrap();
        let all = store.recent(None, 100).await.unwrap();
        assert_eq!(all.len(), 1, "the pre-migration row survived the upgrade");
        assert_eq!(all[0].time_ms, 7);
        assert_eq!(all[0].rtt_ms, Some(12.0));
        assert!(all[0].first_rtt_ms.is_none(), "rows predating the column read as NULL");

        // New rows carry the column, and a second open is a no-op.
        store.insert_batch(&[event(8, ProbeOutcome::Answer, Some(20.0))]).await.unwrap();
        drop(store);
        let store = ProbeStore::open(path_str).await.unwrap();
        let all = store.recent(None, 100).await.unwrap();
        assert_eq!(all.len(), 2, "reopening an already-migrated DB keeps both rows");
        assert_eq!(all[0].first_rtt_ms, Some(50.0));
        reset_db_files(path_str);
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
