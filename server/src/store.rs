//! SQLite-backed query-log storage.

use bulwark_engine::clients::ClientMatcher;
use bulwark_engine::querylog::{LogFilter, LogPage, QueryAction, QueryLogEntry};
use turso::{params::Params, Builder, Connection, Value};

/// Query-log schema. Outcome-specific columns are nullable.
const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS queries (
        id          INTEGER PRIMARY KEY,
        time_ms     INTEGER NOT NULL,
        client_ip   TEXT NOT NULL,
        question    TEXT NOT NULL,
        qtype       TEXT NOT NULL,
        action      TEXT NOT NULL,
        blocked     INTEGER NOT NULL,
        upstream    TEXT,
        rule        TEXT,
        list_id     INTEGER,
        allowlisted INTEGER NOT NULL,
        rcode       TEXT NOT NULL,
        answers     TEXT NOT NULL,
        elapsed_ms  REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_queries_time ON queries(time_ms);
    CREATE INDEX IF NOT EXISTS idx_queries_client ON queries(client_ip);
    CREATE INDEX IF NOT EXISTS idx_queries_blocked ON queries(id) WHERE blocked = 1;
";

// SQLite assigns the persistent row ID.
const INSERT_SQL: &str = "INSERT INTO queries
    (time_ms, client_ip, question, qtype, action, blocked,
     upstream, rule, list_id, allowlisted, rcode, answers, elapsed_ms)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";

/// Validates the columns used by reads and writes.
const SCHEMA_PROBE: &str = "SELECT id, time_ms, client_ip, question, qtype, action, \
    blocked, upstream, rule, list_id, allowlisted, rcode, answers, elapsed_ms \
    FROM queries LIMIT 0";

pub struct QueryStore {
    /// Serialized write connection.
    write: tokio::sync::Mutex<Connection>,
    /// Concurrent read connection.
    read: Connection,
}

impl QueryStore {
    /// Opens a store, recreating an unusable on-disk database.
    pub async fn open(path: &str) -> turso::Result<Self> {
        match Self::try_open(path).await {
            Ok(store) => Ok(store),
            Err(e) if path != ":memory:" => {
                tracing::warn!(error = %e, path, "query log DB unusable; recreating from scratch");
                reset_db_files(path);
                Self::try_open(path).await
            }
            Err(e) => Err(e),
        }
    }

    /// Opens, initializes, and validates a database.
    async fn try_open(path: &str) -> turso::Result<Self> {
        let db = Builder::new_local(path).build().await?;
        let write = db.connect()?;
        write.execute_batch(SCHEMA).await?;
        write.query(SCHEMA_PROBE, ()).await?;
        let read = db.connect()?;
        Ok(Self {
            write: tokio::sync::Mutex::new(write),
            read,
        })
    }

    /// Inserts a batch atomically.
    pub async fn insert_batch(&self, entries: &[QueryLogEntry]) -> turso::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let conn = self.write.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        match Self::insert_all(&conn, entries).await {
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

    /// Inserts entries within the caller's transaction.
    async fn insert_all(conn: &Connection, entries: &[QueryLogEntry]) -> turso::Result<()> {
        let mut stmt = conn.prepare(INSERT_SQL).await?;
        for e in entries {
            stmt.execute(insert_params(e)).await?;
        }
        Ok(())
    }

    /// Delete every entry older than `cutoff_ms`. Returns the number removed.
    pub async fn delete_older_than(&self, cutoff_ms: i64) -> turso::Result<u64> {
        let conn = self.write.lock().await;
        conn.execute(
            "DELETE FROM queries WHERE time_ms < ?1",
            Params::Positional(vec![Value::Integer(cutoff_ms)]),
        )
        .await
    }

    /// Remove all entries.
    pub async fn clear(&self) -> turso::Result<()> {
        let conn = self.write.lock().await;
        conn.execute("DELETE FROM queries", ()).await?;
        Ok(())
    }

    /// Queries newest-first with filtering, pagination, and a total count.
    pub async fn query(
        &self,
        filter: &LogFilter,
        offset: usize,
        limit: usize,
        clients: &ClientMatcher,
    ) -> turso::Result<LogPage> {
        let (where_sql, mut params) = self.build_where(filter, clients).await?;

        let count_sql = format!("SELECT COUNT(*) FROM queries{where_sql}");
        let total: i64 = self
            .read
            .query(&count_sql, Params::Positional(params.clone()))
            .await?
            .next()
            .await?
            .map(|r| r.get(0))
            .transpose()?
            .unwrap_or(0);

        // Keep pagination placeholders after filter parameters.
        let limit_n = params.len() + 1;
        let offset_n = params.len() + 2;
        let page_sql = format!(
            "SELECT id, time_ms, client_ip, question, qtype, action, upstream, \
             rule, list_id, allowlisted, rcode, answers, elapsed_ms \
             FROM queries{where_sql} ORDER BY id DESC LIMIT ?{limit_n} OFFSET ?{offset_n}"
        );
        params.push(Value::Integer(limit as i64));
        params.push(Value::Integer(offset as i64));
        let mut rows = self
            .read
            .query(&page_sql, Params::Positional(params))
            .await?;
        let mut entries = Vec::new();
        while let Some(row) = rows.next().await? {
            entries.push(row_to_entry(&row)?);
        }

        Ok(LogPage {
            entries,
            total: total.max(0) as usize,
        })
    }

    /// Build the shared `WHERE` clause (with leading " WHERE " or empty) and its
    /// positional params for both the count and the page query.
    async fn build_where(
        &self,
        filter: &LogFilter,
        clients: &ClientMatcher,
    ) -> turso::Result<(String, Vec<Value>)> {
        let mut clauses: Vec<String> = Vec::new();
        let mut params: Vec<Value> = Vec::new();

        if filter.blocked_only {
            clauses.push("blocked = 1".into());
        }
        if let Some(search) = filter.search.as_deref().filter(|s| !s.is_empty()) {
            params.push(Value::Text(format!("%{}%", like_escape(search))));
            clauses.push(format!("question LIKE ?{} ESCAPE '\\'", params.len()));
        }
        if let Some(client) = filter.client.as_deref().filter(|s| !s.is_empty()) {
            params.push(Value::Text(format!("%{}%", like_escape(client))));
            let ip_like = format!("client_ip LIKE ?{} ESCAPE '\\'", params.len());

            // Resolve CIDR-backed names against IPs present in the log.
            let needle = client.to_ascii_lowercase();
            let name_ips = self.distinct_client_ips_matching(clients, &needle).await?;
            if name_ips.is_empty() {
                clauses.push(ip_like);
            } else {
                let start = params.len();
                let placeholders: Vec<String> = name_ips
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!("?{}", start + i + 1))
                    .collect();
                for ip in name_ips {
                    params.push(Value::Text(ip));
                }
                clauses.push(format!(
                    "({ip_like} OR client_ip IN ({}))",
                    placeholders.join(", ")
                ));
            }
        }

        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", clauses.join(" AND "))
        };
        Ok((where_sql, params))
    }

    /// Finds stored IPs whose current client name contains `needle`.
    async fn distinct_client_ips_matching(
        &self,
        clients: &ClientMatcher,
        needle: &str,
    ) -> turso::Result<Vec<String>> {
        let mut rows = self
            .read
            .query("SELECT DISTINCT client_ip FROM queries", ())
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            let ip: String = row.get(0)?;
            if clients
                .name_for_str(&ip)
                .is_some_and(|n| n.to_ascii_lowercase().contains(needle))
            {
                out.push(ip);
            }
        }
        Ok(out)
    }
}

/// Bind a [`QueryLogEntry`] to the INSERT statement's positional params.
fn insert_params(e: &QueryLogEntry) -> Params {
    let (action, upstream, rule, list_id) = match &e.action {
        QueryAction::Forwarded { upstream } => ("forwarded", Some(upstream.clone()), None, None),
        QueryAction::Cached => ("cached", None, None, None),
        QueryAction::Blocked { rule, list_id } => {
            ("blocked", None, Some(rule.clone()), Some(*list_id))
        }
        QueryAction::Rewritten { rule, list_id } => {
            ("rewritten", None, Some(rule.clone()), Some(*list_id))
        }
        QueryAction::Error => ("error", None, None, None),
    };
    Params::Positional(vec![
        Value::Integer(e.time_ms),
        Value::Text(e.client_ip.clone()),
        Value::Text(e.question.clone()),
        Value::Text(e.qtype.to_string()),
        Value::Text(action.into()),
        Value::Integer(e.is_blocked() as i64),
        upstream.map(Value::Text).unwrap_or(Value::Null),
        rule.map(Value::Text).unwrap_or(Value::Null),
        list_id
            .map(|v| Value::Integer(v as i64))
            .unwrap_or(Value::Null),
        Value::Integer(e.allowlisted as i64),
        Value::Text(e.rcode.to_string()),
        Value::Text(serde_json::to_string(&e.answers).unwrap_or_else(|_| "[]".into())),
        Value::Real(e.elapsed_ms),
    ])
}

/// Reconstruct a [`QueryLogEntry`] from a result row. Column order matches the
/// SELECT in [`QueryStore::query`].
fn row_to_entry(row: &turso::Row) -> turso::Result<QueryLogEntry> {
    let action_str: String = row.get(5)?;
    let upstream = opt_text(row.get_value(6)?);
    let rule = opt_text(row.get_value(7)?);
    let list_id = opt_int(row.get_value(8)?).map(|v| v as u32);
    let action = match action_str.as_str() {
        "forwarded" => QueryAction::Forwarded {
            upstream: upstream.unwrap_or_default(),
        },
        "blocked" => QueryAction::Blocked {
            rule: rule.unwrap_or_default(),
            list_id: list_id.unwrap_or(0),
        },
        "rewritten" => QueryAction::Rewritten {
            rule: rule.unwrap_or_default(),
            list_id: list_id.unwrap_or(0),
        },
        "error" => QueryAction::Error,
        _ => QueryAction::Cached,
    };
    let answers: std::sync::Arc<[String]> = row
        .get::<String>(11)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| std::sync::Arc::from([]));
    Ok(QueryLogEntry {
        id: row.get::<i64>(0)? as u64,
        time_ms: row.get(1)?,
        client_ip: row.get(2)?,
        question: row.get(3)?,
        qtype: row.get::<String>(4)?.into(),
        action,
        allowlisted: row.get::<i64>(9)? != 0,
        rcode: row.get::<String>(10)?.into(),
        answers,
        elapsed_ms: row.get(12)?,
    })
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

/// Removes a database and its sidecars, best effort.
fn reset_db_files(path: &str) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(format!("{path}{suffix}"));
    }
}

/// Escape the LIKE metacharacters in a user-supplied substring so it matches
/// literally (paired with `ESCAPE '\'`).
fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulwark_config::ClientConfig;

    fn entry(id: u64, question: &str, client_ip: &str, blocked: bool) -> QueryLogEntry {
        QueryLogEntry {
            id,
            time_ms: id as i64,
            client_ip: client_ip.into(),
            question: question.into(),
            qtype: "A".into(),
            action: if blocked {
                QueryAction::Blocked {
                    rule: "||ads^".into(),
                    list_id: 3,
                }
            } else {
                QueryAction::Forwarded {
                    upstream: "1.1.1.1".into(),
                }
            },
            allowlisted: false,
            rcode: "NOERROR".into(),
            answers: std::sync::Arc::from(["A 1.2.3.4".to_string()]),
            elapsed_ms: 0.5,
        }
    }

    async fn store_with(entries: &[QueryLogEntry]) -> QueryStore {
        let store = QueryStore::open(":memory:").await.unwrap();
        store.insert_batch(entries).await.unwrap();
        store
    }

    async fn page(store: &QueryStore, filter: LogFilter, clients: &ClientMatcher) -> LogPage {
        store.query(&filter, 0, 100, clients).await.unwrap()
    }

    #[tokio::test]
    async fn newest_first_with_pagination_total() {
        let entries: Vec<_> = (0..5)
            .map(|i| entry(i, "x.com", "10.0.0.1", false))
            .collect();
        let store = store_with(&entries).await;
        let clients = ClientMatcher::default();

        let p = store
            .query(&LogFilter::default(), 0, 2, &clients)
            .await
            .unwrap();
        assert_eq!(p.total, 5, "total counts all matches, not just the page");
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.entries[0].time_ms, 4, "newest first");
        assert_eq!(p.entries[1].time_ms, 3);
        assert!(
            p.entries[0].id > p.entries[1].id,
            "ids descend with recency"
        );
        let p2 = store
            .query(&LogFilter::default(), 2, 2, &clients)
            .await
            .unwrap();
        assert_eq!(p2.entries[0].time_ms, 2);
    }

    #[tokio::test]
    async fn ids_continue_across_reopen() {
        let dir = std::env::temp_dir().join(format!("bulwark-store-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ql.db");
        let path_str = path.to_str().unwrap();
        reset_db_files(path_str);

        let s1 = QueryStore::open(path_str).await.unwrap();
        s1.insert_batch(&[entry(0, "a.com", "10.0.0.1", false)])
            .await
            .unwrap();
        let clients = ClientMatcher::default();
        let first_id = s1
            .query(&LogFilter::default(), 0, 10, &clients)
            .await
            .unwrap()
            .entries[0]
            .id;
        drop(s1);
        let s2 = QueryStore::open(path_str).await.unwrap();
        s2.insert_batch(&[entry(0, "b.com", "10.0.0.1", false)])
            .await
            .unwrap();
        let page = s2
            .query(&LogFilter::default(), 0, 10, &clients)
            .await
            .unwrap();
        assert_eq!(page.total, 2, "both rows survive the reopen");
        assert!(
            page.entries[0].id > first_id,
            "id continues above the persisted max ({} should be > {})",
            page.entries[0].id,
            first_id
        );
        assert_eq!(page.entries[0].question, "b.com", "newest first");
        drop(s2);
        reset_db_files(path_str);
    }

    #[tokio::test]
    async fn blocked_and_search_filters() {
        let store = store_with(&[
            entry(1, "ads.example.com", "10.0.0.1", true),
            entry(2, "good.example.com", "10.0.0.1", false),
        ])
        .await;
        let clients = ClientMatcher::default();

        let blocked = page(
            &store,
            LogFilter {
                blocked_only: true,
                ..Default::default()
            },
            &clients,
        )
        .await;
        assert_eq!(blocked.total, 1);
        assert!(blocked.entries[0].is_blocked());
        assert!(matches!(
            blocked.entries[0].action,
            QueryAction::Blocked { list_id: 3, .. }
        ));

        let search = page(
            &store,
            LogFilter {
                search: Some("GOOD".into()), // case-insensitive
                ..Default::default()
            },
            &clients,
        )
        .await;
        assert_eq!(search.total, 1);
        assert_eq!(search.entries[0].question, "good.example.com");
    }

    #[tokio::test]
    async fn search_treats_like_metachars_literally() {
        let store = store_with(&[
            entry(1, "a_b.com", "10.0.0.1", false),
            entry(2, "axb.com", "10.0.0.1", false),
        ])
        .await;
        let clients = ClientMatcher::default();
        let p = page(
            &store,
            LogFilter {
                search: Some("a_b".into()),
                ..Default::default()
            },
            &clients,
        )
        .await;
        assert_eq!(p.total, 1);
        assert_eq!(p.entries[0].question, "a_b.com");
    }

    #[tokio::test]
    async fn client_filter_resolves_names_retroactively() {
        let store = store_with(&[entry(1, "x.com", "10.0.0.5", false)]).await;
        let none = page(
            &store,
            LogFilter {
                client: Some("phone".into()),
                ..Default::default()
            },
            &ClientMatcher::default(),
        )
        .await;
        assert_eq!(none.total, 0);
        let m = ClientMatcher::build(&[ClientConfig {
            id: "phone".into(),
            name: "phone".into(),
            ids: vec!["10.0.0.0/8".into()], // CIDR: can't be enumerated to IPs
            tags: vec![],
            filtering_enabled: true,
        }]);
        let hit = page(
            &store,
            LogFilter {
                client: Some("phone".into()),
                ..Default::default()
            },
            &m,
        )
        .await;
        assert_eq!(hit.total, 1);
        assert_eq!(hit.entries[0].client_ip, "10.0.0.5");
        let by_ip = page(
            &store,
            LogFilter {
                client: Some("10.0.0.5".into()),
                ..Default::default()
            },
            &ClientMatcher::default(),
        )
        .await;
        assert_eq!(by_ip.total, 1);
    }

    #[tokio::test]
    async fn clear_and_retention() {
        let store = store_with(&[
            entry(1, "old.com", "10.0.0.1", false),
            entry(2, "new.com", "10.0.0.1", false),
        ])
        .await;
        let clients = ClientMatcher::default();
        let removed = store.delete_older_than(2).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(page(&store, LogFilter::default(), &clients).await.total, 1);

        store.clear().await.unwrap();
        assert_eq!(page(&store, LogFilter::default(), &clients).await.total, 0);
    }
}
