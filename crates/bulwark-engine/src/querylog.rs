//! In-memory query log: a bounded ring buffer of recent queries with filtering
//! and pagination for the UI.

use std::borrow::Cow;
use std::collections::VecDeque;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::clients::ClientMatcher;

/// What happened to a query, together with the data specific to that outcome.
///
/// Modeling the per-outcome fields inside each variant makes invalid
/// combinations (e.g. a cached entry that also names an upstream, or a
/// forwarded entry carrying a blocking rule) unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum QueryAction {
    /// Resolved via an upstream.
    Forwarded { upstream: String },
    /// Served from cache.
    Cached,
    /// Blocked by a filtering rule.
    Blocked { rule: String, list_id: u32 },
    /// Rewritten by a rule (`$dnsrewrite` / hosts IP).
    Rewritten { rule: String, list_id: u32 },
    /// An error response (e.g. SERVFAIL) was returned.
    Error,
}

/// One logged query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogEntry {
    pub id: u64,
    /// Unix epoch milliseconds.
    pub time_ms: i64,
    pub client_ip: String,
    pub client_name: Option<String>,
    pub question: String,
    /// Record type label (`"A"`, `"AAAA"`, …). A `Cow` so the common types are
    /// stored as `&'static str` without a per-query allocation.
    pub qtype: Cow<'static, str>,
    /// The outcome and its associated data. Flattened on the wire so the
    /// discriminator appears as a top-level `"action"` string with the
    /// variant's fields alongside it.
    #[serde(flatten)]
    pub action: QueryAction,
    /// True if an `@@` exception allowed an otherwise-blocked query. Orthogonal
    /// to `action`: an allowlisted query is still forwarded or cached.
    pub allowlisted: bool,
    /// Response code label (`"NOERROR"`, `"NXDOMAIN"`, …); `Cow` for the same
    /// no-allocation reason as `qtype`.
    pub rcode: Cow<'static, str>,
    /// Short summary of answer records (e.g. `["A 1.2.3.4"]`).
    pub answers: Vec<String>,
    pub elapsed_ms: f64,
}

impl QueryLogEntry {
    pub fn is_blocked(&self) -> bool {
        matches!(self.action, QueryAction::Blocked { .. }) && !self.allowlisted
    }

    /// The rule text that matched, if the query was blocked or rewritten.
    pub fn rule(&self) -> Option<&str> {
        match &self.action {
            QueryAction::Blocked { rule, .. } | QueryAction::Rewritten { rule, .. } => Some(rule),
            _ => None,
        }
    }

    /// The filter list responsible, if the query was blocked or rewritten.
    pub fn list_id(&self) -> Option<u32> {
        match self.action {
            QueryAction::Blocked { list_id, .. } | QueryAction::Rewritten { list_id, .. } => {
                Some(list_id)
            }
            _ => None,
        }
    }

    /// The upstream used, if the query was forwarded.
    pub fn upstream(&self) -> Option<&str> {
        match &self.action {
            QueryAction::Forwarded { upstream } => Some(upstream),
            _ => None,
        }
    }

    /// True if the query was served from cache.
    pub fn cached(&self) -> bool {
        matches!(self.action, QueryAction::Cached)
    }
}

/// Filter for querying the log.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct LogFilter {
    /// Case-insensitive substring match on the question name.
    pub search: Option<String>,
    /// Match a specific client (IP or name).
    pub client: Option<String>,
    /// Only blocked entries.
    pub blocked_only: bool,
}

/// A page of log results.
#[derive(Debug, Serialize)]
pub struct LogPage {
    pub entries: Vec<QueryLogEntry>,
    /// Total entries currently held (before paging, after filtering).
    pub total: usize,
}

/// Bounded, newest-first query log.
pub struct QueryLog {
    inner: Mutex<VecDeque<QueryLogEntry>>,
    capacity: parking_lot::RwLock<usize>,
    enabled: std::sync::atomic::AtomicBool,
    /// Optional sink for persistence: each pushed entry is also forwarded here so
    /// a background writer can append it to disk.
    sink: Mutex<Option<tokio::sync::mpsc::UnboundedSender<QueryLogEntry>>>,
}

impl QueryLog {
    pub fn new(capacity: usize, enabled: bool) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            capacity: parking_lot::RwLock::new(capacity.max(1)),
            enabled: std::sync::atomic::AtomicBool::new(enabled),
            sink: Mutex::new(None),
        }
    }

    /// Attach a persistence sink. Entries pushed afterwards are also sent here.
    pub fn set_sink(&self, tx: tokio::sync::mpsc::UnboundedSender<QueryLogEntry>) {
        *self.sink.lock() = Some(tx);
    }

    /// Pre-populate the in-memory ring from persisted entries (oldest-first
    /// input). Does not re-send to the sink.
    pub fn preload(&self, entries: Vec<QueryLogEntry>) {
        let cap = *self.capacity.read();
        let mut q = self.inner.lock();
        for e in entries {
            q.push_front(e);
            while q.len() > cap {
                q.pop_back();
            }
        }
    }

    pub fn reconfigure(&self, capacity: usize, enabled: bool) {
        *self.capacity.write() = capacity.max(1);
        self.enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        let cap = capacity.max(1);
        let mut q = self.inner.lock();
        while q.len() > cap {
            q.pop_back();
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Append a new entry (newest at the front), evicting the oldest if full.
    pub fn push(&self, entry: QueryLogEntry) {
        if !self.is_enabled() {
            return;
        }
        if let Some(tx) = self.sink.lock().as_ref() {
            let _ = tx.send(entry.clone());
        }
        let cap = *self.capacity.read();
        let mut q = self.inner.lock();
        q.push_front(entry);
        while q.len() > cap {
            q.pop_back();
        }
    }

    pub fn clear(&self) {
        self.inner.lock().clear();
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Query the log with filtering + pagination (newest first). `clients` is the
    /// current client matcher: stored entries hold only the client IP, and the
    /// friendly name is resolved here (for both the client filter and the
    /// returned entries) so renames/removals apply retroactively.
    pub fn query(
        &self,
        filter: &LogFilter,
        offset: usize,
        limit: usize,
        clients: &ClientMatcher,
    ) -> LogPage {
        let q = self.inner.lock();
        let search = filter.search.as_ref().map(|s| s.to_ascii_lowercase());
        let client = filter.client.as_ref().map(|s| s.to_ascii_lowercase());

        let matched: Vec<&QueryLogEntry> = q
            .iter()
            .filter(|e| {
                if filter.blocked_only && !e.is_blocked() {
                    return false;
                }
                if let Some(s) = &search {
                    if !e.question.to_ascii_lowercase().contains(s) {
                        return false;
                    }
                }
                if let Some(c) = &client {
                    let name_match = clients
                        .name_for_str(&e.client_ip)
                        .is_some_and(|n| n.to_ascii_lowercase().contains(c));
                    if !e.client_ip.to_ascii_lowercase().contains(c) && !name_match {
                        return false;
                    }
                }
                true
            })
            .collect();

        let total = matched.len();
        let entries = matched
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|e| {
                let mut e = e.clone();
                e.client_name = clients.name_for_str(&e.client_ip).map(str::to_string);
                e
            })
            .collect();
        LogPage { entries, total }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64, q: &str, blocked: bool) -> QueryLogEntry {
        QueryLogEntry {
            id,
            time_ms: id as i64,
            client_ip: "10.0.0.1".into(),
            client_name: Some("laptop".into()),
            question: q.into(),
            qtype: "A".into(),
            action: if blocked {
                QueryAction::Blocked {
                    rule: "||ads^".into(),
                    list_id: 0,
                }
            } else {
                QueryAction::Forwarded {
                    upstream: "1.1.1.1".into(),
                }
            },
            allowlisted: false,
            rcode: "NOERROR".into(),
            answers: vec![],
            elapsed_ms: 1.0,
        }
    }

    #[test]
    fn ring_buffer_evicts_oldest() {
        let log = QueryLog::new(3, true);
        for i in 0..5 {
            log.push(entry(i, "x.com", false));
        }
        assert_eq!(log.len(), 3);
        let page = log.query(&LogFilter::default(), 0, 10, &ClientMatcher::default());
        // Newest first.
        assert_eq!(page.entries[0].id, 4);
        assert_eq!(page.total, 3);
    }

    #[test]
    fn filters_blocked_and_search() {
        let log = QueryLog::new(10, true);
        log.push(entry(1, "ads.example.com", true));
        log.push(entry(2, "good.example.com", false));
        let blocked = log.query(
            &LogFilter {
                blocked_only: true,
                ..Default::default()
            },
            0,
            10,
            &ClientMatcher::default(),
        );
        assert_eq!(blocked.total, 1);
        let search = log.query(
            &LogFilter {
                search: Some("good".into()),
                ..Default::default()
            },
            0,
            10,
            &ClientMatcher::default(),
        );
        assert_eq!(search.total, 1);
        assert_eq!(search.entries[0].id, 2);
    }

    #[test]
    fn client_name_resolved_at_read_time() {
        use bulwark_config::ClientConfig;

        let log = QueryLog::new(10, true);
        // Stored with only an IP; no name baked in.
        let mut e = entry(1, "x.com", false);
        e.client_ip = "10.0.0.5".into();
        e.client_name = None;
        log.push(e);

        // No config: the entry shows the bare IP and matches an IP filter.
        let bare = log.query(&LogFilter::default(), 0, 10, &ClientMatcher::default());
        assert_eq!(bare.entries[0].client_name, None);

        // Name 10.0.0.5 "phone": the name now shows and a name filter matches —
        // retroactively, for an entry logged before the name existed.
        let m = ClientMatcher::build(&[ClientConfig {
            name: "phone".into(),
            ids: vec!["10.0.0.5".into()],
            tags: vec![],
            filtering_enabled: true,
        }]);
        let named = log.query(&LogFilter::default(), 0, 10, &m);
        assert_eq!(named.entries[0].client_name.as_deref(), Some("phone"));

        let by_name = log.query(
            &LogFilter {
                client: Some("phone".into()),
                ..Default::default()
            },
            0,
            10,
            &m,
        );
        assert_eq!(by_name.total, 1);
    }

    #[test]
    fn disabled_log_drops_entries() {
        let log = QueryLog::new(10, false);
        log.push(entry(1, "x.com", false));
        assert_eq!(log.len(), 0);
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    /// The action discriminator and its data must serialize as flat top-level
    /// keys (`action`, plus the variant's fields). The web UI reads them as
    /// `e.action`, `e.rule`, `e.list_id`, `e.upstream`, so this is a contract.
    #[test]
    fn action_flattens_to_top_level_keys() {
        let mut e = QueryLogEntry {
            id: 1,
            time_ms: 0,
            client_ip: "10.0.0.1".into(),
            client_name: None,
            question: "ads.com.".into(),
            qtype: "A".into(),
            action: QueryAction::Blocked {
                rule: "||ads^".into(),
                list_id: 3,
            },
            allowlisted: false,
            rcode: "NXDOMAIN".into(),
            answers: vec![],
            elapsed_ms: 0.5,
        };

        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains(r#""action":"blocked""#));
        assert!(j.contains(r#""rule":"||ads^""#));
        assert!(j.contains(r#""list_id":3"#));
        // The redundant `cached` field is gone for good.
        assert!(!j.contains("cached"));

        // Round-trips back to the same variant.
        let back: QueryLogEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(back.action, e.action);

        e.action = QueryAction::Forwarded {
            upstream: "1.1.1.1".into(),
        };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains(r#""action":"forwarded""#));
        assert!(j.contains(r#""upstream":"1.1.1.1""#));
        assert!(!j.contains("list_id"));
    }
}
