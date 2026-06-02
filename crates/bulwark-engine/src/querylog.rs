//! In-memory query log: a bounded ring buffer of recent queries with filtering
//! and pagination for the UI.

use std::collections::VecDeque;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// What happened to a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryAction {
    /// Resolved via an upstream.
    Forwarded,
    /// Served from cache.
    Cached,
    /// Blocked by a filtering rule.
    Blocked,
    /// Rewritten by a rule (`$dnsrewrite` / hosts IP).
    Rewritten,
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
    pub qtype: String,
    pub action: QueryAction,
    /// True if an `@@` exception allowed an otherwise-blocked query.
    pub allowlisted: bool,
    pub rcode: String,
    /// Short summary of answer records (e.g. `["A 1.2.3.4"]`).
    pub answers: Vec<String>,
    /// The rule text that matched, if any.
    pub rule: Option<String>,
    pub list_id: Option<u32>,
    /// Upstream used, if forwarded.
    pub upstream: Option<String>,
    pub elapsed_ms: f64,
    pub cached: bool,
}

impl QueryLogEntry {
    pub fn is_blocked(&self) -> bool {
        matches!(self.action, QueryAction::Blocked) && !self.allowlisted
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

    /// Query the log with filtering + pagination (newest first).
    pub fn query(&self, filter: &LogFilter, offset: usize, limit: usize) -> LogPage {
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
                    let name_match = e
                        .client_name
                        .as_ref()
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
            .cloned()
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
                QueryAction::Blocked
            } else {
                QueryAction::Forwarded
            },
            allowlisted: false,
            rcode: "NOERROR".into(),
            answers: vec![],
            rule: None,
            list_id: None,
            upstream: None,
            elapsed_ms: 1.0,
            cached: false,
        }
    }

    #[test]
    fn ring_buffer_evicts_oldest() {
        let log = QueryLog::new(3, true);
        for i in 0..5 {
            log.push(entry(i, "x.com", false));
        }
        assert_eq!(log.len(), 3);
        let page = log.query(&LogFilter::default(), 0, 10);
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
        );
        assert_eq!(blocked.total, 1);
        let search = log.query(
            &LogFilter {
                search: Some("good".into()),
                ..Default::default()
            },
            0,
            10,
        );
        assert_eq!(search.total, 1);
        assert_eq!(search.entries[0].id, 2);
    }

    #[test]
    fn disabled_log_drops_entries() {
        let log = QueryLog::new(10, false);
        log.push(entry(1, "x.com", false));
        assert_eq!(log.len(), 0);
    }
}
