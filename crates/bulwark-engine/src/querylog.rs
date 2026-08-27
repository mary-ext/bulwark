//! Query log types and writer channel.

use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use serde::{Deserialize, Serialize};

/// Query outcome and associated data.
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
    pub question: String,
    /// Record type label.
    pub qtype: Cow<'static, str>,
    /// Outcome, flattened under the `action` discriminator.
    #[serde(flatten)]
    pub action: QueryAction,
    /// Whether an `@@` exception matched.
    pub allowlisted: bool,
    /// Response code label.
    pub rcode: Cow<'static, str>,
    /// Short answer summaries, such as `A 1.2.3.4`.
    pub answers: Arc<[String]>,
    pub elapsed_ms: f64,
}

impl QueryLogEntry {
    /// Creates an entry for the caller to fill.
    pub fn empty() -> Self {
        Self {
            id: 0,
            time_ms: 0,
            client_ip: String::new(),
            question: String::new(),
            qtype: Cow::Borrowed(""),
            action: QueryAction::Cached,
            allowlisted: false,
            rcode: Cow::Borrowed(""),
            answers: Arc::from([]),
            elapsed_ms: 0.0,
        }
    }

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
    /// Total entries matching the filter (across all pages), for pagination.
    pub total: usize,
}

/// Send-side gate for the query-log writer.
pub struct QueryLog {
    enabled: std::sync::atomic::AtomicBool,
    /// Omits client IPs from stored entries.
    anonymize: std::sync::atomic::AtomicBool,
    /// Entries dropped because the writer channel was full.
    dropped: AtomicU64,
    /// Bounded background-writer channel.
    sink: ArcSwapOption<tokio::sync::mpsc::Sender<QueryLogEntry>>,
}

impl QueryLog {
    pub fn new(enabled: bool, anonymize: bool) -> Self {
        Self {
            enabled: std::sync::atomic::AtomicBool::new(enabled),
            anonymize: std::sync::atomic::AtomicBool::new(anonymize),
            dropped: AtomicU64::new(0),
            sink: ArcSwapOption::empty(),
        }
    }

    /// Attach the writer sink. Entries pushed afterwards are sent here.
    pub fn set_sink(&self, tx: tokio::sync::mpsc::Sender<QueryLogEntry>) {
        self.sink.store(Some(Arc::new(tx)));
    }

    pub fn reconfigure(&self, enabled: bool, anonymize: bool) {
        self.enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        self.anonymize
            .store(anonymize, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Tries to send an entry without blocking the DNS path.
    pub fn push(&self, mut entry: QueryLogEntry) {
        if !self.is_enabled() {
            return;
        }
        if self.anonymize.load(Ordering::Relaxed) {
            entry.client_ip.clear();
        }
        if let Some(tx) = self.sink.load_full() {
            if tx.try_send(entry).is_err() {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed);
                if n.is_multiple_of(4096) {
                    tracing::warn!(dropped = n + 1, "query log channel full; dropping entries");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_respects_enabled_and_missing_sink() {
        let log = QueryLog::new(false, false);
        log.push(QueryLogEntry::empty()); // disabled: dropped, no panic
        log.reconfigure(true, false);
        log.push(QueryLogEntry::empty()); // enabled but no sink: dropped, no panic
        assert!(log.is_enabled());
    }

    #[test]
    fn push_forwards_to_sink_when_enabled() {
        let log = QueryLog::new(true, false);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        log.set_sink(tx);
        let mut e = QueryLogEntry::empty();
        e.id = 42;
        log.push(e);
        let got = rx.try_recv().expect("entry forwarded");
        assert_eq!(got.id, 42);

        log.reconfigure(false, false);
        log.push(QueryLogEntry::empty());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn anonymize_clears_client_ip_on_push() {
        let log = QueryLog::new(true, true);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        log.set_sink(tx);
        let mut e = QueryLogEntry::empty();
        e.client_ip = "10.0.0.1".into();
        log.push(e);
        let got = rx.try_recv().expect("entry forwarded");
        assert!(
            got.client_ip.is_empty(),
            "client IP dropped when anonymizing"
        );
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    #[test]
    fn action_flattens_to_top_level_keys() {
        let mut e = QueryLogEntry {
            id: 1,
            time_ms: 0,
            client_ip: "10.0.0.1".into(),
            question: "ads.com.".into(),
            qtype: "A".into(),
            action: QueryAction::Blocked {
                rule: "||ads^".into(),
                list_id: 3,
            },
            allowlisted: false,
            rcode: "NXDOMAIN".into(),
            answers: Arc::from([]),
            elapsed_ms: 0.5,
        };

        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains(r#""action":"blocked""#));
        assert!(j.contains(r#""rule":"||ads^""#));
        assert!(j.contains(r#""list_id":3"#));
        assert!(!j.contains("cached"));

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
