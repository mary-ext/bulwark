//! Query log: the shared entry types plus a thin send-side gate.
//!
//! The log is disk-backed (see the server's query store). The DNS hot path
//! builds a [`QueryLogEntry`] and, when logging is enabled, hands it to
//! [`QueryLog::push`], which forwards it to the background writer over a
//! bounded channel (shedding entries if the writer can't keep up). The
//! [`LogFilter`]/[`LogPage`] shapes are defined here but
//! the filtering and pagination they describe run against the database.

use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use serde::{Deserialize, Serialize};

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
    /// Short summary of answer records (e.g. `["A 1.2.3.4"]`). An `Arc<[String]>`
    /// so the wire-byte cache hit can share the summaries it already holds rather
    /// than deep-copying them per query (serde `rc` (de)serializes the slice).
    pub answers: Arc<[String]>,
    pub elapsed_ms: f64,
}

impl QueryLogEntry {
    /// An empty entry whose fields are filled in before use. The placeholder
    /// `Cached` action is always overwritten, so it is never observed.
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

/// A thin send-side gate in front of the disk-backed store. Holds the
/// enabled/disabled toggle and the channel to the background writer; it does not
/// retain entries. The DNS path checks [`is_enabled`](Self::is_enabled) before
/// paying to build an entry, then calls [`push`](Self::push) to hand it off.
pub struct QueryLog {
    enabled: std::sync::atomic::AtomicBool,
    /// When set, client IPs are dropped from logged entries before they reach the
    /// store (and thus the API). The IP is still used to identify the client for
    /// filtering and stats earlier in the pipeline — only the logged copy is
    /// cleared, so enabling this loses per-client attribution in the query log.
    anonymize: std::sync::atomic::AtomicBool,
    /// Count of entries dropped because the writer channel was full. Surfaced
    /// periodically so sustained loss isn't silent.
    dropped: AtomicU64,
    /// Channel to the background writer. Set once at startup; `None` until then
    /// (or when persistence is unwired), in which case pushes are dropped. The
    /// channel is **bounded** so a stalled or slow writer sheds load instead of
    /// growing memory without limit.
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

    /// Forward a completed entry to the background writer. A no-op if logging is
    /// disabled or no sink is attached. Cheap on the hot path: one atomic load
    /// plus a non-blocking channel send (the entry is moved, not cloned).
    ///
    /// Uses `try_send` on the bounded channel: under extreme burst (or a stalled
    /// writer) a full channel drops the entry rather than blocking the DNS hot
    /// path or growing memory unboundedly. Sustained loss is logged periodically.
    pub fn push(&self, mut entry: QueryLogEntry) {
        if !self.is_enabled() {
            return;
        }
        if self.anonymize.load(Ordering::Relaxed) {
            // Drop the client IP entirely before it reaches the store/API.
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

    /// The disabled gate drops entries without touching the (absent) sink, and a
    /// push with no sink attached is a harmless no-op.
    #[test]
    fn gate_respects_enabled_and_missing_sink() {
        let log = QueryLog::new(false, false);
        log.push(QueryLogEntry::empty()); // disabled: dropped, no panic
        log.reconfigure(true, false);
        log.push(QueryLogEntry::empty()); // enabled but no sink: dropped, no panic
        assert!(log.is_enabled());
    }

    /// When a sink is attached, an enabled push forwards the entry to the writer.
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

        // Disabled: nothing forwarded.
        log.reconfigure(false, false);
        log.push(QueryLogEntry::empty());
        assert!(rx.try_recv().is_err());
    }

    /// With anonymization on, the client IP is stripped before the entry reaches
    /// the writer (and thus the store/API).
    #[test]
    fn anonymize_clears_client_ip_on_push() {
        let log = QueryLog::new(true, true);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        log.set_sink(tx);
        let mut e = QueryLogEntry::empty();
        e.client_ip = "10.0.0.1".into();
        log.push(e);
        let got = rx.try_recv().expect("entry forwarded");
        assert!(got.client_ip.is_empty(), "client IP dropped when anonymizing");
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
