//! Query log: the shared entry types plus a thin send-side gate.
//!
//! The log is disk-backed (see the server's query store). The DNS hot path
//! builds a [`QueryLogEntry`] and, when logging is enabled, hands it to
//! [`QueryLog::push`], which forwards it to the background writer over an
//! unbounded channel. The [`LogFilter`]/[`LogPage`] shapes are defined here but
//! the filtering and pagination they describe run against the database.

use std::borrow::Cow;

use parking_lot::Mutex;
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
    /// Short summary of answer records (e.g. `["A 1.2.3.4"]`).
    pub answers: Vec<String>,
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
            answers: Vec::new(),
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
    /// Channel to the background writer. Set once at startup; `None` until then
    /// (or when persistence is unwired), in which case pushes are dropped.
    sink: Mutex<Option<tokio::sync::mpsc::UnboundedSender<QueryLogEntry>>>,
}

impl QueryLog {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: std::sync::atomic::AtomicBool::new(enabled),
            sink: Mutex::new(None),
        }
    }

    /// Attach the writer sink. Entries pushed afterwards are sent here.
    pub fn set_sink(&self, tx: tokio::sync::mpsc::UnboundedSender<QueryLogEntry>) {
        *self.sink.lock() = Some(tx);
    }

    pub fn reconfigure(&self, enabled: bool) {
        self.enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Forward a completed entry to the background writer. A no-op if logging is
    /// disabled or no sink is attached. Cheap on the hot path: one atomic load
    /// plus a lock-free channel send (the entry is moved, not cloned).
    pub fn push(&self, entry: QueryLogEntry) {
        if !self.is_enabled() {
            return;
        }
        if let Some(tx) = self.sink.lock().as_ref() {
            let _ = tx.send(entry);
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
        let log = QueryLog::new(false);
        log.push(QueryLogEntry::empty()); // disabled: dropped, no panic
        log.reconfigure(true);
        log.push(QueryLogEntry::empty()); // enabled but no sink: dropped, no panic
        assert!(log.is_enabled());
    }

    /// When a sink is attached, an enabled push forwards the entry to the writer.
    #[test]
    fn push_forwards_to_sink_when_enabled() {
        let log = QueryLog::new(true);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        log.set_sink(tx);
        let mut e = QueryLogEntry::empty();
        e.id = 42;
        log.push(e);
        let got = rx.try_recv().expect("entry forwarded");
        assert_eq!(got.id, 42);

        // Disabled: nothing forwarded.
        log.reconfigure(false);
        log.push(QueryLogEntry::empty());
        assert!(rx.try_recv().is_err());
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
