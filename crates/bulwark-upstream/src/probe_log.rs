//! Upstream probe events and writer channel.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use serde::{Deserialize, Serialize};

use crate::spec::TransportKind;

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Outcome of one upstream probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// A usable answer to `NS .` — counts as a latency success and feeds the EWMA.
    Answer,
    /// Reachable but refused the query (REFUSED/NOTIMP): an upstream-level fault.
    Reject,
    /// A SERVFAIL or FORMERR response.
    SoftFail,
    /// No response within the query timeout.
    Timeout,
    /// A transport-level error (connect/TLS/IO).
    Error,
}

impl ProbeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeOutcome::Answer => "answer",
            ProbeOutcome::Reject => "reject",
            ProbeOutcome::SoftFail => "soft_fail",
            ProbeOutcome::Timeout => "timeout",
            ProbeOutcome::Error => "error",
        }
    }

    /// Parse back from the stored label; unknown strings fall back to `Error`.
    pub fn from_label(s: &str) -> Self {
        match s {
            "answer" => ProbeOutcome::Answer,
            "reject" => ProbeOutcome::Reject,
            "soft_fail" => ProbeOutcome::SoftFail,
            "timeout" => ProbeOutcome::Timeout,
            _ => ProbeOutcome::Error,
        }
    }
}

/// Structured failure category for a non-answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeErrorKind {
    /// No response within the query timeout.
    Timeout,
    /// The upstream answered with a non-OK rcode (REFUSED/NOTIMP/SERVFAIL/…).
    Rcode,
    /// Plain transport I/O error (connection refused, reset, unreachable).
    Io,
    Tls,
    Quic,
    Http,
    /// Malformed/invalid DNS on the wire.
    Proto,
    /// Bootstrap couldn't resolve the upstream's hostname.
    Bootstrap,
    Other,
}

impl ProbeErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeErrorKind::Timeout => "timeout",
            ProbeErrorKind::Rcode => "rcode",
            ProbeErrorKind::Io => "io",
            ProbeErrorKind::Tls => "tls",
            ProbeErrorKind::Quic => "quic",
            ProbeErrorKind::Http => "http",
            ProbeErrorKind::Proto => "proto",
            ProbeErrorKind::Bootstrap => "bootstrap",
            ProbeErrorKind::Other => "other",
        }
    }

    /// Parse back from the stored label; unknown strings fall back to `Other`.
    pub fn from_label(s: &str) -> Self {
        match s {
            "timeout" => ProbeErrorKind::Timeout,
            "rcode" => ProbeErrorKind::Rcode,
            "io" => ProbeErrorKind::Io,
            "tls" => ProbeErrorKind::Tls,
            "quic" => ProbeErrorKind::Quic,
            "http" => ProbeErrorKind::Http,
            "proto" => ProbeErrorKind::Proto,
            "bootstrap" => ProbeErrorKind::Bootstrap,
            _ => ProbeErrorKind::Other,
        }
    }

    /// Classify the error a failed probe surfaced.
    pub fn from_error(err: &crate::error::UpstreamError) -> Self {
        use crate::error::UpstreamError as E;
        match err {
            E::Timeout => ProbeErrorKind::Timeout,
            E::Rcode(_) => ProbeErrorKind::Rcode,
            E::Io(_) => ProbeErrorKind::Io,
            E::Tls(_) => ProbeErrorKind::Tls,
            E::Quic(_) => ProbeErrorKind::Quic,
            E::Http(_) => ProbeErrorKind::Http,
            E::Proto(_) => ProbeErrorKind::Proto,
            E::Bootstrap(_) => ProbeErrorKind::Bootstrap,
            E::AllFailed(inner) => ProbeErrorKind::from_error(inner),
            E::NoUpstreams | E::InvalidSpec(_) => ProbeErrorKind::Other,
        }
    }
}

/// Recorded probe measurement and resulting health state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeEvent {
    /// Unix epoch milliseconds when the probe completed.
    pub time_ms: i64,
    /// The upstream's display spec (e.g. `udp://1.1.1.1:53`).
    pub upstream: String,
    /// Friendly name, if one is configured (else the display spec).
    pub name: String,
    /// Transport kind, so analysis can group by protocol.
    pub kind: TransportKind,
    pub outcome: ProbeOutcome,
    /// Warm probe round-trip used for routing.
    pub rtt_ms: Option<f64>,
    /// First-shot round-trip, including setup when the connection was cold.
    pub first_rtt_ms: Option<f64>,
    /// Smoothed routing latency after this probe.
    pub ewma_ms: Option<f64>,
    /// Upstream liveness after this probe.
    pub up: bool,
    /// Consecutive failures after this probe (0 on success).
    pub consecutive_failures: u32,
    /// Response code or error text for a non-answer.
    pub detail: Option<String>,
    /// Structured failure class for a non-answer.
    pub error_kind: Option<ProbeErrorKind>,
    /// Smoothed live-query latency at probe time.
    pub live_ewma_ms: Option<f64>,
    /// Cumulative live queries at probe time.
    pub live_queries: u64,
    /// Cumulative live-query failures this upstream has seen, at probe time.
    pub live_failures: u64,
    /// Most recent selection rank; 0 is the leader.
    pub rank: Option<u16>,
    /// Whether hysteresis is retaining this upstream as leader.
    pub lead_held: bool,
}

/// Send-side gate for probe telemetry.
#[derive(Default)]
pub struct ProbeLog {
    enabled: AtomicBool,
    /// Bounded writer channel.
    sink: ArcSwapOption<tokio::sync::mpsc::Sender<ProbeEvent>>,
    /// Events dropped because the writer channel was full.
    dropped: AtomicU64,
}

impl ProbeLog {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            ..Default::default()
        }
    }

    /// Attaches the writer sink.
    pub fn set_sink(&self, tx: tokio::sync::mpsc::Sender<ProbeEvent>) {
        self.sink.store(Some(Arc::new(tx)));
    }

    /// Flip the enable toggle (e.g. on config reload).
    pub fn reconfigure(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Whether persistence is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Tries to send an event without blocking the probe loop.
    pub fn push(&self, event: ProbeEvent) {
        if !self.is_enabled() {
            return;
        }
        if let Some(tx) = self.sink.load_full() {
            if tx.try_send(event).is_err() {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed);
                if n.is_multiple_of(256) {
                    tracing::warn!(dropped = n + 1, "probe log channel full; dropping events");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_without_sink_is_noop() {
        let log = ProbeLog::new(true);
        assert!(log.is_enabled());
        log.push(sample());
    }

    #[test]
    fn disabled_drops_even_with_sink() {
        let log = ProbeLog::new(false);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        log.set_sink(tx);
        assert!(!log.is_enabled());
        log.push(sample());
        assert!(rx.try_recv().is_err(), "disabled gate drops the event");
        log.reconfigure(true);
        log.push(sample());
        assert!(rx.try_recv().is_ok(), "reconfigure(true) takes effect live");
    }

    #[test]
    fn enabled_forwards_when_sink_attached() {
        let log = ProbeLog::new(true);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        log.set_sink(tx);
        log.push(sample());
        let got = rx.try_recv().expect("event forwarded");
        assert_eq!(got.upstream, "udp://1.1.1.1:53");
        assert_eq!(got.outcome, ProbeOutcome::Answer);
    }

    #[test]
    fn outcome_label_round_trips() {
        for o in [
            ProbeOutcome::Answer,
            ProbeOutcome::Reject,
            ProbeOutcome::SoftFail,
            ProbeOutcome::Timeout,
            ProbeOutcome::Error,
        ] {
            assert_eq!(ProbeOutcome::from_label(o.as_str()), o);
        }
    }

    #[test]
    fn error_kind_label_round_trips() {
        for k in [
            ProbeErrorKind::Timeout,
            ProbeErrorKind::Rcode,
            ProbeErrorKind::Io,
            ProbeErrorKind::Tls,
            ProbeErrorKind::Quic,
            ProbeErrorKind::Http,
            ProbeErrorKind::Proto,
            ProbeErrorKind::Bootstrap,
            ProbeErrorKind::Other,
        ] {
            assert_eq!(ProbeErrorKind::from_label(k.as_str()), k);
        }
    }

    fn sample() -> ProbeEvent {
        ProbeEvent {
            time_ms: 1,
            upstream: "udp://1.1.1.1:53".into(),
            name: "cloudflare".into(),
            kind: TransportKind::Udp,
            outcome: ProbeOutcome::Answer,
            rtt_ms: Some(12.0),
            first_rtt_ms: Some(48.0),
            ewma_ms: Some(12.0),
            up: true,
            consecutive_failures: 0,
            detail: None,
            error_kind: None,
            live_ewma_ms: Some(28.0),
            live_queries: 100,
            live_failures: 1,
            rank: Some(0),
            lead_held: false,
        }
    }
}
