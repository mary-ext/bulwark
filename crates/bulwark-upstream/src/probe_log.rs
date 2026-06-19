//! Upstream probe telemetry: the event type plus a thin send-side gate.
//!
//! The background probe loop measures every upstream's `NS .` round-trip on a
//! fixed cadence (see [`crate::pool`]); that probe RTT is the *routing signal*
//! used to rank upstreams. Those measurements — and the health they drive —
//! otherwise live only in memory and vanish on restart, which is exactly when
//! you're doing maintenance and would most want the history ("was this upstream
//! flaky overnight? when did it flap down? is its latency creeping up?").
//!
//! This module is the persistence seam. When enabled, each probe builds a
//! [`ProbeEvent`] and hands it to [`ProbeLog::push`], which forwards it over a
//! bounded channel to the server's background writer (shedding events if the
//! writer can't keep up). It is **off by default**: with no sink attached the
//! gate is a no-op and the probe path pays nothing.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use serde::{Deserialize, Serialize};

use crate::spec::TransportKind;

/// Unix epoch milliseconds, for stamping an event at the moment it's recorded.
pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// What a single probe of an upstream came back as. Mirrors the pool's internal
/// `Verdict` plus the two ways a probe can fail to even get a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// A usable answer to `NS .` — counts as a latency success and feeds the EWMA.
    Answer,
    /// Reachable but refused the query (REFUSED/NOTIMP): an upstream-level fault.
    Reject,
    /// SERVFAIL/FORMERR — health-neutral for live traffic, but for the fixed
    /// `NS .` probe any non-answer indicts the resolver, so it's a failed probe.
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

/// One recorded probe of one upstream. Carries both the raw measurement
/// (`rtt_ms`) and the health state it produced (`ewma_ms`, `up`,
/// `consecutive_failures`) so the persisted stream is self-contained: a reader
/// can chart latency, see the routing figure the selector actually used, and
/// spot up/down flaps from consecutive rows without replaying the algorithm.
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
    /// Measured round-trip of this probe, present only on a successful answer.
    pub rtt_ms: Option<f64>,
    /// The smoothed routing latency *after* folding this sample in — i.e. the
    /// figure selection would rank by. `None` until the first successful probe.
    pub ewma_ms: Option<f64>,
    /// Upstream liveness after this probe.
    pub up: bool,
    /// Consecutive failures after this probe (0 on success).
    pub consecutive_failures: u32,
    /// The response code or error text for a non-answer, for forensics. `None`
    /// on a clean answer.
    pub detail: Option<String>,
}

/// A thin send-side gate in front of the probe-telemetry writer, mirroring the
/// query log's [`bulwark_engine::querylog::QueryLog`]. Holds the enabled toggle
/// and the channel to the background writer; it does not retain events. The
/// probe path checks [`is_enabled`](Self::is_enabled) before paying to build an
/// event.
///
/// `enabled` is a live toggle: the server flips it on config reload via
/// [`reconfigure`](Self::reconfigure), so persistence can be turned on or off
/// without a restart. The sink is wired once at startup; whether it points at a
/// disk or in-memory store (the `persist` choice) is fixed there, as it is for
/// the query log. Off by default — a disabled probe log costs the probe loop a
/// single relaxed atomic load and nothing else.
#[derive(Default)]
pub struct ProbeLog {
    /// Live enable toggle. Updated on config reload; gates every push.
    enabled: AtomicBool,
    /// Channel to the background writer. `None` until a sink is wired at startup.
    /// **Bounded** so a stalled writer sheds events instead of growing memory
    /// without limit.
    sink: ArcSwapOption<tokio::sync::mpsc::Sender<ProbeEvent>>,
    /// Count of events dropped because the writer channel was full. Probes run on
    /// the order of one per upstream per minute, so this should never advance
    /// outside a sustained writer stall; surfaced periodically if it does.
    dropped: AtomicU64,
}

impl ProbeLog {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            ..Default::default()
        }
    }

    /// Attach the writer sink. Wired once at startup regardless of the enabled
    /// state, so a later [`reconfigure(true)`](Self::reconfigure) takes effect
    /// immediately without needing a restart to create the channel.
    pub fn set_sink(&self, tx: tokio::sync::mpsc::Sender<ProbeEvent>) {
        self.sink.store(Some(Arc::new(tx)));
    }

    /// Flip the enable toggle (e.g. on config reload).
    pub fn reconfigure(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Whether persistence is enabled. Checked before building an event so a
    /// disabled probe log costs only one relaxed atomic load.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Forward a probe event to the background writer. A no-op if disabled or no
    /// sink is attached. Uses `try_send` on the bounded channel: a full channel
    /// drops the event rather than blocking the probe loop. Sustained loss is
    /// logged.
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
        // Enabled but no sink wired yet: push is a harmless no-op.
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

        // Toggling on at runtime starts forwarding immediately — no re-wiring.
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

    fn sample() -> ProbeEvent {
        ProbeEvent {
            time_ms: 1,
            upstream: "udp://1.1.1.1:53".into(),
            name: "cloudflare".into(),
            kind: TransportKind::Udp,
            outcome: ProbeOutcome::Answer,
            rtt_ms: Some(12.0),
            ewma_ms: Some(12.0),
            up: true,
            consecutive_failures: 0,
            detail: None,
        }
    }
}
