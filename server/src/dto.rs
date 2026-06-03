//! API-owned data-transfer objects for the engine/upstream read-models.
//!
//! These mirror the internal `bulwark-engine` / `bulwark-upstream` types on the
//! wire, but live in the API layer so those crates stay free of `utoipa` and are
//! free to evolve independently of the public HTTP contract. Config types are
//! deliberately *not* duplicated here: `bulwark-config` is itself the public
//! configuration contract (see its module docs) and derives `ToSchema` directly.

use std::collections::HashMap;

use bulwark_engine::querylog::{QueryAction, QueryLogEntry};
use bulwark_engine::stats::{LatencyPercentiles, SeriesPoint, StatsSummary, TopEntry};
use bulwark_upstream::pool::UpstreamStat;
use bulwark_upstream::spec::TransportKind;
use serde::Serialize;
use utoipa::ToSchema;

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// A name + count pair for top-N lists.
#[derive(Serialize, ToSchema)]
pub struct TopEntryDto {
    pub name: String,
    pub count: u64,
}

impl From<TopEntry> for TopEntryDto {
    fn from(e: TopEntry) -> Self {
        Self {
            name: e.name,
            count: e.count,
        }
    }
}

/// A point in the hourly time series.
#[derive(Serialize, ToSchema)]
pub struct SeriesPointDto {
    pub hour: i64,
    pub total: u64,
    pub blocked: u64,
    pub cached: u64,
}

impl From<SeriesPoint> for SeriesPointDto {
    fn from(p: SeriesPoint) -> Self {
        Self {
            hour: p.hour,
            total: p.total,
            blocked: p.blocked,
            cached: p.cached,
        }
    }
}

/// Approximate latency percentiles (milliseconds).
#[derive(Serialize, ToSchema)]
pub struct LatencyPercentilesDto {
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
}

impl From<LatencyPercentiles> for LatencyPercentilesDto {
    fn from(l: LatencyPercentiles) -> Self {
        Self {
            p50: l.p50,
            p90: l.p90,
            p99: l.p99,
        }
    }
}

/// A statistics snapshot plus live cache counters.
#[derive(Serialize, ToSchema)]
pub struct StatsResponse {
    pub total: u64,
    pub blocked: u64,
    pub cached: u64,
    pub rewritten: u64,
    pub errors: u64,
    pub block_rate: f64,
    pub avg_processing_ms: f64,
    pub latency_buckets: Vec<String>,
    pub latency_hist: Vec<u64>,
    pub top_domains: Vec<TopEntryDto>,
    pub top_blocked_domains: Vec<TopEntryDto>,
    pub top_clients: Vec<TopEntryDto>,
    pub top_upstreams: Vec<TopEntryDto>,
    pub qtypes: Vec<TopEntryDto>,
    pub upstream_avg_rtt_ms: HashMap<String, f64>,
    pub upstream_latency_pct: HashMap<String, LatencyPercentilesDto>,
    pub series: Vec<SeriesPointDto>,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_size: usize,
}

fn top(entries: Vec<TopEntry>) -> Vec<TopEntryDto> {
    entries.into_iter().map(Into::into).collect()
}

impl StatsResponse {
    pub fn new(s: StatsSummary, cache_hits: u64, cache_misses: u64, cache_size: usize) -> Self {
        Self {
            total: s.total,
            blocked: s.blocked,
            cached: s.cached,
            rewritten: s.rewritten,
            errors: s.errors,
            block_rate: s.block_rate,
            avg_processing_ms: s.avg_processing_ms,
            latency_buckets: s.latency_buckets,
            latency_hist: s.latency_hist,
            top_domains: top(s.top_domains),
            top_blocked_domains: top(s.top_blocked_domains),
            top_clients: top(s.top_clients),
            top_upstreams: top(s.top_upstreams),
            qtypes: top(s.qtypes),
            upstream_avg_rtt_ms: s.upstream_avg_rtt_ms,
            upstream_latency_pct: s
                .upstream_latency_pct
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            series: s.series.into_iter().map(Into::into).collect(),
            cache_hits,
            cache_misses,
            cache_size,
        }
    }
}

// ---------------------------------------------------------------------------
// Query log
// ---------------------------------------------------------------------------

/// A query-log entry, flattened for the UI, plus the resolved filter-list name.
///
/// The internal `QueryAction` is an internally-tagged enum; here it is splayed
/// into a plain `action` discriminator string and a few optional fields so the
/// generated TypeScript type is a single flat row (rather than a discriminated
/// union) that the query-log table can consume directly.
#[derive(Serialize, ToSchema)]
pub struct LogEntryView {
    pub id: u64,
    /// Unix epoch milliseconds.
    pub time_ms: i64,
    pub client_ip: String,
    pub client_name: Option<String>,
    pub question: String,
    pub qtype: String,
    /// One of `forwarded`, `cached`, `blocked`, `rewritten`, or `error`.
    pub action: String,
    /// Upstream that answered (forwarded queries only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// Matching rule text (blocked/rewritten queries only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Filter list id responsible (blocked/rewritten queries only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_id: Option<u32>,
    /// True if an `@@` exception allowed an otherwise-blocked query.
    pub allowlisted: bool,
    pub rcode: String,
    /// Short summary of answer records (e.g. `["A 1.2.3.4"]`).
    pub answers: Vec<String>,
    pub elapsed_ms: f64,
    /// Friendly name of the filter list responsible (absent unless the query was
    /// blocked or rewritten by a known list; id 0 is the user's custom rules).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_name: Option<String>,
}

impl LogEntryView {
    /// `client_name` is resolved by the caller from the entry's IP against the
    /// current client config, so it reflects renames/removals retroactively.
    pub fn new(e: QueryLogEntry, list_name: Option<String>, client_name: Option<String>) -> Self {
        let (action, upstream, rule, list_id) = match e.action {
            QueryAction::Forwarded { upstream } => ("forwarded", Some(upstream), None, None),
            QueryAction::Cached => ("cached", None, None, None),
            QueryAction::Blocked { rule, list_id } => ("blocked", None, Some(rule), Some(list_id)),
            QueryAction::Rewritten { rule, list_id } => {
                ("rewritten", None, Some(rule), Some(list_id))
            }
            QueryAction::Error => ("error", None, None, None),
        };
        Self {
            id: e.id,
            time_ms: e.time_ms,
            client_ip: e.client_ip,
            client_name,
            question: e.question,
            qtype: e.qtype.into_owned(),
            action: action.to_string(),
            upstream,
            rule,
            list_id,
            allowlisted: e.allowlisted,
            rcode: e.rcode.into_owned(),
            answers: e.answers,
            elapsed_ms: e.elapsed_ms,
            list_name,
        }
    }
}

/// A page of query-log entries.
#[derive(Serialize, ToSchema)]
pub struct QueryLogResponse {
    pub entries: Vec<LogEntryView>,
    /// Total entries currently held (before paging, after filtering).
    pub total: usize,
}

// ---------------------------------------------------------------------------
// Upstreams
// ---------------------------------------------------------------------------

/// The wire protocol used to reach an upstream.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransportKindDto {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

impl From<TransportKind> for TransportKindDto {
    fn from(k: TransportKind) -> Self {
        match k {
            TransportKind::Udp => TransportKindDto::Udp,
            TransportKind::Tcp => TransportKindDto::Tcp,
            TransportKind::Tls => TransportKindDto::Tls,
            TransportKind::Https => TransportKindDto::Https,
            TransportKind::Quic => TransportKindDto::Quic,
        }
    }
}

/// Per-upstream statistics for the UI.
#[derive(Serialize, ToSchema)]
pub struct UpstreamStatDto {
    pub spec: String,
    pub name: String,
    pub kind: TransportKindDto,
    pub up: bool,
    pub avg_rtt_ms: Option<f64>,
    pub last_rtt_ms: Option<f64>,
    pub total_queries: u64,
    pub total_failures: u64,
    pub last_error: Option<String>,
}

impl From<UpstreamStat> for UpstreamStatDto {
    fn from(s: UpstreamStat) -> Self {
        Self {
            spec: s.spec,
            name: s.name,
            kind: s.kind.into(),
            up: s.up,
            avg_rtt_ms: s.avg_rtt_ms,
            last_rtt_ms: s.last_rtt_ms,
            total_queries: s.total_queries,
            total_failures: s.total_failures,
            last_error: s.last_error,
        }
    }
}
