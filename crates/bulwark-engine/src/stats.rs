//! Statistics aggregation: counters, top-N lists, latency histogram, per-upstream
//! response times, and an hourly time-series for charts.
//!
//! State is serializable (`export`/`import`) so the server can persist it across
//! restarts with its own configurable retention.

use std::collections::HashMap;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::querylog::{QueryAction, QueryLogEntry};

/// Upper bound on distinct keys tracked per top-N map (memory guard).
const MAX_KEYS: usize = 50_000;

/// Latency histogram bucket upper-bounds in milliseconds (last bucket = +inf).
const LATENCY_BUCKETS_MS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0];

fn hist_index(ms: f64) -> usize {
    LATENCY_BUCKETS_MS
        .iter()
        .position(|&b| ms <= b)
        .unwrap_or(LATENCY_BUCKETS_MS.len())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Bucket {
    /// Unix epoch hour (seconds / 3600).
    hour: i64,
    total: u64,
    blocked: u64,
    cached: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StatsInner {
    total: u64,
    blocked: u64,
    cached: u64,
    rewritten: u64,
    errors: u64,

    proc_time_sum_ms: f64,
    proc_time_count: u64,
    /// Histogram with `LATENCY_BUCKETS_MS.len() + 1` slots.
    #[serde(default)]
    latency_hist: Vec<u64>,

    domains: HashMap<String, u64>,
    blocked_domains: HashMap<String, u64>,
    clients: HashMap<String, u64>,
    upstreams: HashMap<String, u64>,
    qtypes: HashMap<String, u64>,
    upstream_rtt_sum: HashMap<String, f64>,
    upstream_rtt_count: HashMap<String, u64>,

    #[serde(default)]
    series: Vec<Bucket>,
}

impl StatsInner {
    fn ensure_hist(&mut self) {
        if self.latency_hist.len() != LATENCY_BUCKETS_MS.len() + 1 {
            self.latency_hist = vec![0; LATENCY_BUCKETS_MS.len() + 1];
        }
    }
}

fn bump(map: &mut HashMap<String, u64>, key: &str, by: u64) {
    if let Some(v) = map.get_mut(key) {
        *v += by;
    } else if map.len() < MAX_KEYS {
        map.insert(key.to_string(), by);
    }
}

/// Aggregated statistics.
pub struct Stats {
    inner: Mutex<StatsInner>,
    enabled: std::sync::atomic::AtomicBool,
    max_buckets: std::sync::atomic::AtomicUsize,
}

impl Stats {
    pub fn new(enabled: bool, retention_days: u32) -> Self {
        let mut inner = StatsInner::default();
        inner.ensure_hist();
        Self {
            inner: Mutex::new(inner),
            enabled: std::sync::atomic::AtomicBool::new(enabled),
            max_buckets: std::sync::atomic::AtomicUsize::new(
                ((retention_days.max(1)) * 24) as usize,
            ),
        }
    }

    pub fn reconfigure(&self, enabled: bool, retention_days: u32) {
        self.enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        let max = ((retention_days.max(1)) * 24) as usize;
        self.max_buckets
            .store(max, std::sync::atomic::Ordering::Relaxed);
        let mut inner = self.inner.lock();
        while inner.series.len() > max {
            inner.series.remove(0);
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record one completed query.
    pub fn record(&self, entry: &QueryLogEntry) {
        if !self.is_enabled() {
            return;
        }
        let mut s = self.inner.lock();
        s.ensure_hist();
        s.total += 1;

        let blocked = entry.is_blocked();
        match entry.action {
            QueryAction::Cached => s.cached += 1,
            QueryAction::Rewritten => s.rewritten += 1,
            QueryAction::Error => s.errors += 1,
            _ => {}
        }
        if blocked {
            s.blocked += 1;
        }

        // Latency.
        s.proc_time_sum_ms += entry.elapsed_ms;
        s.proc_time_count += 1;
        let idx = hist_index(entry.elapsed_ms);
        s.latency_hist[idx] += 1;

        // Top-N counters.
        let domain = entry.question.trim_end_matches('.').to_string();
        bump(&mut s.domains, &domain, 1);
        if blocked {
            bump(&mut s.blocked_domains, &domain, 1);
        }
        let client = entry
            .client_name
            .clone()
            .unwrap_or_else(|| entry.client_ip.clone());
        bump(&mut s.clients, &client, 1);
        bump(&mut s.qtypes, &entry.qtype, 1);
        if let Some(up) = &entry.upstream {
            bump(&mut s.upstreams, up, 1);
            *s.upstream_rtt_sum.entry(up.clone()).or_insert(0.0) += entry.elapsed_ms;
            *s.upstream_rtt_count.entry(up.clone()).or_insert(0) += 1;
        }

        // Time series (hourly).
        let hour = entry.time_ms / 1000 / 3600;
        let max = self.max_buckets.load(std::sync::atomic::Ordering::Relaxed);
        match s.series.last_mut() {
            Some(b) if b.hour == hour => {
                b.total += 1;
                if blocked {
                    b.blocked += 1;
                }
                if matches!(entry.action, QueryAction::Cached) {
                    b.cached += 1;
                }
            }
            _ => {
                s.series.push(Bucket {
                    hour,
                    total: 1,
                    blocked: blocked as u64,
                    cached: matches!(entry.action, QueryAction::Cached) as u64,
                });
                while s.series.len() > max {
                    s.series.remove(0);
                }
            }
        }
    }

    /// Reset all statistics.
    pub fn reset(&self) {
        let mut inner = self.inner.lock();
        *inner = StatsInner::default();
        inner.ensure_hist();
    }

    /// Build a snapshot for the API/UI.
    pub fn snapshot(&self, top_n: usize) -> StatsSummary {
        let s = self.inner.lock();
        let avg_proc = if s.proc_time_count > 0 {
            s.proc_time_sum_ms / s.proc_time_count as f64
        } else {
            0.0
        };
        let upstream_rtt = s
            .upstream_rtt_count
            .iter()
            .map(|(k, &c)| {
                let sum = s.upstream_rtt_sum.get(k).copied().unwrap_or(0.0);
                (k.clone(), if c > 0 { sum / c as f64 } else { 0.0 })
            })
            .collect();

        StatsSummary {
            total: s.total,
            blocked: s.blocked,
            cached: s.cached,
            rewritten: s.rewritten,
            errors: s.errors,
            block_rate: if s.total > 0 {
                s.blocked as f64 / s.total as f64
            } else {
                0.0
            },
            avg_processing_ms: avg_proc,
            latency_buckets: latency_labels(),
            latency_hist: s.latency_hist.clone(),
            top_domains: top_n_of(&s.domains, top_n),
            top_blocked_domains: top_n_of(&s.blocked_domains, top_n),
            top_clients: top_n_of(&s.clients, top_n),
            top_upstreams: top_n_of(&s.upstreams, top_n),
            qtypes: top_n_of(&s.qtypes, top_n),
            upstream_avg_rtt_ms: upstream_rtt,
            series: s
                .series
                .iter()
                .map(|b| SeriesPoint {
                    hour: b.hour,
                    total: b.total,
                    blocked: b.blocked,
                    cached: b.cached,
                })
                .collect(),
        }
    }

    /// Serialize state for persistence.
    pub fn export(&self) -> String {
        serde_json::to_string(&*self.inner.lock()).unwrap_or_default()
    }

    /// Load persisted state (best-effort; ignores malformed data).
    pub fn import(&self, json: &str) {
        if let Ok(mut loaded) = serde_json::from_str::<StatsInner>(json) {
            loaded.ensure_hist();
            *self.inner.lock() = loaded;
        }
    }
}

fn latency_labels() -> Vec<String> {
    let mut v: Vec<String> = LATENCY_BUCKETS_MS
        .iter()
        .map(|b| format!("≤{b}ms"))
        .collect();
    v.push(format!(">{}ms", LATENCY_BUCKETS_MS.last().unwrap()));
    v
}

fn top_n_of(map: &HashMap<String, u64>, n: usize) -> Vec<TopEntry> {
    let mut v: Vec<TopEntry> = map
        .iter()
        .map(|(k, &count)| TopEntry {
            name: k.clone(),
            count,
        })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    v.truncate(n);
    v
}

/// A name + count pair for top-N lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopEntry {
    pub name: String,
    pub count: u64,
}

/// A point in the hourly time series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeriesPoint {
    pub hour: i64,
    pub total: u64,
    pub blocked: u64,
    pub cached: u64,
}

/// A snapshot of statistics for the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSummary {
    pub total: u64,
    pub blocked: u64,
    pub cached: u64,
    pub rewritten: u64,
    pub errors: u64,
    pub block_rate: f64,
    pub avg_processing_ms: f64,
    pub latency_buckets: Vec<String>,
    pub latency_hist: Vec<u64>,
    pub top_domains: Vec<TopEntry>,
    pub top_blocked_domains: Vec<TopEntry>,
    pub top_clients: Vec<TopEntry>,
    pub top_upstreams: Vec<TopEntry>,
    pub qtypes: Vec<TopEntry>,
    pub upstream_avg_rtt_ms: HashMap<String, f64>,
    pub series: Vec<SeriesPoint>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(q: &str, action: QueryAction, ms: f64, up: Option<&str>) -> QueryLogEntry {
        QueryLogEntry {
            id: 0,
            time_ms: 1_700_000_000_000,
            client_ip: "10.0.0.1".into(),
            client_name: Some("laptop".into()),
            question: q.into(),
            qtype: "A".into(),
            action,
            allowlisted: false,
            rcode: "NOERROR".into(),
            answers: vec![],
            rule: None,
            list_id: None,
            upstream: up.map(|s| s.to_string()),
            elapsed_ms: ms,
            cached: matches!(action, QueryAction::Cached),
        }
    }

    #[test]
    fn counts_and_top_n() {
        let s = Stats::new(true, 30);
        s.record(&entry("ads.com.", QueryAction::Blocked, 0.5, None));
        s.record(&entry("ads.com.", QueryAction::Blocked, 0.5, None));
        s.record(&entry(
            "good.com.",
            QueryAction::Forwarded,
            12.0,
            Some("1.1.1.1"),
        ));
        s.record(&entry("good.com.", QueryAction::Cached, 0.1, None));

        let snap = s.snapshot(10);
        assert_eq!(snap.total, 4);
        assert_eq!(snap.blocked, 2);
        assert_eq!(snap.cached, 1);
        assert_eq!(snap.top_domains[0].name, "ads.com");
        assert_eq!(snap.top_blocked_domains[0].count, 2);
        assert!(snap.upstream_avg_rtt_ms.contains_key("1.1.1.1"));
        // latency histogram recorded
        assert!(snap.latency_hist.iter().sum::<u64>() == 4);
    }

    #[test]
    fn export_import_roundtrip() {
        let s = Stats::new(true, 30);
        s.record(&entry(
            "x.com.",
            QueryAction::Forwarded,
            3.0,
            Some("8.8.8.8"),
        ));
        let dump = s.export();
        let s2 = Stats::new(true, 30);
        s2.import(&dump);
        assert_eq!(s2.snapshot(10).total, 1);
    }

    #[test]
    fn time_series_buckets_by_hour() {
        let s = Stats::new(true, 1);
        s.record(&entry("x.com.", QueryAction::Forwarded, 1.0, None));
        s.record(&entry("y.com.", QueryAction::Blocked, 1.0, None));
        let snap = s.snapshot(10);
        assert_eq!(snap.series.len(), 1);
        assert_eq!(snap.series[0].total, 2);
        assert_eq!(snap.series[0].blocked, 1);
    }
}
