//! Sharded query statistics and persistence.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::cache::CacheCounters;
use crate::clients::ClientMatcher;
use crate::querylog::{QueryAction, QueryLogEntry};

/// Maximum distinct keys retained across top-N estimators.
const TOPK_KEYS: usize = 4_096;

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

    /// Whole-query latency histogram excluding errors.
    #[serde(default)]
    proc_time_hist: Vec<u64>,

    // Space-Saving bounds untrusted key cardinality.
    #[serde(default)]
    resolved_domains: HeavyHitters,
    blocked_domains: HeavyHitters,
    clients: HeavyHitters,
    // Upstream maps share exact keys.
    upstreams: HashMap<String, u64>,
    upstream_rtt_sum: HashMap<String, f64>,
    upstream_rtt_count: HashMap<String, u64>,
    /// Per-upstream latency histograms.
    #[serde(default)]
    upstream_latency_hist: HashMap<String, Vec<u64>>,

    #[serde(default)]
    series: Vec<Bucket>,

    // Cache counters are stored here only for persistence.
    #[serde(default)]
    cache_hits: u64,
    #[serde(default)]
    cache_misses: u64,
    #[serde(default)]
    cache_stale_hits: u64,
    #[serde(default)]
    cache_refreshes: u64,
    #[serde(default)]
    cache_refresh_failures: u64,
}

impl StatsInner {
    /// Merges another shard into this snapshot accumulator.
    fn merge_from(&mut self, other: &StatsInner) {
        self.total += other.total;
        self.blocked += other.blocked;
        self.cached += other.cached;
        self.rewritten += other.rewritten;
        self.errors += other.errors;
        if !other.proc_time_hist.is_empty() {
            self.proc_time_hist.resize(LATENCY_BUCKETS_MS.len() + 1, 0);
            for (a, b) in self.proc_time_hist.iter_mut().zip(&other.proc_time_hist) {
                *a += b;
            }
        }

        self.resolved_domains.merge_from(&other.resolved_domains);
        self.blocked_domains.merge_from(&other.blocked_domains);
        self.clients.merge_from(&other.clients);
        merge_counts(&mut self.upstreams, &other.upstreams);
        for (k, v) in &other.upstream_rtt_sum {
            *self.upstream_rtt_sum.entry(k.clone()).or_insert(0.0) += v;
        }
        for (k, v) in &other.upstream_rtt_count {
            *self.upstream_rtt_count.entry(k.clone()).or_insert(0) += v;
        }
        for (k, hist) in &other.upstream_latency_hist {
            let dst = self
                .upstream_latency_hist
                .entry(k.clone())
                .or_insert_with(|| vec![0; LATENCY_BUCKETS_MS.len() + 1]);
            if dst.len() == hist.len() {
                for (a, b) in dst.iter_mut().zip(hist) {
                    *a += b;
                }
            }
        }

        for b in &other.series {
            match self.series.iter_mut().find(|x| x.hour == b.hour) {
                Some(x) => {
                    x.total += b.total;
                    x.blocked += b.blocked;
                    x.cached += b.cached;
                }
                None => self.series.push(b.clone()),
            }
        }
    }
}

fn merge_counts(dst: &mut HashMap<String, u64>, src: &HashMap<String, u64>) {
    for (k, v) in src {
        *dst.entry(k.clone()).or_insert(0) += v;
    }
}

fn bump(map: &mut HashMap<String, u64>, key: &str, by: u64, cap: usize) {
    if let Some(v) = map.get_mut(key) {
        *v += by;
    } else if map.len() < cap {
        map.insert(key.to_string(), by);
    }
}

/// Bounded Space-Saving frequency estimator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
struct HeavyHitters {
    counts: HashMap<String, u64>,
}

impl HeavyHitters {
    /// Record `by` observations of `key`, holding the live key set at `cap`.
    fn bump(&mut self, key: &str, by: u64, cap: usize) {
        if let Some(v) = self.counts.get_mut(key) {
            *v += by;
            return;
        }
        if self.counts.len() < cap {
            self.counts.insert(key.to_string(), by);
            return;
        }
        // New keys inherit the evicted minimum count.
        if let Some((min_key, min_val)) = self
            .counts
            .iter()
            .min_by_key(|&(_, &v)| v)
            .map(|(k, &v)| (k.clone(), v))
        {
            self.counts.remove(&min_key);
            self.counts.insert(key.to_string(), min_val + by);
        }
    }

    /// Merges counts into a transient snapshot accumulator.
    fn merge_from(&mut self, other: &HeavyHitters) {
        for (k, v) in &other.counts {
            *self.counts.entry(k.clone()).or_insert(0) += v;
        }
    }
}

/// Selects a power-of-two shard count near the CPU count.
fn shard_count() -> usize {
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    n.next_power_of_two().clamp(1, 64)
}

/// Returns a stable shard slot for the current thread.
fn thread_slot() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static SLOT: Cell<usize> = Cell::new(NEXT.fetch_add(1, Ordering::Relaxed));
    }
    SLOT.with(|s| s.get())
}

/// Aggregated statistics, split into per-CPU shards to avoid lock contention.
pub struct Stats {
    shards: Vec<Mutex<StatsInner>>,
    /// Bit mask for shard selection (`shards.len()` is a power of two).
    mask: usize,
    /// Per-shard distinct-key cap for the top-N maps.
    key_cap: usize,
    enabled: AtomicBool,
    /// Disables per-client counters.
    anonymize: AtomicBool,
    max_buckets: AtomicUsize,
}

impl Stats {
    pub fn new(enabled: bool, retention_days: u32, anonymize: bool) -> Self {
        let n = shard_count();
        let shards = (0..n).map(|_| Mutex::new(StatsInner::default())).collect();
        Self {
            shards,
            mask: n - 1,
            key_cap: (TOPK_KEYS / n).max(256),
            enabled: AtomicBool::new(enabled),
            anonymize: AtomicBool::new(anonymize),
            max_buckets: AtomicUsize::new(((retention_days.max(1)) * 24) as usize),
        }
    }

    /// The shard this thread records into.
    fn shard(&self) -> &Mutex<StatsInner> {
        &self.shards[thread_slot() & self.mask]
    }

    pub fn reconfigure(&self, enabled: bool, retention_days: u32, anonymize: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        self.anonymize.store(anonymize, Ordering::Relaxed);
        let max = ((retention_days.max(1)) * 24) as usize;
        self.max_buckets.store(max, Ordering::Relaxed);
        for shard in &self.shards {
            let mut inner = shard.lock();
            while inner.series.len() > max {
                inner.series.remove(0);
            }
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Records a completed query and optional upstream RTT.
    pub fn record(&self, entry: &QueryLogEntry, upstream_rtt_ms: Option<f64>) {
        if !self.is_enabled() {
            return;
        }

        let blocked = entry.is_blocked();
        let domain = entry.question.trim_end_matches('.');
        let client = entry.client_ip.as_str();
        let up_ms = upstream_rtt_ms.unwrap_or(entry.elapsed_ms);
        let up_idx = hist_index(up_ms);
        let hour = entry.time_ms / 1000 / 3600;
        let max = self.max_buckets.load(Ordering::Relaxed);
        let cap = self.key_cap;

        let mut s = self.shard().lock();
        s.total += 1;

        match entry.action {
            QueryAction::Cached => s.cached += 1,
            QueryAction::Rewritten { .. } => s.rewritten += 1,
            QueryAction::Error => s.errors += 1,
            _ => {}
        }
        if blocked {
            s.blocked += 1;
        }

        // Errors have a separate signal and do not skew latency.
        if !matches!(entry.action, QueryAction::Error) {
            if s.proc_time_hist.is_empty() {
                s.proc_time_hist = vec![0; LATENCY_BUCKETS_MS.len() + 1];
            }
            s.proc_time_hist[hist_index(entry.elapsed_ms)] += 1;
        }

        if blocked {
            s.blocked_domains.bump(domain, 1, cap);
        } else {
            s.resolved_domains.bump(domain, 1, cap);
        }
        if !self.anonymize.load(Ordering::Relaxed) {
            s.clients.bump(client, 1, cap);
        }
        if let Some(up) = entry.upstream() {
            bump(&mut s.upstreams, up, 1, cap);
            match s.upstream_rtt_sum.get_mut(up) {
                Some(v) => *v += up_ms,
                None => {
                    s.upstream_rtt_sum.insert(up.to_string(), up_ms);
                }
            }
            match s.upstream_rtt_count.get_mut(up) {
                Some(v) => *v += 1,
                None => {
                    s.upstream_rtt_count.insert(up.to_string(), 1);
                }
            }
            match s.upstream_latency_hist.get_mut(up) {
                Some(h) => h[up_idx] += 1,
                None => {
                    let mut h = vec![0; LATENCY_BUCKETS_MS.len() + 1];
                    h[up_idx] += 1;
                    s.upstream_latency_hist.insert(up.to_string(), h);
                }
            }
        }

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

    /// Resets all statistics.
    pub fn reset(&self) {
        for shard in &self.shards {
            let mut inner = shard.lock();
            *inner = StatsInner::default();
        }
    }

    /// Merges all shards into an approximate snapshot.
    fn merged(&self) -> StatsInner {
        let mut acc = StatsInner::default();
        for shard in &self.shards {
            let s = shard.lock();
            acc.merge_from(&s);
        }
        acc.series.sort_by_key(|b| b.hour);
        let max = self.max_buckets.load(Ordering::Relaxed);
        while acc.series.len() > max {
            acc.series.remove(0);
        }
        acc
    }

    /// Builds an API snapshot with current client names.
    pub fn snapshot(&self, top_n: usize, clients: &ClientMatcher) -> StatsSummary {
        let s = self.merged();
        let proc_total: u64 = s.proc_time_hist.iter().sum();
        let p95_proc = quantile(&s.proc_time_hist, proc_total, 0.95);
        let upstream_rtt = s
            .upstream_rtt_count
            .iter()
            .map(|(k, &c)| {
                let sum = s.upstream_rtt_sum.get(k).copied().unwrap_or(0.0);
                (k.clone(), if c > 0 { sum / c as f64 } else { 0.0 })
            })
            .collect();
        let upstream_latency_pct = s
            .upstream_latency_hist
            .iter()
            .map(|(k, hist)| (k.clone(), percentiles(hist)))
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
            p95_processing_ms: p95_proc,
            top_resolved_domains: top_n_of(&s.resolved_domains.counts, top_n),
            top_blocked_domains: top_n_of(&s.blocked_domains.counts, top_n),
            top_clients: top_clients_resolved(&s.clients.counts, clients, top_n),
            top_upstreams: top_n_of(&s.upstreams, top_n),
            upstream_avg_rtt_ms: upstream_rtt,
            upstream_latency_pct,
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

    /// Serializes statistics and cache counters.
    pub fn export(&self, cache: CacheCounters) -> String {
        let mut merged = self.merged();
        merged.cache_hits = cache.hits;
        merged.cache_misses = cache.misses;
        merged.cache_stale_hits = cache.stale_hits;
        merged.cache_refreshes = cache.refreshes;
        merged.cache_refresh_failures = cache.refresh_failures;
        serde_json::to_string(&merged).unwrap_or_default()
    }

    /// Restores statistics and returns persisted cache counters.
    pub fn import(&self, json: &str) -> CacheCounters {
        let Ok(loaded) = serde_json::from_str::<StatsInner>(json) else {
            return CacheCounters::default();
        };
        let cache = CacheCounters {
            hits: loaded.cache_hits,
            misses: loaded.cache_misses,
            stale_hits: loaded.cache_stale_hits,
            refreshes: loaded.cache_refreshes,
            refresh_failures: loaded.cache_refresh_failures,
        };
        for (i, shard) in self.shards.iter().enumerate() {
            let mut g = shard.lock();
            if i == 0 {
                *g = loaded.clone();
            } else {
                *g = StatsInner::default();
            }
        }
        cache
    }
}

/// Inclusive lower / exclusive upper bound (ms) of histogram bucket `i`. The
/// final bucket is unbounded above (`+inf`).
fn bucket_bounds(i: usize) -> (f64, f64) {
    let lower = if i == 0 {
        0.0
    } else {
        LATENCY_BUCKETS_MS[i - 1]
    };
    let upper = LATENCY_BUCKETS_MS.get(i).copied().unwrap_or(f64::INFINITY);
    (lower, upper)
}

/// Approximates a histogram quantile by bucket interpolation.
fn quantile(hist: &[u64], total: u64, q: f64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let target = q * total as f64;
    let mut cum = 0u64;
    for (i, &c) in hist.iter().enumerate() {
        if c == 0 {
            continue;
        }
        if (cum + c) as f64 >= target {
            let (lower, upper) = bucket_bounds(i);
            if !upper.is_finite() {
                return lower;
            }
            let within = (target - cum as f64) / c as f64;
            return lower + (upper - lower) * within;
        }
        cum += c;
    }
    *LATENCY_BUCKETS_MS.last().unwrap()
}

fn percentiles(hist: &[u64]) -> LatencyPercentiles {
    let total: u64 = hist.iter().sum();
    LatencyPercentiles {
        p50: quantile(hist, total, 0.50),
        p90: quantile(hist, total, 0.90),
        p99: quantile(hist, total, 0.99),
    }
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

/// Resolves stored IP counts to current client names.
fn top_clients_resolved(
    counts: &HashMap<String, u64>,
    clients: &ClientMatcher,
    n: usize,
) -> Vec<TopEntry> {
    let mut by_label: HashMap<&str, u64> = HashMap::with_capacity(counts.len());
    for (ip, &count) in counts {
        let label = clients.name_for_str(ip).unwrap_or(ip.as_str());
        *by_label.entry(label).or_insert(0) += count;
    }
    let mut v: Vec<TopEntry> = by_label
        .into_iter()
        .map(|(name, count)| TopEntry {
            name: name.to_string(),
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
    /// p95 of successful-query processing latency (ms). Excludes errored queries
    /// and ignores the top 5% tail, so transient upstream failures don't skew it.
    pub p95_processing_ms: f64,
    /// Most-resolved (non-blocked) query names.
    pub top_resolved_domains: Vec<TopEntry>,
    pub top_blocked_domains: Vec<TopEntry>,
    pub top_clients: Vec<TopEntry>,
    pub top_upstreams: Vec<TopEntry>,
    pub upstream_avg_rtt_ms: HashMap<String, f64>,
    pub upstream_latency_pct: HashMap<String, LatencyPercentiles>,
    pub series: Vec<SeriesPoint>,
}

/// Approximate latency percentiles (milliseconds) derived from a bucketed
/// histogram. Accuracy is bounded by the histogram bucket widths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyPercentiles {
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(q: &str, action: QueryAction, ms: f64) -> QueryLogEntry {
        QueryLogEntry {
            id: 0,
            time_ms: 1_700_000_000_000,
            client_ip: "10.0.0.1".into(),
            question: q.into(),
            qtype: "A".into(),
            action,
            allowlisted: false,
            rcode: "NOERROR".into(),
            answers: std::sync::Arc::from([]),
            elapsed_ms: ms,
        }
    }

    fn blocked() -> QueryAction {
        QueryAction::Blocked {
            rule: "||ads^".into(),
            list_id: 0,
        }
    }

    fn forwarded(up: &str) -> QueryAction {
        QueryAction::Forwarded {
            upstream: up.to_string(),
        }
    }

    #[test]
    fn counts_and_top_n() {
        let s = Stats::new(true, 30, false);
        s.record(&entry("ads.com.", blocked(), 0.5), None);
        s.record(&entry("ads.com.", blocked(), 0.5), None);
        s.record(&entry("good.com.", forwarded("1.1.1.1"), 12.0), Some(12.0));
        s.record(&entry("good.com.", QueryAction::Cached, 0.1), None);

        let snap = s.snapshot(10, &ClientMatcher::default());
        assert_eq!(snap.total, 4);
        assert_eq!(snap.blocked, 2);
        assert_eq!(snap.cached, 1);
        assert_eq!(snap.top_resolved_domains[0].name, "good.com");
        assert_eq!(snap.top_resolved_domains[0].count, 2);
        assert!(snap
            .top_resolved_domains
            .iter()
            .all(|t| t.name != "ads.com"));
        assert_eq!(snap.top_blocked_domains[0].count, 2);
        assert!(snap.upstream_avg_rtt_ms.contains_key("1.1.1.1"));
    }

    fn entry_ip(ip: &str, action: QueryAction) -> QueryLogEntry {
        QueryLogEntry {
            client_ip: ip.into(),
            ..entry("x.com.", action, 1.0)
        }
    }

    #[test]
    fn top_clients_resolve_names_retroactively() {
        use bulwark_config::ClientConfig;

        let s = Stats::new(true, 30, false);
        s.record(&entry_ip("10.0.0.1", forwarded("u")), None);
        s.record(&entry_ip("10.0.0.2", forwarded("u")), None);
        s.record(&entry_ip("10.0.0.2", forwarded("u")), None);
        s.record(&entry_ip("192.168.1.5", forwarded("u")), None);
        let bare = s.snapshot(10, &ClientMatcher::default());
        assert_eq!(bare.top_clients.len(), 3);
        let m = ClientMatcher::build(&[ClientConfig {
            id: "lan".into(),
            name: "lan".into(),
            ids: vec!["10.0.0.0/24".into()],
            tags: vec![],
            filtering_enabled: true,
        }]);
        let named = s.snapshot(10, &m);
        assert_eq!(named.top_clients.len(), 2);
        let lan = named
            .top_clients
            .iter()
            .find(|t| t.name == "lan")
            .expect("named row present");
        assert_eq!(lan.count, 3);
        assert!(named.top_clients.iter().any(|t| t.name == "192.168.1.5"));
    }

    #[test]
    fn anonymize_skips_client_counts() {
        let s = Stats::new(true, 30, true);
        s.record(&entry_ip("10.0.0.1", forwarded("u")), None);
        s.record(&entry_ip("10.0.0.2", forwarded("u")), None);
        let snap = s.snapshot(10, &ClientMatcher::default());
        assert_eq!(snap.total, 2, "queries are still counted");
        assert!(
            snap.top_clients.is_empty(),
            "no client IP is retained when anonymizing"
        );
    }

    #[test]
    fn export_import_roundtrip() {
        let s = Stats::new(true, 30, false);
        s.record(&entry("x.com.", forwarded("8.8.8.8"), 3.0), Some(3.0));
        let dump = s.export(CacheCounters::default());
        let s2 = Stats::new(true, 30, false);
        s2.import(&dump);
        assert_eq!(s2.snapshot(10, &ClientMatcher::default()).total, 1);
    }

    #[test]
    fn cache_counters_survive_export_import() {
        let s = Stats::new(true, 30, false);
        let counters = CacheCounters {
            hits: 900,
            misses: 100,
            stale_hits: 120,
            refreshes: 118,
            refresh_failures: 4,
        };
        let dump = s.export(counters);

        let s2 = Stats::new(true, 30, false);
        let restored = s2.import(&dump);
        assert_eq!(restored.hits, 900);
        assert_eq!(restored.misses, 100);
        assert_eq!(restored.stale_hits, 120);
        assert_eq!(restored.refreshes, 118);
        assert_eq!(restored.refresh_failures, 4);
    }

    #[test]
    fn import_of_legacy_blob_without_cache_counters_is_zero() {
        let s = Stats::new(true, 30, false);
        let legacy = r#"{"total":5,"blocked":1,"cached":2,"rewritten":0,"errors":0,
            "blocked_domains":{},"clients":{},"upstreams":{},
            "upstream_rtt_sum":{},"upstream_rtt_count":{}}"#;
        let restored = s.import(legacy);
        assert_eq!(restored.hits, 0);
        assert_eq!(restored.refreshes, 0);
        assert_eq!(s.snapshot(10, &ClientMatcher::default()).total, 5);
    }

    #[test]
    fn per_upstream_percentiles() {
        let s = Stats::new(true, 30, false);
        for _ in 0..95 {
            s.record(&entry("a.com.", forwarded("up"), 5.0), Some(5.0));
        }
        for _ in 0..5 {
            s.record(&entry("a.com.", forwarded("up"), 300.0), Some(300.0));
        }
        let snap = s.snapshot(10, &ClientMatcher::default());
        let p = snap
            .upstream_latency_pct
            .get("up")
            .expect("upstream present");
        assert!(p.p50 <= 5.0, "p50 = {}", p.p50);
        assert!(p.p90 <= 5.0, "p90 = {}", p.p90);
        assert!(p.p99 > 200.0, "p99 = {}", p.p99);
    }

    #[test]
    fn per_upstream_latency_ignores_failover_wall_clock() {
        let s = Stats::new(true, 30, false);
        for _ in 0..100 {
            s.record(&entry("a.com.", forwarded("fast"), 1010.0), Some(5.0));
        }
        let snap = s.snapshot(10, &ClientMatcher::default());
        let p = snap
            .upstream_latency_pct
            .get("fast")
            .expect("upstream present");
        assert!(
            p.p99 <= 5.0,
            "p99 = {} (should track RTT, not timeout)",
            p.p99
        );
        assert!(
            snap.upstream_avg_rtt_ms["fast"] <= 5.0,
            "avg = {}",
            snap.upstream_avg_rtt_ms["fast"]
        );
        assert!(
            snap.p95_processing_ms >= 1000.0,
            "p95_proc = {}",
            snap.p95_processing_ms
        );
    }

    #[test]
    fn errored_queries_excluded_from_processing_latency() {
        let s = Stats::new(true, 30, false);
        for _ in 0..100 {
            s.record(&entry("ok.com.", forwarded("1.1.1.1"), 3.0), Some(3.0));
        }
        for _ in 0..10 {
            s.record(&entry("dead.com.", QueryAction::Error, 5000.0), None);
        }
        let snap = s.snapshot(10, &ClientMatcher::default());
        assert_eq!(snap.errors, 10);
        assert!(
            snap.p95_processing_ms <= 5.0,
            "p95 should ignore errored timeouts, got {}",
            snap.p95_processing_ms
        );
    }

    #[test]
    fn time_series_buckets_by_hour() {
        let s = Stats::new(true, 1, false);
        s.record(&entry("x.com.", forwarded("1.1.1.1"), 1.0), Some(1.0));
        s.record(&entry("y.com.", blocked(), 1.0), None);
        let snap = s.snapshot(10, &ClientMatcher::default());
        assert_eq!(snap.series.len(), 1);
        assert_eq!(snap.series[0].total, 2);
        assert_eq!(snap.series[0].blocked, 1);
    }

    #[test]
    fn heavy_hitters_bound_memory_under_high_cardinality() {
        let s = Stats::new(true, 30, false);
        for i in 0..200_000u32 {
            let name = format!("h{i}.example.");
            s.record(&entry(&name, forwarded("u"), 1.0), Some(1.0));
        }
        for shard in &s.shards {
            let g = shard.lock();
            assert!(
                g.resolved_domains.counts.len() <= s.key_cap,
                "shard held {} keys, cap is {}",
                g.resolved_domains.counts.len(),
                s.key_cap
            );
        }
    }

    #[test]
    fn late_heavy_hitter_still_ranks() {
        let s = Stats::new(true, 30, false);
        for i in 0..(TOPK_KEYS * 4) {
            let name = format!("noise{i}.example.");
            s.record(&entry(&name, forwarded("u"), 1.0), Some(1.0));
        }
        for _ in 0..500 {
            s.record(
                &entry("late-popular.example.", forwarded("u"), 1.0),
                Some(1.0),
            );
        }
        let snap = s.snapshot(10, &ClientMatcher::default());
        assert!(
            snap.top_resolved_domains
                .iter()
                .any(|t| t.name == "late-popular.example"),
            "late heavy hitter missing from top-N: {:?}",
            snap.top_resolved_domains
        );
    }

    #[test]
    fn heavy_hitters_evicts_minimum_after_serde_round_trip() {
        let cap = 4;
        let mut h = HeavyHitters::default();
        h.bump("a", 5, cap);
        h.bump("b", 1, cap);
        h.bump("c", 3, cap);
        h.bump("hot", 10, cap); // estimator is now full
        let json = serde_json::to_string(&h).unwrap();
        let bare: HashMap<String, u64> = serde_json::from_str(&json).unwrap();
        assert_eq!(bare.get("hot"), Some(&10));
        assert_eq!(bare.len(), 4);

        let mut reloaded: HeavyHitters = serde_json::from_str(&json).unwrap();
        reloaded.bump("new", 1, cap);
        assert!(
            !reloaded.counts.contains_key("b"),
            "min entry must be evicted"
        );
        assert_eq!(
            reloaded.counts.get("new"),
            Some(&2),
            "newcomer inherits min + 1"
        );
        for (k, v) in [("a", 5), ("c", 3), ("hot", 10)] {
            assert_eq!(reloaded.counts.get(k), Some(&v), "{k} must be untouched");
        }
    }

    #[test]
    fn aggregates_across_shards() {
        let s = std::sync::Arc::new(Stats::new(true, 30, false));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let s = s.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    s.record(&entry("ads.com.", blocked(), 0.5), None);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let snap = s.snapshot(10, &ClientMatcher::default());
        assert_eq!(snap.total, 16_000);
        assert_eq!(snap.blocked, 16_000);
        assert_eq!(snap.top_blocked_domains[0].count, 16_000);
    }
}
