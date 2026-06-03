//! Statistics aggregation: counters, top-N lists, latency histogram, per-upstream
//! response times, and an hourly time-series for charts.
//!
//! State is serializable (`export`/`import`) so the server can persist it across
//! restarts with its own configurable retention.
//!
//! # Concurrency
//!
//! Recording happens on every resolved query, so it must not become a
//! serialization point under load. Instead of one global lock, the state is
//! split into a small number of independently-locked shards (one per CPU,
//! rounded to a power of two). Each OS thread is pinned to a single shard, so
//! the tokio worker threads almost never contend with one another. Reads
//! (`snapshot`/`export`) merge the shards under their individual locks.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::querylog::{QueryAction, QueryLogEntry};

/// Upper bound on distinct keys tracked per top-N map, summed across shards
/// (memory guard). Divided evenly between shards at construction.
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
    /// Per-upstream latency histograms (same buckets as `latency_hist`), kept so
    /// the snapshot can derive approximate p50/p90/p99 per upstream.
    #[serde(default)]
    upstream_latency_hist: HashMap<String, Vec<u64>>,

    #[serde(default)]
    series: Vec<Bucket>,
}

impl StatsInner {
    fn ensure_hist(&mut self) {
        if self.latency_hist.len() != LATENCY_BUCKETS_MS.len() + 1 {
            self.latency_hist = vec![0; LATENCY_BUCKETS_MS.len() + 1];
        }
    }

    /// Fold another shard's state into this accumulator (used for snapshots).
    fn merge_from(&mut self, other: &StatsInner) {
        self.total += other.total;
        self.blocked += other.blocked;
        self.cached += other.cached;
        self.rewritten += other.rewritten;
        self.errors += other.errors;
        self.proc_time_sum_ms += other.proc_time_sum_ms;
        self.proc_time_count += other.proc_time_count;

        self.ensure_hist();
        if other.latency_hist.len() == self.latency_hist.len() {
            for (a, b) in self.latency_hist.iter_mut().zip(&other.latency_hist) {
                *a += b;
            }
        }

        merge_counts(&mut self.domains, &other.domains);
        merge_counts(&mut self.blocked_domains, &other.blocked_domains);
        merge_counts(&mut self.clients, &other.clients);
        merge_counts(&mut self.upstreams, &other.upstreams);
        merge_counts(&mut self.qtypes, &other.qtypes);
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

/// Number of shards: one per CPU, rounded up to a power of two so shard
/// selection is a cheap mask, and clamped to a sane range.
fn shard_count() -> usize {
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    n.next_power_of_two().clamp(1, 64)
}

/// A stable, process-wide slot for the calling thread, used to pin each thread
/// to one shard. Worker threads are long-lived, so this is computed once.
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
    max_buckets: AtomicUsize,
}

impl Stats {
    pub fn new(enabled: bool, retention_days: u32) -> Self {
        let n = shard_count();
        let shards = (0..n)
            .map(|_| {
                let mut inner = StatsInner::default();
                inner.ensure_hist();
                Mutex::new(inner)
            })
            .collect();
        Self {
            shards,
            mask: n - 1,
            key_cap: (MAX_KEYS / n).max(1024),
            enabled: AtomicBool::new(enabled),
            max_buckets: AtomicUsize::new(((retention_days.max(1)) * 24) as usize),
        }
    }

    /// The shard this thread records into.
    fn shard(&self) -> &Mutex<StatsInner> {
        &self.shards[thread_slot() & self.mask]
    }

    pub fn reconfigure(&self, enabled: bool, retention_days: u32) {
        self.enabled.store(enabled, Ordering::Relaxed);
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

    /// Record one completed query.
    pub fn record(&self, entry: &QueryLogEntry) {
        if !self.is_enabled() {
            return;
        }

        // Prepare everything that doesn't need the lock first, and keep the
        // critical section to cheap map probes / increments. The top-N maps take
        // `&str` keys and only allocate when a *new* key is inserted, so the
        // common (existing-key) path holds the lock without allocating.
        let blocked = entry.is_blocked();
        let domain = entry.question.trim_end_matches('.');
        let client = entry
            .client_name
            .as_deref()
            .unwrap_or(entry.client_ip.as_str());
        let idx = hist_index(entry.elapsed_ms);
        let hour = entry.time_ms / 1000 / 3600;
        let max = self.max_buckets.load(Ordering::Relaxed);
        let cap = self.key_cap;

        let mut s = self.shard().lock();
        s.ensure_hist();
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

        // Latency.
        s.proc_time_sum_ms += entry.elapsed_ms;
        s.proc_time_count += 1;
        s.latency_hist[idx] += 1;

        // Top-N counters.
        bump(&mut s.domains, domain, 1, cap);
        if blocked {
            bump(&mut s.blocked_domains, domain, 1, cap);
        }
        bump(&mut s.clients, client, 1, cap);
        bump(&mut s.qtypes, entry.qtype.as_ref(), 1, cap);
        if let Some(up) = entry.upstream() {
            bump(&mut s.upstreams, up, 1, cap);
            // Avoid cloning the upstream name on the hot (existing-key) path.
            match s.upstream_rtt_sum.get_mut(up) {
                Some(v) => *v += entry.elapsed_ms,
                None => {
                    s.upstream_rtt_sum.insert(up.to_string(), entry.elapsed_ms);
                }
            }
            match s.upstream_rtt_count.get_mut(up) {
                Some(v) => *v += 1,
                None => {
                    s.upstream_rtt_count.insert(up.to_string(), 1);
                }
            }
            match s.upstream_latency_hist.get_mut(up) {
                Some(h) => h[idx] += 1,
                None => {
                    let mut h = vec![0; LATENCY_BUCKETS_MS.len() + 1];
                    h[idx] += 1;
                    s.upstream_latency_hist.insert(up.to_string(), h);
                }
            }
        }

        // Time series (hourly).
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
        for shard in &self.shards {
            let mut inner = shard.lock();
            *inner = StatsInner::default();
            inner.ensure_hist();
        }
    }

    /// Merge every shard into a single view. Shards are locked one at a time, so
    /// a concurrently-recording thread may land just before or after the merge
    /// point — acceptable for monotonic, approximate statistics.
    fn merged(&self) -> StatsInner {
        let mut acc = StatsInner::default();
        acc.ensure_hist();
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

    /// Build a snapshot for the API/UI.
    pub fn snapshot(&self, top_n: usize) -> StatsSummary {
        let s = self.merged();
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
            avg_processing_ms: avg_proc,
            latency_buckets: latency_labels(),
            latency_hist: s.latency_hist.clone(),
            top_domains: top_n_of(&s.domains, top_n),
            top_blocked_domains: top_n_of(&s.blocked_domains, top_n),
            top_clients: top_n_of(&s.clients, top_n),
            top_upstreams: top_n_of(&s.upstreams, top_n),
            qtypes: top_n_of(&s.qtypes, top_n),
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

    /// Serialize state for persistence.
    pub fn export(&self) -> String {
        serde_json::to_string(&self.merged()).unwrap_or_default()
    }

    /// Load persisted state (best-effort; ignores malformed data). Everything is
    /// loaded into a single shard; the rest are cleared.
    pub fn import(&self, json: &str) {
        let Ok(mut loaded) = serde_json::from_str::<StatsInner>(json) else {
            return;
        };
        loaded.ensure_hist();
        for (i, shard) in self.shards.iter().enumerate() {
            let mut g = shard.lock();
            if i == 0 {
                *g = loaded.clone();
            } else {
                *g = StatsInner::default();
                g.ensure_hist();
            }
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

/// Inclusive lower / exclusive upper bound (ms) of histogram bucket `i`. The
/// final bucket is unbounded above (`+inf`).
fn bucket_bounds(i: usize) -> (f64, f64) {
    let lower = if i == 0 { 0.0 } else { LATENCY_BUCKETS_MS[i - 1] };
    let upper = LATENCY_BUCKETS_MS.get(i).copied().unwrap_or(f64::INFINITY);
    (lower, upper)
}

/// Approximate the `q` quantile (0..=1) of a bucketed histogram by linear
/// interpolation within the bucket that holds the target rank. Samples in the
/// unbounded final bucket pin to its lower bound (can't interpolate to +inf).
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
            client_name: Some("laptop".into()),
            question: q.into(),
            qtype: "A".into(),
            action,
            allowlisted: false,
            rcode: "NOERROR".into(),
            answers: vec![],
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
        let s = Stats::new(true, 30);
        s.record(&entry("ads.com.", blocked(), 0.5));
        s.record(&entry("ads.com.", blocked(), 0.5));
        s.record(&entry("good.com.", forwarded("1.1.1.1"), 12.0));
        s.record(&entry("good.com.", QueryAction::Cached, 0.1));

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
        s.record(&entry("x.com.", forwarded("8.8.8.8"), 3.0));
        let dump = s.export();
        let s2 = Stats::new(true, 30);
        s2.import(&dump);
        assert_eq!(s2.snapshot(10).total, 1);
    }

    #[test]
    fn per_upstream_percentiles() {
        let s = Stats::new(true, 30);
        // 100 fast samples (~5ms) and a few slow ones to push the tail up.
        for _ in 0..95 {
            s.record(&entry("a.com.", forwarded("up"), 5.0));
        }
        for _ in 0..5 {
            s.record(&entry("a.com.", forwarded("up"), 300.0));
        }
        let snap = s.snapshot(10);
        let p = snap.upstream_latency_pct.get("up").expect("upstream present");
        // p50/p90 fall in the ≤5ms bucket; p99 lands in the slow tail.
        assert!(p.p50 <= 5.0, "p50 = {}", p.p50);
        assert!(p.p90 <= 5.0, "p90 = {}", p.p90);
        assert!(p.p99 > 200.0, "p99 = {}", p.p99);
    }

    #[test]
    fn time_series_buckets_by_hour() {
        let s = Stats::new(true, 1);
        s.record(&entry("x.com.", forwarded("1.1.1.1"), 1.0));
        s.record(&entry("y.com.", blocked(), 1.0));
        let snap = s.snapshot(10);
        assert_eq!(snap.series.len(), 1);
        assert_eq!(snap.series[0].total, 2);
        assert_eq!(snap.series[0].blocked, 1);
    }

    #[test]
    fn aggregates_across_shards() {
        // Spread records across many threads so multiple shards are populated,
        // then confirm the merged snapshot is exact.
        let s = std::sync::Arc::new(Stats::new(true, 30));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let s = s.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    s.record(&entry("ads.com.", blocked(), 0.5));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let snap = s.snapshot(10);
        assert_eq!(snap.total, 16_000);
        assert_eq!(snap.blocked, 16_000);
        assert_eq!(snap.top_blocked_domains[0].count, 16_000);
        assert_eq!(snap.latency_hist.iter().sum::<u64>(), 16_000);
    }
}
