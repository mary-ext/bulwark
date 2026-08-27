//! Upstream selection, sequential failover, request coalescing, and health probes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::{BoxFuture, Shared};
use futures::FutureExt;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::bootstrap::{Bootstrap, SharedBootstrap};
use crate::doh::DohTransport;
use crate::doq::DoqTransport;
use crate::dot::DotTransport;
use crate::error::{Result, SharedResult, UpstreamError};
use crate::plain::{TcpTransport, UdpTransport};
use crate::probe_log::{now_ms, ProbeErrorKind, ProbeEvent, ProbeLog, ProbeOutcome};
use crate::spec::{Host, TransportKind, UpstreamSpec};
use crate::transport::{normalize_upstream_edns, QueryKey, Transport};

/// One configured upstream as seen by the pool.
#[derive(Debug, Clone)]
pub struct PoolEntry {
    pub spec: String,
    pub name: Option<String>,
}

/// Pool-wide tuning.
#[derive(Debug, Clone)]
pub struct PoolSettings {
    /// Per-attempt query timeout.
    pub query_timeout: Duration,
    /// EWMA smoothing factor for latency (0..1, higher = more reactive).
    pub ewma_alpha: f64,
    /// Consecutive failures before an upstream is marked down.
    pub failure_threshold: u32,
    /// Plain-DNS bootstrap servers for resolving DoT/DoH/DoQ hostnames.
    pub bootstrap: Vec<SocketAddr>,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            query_timeout: Duration::from_secs(5),
            ewma_alpha: 0.2,
            failure_threshold: 2,
            bootstrap: Vec::new(),
        }
    }
}

/// Probe cadence for routing candidates.
const LEAD_PROBE_WINDOW: Duration = Duration::from_secs(180);

/// Probe cadence for failover candidates.
const BENCH_PROBE_WINDOW: Duration = Duration::from_secs(900);

/// Ranks probed at the leader cadence.
const LEAD_PROBE_RANKS: u16 = 2;

/// Returns the probe cadence for a rank.
fn healthy_probe_window(rank: Option<u16>) -> Duration {
    match rank {
        Some(r) if r >= LEAD_PROBE_RANKS => BENCH_PROBE_WINDOW,
        _ => LEAD_PROBE_WINDOW,
    }
}

/// Initial recovery probe delay.
const DOWN_PROBE_BASE: Duration = Duration::from_secs(5);

/// Maximum recovery probe delay.
const DOWN_PROBE_MAX: Duration = Duration::from_secs(60);

/// Calculates the capped exponential recovery delay.
fn retry_backoff(consecutive_failures: u32) -> Duration {
    let steps = consecutive_failures.saturating_sub(1).min(16);
    Duration::from_secs(DOWN_PROBE_BASE.as_secs() << steps).min(DOWN_PROBE_MAX)
}

/// Applies ±25% scheduling jitter.
fn jitter(delay: Duration) -> Duration {
    let factor = 0.75 + rand::random::<f64>() * 0.5; // [0.75, 1.25)
    delay.mul_f64(factor)
}

/// Maximum delay before an upstream's first probe.
const STARTUP_PROBE_SPREAD: Duration = Duration::from_secs(2);

fn startup_delay(max: Duration) -> Duration {
    max.mul_f64(rand::random::<f64>())
}

/// Prevents connection churn between similarly fast upstreams.
const LEADER_STICKY_FRACTION: f64 = 0.15;
const LEADER_STICKY_FLOOR_MS: f64 = 5.0;

/// Minimum latency advantage required to replace the current leader.
fn switch_margin(incumbent_ms: f64) -> f64 {
    (incumbent_ms * LEADER_STICKY_FRACTION).max(LEADER_STICKY_FLOOR_MS)
}

fn ewma(samples: u64, prev_ms: f64, sample_ms: f64, alpha: f64) -> f64 {
    if samples == 0 {
        sample_ms
    } else {
        alpha * sample_ms + (1.0 - alpha) * prev_ms
    }
}

#[derive(Debug, Clone)]
struct Health {
    /// Smoothed probe latency used for routing.
    probe_ewma_ms: f64,
    probe_samples: u64,
    probe_at: Option<Instant>,
    /// New upstreams remain eligible until they cross the failure threshold.
    up: bool,
    consecutive_failures: u32,
    /// Live query counters; probes are excluded.
    total_queries: u64,
    total_failures: u64,
    /// Most recent live-query latency.
    last_rtt_ms: Option<f64>,
    /// Smoothed live-query latency for telemetry only.
    live_ewma_ms: f64,
    live_samples: u64,
    /// Last selection rank and whether hysteresis retained the lead.
    last_rank: Option<u16>,
    lead_held: bool,
    last_error: Option<String>,
    /// Next scheduled probe; `None` means immediately due.
    next_probe_at: Option<Instant>,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            probe_ewma_ms: 0.0,
            probe_samples: 0,
            probe_at: None,
            up: true,
            consecutive_failures: 0,
            total_queries: 0,
            total_failures: 0,
            last_rtt_ms: None,
            live_ewma_ms: 0.0,
            live_samples: 0,
            last_rank: None,
            lead_held: false,
            last_error: None,
            next_probe_at: None,
        }
    }
}

impl Health {
    /// Returns the comparable probe latency used for routing.
    fn routing_latency_ms(&self) -> Option<f64> {
        (self.probe_samples > 0).then_some(self.probe_ewma_ms)
    }

    /// Returns telemetry-only live-query latency.
    fn live_latency_ms(&self) -> Option<f64> {
        (self.live_samples > 0).then_some(self.live_ewma_ms)
    }

    /// Captures probe telemetry while holding the health lock.
    fn snapshot(&self) -> ProbeSnapshot {
        ProbeSnapshot {
            ewma_ms: self.routing_latency_ms(),
            up: self.up,
            consecutive_failures: self.consecutive_failures,
            live_ewma_ms: self.live_latency_ms(),
            live_queries: self.total_queries,
            live_failures: self.total_failures,
            rank: self.last_rank,
            lead_held: self.lead_held,
        }
    }
}

/// Health fields captured after a probe update.
struct ProbeSnapshot {
    ewma_ms: Option<f64>,
    up: bool,
    consecutive_failures: u32,
    live_ewma_ms: Option<f64>,
    live_queries: u64,
    live_failures: u64,
    rank: Option<u16>,
    lead_held: bool,
}

/// A single upstream and its live health.
pub struct Upstream {
    pub spec: UpstreamSpec,
    pub name: String,
    transport: Box<dyn Transport>,
    health: Mutex<Health>,
}

impl Upstream {
    /// Records a successful live query without changing probe-based routing data.
    fn record_live_success(&self, rtt: Duration, alpha: f64) {
        let mut h = self.health.lock();
        let ms = rtt.as_secs_f64() * 1000.0;
        h.total_queries += 1;
        h.last_rtt_ms = Some(ms);
        h.live_ewma_ms = ewma(h.live_samples, h.live_ewma_ms, ms, alpha);
        h.live_samples += 1;
        h.consecutive_failures = 0;
        h.up = true;
        h.last_error = None;
    }

    /// Records a successful probe and schedules the next one.
    fn record_probe_success(&self, rtt: Duration, alpha: f64) -> ProbeSnapshot {
        let mut h = self.health.lock();
        let ms = rtt.as_secs_f64() * 1000.0;
        h.probe_ewma_ms = ewma(h.probe_samples, h.probe_ewma_ms, ms, alpha);
        h.probe_samples += 1;
        h.probe_at = Some(Instant::now());
        self.fold_probe_alive(&mut h);
        h.snapshot()
    }

    /// Records reachability without updating latency.
    fn record_probe_alive(&self, err: &UpstreamError) -> ProbeSnapshot {
        let mut h = self.health.lock();
        self.fold_probe_alive(&mut h);
        h.last_error = Some(err.to_string());
        h.snapshot()
    }

    fn fold_probe_alive(&self, h: &mut Health) {
        h.consecutive_failures = 0;
        h.up = true;
        h.last_error = None;
        h.next_probe_at = Some(Instant::now() + jitter(healthy_probe_window(h.last_rank)));
    }

    /// Records a hard live-query failure.
    fn record_live_failure(&self, err: &UpstreamError, threshold: u32) {
        let mut h = self.health.lock();
        h.total_queries += 1;
        h.total_failures += 1;
        self.fold_failure(&mut h, err, threshold);
    }

    /// Records a probe failure without changing live-query counters.
    fn record_probe_failure(&self, err: &UpstreamError, threshold: u32) -> ProbeSnapshot {
        let mut h = self.health.lock();
        self.fold_failure(&mut h, err, threshold);
        h.snapshot()
    }

    /// Applies shared failure and recovery scheduling state.
    fn fold_failure(&self, h: &mut Health, err: &UpstreamError, threshold: u32) {
        h.consecutive_failures += 1;
        h.last_error = Some(err.to_string());
        if h.consecutive_failures >= threshold {
            h.up = false;
        }
        h.next_probe_at = Some(Instant::now() + jitter(retry_backoff(h.consecutive_failures)));
    }

    /// Records a query-level failure without penalizing upstream health.
    fn record_soft_failure(&self, err: &UpstreamError) {
        let mut h = self.health.lock();
        h.total_queries += 1;
        h.total_failures += 1;
        h.last_error = Some(err.to_string());
    }

    /// Schedules a new upstream's first probe with startup jitter.
    fn schedule_initial_probe(&self) {
        let mut h = self.health.lock();
        if h.next_probe_at.is_none() {
            h.next_probe_at = Some(Instant::now() + startup_delay(STARTUP_PROBE_SPREAD));
        }
    }

    /// Returns the remaining delay, or `None` when due.
    fn probe_due_in(&self, now: Instant) -> Option<Duration> {
        let at = self.health.lock().next_probe_at?;
        (at > now).then(|| at - now)
    }

    /// Ranks clean sampled, probationary, unsampled, then down upstreams.
    fn sort_key(&self) -> (bool, bool, bool, u64) {
        let h = self.health.lock();
        let down = !h.up;
        let est = h.routing_latency_ms();
        let unsampled = est.is_none();
        let recent_hard_failure = h.consecutive_failures > 0;
        let lat = est.unwrap_or(0.0).round() as u64;
        (down, unsampled, recent_hard_failure, lat)
    }

    /// Returns latency only for healthy, sampled, non-probationary upstreams.
    fn routing_latency_if_eligible(&self) -> Option<f64> {
        let h = self.health.lock();
        (h.up && h.consecutive_failures == 0)
            .then(|| h.routing_latency_ms())
            .flatten()
    }

    #[cfg(test)]
    pub(crate) fn set_routing_latency_for_test(&self, ms: f64) {
        let mut h = self.health.lock();
        h.probe_ewma_ms = ms;
        h.probe_samples = h.probe_samples.max(1);
        h.up = true;
        h.consecutive_failures = 0;
    }
    #[cfg(test)]
    pub(crate) fn set_recent_failure_for_test(&self) {
        self.health.lock().consecutive_failures = 1;
    }
    pub fn stat(&self) -> UpstreamStat {
        let h = self.health.lock();
        UpstreamStat {
            spec: self.spec.display.clone(),
            name: self.name.clone(),
            kind: self.spec.kind,
            up: h.up,
            avg_rtt_ms: h.routing_latency_ms(),
            last_rtt_ms: h.last_rtt_ms,
            total_queries: h.total_queries,
            total_failures: h.total_failures,
            last_error: h.last_error.clone(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamStat {
    pub spec: String,
    pub name: String,
    pub kind: TransportKind,
    pub up: bool,
    pub avg_rtt_ms: Option<f64>,
    pub last_rtt_ms: Option<f64>,
    pub total_queries: u64,
    pub total_failures: u64,
    pub last_error: Option<String>,
}
#[derive(Debug, Clone)]
pub struct Resolved {
    pub message: Message,
    pub upstream: String,
    pub rtt_ms: f64,
}

type ResolveFuture = Shared<BoxFuture<'static, SharedResult<Resolved>>>;
struct InflightGuard<'a> {
    map: &'a Mutex<HashMap<QueryKey, ResolveFuture>>,
    key: QueryKey,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.map.lock().remove(&self.key);
    }
}
pub struct UpstreamPool {
    upstreams: Vec<Arc<Upstream>>,
    inflight: Mutex<HashMap<QueryKey, ResolveFuture>>,
    current_leader: Mutex<Option<Arc<Upstream>>>,
    settings: PoolSettings,
    bootstrap: SharedBootstrap,
    probe_log: Arc<ProbeLog>,
    probe_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for UpstreamPool {
    fn drop(&mut self) {
        for task in &self.probe_tasks {
            task.abort();
        }
    }
}

impl UpstreamPool {
    pub async fn build(entries: &[PoolEntry], settings: PoolSettings) -> Result<Self> {
        let bootstrap: SharedBootstrap = Arc::new(Bootstrap::new(settings.bootstrap.clone()));
        let mut upstreams = Vec::new();
        for entry in entries {
            let spec = UpstreamSpec::parse(&entry.spec)?;
            let transport = make_transport(&spec, bootstrap.clone()).await?;
            let name = entry.name.clone().unwrap_or_else(|| spec.display.clone());
            upstreams.push(Arc::new(Upstream {
                spec,
                name,
                transport,
                health: Mutex::new(Health::default()),
            }));
        }
        Ok(Self {
            upstreams,
            inflight: Mutex::new(HashMap::new()),
            current_leader: Mutex::new(None),
            settings,
            bootstrap,
            probe_log: Arc::new(ProbeLog::new(false)),
            probe_tasks: Vec::new(),
        })
    }
    pub fn set_probe_log(&mut self, probe_log: Arc<ProbeLog>) {
        self.probe_log = probe_log;
    }

    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty()
    }

    pub fn upstreams(&self) -> &[Arc<Upstream>] {
        &self.upstreams
    }
    pub fn stats(&self) -> Vec<UpstreamStat> {
        self.upstreams.iter().map(|u| u.stat()).collect()
    }

    pub fn bootstrap(&self) -> &SharedBootstrap {
        &self.bootstrap
    }
    pub(crate) fn ordered(&self) -> Vec<Arc<Upstream>> {
        let mut v: Vec<Arc<Upstream>> = self.upstreams.clone();
        v.sort_by_key(|u| u.sort_key());

        let mut leader = self.current_leader.lock();
        let mut held_lead = false;
        if let Some(cur) = leader.as_ref() {
            if let Some(pos) = v.iter().position(|u| Arc::ptr_eq(u, cur)) {
                if pos != 0 {
                    if let (Some(inc), Some(best)) = (
                        v[pos].routing_latency_if_eligible(),
                        v[0].routing_latency_if_eligible(),
                    ) {
                        if inc - best <= switch_margin(inc) {
                            let held = v.remove(pos);
                            v.insert(0, held);
                            held_lead = true;
                        }
                    }
                }
            }
        }
        *leader = v.first().cloned();
        for (i, u) in v.iter().enumerate() {
            let mut h = u.health.lock();
            h.last_rank = Some(i.min(u16::MAX as usize) as u16);
            h.lead_held = i == 0 && held_lead;
        }
        v
    }
    pub async fn resolve(&self, query: &Message) -> Result<Resolved> {
        if self.upstreams.is_empty() {
            return Err(UpstreamError::NoUpstreams);
        }
        let key = match QueryKey::from_message(query) {
            Some(k) => k,
            None => return Err(UpstreamError::Proto("query has no question".into())),
        };
        let (fut, _guard) = {
            let map = self.inflight.lock();
            if let Some(existing) = map.get(&key) {
                (existing.clone(), None)
            } else {
                drop(map);
                let ordered = self.ordered();
                let timeout = self.settings.query_timeout;
                let threshold = self.settings.failure_threshold;
                let alpha = self.settings.ewma_alpha;
                let mut q = query.clone();
                normalize_upstream_edns(&mut q);
                let fut: ResolveFuture =
                    async move { resolve_sequential(ordered, q, timeout, threshold, alpha).await }
                        .boxed()
                        .shared();
                let mut map = self.inflight.lock();
                if let Some(existing) = map.get(&key) {
                    (existing.clone(), None)
                } else {
                    map.insert(key.clone(), fut.clone());
                    let guard = InflightGuard {
                        map: &self.inflight,
                        key: key.clone(),
                    };
                    (fut, Some(guard))
                }
            }
        };

        let result = fut.await;

        match result {
            Ok(mut resolved) => {
                resolved.message.metadata.id = query.metadata.id;
                Ok(resolved)
            }
            Err(arc) => Err((*arc).clone()),
        }
    }
    pub async fn probe_all(&self) {
        let query = probe_query();
        for up in &self.upstreams {
            probe_once(up, &query, &self.settings, &self.probe_log).await;
        }
    }
    pub fn start_probing(&mut self) {
        for up in &self.upstreams {
            up.schedule_initial_probe();
            let up = up.clone();
            let settings = self.settings.clone();
            let probe_log = self.probe_log.clone();
            self.probe_tasks
                .push(tokio::spawn(probe_loop(up, settings, probe_log)));
        }
    }
    pub fn adopt_health_from(&self, old: &UpstreamPool) {
        let prior: HashMap<String, &Arc<Upstream>> = old
            .upstreams
            .iter()
            .map(|u| (u.spec.identity(), u))
            .collect();
        for up in &self.upstreams {
            if let Some(old_up) = prior.get(&up.spec.identity()) {
                let carried = old_up.health.lock().clone();
                *up.health.lock() = carried;
            }
        }
    }
}
async fn probe_loop(up: Arc<Upstream>, settings: PoolSettings, probe_log: Arc<ProbeLog>) {
    let query = probe_query();
    loop {
        match up.probe_due_in(Instant::now()) {
            Some(remaining) => tokio::time::sleep(remaining).await,
            None => probe_once(&up, &query, &settings, &probe_log).await,
        }
    }
}
enum Shot {
    Answered(Duration),
    Failed(ProbeOutcome, UpstreamError),
}
async fn probe_shot(up: &Upstream, query: &Message, timeout: Duration) -> Shot {
    let start = Instant::now();
    match tokio::time::timeout(timeout, up.transport.query(query)).await {
        Ok(Ok(resp)) => match classify(&resp) {
            Verdict::Answer => Shot::Answered(start.elapsed()),
            Verdict::Reject => Shot::Failed(ProbeOutcome::Reject, rcode_err(&resp)),
            Verdict::SoftFail => Shot::Failed(ProbeOutcome::SoftFail, rcode_err(&resp)),
        },
        Ok(Err(e)) => Shot::Failed(ProbeOutcome::Error, e),
        Err(_) => Shot::Failed(ProbeOutcome::Timeout, UpstreamError::Timeout),
    }
}
/// Uses the first shot for liveness and the second for latency.
async fn probe_once(up: &Upstream, query: &Message, settings: &PoolSettings, probe_log: &ProbeLog) {
    let (outcome, first_rtt_ms, rtt_ms, snap, err) =
        match probe_shot(up, query, settings.query_timeout).await {
            Shot::Answered(first) => {
                let first_ms = Some(first.as_secs_f64() * 1000.0);
                match probe_shot(up, query, settings.query_timeout).await {
                    Shot::Answered(warm) => {
                        let snap = up.record_probe_success(warm, settings.ewma_alpha);
                        let ms = warm.as_secs_f64() * 1000.0;
                        (ProbeOutcome::Answer, first_ms, Some(ms), snap, None)
                    }
                    Shot::Failed(_, e) => {
                        let snap = up.record_probe_alive(&e);
                        (ProbeOutcome::MeasureFail, first_ms, None, snap, Some(e))
                    }
                }
            }
            Shot::Failed(outcome, e) => {
                let snap = up.record_probe_failure(&e, settings.failure_threshold);
                (outcome, None, None, snap, Some(e))
            }
        };
    if probe_log.is_enabled() {
        let error_kind = err.as_ref().map(ProbeErrorKind::from_error);
        probe_log.push(ProbeEvent {
            time_ms: now_ms(),
            upstream: up.spec.display.clone(),
            name: up.name.clone(),
            kind: up.spec.kind,
            outcome,
            rtt_ms,
            first_rtt_ms,
            ewma_ms: snap.ewma_ms,
            up: snap.up,
            consecutive_failures: snap.consecutive_failures,
            detail: err.map(|e| e.to_string()),
            error_kind,
            live_ewma_ms: snap.live_ewma_ms,
            live_queries: snap.live_queries,
            live_failures: snap.live_failures,
            rank: snap.rank,
            lead_held: snap.lead_held,
        });
    }
}
enum Verdict {
    Answer,
    Reject,
    SoftFail,
}
fn classify(resp: &Message) -> Verdict {
    match resp.metadata.response_code {
        ResponseCode::Refused | ResponseCode::NotImp => Verdict::Reject,
        ResponseCode::ServFail | ResponseCode::FormErr => Verdict::SoftFail,
        _ => Verdict::Answer,
    }
}
fn rcode_err(resp: &Message) -> UpstreamError {
    UpstreamError::Rcode(format!("{:?}", resp.metadata.response_code))
}
async fn resolve_sequential(
    ordered: Vec<Arc<Upstream>>,
    query: Message,
    timeout: Duration,
    threshold: u32,
    alpha: f64,
) -> SharedResult<Resolved> {
    let mut last = UpstreamError::NoUpstreams;
    let mut fallback: Option<Resolved> = None;
    for up in ordered {
        let start = Instant::now();
        match tokio::time::timeout(timeout, up.transport.query(&query)).await {
            Ok(Ok(resp)) => {
                let rtt = start.elapsed();
                let rtt_ms = rtt.as_secs_f64() * 1000.0;
                match classify(&resp) {
                    Verdict::Answer => {
                        up.record_live_success(rtt, alpha);
                        return Ok(Resolved {
                            message: resp,
                            upstream: up.name.clone(),
                            rtt_ms,
                        });
                    }
                    verdict => {
                        let err = rcode_err(&resp);
                        match verdict {
                            Verdict::Reject => up.record_live_failure(&err, threshold),
                            _ => up.record_soft_failure(&err),
                        }
                        if fallback.is_none() {
                            fallback = Some(Resolved {
                                message: resp,
                                upstream: up.name.clone(),
                                rtt_ms,
                            });
                        }
                        last = err;
                    }
                }
            }
            Ok(Err(e)) => {
                up.record_live_failure(&e, threshold);
                last = e;
            }
            Err(_) => {
                up.record_live_failure(&UpstreamError::Timeout, threshold);
                last = UpstreamError::Timeout;
            }
        }
    }
    if let Some(resolved) = fallback {
        return Ok(resolved);
    }
    Err(Arc::new(UpstreamError::AllFailed(Box::new(last))))
}
pub(crate) async fn make_transport(
    spec: &UpstreamSpec,
    bootstrap: SharedBootstrap,
) -> Result<Box<dyn Transport>> {
    match spec.kind {
        TransportKind::Udp => Ok(Box::new(UdpTransport::new(
            plain_addr(spec, &bootstrap).await?,
        ))),
        TransportKind::Tcp => Ok(Box::new(TcpTransport::new(
            plain_addr(spec, &bootstrap).await?,
        ))),
        TransportKind::Tls => Ok(Box::new(DotTransport::new(spec.clone(), bootstrap)?)),
        TransportKind::Https => Ok(Box::new(DohTransport::new(spec.clone(), bootstrap))),
        TransportKind::Quic => Ok(Box::new(DoqTransport::new(spec.clone(), bootstrap))),
    }
}
async fn plain_addr(spec: &UpstreamSpec, bootstrap: &Bootstrap) -> Result<SocketAddr> {
    match &spec.host {
        Host::Ip(ip) => Ok(SocketAddr::new(*ip, spec.port)),
        Host::Name(name) => {
            let ips = bootstrap.resolve(name).await?;
            let ip = ips
                .into_iter()
                .next()
                .ok_or_else(|| UpstreamError::Bootstrap(name.clone()))?;
            Ok(SocketAddr::new(ip, spec.port))
        }
    }
}
fn probe_query() -> Message {
    let mut msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut q = Query::query(Name::from_str(".").unwrap(), RecordType::NS);
    q.set_query_class(DNSClass::IN);
    msg.queries.push(q);
    msg
}
pub async fn test_spec(
    spec_str: &str,
    bootstrap: SharedBootstrap,
    timeout: Duration,
) -> Result<Duration> {
    let spec = UpstreamSpec::parse(spec_str)?;
    let transport = make_transport(&spec, bootstrap).await?;
    let mut msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut q = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);
    q.set_query_class(DNSClass::IN);
    msg.queries.push(q);

    let start = Instant::now();
    tokio::time::timeout(timeout, transport.query(&msg))
        .await
        .map_err(|_| UpstreamError::Timeout)??;
    Ok(start.elapsed())
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    #[test]
    fn retry_backoff_doubles_then_caps() {
        assert_eq!(retry_backoff(1), DOWN_PROBE_BASE);
        assert_eq!(retry_backoff(2), DOWN_PROBE_BASE * 2);
        assert_eq!(retry_backoff(3), DOWN_PROBE_BASE * 4);
        assert_eq!(retry_backoff(100), DOWN_PROBE_MAX);
        assert!(retry_backoff(u32::MAX) <= DOWN_PROBE_MAX);
    }

    #[test]
    fn jitter_stays_within_25_percent() {
        let base = Duration::from_secs(100);
        for _ in 0..1000 {
            let j = jitter(base);
            assert!(j >= base.mul_f64(0.75) && j <= base.mul_f64(1.25), "{j:?}");
        }
    }

    #[test]
    fn recovery_is_always_more_eager_than_resampling() {
        assert!(
            DOWN_PROBE_MAX < LEAD_PROBE_WINDOW,
            "a down upstream must be retried sooner than a healthy one is resampled"
        );
    }

    #[test]
    fn cadence_follows_rank() {
        assert_eq!(healthy_probe_window(Some(0)), LEAD_PROBE_WINDOW);
        assert_eq!(healthy_probe_window(Some(1)), LEAD_PROBE_WINDOW);
        assert_eq!(healthy_probe_window(Some(2)), BENCH_PROBE_WINDOW);
        assert_eq!(healthy_probe_window(Some(7)), BENCH_PROBE_WINDOW);
        assert_eq!(
            healthy_probe_window(None),
            LEAD_PROBE_WINDOW,
            "an unranked upstream converges at the leader cadence"
        );
    }

    #[test]
    fn routing_latency_is_probe_only() {
        let h = Health {
            probe_ewma_ms: 19.0,
            probe_samples: 1,
            probe_at: Some(Instant::now()),
            last_rtt_ms: Some(120.0),
            ..Health::default()
        };
        assert_eq!(h.routing_latency_ms(), Some(19.0));
        assert_eq!(Health::default().routing_latency_ms(), None);
    }
}
