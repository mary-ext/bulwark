//! The upstream pool: fastest-upstream selection, **sequential** failover (one
//! upstream per query — never a parallel fan-out), single-flight de-duplication
//! of identical in-flight queries, and polite background latency probing.

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

/// How long after a healthy sample the next probe is scheduled. Live queries
/// refresh the same health, so a busy upstream keeps pushing this out and is
/// effectively never probed — only idle upstreams (e.g. standby fallbacks) get
/// probed, and only to keep their latency estimate from going stale.
const HEALTHY_PROBE_WINDOW: Duration = Duration::from_secs(60);

/// First retry delay after an upstream goes down. A downed upstream gets no live
/// traffic (it sorts last), so probing is the only thing that can recover it —
/// hence we retry soon at first, then [`retry_backoff`] doubles the gap on each
/// further consecutive failure up to [`DOWN_PROBE_MAX`].
const DOWN_PROBE_BASE: Duration = Duration::from_secs(5);

/// Ceiling on the retry backoff so a long-dead upstream is still re-checked
/// periodically rather than drifting toward never.
const DOWN_PROBE_MAX: Duration = Duration::from_secs(300);

/// Exponential backoff for a failing upstream: `DOWN_PROBE_BASE`, doubling on
/// each consecutive failure, clamped to `DOWN_PROBE_MAX`. `consecutive_failures`
/// is 1 on the first failure, so the first retry waits the base delay.
fn retry_backoff(consecutive_failures: u32) -> Duration {
    // Cap the shift well before it could overflow the seconds count; the `.min`
    // clamp makes anything past a few steps moot anyway.
    let steps = consecutive_failures.saturating_sub(1).min(16);
    Duration::from_secs(DOWN_PROBE_BASE.as_secs() << steps).min(DOWN_PROBE_MAX)
}

/// Apply ±25% random jitter to a scheduling delay so probes across a fleet of
/// upstreams de-correlate instead of stampeding in the same tick.
fn jitter(delay: Duration) -> Duration {
    let factor = 0.75 + rand::random::<f64>() * 0.5; // [0.75, 1.25)
    delay.mul_f64(factor)
}

/// Spread for the *first* probe of each upstream after a pool is built. That
/// probe is scheduled at a uniform-random point in `[0, this)`, so a pool of N
/// upstreams — at cold start *or* on every config reload — doesn't fire N probes
/// at the same instant.
const STARTUP_PROBE_SPREAD: Duration = Duration::from_secs(2);

/// A uniform-random delay in `[0, max)`.
fn startup_delay(max: Duration) -> Duration {
    max.mul_f64(rand::random::<f64>())
}

/// How long to wait before re-probing a *healthy idle* upstream, from its own
/// smoothed latency and the lowest among its healthy peers.
///
/// With several upstreams configured, some are simply always slower and will
/// never be picked. There's no point polling them as often as the contenders —
/// so an upstream competitive with the leader keeps the base cadence, while one
/// that sits progressively further behind gets a progressively longer interval
/// (up to 8×). The leader itself is kept fresh; we only back off the also-rans,
/// and only by latency margin, so a backup that's *close* still stays warm for
/// failover. Unknown latency (just came up) counts as competitive so we sample
/// it properly first.
fn idle_probe_window(self_ewma: Option<f64>, best_ewma: Option<f64>) -> Duration {
    let mult = match (self_ewma, best_ewma) {
        (Some(mine), Some(best)) => match mine / best.max(1.0) {
            // Floor `best` at 1ms so a near-zero leader (e.g. a LAN resolver)
            // can't blow the ratio up to infinity.
            r if r <= 1.5 => 1,
            r if r <= 3.0 => 2,
            r if r <= 6.0 => 4,
            _ => 8,
        },
        _ => 1,
    };
    HEALTHY_PROBE_WINDOW * mult
}

/// Where a latency sample came from. Live and background-probe latencies are
/// tracked in separate EWMAs because they measure different things: the probe is
/// a tiny, cache-hot `NS .`, while live traffic is real A/AAAA/HTTPS lookups that
/// may exercise slower resolver paths. Mixing them into one average lets the
/// cheap probe flatter (or the real traffic distort) the other.
#[derive(Clone, Copy)]
enum Source {
    Live,
    Probe,
}

/// EWMA update: the first sample seeds the average, later ones blend in by
/// `alpha`.
fn ewma(samples: u64, prev_ms: f64, sample_ms: f64, alpha: f64) -> f64 {
    if samples == 0 {
        sample_ms
    } else {
        alpha * sample_ms + (1.0 - alpha) * prev_ms
    }
}

#[derive(Debug, Clone)]
struct Health {
    /// Smoothed latency of real user queries, with its sample count and the
    /// instant of the most recent sample (used to decide which estimate is
    /// fresher — see [`Health::estimate_ms`]).
    live_ewma_ms: f64,
    live_samples: u64,
    live_at: Option<Instant>,
    /// Smoothed latency of background probes, kept apart from the live figure.
    probe_ewma_ms: f64,
    probe_samples: u64,
    probe_at: Option<Instant>,
    /// Presumed up until proven down. A fresh upstream starts up so it gets a
    /// chance; it's marked down only after crossing the failure threshold. (If
    /// this defaulted to false, a never-*successful* upstream couldn't be
    /// distinguished from an untried one and would never sort as down.)
    up: bool,
    consecutive_failures: u32,
    total_queries: u64,
    total_failures: u64,
    last_rtt_ms: Option<f64>,
    last_error: Option<String>,
    /// When this upstream is next due for a background probe. Rescheduled by
    /// every probe *and* every live query: a healthy sample pushes it out a full
    /// window, a failure pushes it out by an exponentially-backed-off (and
    /// jittered) retry delay. `None` means "due now" — never sampled yet. This is
    /// the whole self-tuning cadence: busy upstreams keep deferring their probe
    /// via live traffic, idle ones get kept warm, dead ones back off.
    next_probe_at: Option<Instant>,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            live_ewma_ms: 0.0,
            live_samples: 0,
            live_at: None,
            probe_ewma_ms: 0.0,
            probe_samples: 0,
            probe_at: None,
            up: true,
            consecutive_failures: 0,
            total_queries: 0,
            total_failures: 0,
            last_rtt_ms: None,
            last_error: None,
            next_probe_at: None,
        }
    }
}

impl Health {
    /// The latency estimate to rank by: the EWMA of whichever source sampled
    /// most recently. A busy upstream's live samples dominate; an idle backup
    /// falls back to its background probe; a former leader gone idle switches to
    /// the probe once that's the fresher signal. `None` until either source has
    /// a sample (a never-touched upstream has no latency knowledge at all).
    fn estimate_ms(&self) -> Option<f64> {
        match (self.live_at, self.probe_at) {
            (Some(l), Some(p)) => Some(if l >= p {
                self.live_ewma_ms
            } else {
                self.probe_ewma_ms
            }),
            (Some(_), None) => Some(self.live_ewma_ms),
            (None, Some(_)) => Some(self.probe_ewma_ms),
            (None, None) => None,
        }
    }
}

/// A single upstream and its live health.
pub struct Upstream {
    pub spec: UpstreamSpec,
    pub name: String,
    transport: Box<dyn Transport>,
    health: Mutex<Health>,
}

impl Upstream {
    fn record_success(&self, rtt: Duration, alpha: f64, source: Source) {
        let mut h = self.health.lock();
        let ms = rtt.as_secs_f64() * 1000.0;
        let now = Instant::now();
        // Fold the sample into the matching EWMA only, so live and probe
        // latencies stay independent.
        match source {
            Source::Live => {
                h.live_ewma_ms = ewma(h.live_samples, h.live_ewma_ms, ms, alpha);
                h.live_samples += 1;
                h.live_at = Some(now);
            }
            Source::Probe => {
                h.probe_ewma_ms = ewma(h.probe_samples, h.probe_ewma_ms, ms, alpha);
                h.probe_samples += 1;
                h.probe_at = Some(now);
            }
        }
        h.total_queries += 1;
        h.last_rtt_ms = Some(ms);
        h.consecutive_failures = 0;
        h.up = true;
        h.last_error = None;
        // Healthy: defer the next probe a full window (jittered to de-sync).
        h.next_probe_at = Some(now + jitter(HEALTHY_PROBE_WINDOW));
    }

    fn record_failure(&self, err: &UpstreamError, threshold: u32) {
        let mut h = self.health.lock();
        h.total_queries += 1;
        h.total_failures += 1;
        h.consecutive_failures += 1;
        h.last_error = Some(err.to_string());
        if h.consecutive_failures >= threshold {
            h.up = false;
        }
        // Failing: retry with exponential backoff + jitter so a dead upstream is
        // probed often at first, then ever less aggressively.
        h.next_probe_at = Some(Instant::now() + jitter(retry_backoff(h.consecutive_failures)));
    }

    /// Record an attempt that didn't usefully answer but doesn't indict the
    /// upstream's health — a SERVFAIL/FORMERR that's plausibly the *query's*
    /// fault (a DNSSEC-bogus or malformed name), not the resolver's. It shows up
    /// in the totals so the UI reflects the miss, but it leaves `up`,
    /// `consecutive_failures`, the latency EWMA, and the probe schedule alone:
    /// otherwise one repeatedly-queried bogus domain could mark every upstream
    /// down, and a fast SERVFAIL could capture the latency lead.
    fn record_soft_failure(&self, err: &UpstreamError) {
        let mut h = self.health.lock();
        h.total_queries += 1;
        h.total_failures += 1;
        h.last_error = Some(err.to_string());
    }

    /// This upstream's smoothed latency, but only if it's currently a viable
    /// pick — healthy and actually sampled. `None` for a down or never-sampled
    /// upstream (which shouldn't count toward "the fastest peer").
    fn healthy_ewma(&self) -> Option<f64> {
        let h = self.health.lock();
        h.up.then(|| h.estimate_ms()).flatten()
    }

    /// After a probe, stretch this upstream's next-probe deadline if it's clearly
    /// outclassed by a faster peer — a perennial loser needn't be polled as often
    /// (see [`idle_probe_window`]). Only adjusts a healthy upstream; a down one
    /// keeps the failure backoff that `record_failure` just set.
    fn defer_if_outclassed(&self, peers: &[Arc<Upstream>]) {
        let Some(mine) = self.healthy_ewma() else {
            return;
        };
        // Fastest healthy peer (starting from `mine`, so an upstream that is the
        // best — or the only one up — compares against itself and stays at base).
        let best = peers.iter().filter_map(|u| u.healthy_ewma()).fold(mine, f64::min);
        let window = idle_probe_window(Some(mine), Some(best));
        self.health.lock().next_probe_at = Some(Instant::now() + jitter(window));
    }

    /// Give a not-yet-scheduled upstream its first probe at a random point within
    /// the startup spread, so a freshly built pool of N doesn't probe all at
    /// once. A no-op when the schedule was carried over from a prior pool (on
    /// config reload) — we don't want a reload to re-probe upstreams we know.
    fn schedule_initial_probe(&self) {
        let mut h = self.health.lock();
        if h.next_probe_at.is_none() {
            h.next_probe_at = Some(Instant::now() + startup_delay(STARTUP_PROBE_SPREAD));
        }
    }

    /// Remaining time until this upstream is next due for a probe, or `None` if
    /// it's due now (never sampled, or its scheduled time has passed).
    fn probe_due_in(&self, now: Instant) -> Option<Duration> {
        let at = self.health.lock().next_probe_at?;
        (at > now).then(|| at - now)
    }

    /// Sort key for live selection, ascending: healthy-and-sampled upstreams
    /// first (ordered by latency), then healthy-but-unsampled, then down ones.
    ///
    /// An unsampled upstream sorts *after* every proven-healthy one rather than
    /// as "fastest": we don't yet know its latency, so it must not preempt a
    /// known-good leader for live traffic — a new upstream that accepts the
    /// connection but black-holes the query would otherwise cost a full timeout
    /// on real queries before being demoted. It stays eligible (ahead of down
    /// upstreams), and the background probe warms its latency estimate without
    /// risking live queries on it. `up` is presumed-true until the failure
    /// threshold is crossed, so a never-sampled upstream still outranks a downed
    /// one. At cold start every upstream is unsampled and ties here, so the
    /// stable sort preserves configured order.
    fn sort_key(&self) -> (bool, bool, u64) {
        let h = self.health.lock();
        let down = !h.up;
        let est = h.estimate_ms();
        let unsampled = est.is_none();
        let lat = est.unwrap_or(0.0).round() as u64;
        (down, unsampled, lat)
    }

    /// A snapshot of this upstream's stats for the UI.
    pub fn stat(&self) -> UpstreamStat {
        let h = self.health.lock();
        UpstreamStat {
            spec: self.spec.display.clone(),
            name: self.name.clone(),
            kind: self.spec.kind,
            up: h.up,
            avg_rtt_ms: h.estimate_ms(),
            last_rtt_ms: h.last_rtt_ms,
            total_queries: h.total_queries,
            total_failures: h.total_failures,
            last_error: h.last_error.clone(),
        }
    }
}

/// Serializable per-upstream statistics for the API/UI.
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

/// A successful resolution: the response plus the upstream that answered.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub message: Message,
    /// Display name of the upstream that produced the answer.
    pub upstream: String,
    /// Round-trip time of the answering attempt, in milliseconds. This is the
    /// single successful attempt only — it excludes any time spent on earlier
    /// upstreams that timed out or failed before failover, so it reflects the
    /// answering upstream's own latency rather than the whole-query wall-clock.
    pub rtt_ms: f64,
}

type ResolveFuture = Shared<BoxFuture<'static, SharedResult<Resolved>>>;

/// Removes a single-flight entry when the leader's `resolve` finishes or is
/// cancelled. Held only by the leader (the caller that created the entry), so a
/// dropped leader can't leave a stale completed future in the map.
struct InflightGuard<'a> {
    map: &'a Mutex<HashMap<QueryKey, ResolveFuture>>,
    key: QueryKey,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.map.lock().remove(&self.key);
    }
}

/// A pool of upstream resolvers.
pub struct UpstreamPool {
    upstreams: Vec<Arc<Upstream>>,
    inflight: Mutex<HashMap<QueryKey, ResolveFuture>>,
    settings: PoolSettings,
    bootstrap: SharedBootstrap,
    /// One background probe task per upstream, spawned by [`start_probing`].
    /// Aborted when the pool is dropped (e.g. on config reload) — each task
    /// holds only an `Arc<Upstream>`, never the pool, so the pool can drop.
    ///
    /// [`start_probing`]: UpstreamPool::start_probing
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
    /// Build a pool from configured entries.
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
            settings,
            bootstrap,
            probe_tasks: Vec::new(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty()
    }

    pub fn upstreams(&self) -> &[Arc<Upstream>] {
        &self.upstreams
    }

    /// Snapshot all upstream stats.
    pub fn stats(&self) -> Vec<UpstreamStat> {
        self.upstreams.iter().map(|u| u.stat()).collect()
    }

    pub fn bootstrap(&self) -> &SharedBootstrap {
        &self.bootstrap
    }

    /// Upstreams ordered best-first for this moment.
    fn ordered(&self) -> Vec<Arc<Upstream>> {
        let mut v: Vec<Arc<Upstream>> = self.upstreams.clone();
        v.sort_by_key(|u| u.sort_key());
        v
    }

    /// Resolve a query, honouring single-flight and fastest-upstream selection.
    pub async fn resolve(&self, query: &Message) -> Result<Resolved> {
        if self.upstreams.is_empty() {
            return Err(UpstreamError::NoUpstreams);
        }
        let key = match QueryKey::from_message(query) {
            Some(k) => k,
            None => return Err(UpstreamError::Proto("query has no question".into())),
        };

        // Single-flight: coalesce identical concurrent queries. The leader (the
        // caller that created the in-flight entry) owns its cleanup via an RAII
        // guard, so the entry is removed when the shared future completes *or* if
        // this `resolve` is cancelled mid-await — a dropped leader can no longer
        // leak a completed entry that later callers would inherit forever.
        // Followers get no guard: they don't own the entry.
        let (fut, _guard) = {
            let mut map = self.inflight.lock();
            if let Some(existing) = map.get(&key) {
                (existing.clone(), None)
            } else {
                let ordered = self.ordered();
                let timeout = self.settings.query_timeout;
                let alpha = self.settings.ewma_alpha;
                let threshold = self.settings.failure_threshold;
                // Forward only the EDNS we honour/key on: strip client options
                // (ECS, COOKIE, NSID, …) so a query differing only in such an
                // option can't be cross-served from this shared single-flight
                // (or cache) entry, and client identifiers don't leak upstream.
                let mut q = query.clone();
                normalize_upstream_edns(&mut q);
                let fut: ResolveFuture =
                    async move { resolve_sequential(ordered, q, timeout, alpha, threshold).await }
                        .boxed()
                        .shared();
                map.insert(key.clone(), fut.clone());
                let guard = InflightGuard {
                    map: &self.inflight,
                    key: key.clone(),
                };
                (fut, Some(guard))
            }
        };

        let result = fut.await;

        match result {
            Ok(mut resolved) => {
                // Restore the caller's transaction id.
                resolved.message.metadata.id = query.metadata.id;
                Ok(resolved)
            }
            Err(arc) => Err((*arc).clone()),
        }
    }

    /// Politely probe every upstream once to refresh latency/health, regardless
    /// of staleness. Probes run sequentially.
    pub async fn probe_all(&self) {
        let query = probe_query();
        for up in &self.upstreams {
            probe_once(up, &query, &self.settings).await;
        }
    }

    /// Spawn one self-scheduling probe task per upstream and keep their handles.
    ///
    /// This is what makes the probe cadence *self-tuning and per-upstream* —
    /// there is no fixed interval and no global sweep. Each task owns its
    /// upstream's deadline independently: sleep until due, probe, reschedule. So
    /// a slow probe to one upstream never delays another, a busy upstream keeps
    /// deferring its probe via live traffic (and is effectively never probed),
    /// an idle one is kept warm a window at a time, and a down one backs off
    /// exponentially (see [`retry_backoff`]). Deadlines are jittered to avoid a
    /// stampede.
    ///
    /// Call once after building. The tasks are aborted when the pool is dropped.
    pub fn start_probing(&mut self) {
        for up in &self.upstreams {
            // Spread the first probe across the startup window (no-op for an
            // upstream whose schedule was carried over by `adopt_health_from`).
            up.schedule_initial_probe();
            let up = up.clone();
            // Each task can see all upstreams so it can rank itself against the
            // fastest and back off if it's clearly outclassed.
            let peers = self.upstreams.clone();
            let settings = self.settings.clone();
            self.probe_tasks
                .push(tokio::spawn(probe_loop(up, peers, settings)));
        }
    }

    /// Carry accumulated health — latency, success/failure tallies, up/down
    /// state, last error, and the probe schedule — from a previous pool for every
    /// upstream whose spec is unchanged. Used on config reload so a settings
    /// tweak doesn't reset the per-upstream stats or trigger a probe storm.
    /// Upstreams new in this pool keep their blank health and get a fresh
    /// (jittered) first probe via [`start_probing`].
    ///
    /// Call after [`build`](Self::build) and before [`start_probing`](Self::start_probing).
    pub fn adopt_health_from(&self, old: &UpstreamPool) {
        // Key on the canonical endpoint identity, not the raw spec text, so a
        // cosmetic rewrite (`8.8.8.8` → `udp://8.8.8.8`) still counts as the same
        // upstream and keeps its stats.
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

/// A single upstream's probe loop: wait until it's due, probe it, repeat. Reads
/// the deadline fresh each pass, so a live query that refreshes health while we
/// sleep simply pushes the next probe out instead of us probing needlessly.
/// After a probe, a healthy-but-outclassed upstream stretches its own interval.
async fn probe_loop(up: Arc<Upstream>, peers: Vec<Arc<Upstream>>, settings: PoolSettings) {
    let query = probe_query();
    loop {
        match up.probe_due_in(Instant::now()) {
            Some(remaining) => tokio::time::sleep(remaining).await,
            None => {
                probe_once(&up, &query, &settings).await;
                up.defer_if_outclassed(&peers);
            }
        }
    }
}

/// Probe a single upstream once and fold the outcome into its health.
async fn probe_once(up: &Upstream, query: &Message, settings: &PoolSettings) {
    let start = Instant::now();
    match tokio::time::timeout(settings.query_timeout, up.transport.query(query)).await {
        // The probe is a fixed, universally-answerable query (`NS .`), so unlike
        // an arbitrary live query, *any* non-answer to it (SERVFAIL as much as
        // REFUSED) genuinely indicts the resolver — treat it as a failed probe.
        Ok(Ok(resp)) => match classify(&resp) {
            Verdict::Answer => up.record_success(start.elapsed(), settings.ewma_alpha, Source::Probe),
            _ => up.record_failure(&rcode_err(&resp), settings.failure_threshold),
        },
        Ok(Err(e)) => up.record_failure(&e, settings.failure_threshold),
        Err(_) => up.record_failure(&UpstreamError::Timeout, settings.failure_threshold),
    }
}

/// What a protocol-valid DNS response means for selection and health.
enum Verdict {
    /// A usable answer — NOERROR (incl. NODATA), NXDOMAIN, and other valid
    /// results. Counts as a latency success and is returned to the client. A
    /// negative answer like NXDOMAIN is a real answer: we must NOT fail over.
    Answer,
    /// The upstream is reachable but won't serve this query (REFUSED/NOTIMP).
    /// That's an upstream-level problem: fail over and count it against health.
    Reject,
    /// A failure that's plausibly the query's fault rather than the upstream's
    /// (SERVFAIL/FORMERR — e.g. a DNSSEC-bogus or malformed name). Fail over to
    /// give another resolver a shot, but don't penalise the upstream's health.
    SoftFail,
}

/// Classify a response code for failover and health accounting. The point is
/// that a *fast* SERVFAIL/REFUSED must not look like a success: otherwise such
/// an upstream becomes the latency leader and blocks failover to one that would
/// actually answer.
fn classify(resp: &Message) -> Verdict {
    match resp.metadata.response_code {
        ResponseCode::Refused | ResponseCode::NotImp => Verdict::Reject,
        ResponseCode::ServFail | ResponseCode::FormErr => Verdict::SoftFail,
        _ => Verdict::Answer,
    }
}

/// The error carrying an upstream's non-answer response code, for `last_error`
/// reporting and the "all failed" fallthrough.
fn rcode_err(resp: &Message) -> UpstreamError {
    UpstreamError::Rcode(format!("{:?}", resp.metadata.response_code))
}

/// Try each upstream in order until one answers. Never queries more than one
/// upstream at a time.
async fn resolve_sequential(
    ordered: Vec<Arc<Upstream>>,
    query: Message,
    timeout: Duration,
    alpha: f64,
    threshold: u32,
) -> SharedResult<Resolved> {
    let mut last = UpstreamError::NoUpstreams;
    // A non-answer response (SERVFAIL/REFUSED/…) to hand back if no upstream
    // produces a real answer. Returning the upstream's own SERVFAIL is the
    // correct DNS behaviour — and more useful to the client than an opaque
    // "all failed". Holds the first one seen, i.e. from the most-preferred
    // upstream.
    let mut fallback: Option<Resolved> = None;
    for up in ordered {
        let start = Instant::now();
        match tokio::time::timeout(timeout, up.transport.query(&query)).await {
            Ok(Ok(resp)) => {
                let rtt = start.elapsed();
                let rtt_ms = rtt.as_secs_f64() * 1000.0;
                match classify(&resp) {
                    Verdict::Answer => {
                        up.record_success(rtt, alpha, Source::Live);
                        return Ok(Resolved {
                            message: resp,
                            upstream: up.name.clone(),
                            rtt_ms,
                        });
                    }
                    // A rejection/soft-failure must not become the latency
                    // leader, so neither path calls `record_success`. Reject
                    // counts against health; SoftFail is logged but health-
                    // neutral (see `record_soft_failure`). Either way we keep the
                    // response and try the next upstream.
                    verdict => {
                        let err = rcode_err(&resp);
                        match verdict {
                            Verdict::Reject => up.record_failure(&err, threshold),
                            _ => up.record_soft_failure(&err),
                        }
                        // Keep the first (most-preferred) non-answer as fallback.
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
                up.record_failure(&e, threshold);
                last = e;
            }
            Err(_) => {
                up.record_failure(&UpstreamError::Timeout, threshold);
                last = UpstreamError::Timeout;
            }
        }
    }
    // Every upstream failed. Prefer returning a real upstream response (e.g. a
    // SERVFAIL) over the synthetic "all failed" error.
    if let Some(resolved) = fallback {
        return Ok(resolved);
    }
    Err(Arc::new(UpstreamError::AllFailed(Box::new(last))))
}

/// Construct the transport for a spec.
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

/// Resolve a plain-DNS upstream's socket address (resolving a hostname via
/// bootstrap if needed).
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

/// A lightweight, cache-friendly probe query: `NS .`.
fn probe_query() -> Message {
    let mut msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut q = Query::query(Name::from_str(".").unwrap(), RecordType::NS);
    q.set_query_class(DNSClass::IN);
    msg.queries.push(q);
    msg
}

/// Test a single upstream spec: resolve `example.com` and report the round-trip.
/// Used by the "test upstream" UI action.
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
        // First failure waits the base delay, then each further consecutive
        // failure doubles it...
        assert_eq!(retry_backoff(1), DOWN_PROBE_BASE);
        assert_eq!(retry_backoff(2), DOWN_PROBE_BASE * 2);
        assert_eq!(retry_backoff(3), DOWN_PROBE_BASE * 4);
        // ...until it saturates at the ceiling and stays there.
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
    fn estimate_uses_the_freshest_source() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(10);

        // Both sampled, live more recently (a busy leader) → rank by live.
        let h = Health {
            live_ewma_ms: 10.0,
            live_samples: 1,
            live_at: Some(t1),
            probe_ewma_ms: 99.0,
            probe_samples: 1,
            probe_at: Some(t0),
            ..Health::default()
        };
        assert_eq!(h.estimate_ms(), Some(10.0));

        // Probe sampled more recently (a former leader gone idle) → rank by probe,
        // not the now-stale live figure.
        let h = Health {
            live_ewma_ms: 10.0,
            live_samples: 1,
            live_at: Some(t0),
            probe_ewma_ms: 99.0,
            probe_samples: 1,
            probe_at: Some(t1),
            ..Health::default()
        };
        assert_eq!(h.estimate_ms(), Some(99.0));

        // Only one source sampled, and never-sampled.
        let h = Health {
            probe_ewma_ms: 42.0,
            probe_samples: 1,
            probe_at: Some(t0),
            ..Health::default()
        };
        assert_eq!(h.estimate_ms(), Some(42.0));
        assert_eq!(Health::default().estimate_ms(), None);
    }

    #[test]
    fn idle_window_stretches_for_perennial_losers() {
        let base = HEALTHY_PROBE_WINDOW;
        // The leader (or anyone within 1.5×) keeps the base cadence.
        assert_eq!(idle_probe_window(Some(20.0), Some(20.0)), base);
        assert_eq!(idle_probe_window(Some(28.0), Some(20.0)), base); // 1.4×
        // The further behind, the longer the interval...
        assert_eq!(idle_probe_window(Some(50.0), Some(20.0)), base * 2); // 2.5×
        assert_eq!(idle_probe_window(Some(100.0), Some(20.0)), base * 4); // 5×
        assert_eq!(idle_probe_window(Some(400.0), Some(20.0)), base * 8); // 20×
        // A just-came-up upstream with no estimate yet is probed at base cadence.
        assert_eq!(idle_probe_window(None, Some(20.0)), base);
        // A near-zero leader can't blow the ratio up to infinity.
        assert_eq!(idle_probe_window(Some(5.0), Some(0.0)), base * 4);
    }
}
