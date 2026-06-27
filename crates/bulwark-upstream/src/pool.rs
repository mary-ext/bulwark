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
use crate::probe_log::{now_ms, ProbeEvent, ProbeLog, ProbeOutcome};
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

/// How often a healthy upstream is probed. The probe RTT *is* the routing
/// signal (see [`Health::routing_latency_ms`]), measured on the same cadence for
/// every upstream — busy or idle — so the estimates stay directly comparable.
///
/// Sized from the captured probe log: routing latency drifts only a few ms over
/// ten minutes, so the old 60s beat was ~3× oversampled for the ranking it
/// feeds — replaying the log at 180s costs ~2.5ms of mean selection regret while
/// cutting probe volume threefold. The binding constraint on the interval isn't
/// latency tracking but failure detection, and a *live* query failure already
/// marks an upstream down at once (see [`Upstream::record_live_failure`]), so
/// this cadence only gates recovery of *idle* upstreams — which tolerates a
/// slower beat. The idle-close window on the transports is shorter than this, so
/// a connection still reclaims in the gap between probes.
const HEALTHY_PROBE_WINDOW: Duration = Duration::from_secs(180);

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

/// Leadership hysteresis. Selection is lowest-routing-latency-wins, but the probe
/// EWMAs of near-tied upstreams cross constantly — the captured log showed the
/// lead changing ~7×/hour, almost all of it between upstreams within a
/// millisecond of each other. Each handoff churns a warm QUIC/TLS connection for
/// no real latency gain, so the standing leader keeps the front of the ranking
/// unless a challenger beats it by at least `max(LEADER_STICKY_FRACTION × leader,
/// LEADER_STICKY_FLOOR_MS)` (see [`switch_margin`]). A genuine winner — one
/// materially faster, like the storm survivor at 15ms vs the field at 24ms —
/// still clears the margin and takes over immediately.
const LEADER_STICKY_FRACTION: f64 = 0.15;
const LEADER_STICKY_FLOOR_MS: f64 = 5.0;

/// How much faster than the incumbent (in ms) a challenger must be to seize
/// leadership. A relative band handles the fast upstreams where a few ms is
/// significant; the floor keeps slow ones from flapping over sub-percent noise.
fn switch_margin(incumbent_ms: f64) -> f64 {
    (incumbent_ms * LEADER_STICKY_FRACTION).max(LEADER_STICKY_FLOOR_MS)
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
    /// Smoothed latency of background probes (`NS .`). This is the routing
    /// signal: measured the same way for every upstream so they're directly
    /// comparable (see [`Health::routing_latency_ms`]).
    probe_ewma_ms: f64,
    probe_samples: u64,
    probe_at: Option<Instant>,
    /// Presumed up until proven down. A fresh upstream starts up so it gets a
    /// chance; it's marked down only after crossing the failure threshold. (If
    /// this defaulted to false, a never-*successful* upstream couldn't be
    /// distinguished from an untried one and would never sort as down.)
    up: bool,
    consecutive_failures: u32,
    /// Live query counters (probes don't count toward these — they're the volume
    /// of *real* traffic this upstream served, for the UI).
    total_queries: u64,
    total_failures: u64,
    /// Latency of the most recent live query (not probes), for the UI.
    last_rtt_ms: Option<f64>,
    last_error: Option<String>,
    /// When this upstream is next due for a background probe. Rescheduled by each
    /// probe: a healthy probe pushes it out a full window, a failed one by an
    /// exponentially-backed-off (and jittered) retry delay. `None` means "due
    /// now" — never probed yet. Live traffic no longer touches this; probing is
    /// independent so the routing latency stays fresh even for a busy upstream.
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
            last_error: None,
            next_probe_at: None,
        }
    }
}

impl Health {
    /// The latency to rank by for selection: the smoothed background-probe RTT.
    /// `None` until the first probe lands (an unprobed upstream sorts after
    /// proven ones — see [`Upstream::sort_key`]).
    ///
    /// Live query latency is deliberately *not* used here. It mixes in recursion
    /// time (so it's on a different, higher scale than the cache-hot `NS .`
    /// probe) and is only sampled on whichever upstream happened to get traffic.
    /// Ranking on it meant the act of answering a query bumped an upstream onto
    /// the slower live scale and demoted it below idle peers still showing their
    /// cheap probe figure — so the fastest upstream kept handing off leadership
    /// the moment it was used. Probe RTT is the one signal measured identically
    /// for every upstream, busy or idle, so selection is stable and comparable.
    fn routing_latency_ms(&self) -> Option<f64> {
        (self.probe_samples > 0).then_some(self.probe_ewma_ms)
    }

    /// The post-update fields a [`ProbeEvent`] persists, captured under the same
    /// lock acquisition that recorded the probe so the event reflects exactly the
    /// state the update produced.
    fn snapshot(&self) -> ProbeSnapshot {
        ProbeSnapshot {
            ewma_ms: self.routing_latency_ms(),
            up: self.up,
            consecutive_failures: self.consecutive_failures,
        }
    }
}

/// The health fields captured right after recording a probe, handed back to the
/// probe loop so it can build a self-contained [`ProbeEvent`] without re-locking.
struct ProbeSnapshot {
    ewma_ms: Option<f64>,
    up: bool,
    consecutive_failures: u32,
}

/// A single upstream and its live health.
pub struct Upstream {
    pub spec: UpstreamSpec,
    pub name: String,
    transport: Box<dyn Transport>,
    health: Mutex<Health>,
}

impl Upstream {
    /// Record a successful *live* query. Updates the real-traffic counters and
    /// liveness, but deliberately does NOT touch the routing latency (that's the
    /// probe's job) or the probe cadence (probing runs independently so a busy
    /// upstream's estimate doesn't go stale).
    fn record_live_success(&self, rtt: Duration) {
        let mut h = self.health.lock();
        h.total_queries += 1;
        h.last_rtt_ms = Some(rtt.as_secs_f64() * 1000.0);
        h.consecutive_failures = 0;
        h.up = true;
        h.last_error = None;
    }

    /// Record a successful background probe: fold its RTT into the routing EWMA,
    /// confirm liveness, and schedule the next probe a full window out. Returns
    /// the resulting health for telemetry.
    fn record_probe_success(&self, rtt: Duration, alpha: f64) -> ProbeSnapshot {
        let mut h = self.health.lock();
        let ms = rtt.as_secs_f64() * 1000.0;
        h.probe_ewma_ms = ewma(h.probe_samples, h.probe_ewma_ms, ms, alpha);
        h.probe_samples += 1;
        h.probe_at = Some(Instant::now());
        h.consecutive_failures = 0;
        h.up = true;
        h.last_error = None;
        h.next_probe_at = Some(Instant::now() + jitter(HEALTHY_PROBE_WINDOW));
        h.snapshot()
    }

    /// Record a failed *live* query: count it against real-traffic totals and
    /// health, mark down past the threshold, and bring the recovery probe forward.
    fn record_live_failure(&self, err: &UpstreamError, threshold: u32) {
        let mut h = self.health.lock();
        h.total_queries += 1;
        h.total_failures += 1;
        self.fold_failure(&mut h, err, threshold);
    }

    /// Record a failed background probe: it drives health and the recovery
    /// schedule but is not real traffic, so it doesn't touch the query counters.
    /// Returns the resulting health for telemetry.
    fn record_probe_failure(&self, err: &UpstreamError, threshold: u32) -> ProbeSnapshot {
        let mut h = self.health.lock();
        self.fold_failure(&mut h, err, threshold);
        h.snapshot()
    }

    /// Shared failure bookkeeping: bump consecutive failures, mark down past the
    /// threshold, and retry with exponential backoff + jitter so a dead upstream
    /// is probed often at first, then ever less aggressively.
    fn fold_failure(&self, h: &mut Health, err: &UpstreamError, threshold: u32) {
        h.consecutive_failures += 1;
        h.last_error = Some(err.to_string());
        if h.consecutive_failures >= threshold {
            h.up = false;
        }
        h.next_probe_at = Some(Instant::now() + jitter(retry_backoff(h.consecutive_failures)));
    }

    /// Record a live attempt that didn't usefully answer but doesn't indict the
    /// upstream's health — a SERVFAIL/FORMERR that's plausibly the *query's*
    /// fault (a DNSSEC-bogus or malformed name), not the resolver's. It shows up
    /// in the totals so the UI reflects the miss, but it leaves `up`,
    /// `consecutive_failures`, the routing latency, and the probe schedule alone:
    /// otherwise one repeatedly-queried bogus domain could mark every upstream
    /// down.
    fn record_soft_failure(&self, err: &UpstreamError) {
        let mut h = self.health.lock();
        h.total_queries += 1;
        h.total_failures += 1;
        h.last_error = Some(err.to_string());
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
        let est = h.routing_latency_ms();
        let unsampled = est.is_none();
        let lat = est.unwrap_or(0.0).round() as u64;
        (down, unsampled, lat)
    }

    /// Routing latency for leadership hysteresis: `Some(ms)` only when the
    /// upstream is both up and probe-sampled. A down or never-sampled incumbent
    /// returns `None` so hysteresis can't pin the lead on it — the ranking falls
    /// through to the freshly sorted best instead.
    fn routing_latency_if_eligible(&self) -> Option<f64> {
        let h = self.health.lock();
        h.up.then(|| h.routing_latency_ms()).flatten()
    }

    /// Force this upstream's routing latency (marking it up and sampled) so a test
    /// can drive selection deterministically without depending on probe timing.
    #[cfg(test)]
    pub(crate) fn set_routing_latency_for_test(&self, ms: f64) {
        let mut h = self.health.lock();
        h.probe_ewma_ms = ms;
        h.probe_samples = h.probe_samples.max(1);
        h.up = true;
        h.consecutive_failures = 0;
    }

    /// A snapshot of this upstream's stats for the UI.
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
    /// The upstream currently at the front of the ranking, remembered across
    /// queries so leadership is sticky: [`ordered`](Self::ordered) holds it first
    /// unless a challenger clears the [`switch_margin`]. Implicitly reset when the
    /// pool is rebuilt on reload (a fresh leader re-establishes on the first
    /// query).
    current_leader: Mutex<Option<Arc<Upstream>>>,
    settings: PoolSettings,
    bootstrap: SharedBootstrap,
    /// Sink for probe telemetry. Defaults to a detached (no-sink) [`ProbeLog`]
    /// that drops every event; the server swaps in a wired one via
    /// [`set_probe_log`](UpstreamPool::set_probe_log) when persistence is enabled.
    /// Shared with each probe task so the wiring survives — it's set before
    /// [`start_probing`].
    probe_log: Arc<ProbeLog>,
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
            current_leader: Mutex::new(None),
            settings,
            bootstrap,
            probe_log: Arc::new(ProbeLog::new(false)),
            probe_tasks: Vec::new(),
        })
    }

    /// Attach a probe-telemetry sink, shared with the per-upstream probe tasks.
    /// Call after [`build`](Self::build) and before
    /// [`start_probing`](Self::start_probing); a no-op telemetry log is used
    /// otherwise, so persistence stays entirely off until this is wired.
    pub fn set_probe_log(&mut self, probe_log: Arc<ProbeLog>) {
        self.probe_log = probe_log;
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
    ///
    /// Lowest routing latency wins, then leadership hysteresis is applied: the
    /// standing leader is held at the front unless the sorted best beats it by the
    /// [`switch_margin`], so near-tied upstreams don't trade the lead every probe
    /// and churn warm connections. An incumbent that has gone down or is unsampled
    /// is not eligible to be held, so it falls through to the freshly sorted best.
    pub(crate) fn ordered(&self) -> Vec<Arc<Upstream>> {
        let mut v: Vec<Arc<Upstream>> = self.upstreams.clone();
        v.sort_by_key(|u| u.sort_key());

        let mut leader = self.current_leader.lock();
        if let Some(cur) = leader.as_ref() {
            if let Some(pos) = v.iter().position(|u| Arc::ptr_eq(u, cur)) {
                // Only an off-front incumbent that's still eligible can be held,
                // and only when the best challenger hasn't cleared the margin.
                if pos != 0 {
                    if let (Some(inc), Some(best)) = (
                        v[pos].routing_latency_if_eligible(),
                        v[0].routing_latency_if_eligible(),
                    ) {
                        if inc - best <= switch_margin(inc) {
                            let held = v.remove(pos);
                            v.insert(0, held);
                        }
                    }
                }
            }
        }
        *leader = v.first().cloned();
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
        //
        // The inflight mutex guards only the map get/insert. Building the resolve
        // future — ranking the upstreams (which locks each upstream's health) and
        // cloning/normalizing the query — is done *outside* the lock so unrelated
        // misses don't serialize behind that work. The slow path double-checks the
        // map after re-locking in case an identical miss raced us; the loser drops
        // its freshly-built (never-polled) future, which has no side effects.
        let (fut, _guard) = {
            let map = self.inflight.lock();
            if let Some(existing) = map.get(&key) {
                (existing.clone(), None)
            } else {
                drop(map);
                let ordered = self.ordered();
                let timeout = self.settings.query_timeout;
                let threshold = self.settings.failure_threshold;
                // Forward only the EDNS we honour/key on: strip client options
                // (ECS, COOKIE, NSID, …) so a query differing only in such an
                // option can't be cross-served from this shared single-flight
                // (or cache) entry, and client identifiers don't leak upstream.
                let mut q = query.clone();
                normalize_upstream_edns(&mut q);
                let fut: ResolveFuture =
                    async move { resolve_sequential(ordered, q, timeout, threshold).await }
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
            probe_once(up, &query, &self.settings, &self.probe_log).await;
        }
    }

    /// Spawn one self-scheduling probe task per upstream and keep their handles.
    ///
    /// Each task owns its upstream's deadline independently: sleep until due,
    /// probe, reschedule. So a slow probe to one upstream never delays another;
    /// a healthy upstream re-probes every window (the probe RTT is the routing
    /// signal, kept fresh regardless of live traffic), and a down one backs off
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
            let settings = self.settings.clone();
            let probe_log = self.probe_log.clone();
            self.probe_tasks
                .push(tokio::spawn(probe_loop(up, settings, probe_log)));
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
/// the deadline fresh each pass; the probe RTT is the routing signal, so every
/// healthy upstream is probed on the same cadence (a probe reschedules itself a
/// window out; a failure backs off — see [`Upstream::record_probe_success`] /
/// [`Upstream::record_probe_failure`]).
async fn probe_loop(up: Arc<Upstream>, settings: PoolSettings, probe_log: Arc<ProbeLog>) {
    let query = probe_query();
    loop {
        match up.probe_due_in(Instant::now()) {
            Some(remaining) => tokio::time::sleep(remaining).await,
            None => probe_once(&up, &query, &settings, &probe_log).await,
        }
    }
}

/// Probe a single upstream once, fold the outcome into its health, and — when a
/// sink is attached — persist the measurement and resulting health as a
/// [`ProbeEvent`]. Building the event is gated on [`ProbeLog::is_enabled`], so a
/// pool without telemetry wired pays nothing here beyond a relaxed atomic load.
async fn probe_once(up: &Upstream, query: &Message, settings: &PoolSettings, probe_log: &ProbeLog) {
    let start = Instant::now();
    // Each arm records health (under one lock, returning the resulting snapshot)
    // and surfaces the non-answer error, if any. The error is kept as a value and
    // only stringified for the event below, so a disabled probe log allocates
    // nothing here.
    let (outcome, rtt_ms, snap, err) =
        match tokio::time::timeout(settings.query_timeout, up.transport.query(query)).await {
            // The probe is a fixed, universally-answerable query (`NS .`), so
            // unlike an arbitrary live query, *any* non-answer to it (SERVFAIL as
            // much as REFUSED) genuinely indicts the resolver — failed probe.
            Ok(Ok(resp)) => match classify(&resp) {
                Verdict::Answer => {
                    let rtt = start.elapsed();
                    let snap = up.record_probe_success(rtt, settings.ewma_alpha);
                    (ProbeOutcome::Answer, Some(rtt.as_secs_f64() * 1000.0), snap, None)
                }
                verdict => {
                    let err = rcode_err(&resp);
                    let snap = up.record_probe_failure(&err, settings.failure_threshold);
                    let outcome = match verdict {
                        Verdict::Reject => ProbeOutcome::Reject,
                        _ => ProbeOutcome::SoftFail,
                    };
                    (outcome, None, snap, Some(err))
                }
            },
            Ok(Err(e)) => {
                let snap = up.record_probe_failure(&e, settings.failure_threshold);
                (ProbeOutcome::Error, None, snap, Some(e))
            }
            Err(_) => {
                let err = UpstreamError::Timeout;
                let snap = up.record_probe_failure(&err, settings.failure_threshold);
                (ProbeOutcome::Timeout, None, snap, Some(err))
            }
        };

    // Build and persist the event only when telemetry is on; this gate skips the
    // field clones and the error-to-string entirely when off. `push` re-checks
    // the toggle as its own invariant.
    if probe_log.is_enabled() {
        probe_log.push(ProbeEvent {
            time_ms: now_ms(),
            upstream: up.spec.display.clone(),
            name: up.name.clone(),
            kind: up.spec.kind,
            outcome,
            rtt_ms,
            ewma_ms: snap.ewma_ms,
            up: snap.up,
            consecutive_failures: snap.consecutive_failures,
            detail: err.map(|e| e.to_string()),
        });
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
                        up.record_live_success(rtt);
                        return Ok(Resolved {
                            message: resp,
                            upstream: up.name.clone(),
                            rtt_ms,
                        });
                    }
                    // A rejection/soft-failure must not be treated as a clean
                    // answer. Reject counts against health; SoftFail is logged but
                    // health-neutral (see `record_soft_failure`). Either way we
                    // keep the response and try the next upstream.
                    verdict => {
                        let err = rcode_err(&resp);
                        match verdict {
                            Verdict::Reject => up.record_live_failure(&err, threshold),
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
                up.record_live_failure(&e, threshold);
                last = e;
            }
            Err(_) => {
                up.record_live_failure(&UpstreamError::Timeout, threshold);
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
    fn routing_latency_is_probe_only() {
        // Ranking uses the probe EWMA and ignores live traffic entirely, so an
        // upstream that just served a slow live query is NOT demoted below an idle
        // peer's cheap probe figure (the serve-to-demote oscillation we fixed).
        let h = Health {
            probe_ewma_ms: 19.0,
            probe_samples: 1,
            probe_at: Some(Instant::now()),
            // A live success records last_rtt_ms but must not affect routing.
            last_rtt_ms: Some(120.0),
            ..Health::default()
        };
        assert_eq!(h.routing_latency_ms(), Some(19.0));

        // No probe yet → no routing latency (sorts after proven upstreams).
        assert_eq!(Health::default().routing_latency_ms(), None);
    }
}
