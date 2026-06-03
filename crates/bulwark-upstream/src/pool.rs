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
use hickory_proto::op::{Message, MessageType, OpCode, Query};
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
use crate::transport::{QueryKey, Transport};

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

#[derive(Debug, Default, Clone)]
struct Health {
    ewma_ms: f64,
    samples: u64,
    up: bool,
    consecutive_failures: u32,
    total_queries: u64,
    total_failures: u64,
    last_rtt_ms: Option<f64>,
    last_error: Option<String>,
}

/// A single upstream and its live health.
pub struct Upstream {
    pub spec: UpstreamSpec,
    pub name: String,
    transport: Box<dyn Transport>,
    health: Mutex<Health>,
}

impl Upstream {
    fn record_success(&self, rtt: Duration, alpha: f64) {
        let mut h = self.health.lock();
        let ms = rtt.as_secs_f64() * 1000.0;
        h.ewma_ms = if h.samples == 0 {
            ms
        } else {
            alpha * ms + (1.0 - alpha) * h.ewma_ms
        };
        h.samples += 1;
        h.total_queries += 1;
        h.last_rtt_ms = Some(ms);
        h.consecutive_failures = 0;
        h.up = true;
        h.last_error = None;
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
    }

    /// Sort key: healthy upstreams first, then by latency (unknown latency
    /// sorts as "fast" so a fresh upstream gets a chance).
    fn sort_key(&self) -> (bool, u64) {
        let h = self.health.lock();
        let down = !h.up && h.samples > 0;
        let lat = if h.samples == 0 {
            0
        } else {
            h.ewma_ms.round() as u64
        };
        (down, lat)
    }

    /// A snapshot of this upstream's stats for the UI.
    pub fn stat(&self) -> UpstreamStat {
        let h = self.health.lock();
        UpstreamStat {
            spec: self.spec.display.clone(),
            name: self.name.clone(),
            kind: self.spec.kind,
            up: h.up || h.samples == 0,
            avg_rtt_ms: if h.samples == 0 {
                None
            } else {
                Some(h.ewma_ms)
            },
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

/// A pool of upstream resolvers.
pub struct UpstreamPool {
    upstreams: Vec<Arc<Upstream>>,
    inflight: Mutex<HashMap<QueryKey, ResolveFuture>>,
    settings: PoolSettings,
    bootstrap: SharedBootstrap,
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

        // Single-flight: coalesce identical concurrent queries.
        let (fut, leader) = {
            let mut map = self.inflight.lock();
            if let Some(existing) = map.get(&key) {
                (existing.clone(), false)
            } else {
                let ordered = self.ordered();
                let timeout = self.settings.query_timeout;
                let alpha = self.settings.ewma_alpha;
                let threshold = self.settings.failure_threshold;
                let q = query.clone();
                let fut: ResolveFuture =
                    async move { resolve_sequential(ordered, q, timeout, alpha, threshold).await }
                        .boxed()
                        .shared();
                map.insert(key.clone(), fut.clone());
                (fut, true)
            }
        };

        let result = fut.await;
        if leader {
            self.inflight.lock().remove(&key);
        }

        match result {
            Ok(mut resolved) => {
                // Restore the caller's transaction id.
                resolved.message.metadata.id = query.metadata.id;
                Ok(resolved)
            }
            Err(arc) => Err((*arc).clone()),
        }
    }

    /// Politely probe every upstream once to refresh latency/health. Intended to
    /// be called on a timer by the server. Probes run sequentially.
    pub async fn probe_all(&self) {
        let query = probe_query();
        for up in &self.upstreams {
            let start = Instant::now();
            match tokio::time::timeout(self.settings.query_timeout, up.transport.query(&query))
                .await
            {
                Ok(Ok(_)) => up.record_success(start.elapsed(), self.settings.ewma_alpha),
                Ok(Err(e)) => up.record_failure(&e, self.settings.failure_threshold),
                Err(_) => {
                    up.record_failure(&UpstreamError::Timeout, self.settings.failure_threshold)
                }
            }
        }
    }
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
    for up in ordered {
        let start = Instant::now();
        match tokio::time::timeout(timeout, up.transport.query(&query)).await {
            Ok(Ok(resp)) => {
                let rtt = start.elapsed();
                up.record_success(rtt, alpha);
                return Ok(Resolved {
                    message: resp,
                    upstream: up.name.clone(),
                    rtt_ms: rtt.as_secs_f64() * 1000.0,
                });
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
