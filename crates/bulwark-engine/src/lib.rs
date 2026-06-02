//! Bulwark engine: the DNS query-processing pipeline tying together filtering,
//! caching, upstream resolution, client identification, query logging, and
//! statistics, plus the UDP/TCP DNS server.
//!
//! The mutable parts (compiled filter, upstream pool, client map, filtering
//! knobs) live behind an [`arc_swap::ArcSwap`] so config changes hot-reload
//! without dropping traffic. The cache, query log, and stats persist across
//! reloads (so we never lose accumulated data on a settings change).

#![forbid(unsafe_code)]

pub mod block;
pub mod cache;
pub mod clients;
pub mod querylog;
pub mod server;
pub mod stats;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bulwark_config::BlockingMode;
use bulwark_filter::{ClientInfo, FilterEngine, Verdict};
use bulwark_upstream::{QueryKey, UpstreamPool};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};

use crate::block::{block_response, error_response, rewrite_response, Rewritten};
use crate::cache::DnsCache;
use crate::clients::{ClientMatcher, ResolvedClient};
use crate::querylog::{QueryAction, QueryLog, QueryLogEntry};
use crate::stats::Stats;

/// The hot-swappable part of the engine's configuration.
pub struct EngineState {
    pub filter: Arc<FilterEngine>,
    pub pool: Arc<UpstreamPool>,
    pub clients: Arc<ClientMatcher>,
    pub filtering_enabled: bool,
    pub blocking_mode: BlockingMode,
    pub block_v4: Ipv4Addr,
    pub block_v6: Ipv6Addr,
    pub blocked_ttl: u32,
}

/// The DNS engine.
pub struct Engine {
    state: ArcSwap<EngineState>,
    cache: Arc<DnsCache>,
    log: Arc<QueryLog>,
    stats: Arc<Stats>,
    seq: AtomicU64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Summarise an answer record as e.g. `"A 1.2.3.4"`.
fn summarize(rec: &hickory_proto::rr::Record) -> String {
    format!("{} {}", rec.record_type(), rec.data)
}

impl Engine {
    pub fn new(
        state: EngineState,
        cache: Arc<DnsCache>,
        log: Arc<QueryLog>,
        stats: Arc<Stats>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: ArcSwap::from_pointee(state),
            cache,
            log,
            stats,
            seq: AtomicU64::new(0),
        })
    }

    /// Replace the hot-swappable state (used on config reload).
    pub fn swap_state(&self, state: EngineState) {
        self.state.store(Arc::new(state));
    }

    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }
    pub fn log(&self) -> &Arc<QueryLog> {
        &self.log
    }
    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }
    pub fn pool(&self) -> Arc<UpstreamPool> {
        self.state.load().pool.clone()
    }

    /// A snapshot of the current compiled filter (for the "check domain" tool).
    pub fn filter_snapshot(&self) -> Arc<FilterEngine> {
        self.state.load().filter.clone()
    }

    /// Process a query and return the response, recording log + stats.
    pub async fn handle(&self, query: Message, client_ip: IpAddr) -> Message {
        let start = Instant::now();
        let state = self.state.load();
        let client = state.clients.identify(client_ip);

        // A query must have a question.
        let Some(question) = query.queries.first().cloned() else {
            let resp = error_response(&query, ResponseCode::FormErr);
            return resp;
        };
        let rtype = question.query_type();
        let rtype_str = rtype.to_string();
        let qname_display = question.name().to_ascii();
        let domain = qname_display.trim_end_matches('.').to_ascii_lowercase();

        let mut log = LogBuilder::new(&client, &qname_display, &rtype_str);

        // ---- Filtering ----
        if state.filtering_enabled && client.filtering_enabled {
            let ci = ClientInfo {
                ip: Some(client.ip),
                name: client.name.as_deref(),
                tags: &client.tags,
            };
            match state.filter.check(&domain, &rtype_str, &ci) {
                Verdict::Block(info) => {
                    let resp = block_response(
                        &query,
                        state.blocking_mode,
                        state.block_v4,
                        state.block_v6,
                        state.blocked_ttl,
                    );
                    log.rule = Some(info.rule);
                    log.list_id = Some(info.list_id);
                    return self.finalize(resp, QueryAction::Blocked, log, start);
                }
                Verdict::Rewrite { info, data } => {
                    log.rule = Some(info.rule);
                    log.list_id = Some(info.list_id);
                    let resp = match rewrite_response(&query, &data, state.blocked_ttl) {
                        Rewritten::Done(m) => m,
                        Rewritten::ResolveCname {
                            mut message,
                            target,
                        } => {
                            self.resolve_cname(&state.pool, &mut message, target, rtype)
                                .await;
                            message
                        }
                    };
                    return self.finalize(resp, QueryAction::Rewritten, log, start);
                }
                Verdict::Allow { rule } => {
                    log.allowlisted = rule.is_some();
                }
            }
        }

        // ---- Cache ----
        let key = QueryKey::from_message(&query);
        if let Some(key) = &key {
            if let Some(hit) = self.cache.get(key) {
                let mut resp = hit.message;
                resp.metadata.id = query.metadata.id;
                if hit.stale {
                    // Optimistic: refresh in the background (single-flight in the
                    // pool ensures only one upstream request).
                    self.spawn_refresh(state.pool.clone(), query.clone(), key.clone());
                }
                return self.finalize(resp, QueryAction::Cached, log, start);
            }
        }

        // ---- Upstream ----
        match state.pool.resolve(&query).await {
            Ok(resolved) => {
                if let Some(key) = key {
                    self.cache.insert(key, &resolved.message);
                }
                log.upstream = Some(resolved.upstream);
                self.finalize(resolved.message, QueryAction::Forwarded, log, start)
            }
            Err(e) => {
                tracing::debug!(%domain, error = %e, "upstream resolution failed");
                let resp = error_response(&query, ResponseCode::ServFail);
                self.finalize(resp, QueryAction::Error, log, start)
            }
        }
    }

    /// Resolve a CNAME rewrite target and append its A/AAAA answers.
    async fn resolve_cname(
        &self,
        pool: &UpstreamPool,
        message: &mut Message,
        target: Name,
        rtype: RecordType,
    ) {
        let mut q = Message::new(rand::random(), MessageType::Query, OpCode::Query);
        q.metadata.recursion_desired = true;
        let mut query = Query::query(target, rtype);
        query.set_query_class(DNSClass::IN);
        q.queries.push(query);
        if let Ok(resolved) = pool.resolve(&q).await {
            for ans in resolved.message.answers {
                message.answers.push(ans);
            }
        }
    }

    /// Spawn a background cache refresh for a stale entry.
    fn spawn_refresh(&self, pool: Arc<UpstreamPool>, query: Message, key: QueryKey) {
        let cache = self.cache.clone();
        tokio::spawn(async move {
            if let Ok(resolved) = pool.resolve(&query).await {
                cache.insert(key, &resolved.message);
            }
        });
    }

    fn finalize(
        &self,
        resp: Message,
        action: QueryAction,
        mut log: LogBuilder,
        start: Instant,
    ) -> Message {
        log.elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        log.action = action;
        log.rcode = format!("{:?}", resp.metadata.response_code).to_uppercase();
        log.answers = resp.answers.iter().map(summarize).collect();
        log.cached = matches!(action, QueryAction::Cached);

        let entry = log.build(self.seq.fetch_add(1, Ordering::Relaxed));
        self.stats.record(&entry);
        self.log.push(entry);
        resp
    }
}

/// Accumulates fields for a [`QueryLogEntry`] during processing.
struct LogBuilder {
    client_ip: String,
    client_name: Option<String>,
    question: String,
    qtype: String,
    action: QueryAction,
    allowlisted: bool,
    rcode: String,
    answers: Vec<String>,
    rule: Option<String>,
    list_id: Option<u32>,
    upstream: Option<String>,
    elapsed_ms: f64,
    cached: bool,
}

impl LogBuilder {
    fn new(client: &ResolvedClient, question: &str, qtype: &str) -> Self {
        Self {
            client_ip: client.ip.to_string(),
            client_name: client.name.clone(),
            question: question.to_string(),
            qtype: qtype.to_string(),
            action: QueryAction::Forwarded,
            allowlisted: false,
            rcode: String::new(),
            answers: Vec::new(),
            rule: None,
            list_id: None,
            upstream: None,
            elapsed_ms: 0.0,
            cached: false,
        }
    }

    fn build(self, id: u64) -> QueryLogEntry {
        QueryLogEntry {
            id,
            time_ms: now_ms(),
            client_ip: self.client_ip,
            client_name: self.client_name,
            question: self.question,
            qtype: self.qtype,
            action: self.action,
            allowlisted: self.allowlisted,
            rcode: self.rcode,
            answers: self.answers,
            rule: self.rule,
            list_id: self.list_id,
            upstream: self.upstream,
            elapsed_ms: self.elapsed_ms,
            cached: self.cached,
        }
    }
}

#[cfg(test)]
mod tests;
