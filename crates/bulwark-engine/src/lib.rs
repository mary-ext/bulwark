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

use std::borrow::Cow;
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

/// The display label for a response code. Returns a borrowed `&'static str` for
/// the codes we actually emit, so the common hot path allocates nothing; only an
/// exotic code falls back to an owned `format!`.
fn rcode_label(code: ResponseCode) -> Cow<'static, str> {
    let s = match code {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        other => return Cow::Owned(format!("{other:?}").to_uppercase()),
    };
    Cow::Borrowed(s)
}

/// The display label for a record type. Returns a borrowed `&'static str` for the
/// common types (which covers essentially all real traffic), avoiding the
/// per-query `RecordType::to_string()` heap allocation; rare types fall back to an
/// owned string.
fn rtype_label(rt: RecordType) -> Cow<'static, str> {
    let s = match rt {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::CNAME => "CNAME",
        RecordType::MX => "MX",
        RecordType::NS => "NS",
        RecordType::PTR => "PTR",
        RecordType::SOA => "SOA",
        RecordType::SRV => "SRV",
        RecordType::TXT => "TXT",
        RecordType::CAA => "CAA",
        RecordType::HTTPS => "HTTPS",
        RecordType::SVCB => "SVCB",
        RecordType::DS => "DS",
        RecordType::DNSKEY => "DNSKEY",
        RecordType::NAPTR => "NAPTR",
        RecordType::TLSA => "TLSA",
        other => return Cow::Owned(other.to_string()),
    };
    Cow::Borrowed(s)
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
        let rtype_str = rtype_label(rtype);
        let qname_display = question.name().to_ascii();
        // Normalize the name once (lowercased, dot-terminated) and reuse it for
        // both filtering and the cache/single-flight key. `domain` is a borrow
        // into it, so the common path allocates the name exactly once.
        let name_lower = qname_display.to_ascii_lowercase();
        let domain = name_lower.trim_end_matches('.');

        // Cloning a borrowed Cow is a pointer copy (no allocation) for the common
        // record types; `rtype_str` itself is reused by `filter.check` below.
        let mut log = LogBuilder::new(&client, qname_display, rtype_str.clone());

        // ---- Filtering ----
        if state.filtering_enabled && client.filtering_enabled {
            let ci = ClientInfo {
                ip: Some(client.ip),
                name: client.name.as_deref(),
                tags: &client.tags,
            };
            match state.filter.check(domain, rtype_str.as_ref(), &ci) {
                Verdict::Block(info) => {
                    let resp = block_response(
                        &query,
                        state.blocking_mode,
                        state.block_v4,
                        state.block_v6,
                        state.blocked_ttl,
                    );
                    let action = QueryAction::Blocked {
                        rule: info.rule,
                        list_id: info.list_id,
                    };
                    return self.finalize(resp, action, log, start);
                }
                Verdict::Rewrite { info, data } => {
                    let action = QueryAction::Rewritten {
                        rule: info.rule,
                        list_id: info.list_id,
                    };
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
                    return self.finalize(resp, action, log, start);
                }
                Verdict::Allow { rule } => {
                    log.allowlisted = rule.is_some();
                }
            }
        }

        // ---- Cache ----
        // Built from the name we already normalized above — no second wire-walk
        // or lowercase pass.
        let key = QueryKey {
            name: name_lower,
            rtype,
            class: question.query_class(),
        };
        if let Some(hit) = self.cache.get(&key) {
            let mut resp = hit.message;
            resp.metadata.id = query.metadata.id;
            if hit.stale {
                // Optimistic: refresh in the background (single-flight in the
                // pool ensures only one upstream request).
                self.spawn_refresh(state.pool.clone(), query.clone(), key.clone());
            }
            return self.finalize(resp, QueryAction::Cached, log, start);
        }

        // ---- Upstream ----
        match state.pool.resolve(&query).await {
            Ok(resolved) => {
                self.cache.insert(key, &resolved.message);
                let action = QueryAction::Forwarded {
                    upstream: resolved.upstream,
                };
                self.finalize(resolved.message, action, log, start)
            }
            Err(e) => {
                tracing::debug!(name = %key.name, error = %e, "upstream resolution failed");
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
        // If nothing will consume the entry, don't pay to build it: the answer
        // summaries, rcode label, client-IP string, and the entry itself are all
        // pure logging/stats overhead.
        let stats_on = self.stats.is_enabled();
        let log_on = self.log.is_enabled();
        if !stats_on && !log_on {
            return resp;
        }

        log.elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        log.rcode = rcode_label(resp.metadata.response_code);
        log.answers = resp.answers.iter().map(summarize).collect();

        let entry = log.build(self.seq.fetch_add(1, Ordering::Relaxed), action);
        if stats_on {
            self.stats.record(&entry);
        }
        if log_on {
            self.log.push(entry);
        }
        resp
    }
}

/// Accumulates the outcome-independent fields for a [`QueryLogEntry`] during
/// processing. The outcome-specific data lives in the [`QueryAction`] passed to
/// [`build`](LogBuilder::build).
struct LogBuilder {
    client_ip: IpAddr,
    client_name: Option<String>,
    question: String,
    qtype: Cow<'static, str>,
    allowlisted: bool,
    rcode: Cow<'static, str>,
    answers: Vec<String>,
    elapsed_ms: f64,
}

impl LogBuilder {
    fn new(client: &ResolvedClient, question: String, qtype: Cow<'static, str>) -> Self {
        Self {
            // Kept as an `IpAddr` (Copy); only stringified in `build()`, which the
            // caller skips entirely when neither logging nor stats is enabled.
            client_ip: client.ip,
            client_name: client.name.clone(),
            question,
            qtype,
            allowlisted: false,
            rcode: Cow::Borrowed(""),
            answers: Vec::new(),
            elapsed_ms: 0.0,
        }
    }

    fn build(self, id: u64, action: QueryAction) -> QueryLogEntry {
        QueryLogEntry {
            id,
            time_ms: now_ms(),
            client_ip: self.client_ip.to_string(),
            client_name: self.client_name,
            question: self.question,
            qtype: self.qtype,
            action,
            allowlisted: self.allowlisted,
            rcode: self.rcode,
            answers: self.answers,
            elapsed_ms: self.elapsed_ms,
        }
    }
}

#[cfg(test)]
mod tests;
