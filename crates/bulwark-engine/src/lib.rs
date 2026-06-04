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
pub mod wire;

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bulwark_config::BlockingMode;
use bulwark_filter::{ClientInfo, FilterEngine, Verdict};
use bulwark_upstream::{QueryKey, UpstreamPool};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};

use crate::block::{block_response, error_response, rewrite_response, Rewritten};
use crate::cache::{CachedResponse, DnsCache};
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
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Fill `dst` with one `"A 1.2.3.4"`-style summary per answer record, reusing
/// `dst`'s existing `String` buffers (clear + rewrite) instead of allocating
/// fresh ones. `dst` comes from a recycled log entry, so at steady state this
/// allocates nothing.
fn fill_answer_summaries(dst: &mut Vec<String>, src: &[hickory_proto::rr::Record]) {
    use std::fmt::Write as _;
    for (i, rec) in src.iter().enumerate() {
        if let Some(s) = dst.get_mut(i) {
            s.clear();
            let _ = write!(s, "{} {}", rec.record_type(), rec.data);
        } else {
            dst.push(format!("{} {}", rec.record_type(), rec.data));
        }
    }
    dst.truncate(src.len());
}

/// Copy precomputed answer summaries into `dst`, reusing its existing `String`
/// buffers. Used by the wire cache path, whose summaries are stored on the entry.
fn fill_from_summaries(dst: &mut Vec<String>, src: &[String]) {
    for (i, s) in src.iter().enumerate() {
        if let Some(d) = dst.get_mut(i) {
            d.clear();
            d.push_str(s);
        } else {
            dst.push(s.clone());
        }
    }
    dst.truncate(src.len());
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
    /// The current (hot-swappable) client matcher. Used to resolve client names
    /// at read time so renames/removals apply retroactively to stats and logs.
    pub fn clients(&self) -> Arc<ClientMatcher> {
        self.state.load().clients.clone()
    }
    pub fn pool(&self) -> Arc<UpstreamPool> {
        self.state.load().pool.clone()
    }

    /// A snapshot of the current compiled filter (for the "check domain" tool).
    pub fn filter_snapshot(&self) -> Arc<FilterEngine> {
        self.state.load().filter.clone()
    }

    /// Process a query and return the response, recording log + stats.
    pub async fn handle(&self, query: Message, client_ip: IpAddr) -> EngineResponse {
        let start = Instant::now();
        let state = self.state.load();
        let client = state.clients.identify(client_ip);

        // A query must have a question.
        let Some(question) = query.queries.first().cloned() else {
            return EngineResponse::Message(error_response(&query, ResponseCode::FormErr));
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
        if let Some(hit) = self.cache.get(&key, query.metadata.id) {
            if hit.stale {
                // Optimistic: refresh in the background (single-flight in the
                // pool ensures only one upstream request).
                self.spawn_refresh(state.pool.clone(), query.clone(), key.clone());
            }
            return match hit.response {
                // Fast path: pre-encoded bytes with id + TTLs already patched.
                CachedResponse::Wire {
                    bytes,
                    rcode,
                    answers,
                } => self.finalize_wire(bytes, rcode, answers, log, start),
                CachedResponse::Message(resp) => {
                    self.finalize(resp, QueryAction::Cached, log, start)
                }
            };
        }

        // ---- Upstream ----
        match state.pool.resolve(&query).await {
            Ok(resolved) => {
                self.cache.insert(key, &resolved.message);
                // Attribute the answering upstream's own round-trip to per-upstream
                // stats, not the whole-query wall-clock: with sequential failover a
                // query that waited out an earlier upstream's timeout would otherwise
                // charge that ~1s to the upstream that actually answered quickly.
                log.upstream_rtt_ms = Some(resolved.rtt_ms);
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

    /// Build + record the query-log entry and stats for a completed query.
    /// `rcode` and `fill_answers` supply the response-derived fields without
    /// requiring a `Message`, so the wire fast path needs no decode. The entry is
    /// handed to the background writer (or dropped if logging is off).
    fn record(
        &self,
        log: LogBuilder,
        action: QueryAction,
        rcode: Cow<'static, str>,
        fill_answers: impl FnOnce(&mut Vec<String>),
        start: Instant,
    ) {
        // If nothing will consume the entry, don't pay to build it: the answer
        // summaries, client-IP string, and the entry itself are all pure
        // logging/stats overhead.
        let stats_on = self.stats.is_enabled();
        let log_on = self.log.is_enabled();
        if !stats_on && !log_on {
            return;
        }

        // Only forwarded queries set the per-upstream RTT.
        let upstream_rtt_ms = log.upstream_rtt_ms;

        // Build the entry. The `question` buffer is moved in from the name we
        // already normalised, so it costs no extra allocation. `id` is left 0:
        // the disk store assigns the real id (SQLite rowid) on insert, and only
        // the stored id is ever read back.
        let mut entry = QueryLogEntry::empty();
        entry.time_ms = now_ms();
        {
            use std::fmt::Write as _;
            let _ = write!(entry.client_ip, "{}", log.client_ip);
        }
        entry.question = log.question;
        entry.qtype = log.qtype;
        entry.action = action;
        entry.allowlisted = log.allowlisted;
        entry.rcode = rcode;
        fill_answers(&mut entry.answers);
        entry.elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        if stats_on {
            self.stats.record(&entry, upstream_rtt_ms);
        }
        if log_on {
            // Hand off to the background writer (the entry is moved, not cloned).
            self.log.push(entry);
        }
    }

    /// Record a freshly-built `Message` response (forwarded / blocked / rewritten
    /// / error / non-wire cache hit) and return it for the server to encode.
    fn finalize(
        &self,
        resp: Message,
        action: QueryAction,
        log: LogBuilder,
        start: Instant,
    ) -> EngineResponse {
        let rcode = rcode_label(resp.metadata.response_code);
        self.record(
            log,
            action,
            rcode,
            |dst| fill_answer_summaries(dst, &resp.answers),
            start,
        );
        EngineResponse::Message(resp)
    }

    /// Record a wire-byte cache hit (bytes already id/TTL-patched) using the
    /// precomputed rcode + answer summaries, and return the bytes ready to send —
    /// no `Message` clone, no re-encode.
    fn finalize_wire(
        &self,
        bytes: Vec<u8>,
        rcode: ResponseCode,
        answers: Arc<[String]>,
        log: LogBuilder,
        start: Instant,
    ) -> EngineResponse {
        self.record(
            log,
            QueryAction::Cached,
            rcode_label(rcode),
            |dst| fill_from_summaries(dst, &answers),
            start,
        );
        EngineResponse::Wire(bytes)
    }
}

/// A processed response, ready for the server to put on the wire. The hot cache
/// path yields pre-encoded `Wire` bytes (no re-encode); every other path yields
/// a `Message` the server encodes itself.
pub enum EngineResponse {
    Message(Message),
    Wire(Vec<u8>),
}

impl EngineResponse {
    /// Decode to a structured `Message` (re-parsing `Wire` bytes). Off the hot
    /// path — used by the UDP truncation fallback and by tests.
    pub fn into_message(self) -> Message {
        match self {
            EngineResponse::Message(m) => m,
            EngineResponse::Wire(b) => Message::from_vec(&b)
                .unwrap_or_else(|_| Message::new(0, MessageType::Response, OpCode::Query)),
        }
    }

    /// Encode to wire bytes with no length limit (TCP). `Wire` bytes pass through
    /// unchanged; a `Message` is encoded here.
    pub fn into_wire(self) -> Option<Vec<u8>> {
        match self {
            EngineResponse::Message(m) => m.to_vec().ok(),
            EngineResponse::Wire(b) => Some(b),
        }
    }
}

/// Accumulates the outcome-independent fields for a [`QueryLogEntry`] during
/// processing. The outcome-specific data (action, rcode, answers) is supplied to
/// [`Engine::record`] at finalize time.
struct LogBuilder {
    /// Kept as an `IpAddr` (Copy); only stringified in `finalize`, which the
    /// caller skips entirely when neither logging nor stats is enabled.
    client_ip: IpAddr,
    question: String,
    qtype: Cow<'static, str>,
    allowlisted: bool,
    /// Answering upstream's own round-trip (ms), set only when the query was
    /// forwarded. Kept out of the stored [`QueryLogEntry`] — it feeds per-upstream
    /// latency stats but isn't part of the log schema.
    upstream_rtt_ms: Option<f64>,
}

impl LogBuilder {
    fn new(client: &ResolvedClient, question: String, qtype: Cow<'static, str>) -> Self {
        Self {
            client_ip: client.ip,
            question,
            qtype,
            allowlisted: false,
            upstream_rtt_ms: None,
        }
    }
}

#[cfg(test)]
mod tests;
