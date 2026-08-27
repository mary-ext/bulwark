//! DNS filtering, caching, upstream resolution, logging, and statistics.

#![forbid(unsafe_code)]

pub mod block;
pub mod cache;
pub mod clients;
pub mod querylog;
pub mod server;
pub mod stats;
pub mod wire;

use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bulwark_config::BlockingMode;
use bulwark_filter::{ClientInfo, FilterEngine, MatchInfo, Verdict};
use bulwark_upstream::{QueryKey, UpstreamPool};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::svcb::{SvcParamValue, SVCB};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use crate::block::{block_response, error_response, rewrite_response, Rewritten};
use crate::cache::{CachedResponse, DnsCache, InsertedWire, Outcome, ResponseVerdict};
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

/// Builds query-log answer summaries.
fn summarize_answers(src: &[hickory_proto::rr::Record]) -> Arc<[String]> {
    src.iter()
        .map(|rec| format!("{} {}", rec.record_type(), rec.data))
        .collect()
}

/// Stack buffer large enough for an IPv6 literal.
struct IpBuf {
    buf: [u8; 48],
    len: usize,
}

impl IpBuf {
    fn new() -> Self {
        Self {
            buf: [0; 48],
            len: 0,
        }
    }

    fn render(&mut self, ip: impl fmt::Display) -> &str {
        use fmt::Write as _;
        self.len = 0;
        let _ = write!(self, "{ip}");
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl fmt::Write for IpBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        let dst = self.buf.get_mut(self.len..end).ok_or(fmt::Error)?;
        dst.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn filter_answers(
    filter: &FilterEngine,
    client: &ResolvedClient,
    answers: &[Record],
) -> Option<MatchInfo> {
    let ci = ClientInfo {
        ip: Some(client.ip),
        name: client.name.as_deref(),
        tags: &client.tags,
    };
    let block_of = |v: Verdict| match v {
        Verdict::Block(info) => Some(info),
        _ => None,
    };
    let mut ipbuf = IpBuf::new();
    for rec in answers {
        let hit = match &rec.data {
            RData::CNAME(cname) => {
                block_of(filter.check(cname.0.to_ascii().trim_end_matches('.'), "CNAME", &ci))
            }
            RData::A(ip) => block_of(filter.check(ipbuf.render(ip.0), "A", &ci)),
            RData::AAAA(ip) => block_of(filter.check(ipbuf.render(ip.0), "AAAA", &ci)),
            RData::HTTPS(https) => hint_block(&https.0, filter, &ci, &mut ipbuf),
            RData::SVCB(svcb) => hint_block(svcb, filter, &ci, &mut ipbuf),
            _ => continue,
        };
        if hit.is_some() {
            return hit;
        }
    }
    None
}

/// Checks HTTPS/SVCB address hints against the filter.
fn hint_block(
    svcb: &SVCB,
    filter: &FilterEngine,
    ci: &ClientInfo<'_>,
    ipbuf: &mut IpBuf,
) -> Option<MatchInfo> {
    let check = |ipbuf: &mut IpBuf, ip: &dyn fmt::Display| match filter.check(
        ipbuf.render(ip),
        "HTTPS",
        ci,
    ) {
        Verdict::Block(info) => Some(info),
        _ => None,
    };
    for (_, value) in &svcb.svc_params {
        let blocked = match value {
            SvcParamValue::Ipv4Hint(h) => h.0.iter().find_map(|a| check(ipbuf, &a.0)),
            SvcParamValue::Ipv6Hint(h) => h.0.iter().find_map(|a| check(ipbuf, &a.0)),
            _ => None,
        };
        if blocked.is_some() {
            return blocked;
        }
    }
    None
}

/// Extracts cached answers for response-side filtering.
fn cached_answers(resp: &CachedResponse) -> Vec<Record> {
    match resp {
        CachedResponse::Wire { bytes, .. } => Message::from_vec(bytes)
            .map(|m| m.answers)
            .unwrap_or_default(),
        CachedResponse::Message(m) => m.answers.clone(),
    }
}

/// Returns a borrowed label for common response codes.
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

/// Returns a borrowed label for common record types.
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
    /// Returns the current client matcher.
    pub fn clients(&self) -> Arc<ClientMatcher> {
        self.state.load().clients.clone()
    }
    pub fn pool(&self) -> Arc<UpstreamPool> {
        self.state.load().pool.clone()
    }

    /// Returns the current compiled filter.
    pub fn filter_snapshot(&self) -> Arc<FilterEngine> {
        self.state.load().filter.clone()
    }

    /// Processes a query and records its outcome.
    pub async fn handle(&self, ingress: Ingress, client_ip: IpAddr) -> EngineResponse {
        let start = Instant::now();
        let state = self.state.load();
        let client = state.clients.identify(client_ip);

        let (fields, lazy) = match ingress.into_parts() {
            Ok(parts) => parts,
            Err(msg) => {
                return EngineResponse::Message(error_response(&msg, ResponseCode::FormErr))
            }
        };
        let QueryFields {
            id,
            rtype,
            class,
            qname_display,
            name_lower,
            dnssec_ok,
            checking_disabled,
        } = fields;
        let rtype_str = rtype_label(rtype);
        let domain = name_lower.trim_end_matches('.');

        let mut log = LogBuilder::new(&client, qname_display, rtype_str.clone());

        if state.filtering_enabled && client.filtering_enabled {
            let ci = ClientInfo {
                ip: Some(client.ip),
                name: client.name.as_deref(),
                tags: &client.tags,
            };
            match state.filter.check(domain, rtype_str.as_ref(), &ci) {
                Verdict::Block(info) => {
                    let Some(query) = lazy.into_message() else {
                        return self.finalize(formerr(id), QueryAction::Error, log, start);
                    };
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
                    let Some(query) = lazy.into_message() else {
                        return self.finalize(formerr(id), QueryAction::Error, log, start);
                    };
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

        let key = QueryKey {
            name: name_lower,
            rtype,
            class,
            dnssec_ok,
            checking_disabled,
        };
        if let Some(hit) = self.cache.get(&key, id) {
            // Raw cached answers require a trusted or recomputed filter verdict.
            let filtering = state.filtering_enabled && client.filtering_enabled;
            let block_info: Option<MatchInfo> = if filtering {
                let client_dependent = state.filter.has_client_dependent_rules();
                let live_gen = state.filter.content_hash();
                match &hit.verdict {
                    Some(v) if !client_dependent && v.generation == live_gen => match &v.outcome {
                        Outcome::Clean => None,
                        Outcome::Block(info) => Some(info.clone()),
                    },
                    _ => filter_answers(&state.filter, &client, &cached_answers(&hit.response)),
                }
            } else {
                None
            };

            let memoize = state.filtering_enabled && !state.filter.has_client_dependent_rules();

            if let Some(info) = block_info {
                // Synthesize blocks from current settings, not cached settings.
                let Some(query) = lazy.into_message() else {
                    return self.finalize(formerr(id), QueryAction::Error, log, start);
                };
                let resp = block_response(
                    &query,
                    state.blocking_mode,
                    state.block_v4,
                    state.block_v6,
                    state.blocked_ttl,
                );
                if hit.freshness.requires_refresh() {
                    self.spawn_refresh(&state, memoize, Lazy::Msg(query), key.clone());
                }
                let action = QueryAction::Blocked {
                    rule: info.rule,
                    list_id: info.list_id,
                };
                return self.finalize(resp, action, log, start);
            }

            if hit.freshness.requires_refresh() {
                self.spawn_refresh(&state, memoize, lazy, key.clone());
            }
            return match hit.response {
                CachedResponse::Wire {
                    bytes,
                    rcode,
                    answers,
                } => self.finalize_wire(bytes, rcode, answers, QueryAction::Cached, log, start),
                CachedResponse::Message(resp) => {
                    self.finalize(resp, QueryAction::Cached, log, start)
                }
            };
        }

        let Some(query) = lazy.into_message() else {
            return self.finalize(formerr(id), QueryAction::Error, log, start);
        };
        match state.pool.resolve(&query).await {
            Ok(resolved) => {
                log.upstream_rtt_ms = Some(resolved.rtt_ms);

                // Cache raw answers; synthetic blocks depend on current client settings.
                let client_filtered = state.filtering_enabled && client.filtering_enabled;
                let memoize = state.filtering_enabled && !state.filter.has_client_dependent_rules();
                let generation = state.filter.content_hash();

                let this_block = if client_filtered {
                    filter_answers(&state.filter, &client, &resolved.message.answers)
                } else {
                    None
                };

                if let Some(info) = this_block {
                    if memoize {
                        let verdict = ResponseVerdict::block(info.clone(), generation);
                        self.cache
                            .insert_with_verdict(key, &resolved.message, Some(verdict));
                    } else {
                        self.cache.insert(key, &resolved.message);
                    }
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

                let verdict = if memoize {
                    Some(if client_filtered {
                        ResponseVerdict::clean(generation)
                    } else {
                        match filter_answers(&state.filter, &client, &resolved.message.answers) {
                            Some(info) => ResponseVerdict::block(info, generation),
                            None => ResponseVerdict::clean(generation),
                        }
                    })
                } else {
                    None
                };
                let served = self.cache.insert_returning(key, &resolved.message, verdict);
                let action = QueryAction::Forwarded {
                    upstream: resolved.upstream,
                };
                match served {
                    Some(InsertedWire {
                        bytes,
                        rcode,
                        answers,
                    }) => self.finalize_wire(bytes, rcode, answers, action, log, start),
                    None => self.finalize(resolved.message, action, log, start),
                }
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

    /// Refreshes a stale entry in the background.
    fn spawn_refresh(&self, state: &EngineState, memoize: bool, lazy: Lazy, key: QueryKey) {
        let cache = self.cache.clone();
        let pool = state.pool.clone();
        let filter = state.filter.clone();
        let generation = state.filter.content_hash();
        cache.note_refresh_started();
        tokio::spawn(async move {
            let Some(query) = lazy.into_message() else {
                cache.note_refresh_failed();
                return;
            };
            let resolved = match pool.resolve(&query).await {
                Ok(resolved) => resolved,
                Err(_) => {
                    cache.note_refresh_failed();
                    return;
                }
            };
            if memoize {
                let placeholder = ResolvedClient {
                    ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    name: None,
                    tags: Arc::from(Vec::new()),
                    filtering_enabled: true,
                };
                let verdict = match filter_answers(&filter, &placeholder, &resolved.message.answers)
                {
                    Some(info) => ResponseVerdict::block(info, generation),
                    None => ResponseVerdict::clean(generation),
                };
                cache.insert_with_verdict(key, &resolved.message, Some(verdict));
            } else {
                cache.insert(key, &resolved.message);
            }
        });
    }

    /// Records a completed query without forcing a wire response decode.
    fn record(
        &self,
        log: LogBuilder,
        action: QueryAction,
        rcode: Cow<'static, str>,
        make_answers: impl FnOnce() -> Arc<[String]>,
        start: Instant,
    ) {
        let stats_on = self.stats.is_enabled();
        let log_on = self.log.is_enabled();
        if !stats_on && !log_on {
            return;
        }

        let upstream_rtt_ms = log.upstream_rtt_ms;

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
        if log_on {
            entry.answers = make_answers();
        }
        entry.elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        if stats_on {
            self.stats.record(&entry, upstream_rtt_ms);
        }
        if log_on {
            self.log.push(entry);
        }
    }

    /// Records and returns a structured response.
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
            || summarize_answers(&resp.answers),
            start,
        );
        EngineResponse::Message(resp)
    }

    /// Records and returns an encoded cache hit.
    fn finalize_wire(
        &self,
        bytes: Vec<u8>,
        rcode: ResponseCode,
        answers: Arc<[String]>,
        action: QueryAction,
        log: LogBuilder,
        start: Instant,
    ) -> EngineResponse {
        self.record(log, action, rcode_label(rcode), || answers, start);
        EngineResponse::Wire(bytes)
    }
}

/// Parsed query ingress, retaining wire bytes for lazy full parsing.
#[derive(Clone)]
pub enum Ingress {
    /// Minimal parse plus original bytes.
    Fast {
        bytes: Vec<u8>,
        parsed: wire::ParsedQuery,
    },
    /// Fully parsed fallback.
    Full(Message),
}

impl Ingress {
    /// Parses borrowed query bytes.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match wire::parse_query(bytes) {
            Some(parsed) => Some(Ingress::Fast {
                bytes: bytes.to_vec(),
                parsed,
            }),
            None => Message::from_vec(bytes).ok().map(Ingress::Full),
        }
    }

    /// Parses and retains owned query bytes.
    pub fn parse_owned(bytes: Vec<u8>) -> Option<Self> {
        match wire::parse_query(&bytes) {
            Some(parsed) => Some(Ingress::Fast { bytes, parsed }),
            None => Message::from_vec(&bytes).ok().map(Ingress::Full),
        }
    }

    /// Returns the advertised UDP payload clamped to 512..=4096.
    pub fn udp_max_payload(&self) -> usize {
        let advertised = match self {
            Ingress::Fast { parsed, .. } => parsed.edns_payload.unwrap_or(512),
            Ingress::Full(m) => m.edns.as_ref().map(|e| e.max_payload()).unwrap_or(512),
        };
        (advertised as usize).clamp(512, 4096)
    }

    /// Splits hot-path fields from the lazy message source.
    fn into_parts(self) -> Result<(QueryFields, Lazy), Box<Message>> {
        match self {
            Ingress::Fast { bytes, parsed } => {
                Ok((QueryFields::from_parsed(parsed), Lazy::Bytes(bytes)))
            }
            Ingress::Full(msg) => match QueryFields::from_message(&msg) {
                Some(fields) => Ok((fields, Lazy::Msg(msg))),
                None => Err(Box::new(msg)),
            },
        }
    }
}

/// Lazy structured message.
enum Lazy {
    Bytes(Vec<u8>),
    Msg(Message),
}

impl Lazy {
    /// Materializes the full message.
    fn into_message(self) -> Option<Message> {
        match self {
            Lazy::Msg(m) => Some(m),
            Lazy::Bytes(b) => Message::from_vec(&b).ok(),
        }
    }
}

/// Builds a header-only FORMERR response.
fn formerr(id: u16) -> Message {
    let mut m = Message::new(id, MessageType::Response, OpCode::Query);
    m.metadata.response_code = ResponseCode::FormErr;
    m
}

/// Query fields used before full parsing.
struct QueryFields {
    id: u16,
    rtype: RecordType,
    class: DNSClass,
    /// Original on-the-wire case, for the query log.
    qname_display: String,
    /// Lowercased, dot-terminated — the cache/filter key.
    name_lower: String,
    dnssec_ok: bool,
    checking_disabled: bool,
}

impl QueryFields {
    fn from_parsed(p: wire::ParsedQuery) -> Self {
        let name_lower = p.qname.to_ascii_lowercase();
        QueryFields {
            id: p.id,
            rtype: RecordType::from(p.qtype),
            class: DNSClass::from(p.qclass),
            qname_display: p.qname,
            name_lower,
            dnssec_ok: p.dnssec_ok,
            checking_disabled: p.checking_disabled,
        }
    }

    fn from_message(m: &Message) -> Option<Self> {
        let q = m.queries.first()?;
        let qname_display = q.name().to_ascii();
        let name_lower = qname_display.to_ascii_lowercase();
        Some(QueryFields {
            id: m.metadata.id,
            rtype: q.query_type(),
            class: q.query_class(),
            qname_display,
            name_lower,
            dnssec_ok: bulwark_upstream::dnssec_ok(m),
            checking_disabled: m.metadata.checking_disabled,
        })
    }
}

/// Structured or pre-encoded engine response.
pub enum EngineResponse {
    Message(Message),
    Wire(Vec<u8>),
}

impl EngineResponse {
    /// Decodes a structured message.
    pub fn into_message(self) -> Message {
        match self {
            EngineResponse::Message(m) => m,
            EngineResponse::Wire(b) => Message::from_vec(&b)
                .unwrap_or_else(|_| Message::new(0, MessageType::Response, OpCode::Query)),
        }
    }

    /// Encodes wire bytes without a length limit.
    pub fn into_wire(self) -> Option<Vec<u8>> {
        match self {
            EngineResponse::Message(m) => m.to_vec().ok(),
            EngineResponse::Wire(b) => Some(b),
        }
    }
}

/// Query-log fields accumulated during processing.
struct LogBuilder {
    client_ip: IpAddr,
    question: String,
    qtype: Cow<'static, str>,
    allowlisted: bool,
    /// Answering upstream's round-trip time.
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
