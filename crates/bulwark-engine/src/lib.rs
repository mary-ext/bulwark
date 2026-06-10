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
use crate::cache::{CachedResponse, DnsCache, Outcome, ResponseVerdict};
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
/// Build the short answer-record summaries (e.g. `"A 1.2.3.4"`) for the query
/// log, used by the non-cache paths that have a freshly-built `Message`. The
/// wire-byte cache hit instead shares the `Arc<[String]>` the cache already holds.
fn summarize_answers(src: &[hickory_proto::rr::Record]) -> Arc<[String]> {
    src.iter()
        .map(|rec| format!("{} {}", rec.record_type(), rec.data))
        .collect()
}

/// Response-side filtering: re-check the records an upstream actually returned
/// against the blocklist. The query name can pass the request-side check while
/// the answer points at a blocked target. Two cases:
///
/// - *CNAME cloaking*: a tracker hides behind a first-party `CNAME`
///   (`data.brand.com -> tracker.evil.net`); the query-name check never sees it.
/// - *IP blocking*: the resolved `A`/`AAAA` address itself matches a rule (e.g.
///   a known ad-serving IP), regardless of the name that resolved to it.
/// - *HTTPS/SVCB hints*: RFC 9460 `ipv4hint`/`ipv6hint` params let a client
///   reach an address without a separate `A`/`AAAA` lookup, so a hinted blocked
///   IP is the same threat as a blocked `A`/`AAAA` — and, as in AdGuard Home,
///   blocks the whole response.
///
/// Returns the matching rule for the first blocked record, or `None` if the
/// whole answer chain is clean. The records are already parsed (the upstream
/// pool decoded them), and the per-record `filter.check` only fires for the
/// record types we inspect, so this rides along the cache-miss path that is
/// already network-bound.
/// Stack buffer for an IP literal. 48 bytes clears the longest text `Display`
/// emits for an address — 39 chars for an all-hextet IPv6 like
/// `ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff` (Rust only uses the shorter
/// IPv4-embedded form for mapped/compatible addresses), and well under the
/// 45-char `INET6_ADDRSTRLEN` upper bound. Lets the per-answer filter stringify
/// `A`/`AAAA`/hint addresses without a heap allocation per record.
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

    /// Render `ip` into the buffer and return it as `&str`. Reused across records.
    fn render(&mut self, ip: impl fmt::Display) -> &str {
        use fmt::Write as _;
        self.len = 0;
        // The buffer holds the longest possible IP literal and `Display` for IP
        // addresses only emits ASCII, so neither write nor utf8 validation fails.
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
        // `Name::to_ascii` carries a trailing dot; `filter.check` normalises it,
        // but trim here so the comparison is unambiguous. IP literals stringify
        // without a trailing dot, so the trim is a no-op for them.
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

/// Return the matching rule if any `ipv4hint`/`ipv6hint` address in an
/// HTTPS/SVCB record is blocklisted. The rtype mirrors AdGuard Home, which
/// checks hint IPs as `HTTPS`.
fn hint_block(
    svcb: &SVCB,
    filter: &FilterEngine,
    ci: &ClientInfo<'_>,
    ipbuf: &mut IpBuf,
) -> Option<MatchInfo> {
    let check = |ipbuf: &mut IpBuf, ip: &dyn fmt::Display| match filter
        .check(ipbuf.render(ip), "HTTPS", ci)
    {
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

/// Parse the answer records out of a cached response so the response-side filter
/// can re-run on a hit whose verdict isn't trusted. Cold path only — trusted
/// (or filtering-off) hits never call this. The wire bytes are our own prior
/// encoding (and snapshot imports are validated to parse), so `from_vec`
/// round-trips; an unreachable failure yields no answers, i.e. nothing to block.
fn cached_answers(resp: &CachedResponse) -> Vec<Record> {
    match resp {
        CachedResponse::Wire { bytes, .. } => {
            Message::from_vec(bytes).map(|m| m.answers).unwrap_or_default()
        }
        CachedResponse::Message(m) => m.answers.clone(),
    }
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
    ///
    /// The [`Ingress`] carries either the cheap [`wire::parse_query`] fields (with
    /// the raw bytes kept for a lazy full parse) or a fully-parsed `Message`. A
    /// plain cache hit reads only the cheap fields and never builds a `Message`;
    /// the full parse happens lazily on the block / rewrite / forward / refresh
    /// paths, which need one to echo, synthesize, or forward.
    pub async fn handle(&self, ingress: Ingress, client_ip: IpAddr) -> EngineResponse {
        let start = Instant::now();
        let state = self.state.load();
        let client = state.clients.identify(client_ip);

        // Extract the hot-path fields up front; `lazy` defers the full `Message`.
        let (fields, lazy) = match ingress.into_parts() {
            Ok(parts) => parts,
            // No question to act on: FormErr against a best-effort echo.
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
        // `domain` borrows `name_lower`; its last use is in `filter.check`, so the
        // name can still be moved into the cache key afterwards.
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

        // ---- Cache ----
        // Built from the name we already normalized above — no second wire-walk
        // or lowercase pass.
        let key = QueryKey {
            name: name_lower,
            rtype,
            class,
            // Keep DNSSEC-sensitive queries in distinct cache/single-flight
            // entries so a DO/CD response is never cross-served (see `QueryKey`).
            dnssec_ok,
            checking_disabled,
        };
        if let Some(hit) = self.cache.get(&key, id) {
            // Response-side gate. A cache hit holds the *raw* upstream answer, so
            // before serving it to a filtering client we must establish the answer
            // is clean — either from a trusted memoised verdict or by re-running
            // the answer filter for this client. We never serve raw bytes to a
            // filtering client without that proof (see `cache::ResponseVerdict`).
            let filtering = state.filtering_enabled && client.filtering_enabled;
            let block_info: Option<MatchInfo> = if filtering {
                let client_dependent = state.filter.has_client_dependent_rules();
                let live_gen = state.filter.content_hash();
                match &hit.verdict {
                    // Trusted memo: client-independent and computed under the live
                    // filter. Reuse it without touching the cached bytes.
                    Some(v) if !client_dependent && v.generation == live_gen => match &v.outcome {
                        Outcome::Clean => None,
                        Outcome::Block(info) => Some(info.clone()),
                    },
                    // Untrusted: stale generation, no memo, or client-dependent
                    // rules in play. Recompute against the cached answer for this
                    // client. This re-parses the cached wire — the cold path only;
                    // the trusted-clean hit above stays a pure byte clone.
                    _ => filter_answers(&state.filter, &client, &cached_answers(&hit.response)),
                }
            } else {
                None
            };

            // A background refresh may memoise a global verdict only when filtering
            // is on and no rule's outcome depends on the client.
            let memoize = state.filtering_enabled && !state.filter.has_client_dependent_rules();

            if let Some(info) = block_info {
                // Blocked: synthesise a fresh block from the *current* config (not
                // whatever the cached answer was), so a reload of blocking mode /
                // TTL takes effect immediately rather than at entry expiry.
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
                if hit.stale {
                    self.spawn_refresh(&state, memoize, query, key.clone());
                }
                let action = QueryAction::Blocked {
                    rule: info.rule,
                    list_id: info.list_id,
                };
                return self.finalize(resp, action, log, start);
            }

            // Clean (or filtering off for this client): serve the cached answer.
            if hit.stale {
                // Optimistic: refresh in the background (single-flight in the pool
                // ensures only one upstream request). If the query somehow won't
                // re-parse, skip the refresh and still serve the cached hit.
                if let Some(refresh) = lazy.into_message() {
                    self.spawn_refresh(&state, memoize, refresh, key.clone());
                }
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
        let Some(query) = lazy.into_message() else {
            return self.finalize(formerr(id), QueryAction::Error, log, start);
        };
        match state.pool.resolve(&query).await {
            Ok(resolved) => {
                // Attribute the answering upstream's own round-trip to per-upstream
                // stats, not the whole-query wall-clock: with sequential failover a
                // query that waited out an earlier upstream's timeout would otherwise
                // charge that ~1s to the upstream that actually answered quickly.
                log.upstream_rtt_ms = Some(resolved.rtt_ms);

                // Response-side filtering: the query name passed the request-side
                // check, but the answer may point at a blocked target (a cloaked
                // CNAME, a blocklisted A/AAAA, or an HTTPS/SVCB IP hint).
                //
                // We cache the *raw* upstream answer either way and attach the
                // verdict as memoised metadata — never a synthetic block. That
                // keeps a cloaked domain cacheable (no upstream re-fetch on every
                // query) while letting the block be re-decided per client and
                // re-synthesised from current config after a reload.
                let client_filtered = state.filtering_enabled && client.filtering_enabled;
                let memoize = state.filtering_enabled && !state.filter.has_client_dependent_rules();
                let generation = state.filter.content_hash();

                // The verdict for *this* client (only when this client is filtered).
                let this_block = if client_filtered {
                    filter_answers(&state.filter, &client, &resolved.message.answers)
                } else {
                    None
                };

                if let Some(info) = this_block {
                    // Blocked for this client. Cache the raw answer — with a global
                    // verdict when safe so other clients reuse it — then return a
                    // fresh synthetic block.
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

                // Not blocked for this client (or this client is unfiltered). Cache
                // the raw answer. When a global verdict is memoisable, compute it
                // even for an unfiltered requester so filtered clients get the fast
                // path on their first hit rather than re-evaluating every time.
                if memoize {
                    let verdict = if client_filtered {
                        // Already known clean for this — hence every — client.
                        ResponseVerdict::clean(generation)
                    } else {
                        match filter_answers(&state.filter, &client, &resolved.message.answers) {
                            Some(info) => ResponseVerdict::block(info, generation),
                            None => ResponseVerdict::clean(generation),
                        }
                    };
                    self.cache
                        .insert_with_verdict(key, &resolved.message, Some(verdict));
                } else {
                    self.cache.insert(key, &resolved.message);
                }
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

    /// Spawn a background cache refresh for a stale entry. Re-inserts the raw
    /// upstream answer; when `memoize` (filtering on, no client-dependent rules)
    /// it also recomputes the client-independent verdict so the refreshed entry
    /// keeps its fast path. Otherwise it inserts without a verdict and the next
    /// filtering hit re-evaluates.
    fn spawn_refresh(&self, state: &EngineState, memoize: bool, query: Message, key: QueryKey) {
        let cache = self.cache.clone();
        let pool = state.pool.clone();
        let filter = state.filter.clone();
        let generation = state.filter.content_hash();
        // Count the dispatch up front so the metric reflects intent even if the
        // task is still in flight; the outcome is recorded when it completes.
        cache.note_refresh_started();
        tokio::spawn(async move {
            let resolved = match pool.resolve(&query).await {
                Ok(resolved) => resolved,
                Err(_) => {
                    // Upstream didn't answer: keep serving stale and try again on
                    // the next hit. Surfaced so a dead upstream behind a healthy
                    // hit rate is visible.
                    cache.note_refresh_failed();
                    return;
                }
            };
            if memoize {
                // No client context in the background, but `memoize` implies no
                // client-dependent rules, so the verdict is identical for every
                // client; a placeholder client yields the same result.
                let placeholder = ResolvedClient {
                    ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    name: None,
                    tags: Arc::from(Vec::new()),
                    filtering_enabled: true,
                };
                let verdict =
                    match filter_answers(&filter, &placeholder, &resolved.message.answers) {
                        Some(info) => ResponseVerdict::block(info, generation),
                        None => ResponseVerdict::clean(generation),
                    };
                cache.insert_with_verdict(key, &resolved.message, Some(verdict));
            } else {
                cache.insert(key, &resolved.message);
            }
        });
    }

    /// Build + record the query-log entry and stats for a completed query.
    /// `rcode` and `make_answers` supply the response-derived fields without
    /// requiring a `Message`, so the wire fast path needs no decode. The entry is
    /// handed to the background writer (or dropped if logging is off).
    fn record(
        &self,
        log: LogBuilder,
        action: QueryAction,
        rcode: Cow<'static, str>,
        make_answers: impl FnOnce() -> Arc<[String]>,
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
        // The answer summaries feed only the query log, not stats — so build them
        // only when logging is on. On a wire-byte hit this is an `Arc` clone of
        // the summaries the cache already holds, not a per-string deep copy.
        if log_on {
            entry.answers = make_answers();
        }
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
            || summarize_answers(&resp.answers),
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
        // The cache already holds these summaries as an `Arc`; share it (clone the
        // pointer) instead of deep-copying each string into the entry.
        self.record(
            log,
            QueryAction::Cached,
            rcode_label(rcode),
            || answers,
            start,
        );
        EngineResponse::Wire(bytes)
    }
}

/// What the listener hands [`Engine::handle`]: either the cheap
/// [`wire::parse_query`] fields with the raw bytes kept for a lazy full parse, or
/// a fully-parsed `Message` for anything the minimal parser couldn't handle.
#[derive(Clone)]
pub enum Ingress {
    /// Fast path: minimal parse plus the original bytes, re-parsed into a
    /// `Message` only if a block / rewrite / forward / refresh path needs one.
    Fast {
        bytes: Vec<u8>,
        parsed: wire::ParsedQuery,
    },
    /// The minimal parser bailed (compression, escaping, or a quirk it declines
    /// to handle); the listener fell back to a full parse.
    Full(Message),
}

impl Ingress {
    /// Parse inbound query bytes: the minimal fast path when possible, else a
    /// full `Message`. Returns `None` only when the bytes aren't a decodable DNS
    /// query at all (the listener drops those without replying).
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match wire::parse_query(bytes) {
            Some(parsed) => Some(Ingress::Fast {
                bytes: bytes.to_vec(),
                parsed,
            }),
            None => Message::from_vec(bytes).ok().map(Ingress::Full),
        }
    }

    /// Like [`parse`](Self::parse) but takes ownership of the query bytes, so the
    /// fast path keeps them without a second copy. Used by the TCP listener, whose
    /// per-query body buffer is exactly sized and used only here — unlike the UDP
    /// recv buffer, which is reused across datagrams and must stay borrowed.
    pub fn parse_owned(bytes: Vec<u8>) -> Option<Self> {
        match wire::parse_query(&bytes) {
            Some(parsed) => Some(Ingress::Fast { bytes, parsed }),
            None => Message::from_vec(&bytes).ok().map(Ingress::Full),
        }
    }

    /// The client's maximum acceptable UDP payload (EDNS advertised size, clamped
    /// to 512..=4096) — identical to what the full-parse path computed from `edns`.
    pub fn udp_max_payload(&self) -> usize {
        let advertised = match self {
            Ingress::Fast { parsed, .. } => parsed.edns_payload.unwrap_or(512),
            Ingress::Full(m) => m.edns.as_ref().map(|e| e.max_payload()).unwrap_or(512),
        };
        (advertised as usize).clamp(512, 4096)
    }

    /// Split into the cheap hot-path fields and the lazy `Message` source. Returns
    /// `Err(message)` when a fully-parsed query carries no question, so the caller
    /// can answer FormErr against it. The error message is boxed — it is the rare
    /// path, and boxing keeps the common `Ok` return small.
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

/// The lazily-materialised full `Message`: either already parsed, or the raw
/// bytes re-parsed on demand for a path that needs a structured query.
enum Lazy {
    Bytes(Vec<u8>),
    Msg(Message),
}

impl Lazy {
    /// Build the full `Message` for a path that needs one. For the fast variant
    /// this re-parses the kept bytes; [`wire::parse_query`] accepts only a strict
    /// subset of what `from_vec` accepts, so this succeeds for every query that
    /// took the fast path. `None` (a `from_vec` failure) is therefore effectively
    /// unreachable — but the caller handles it by answering FORMERR rather than
    /// fabricating a question-less query for the block/rewrite/forward synthesis.
    fn into_message(self) -> Option<Message> {
        match self {
            Lazy::Msg(m) => Some(m),
            Lazy::Bytes(b) => Message::from_vec(&b).ok(),
        }
    }
}

/// A header-only FORMERR response carrying `id`, for the effectively-unreachable
/// path where a fast-parsed query fails to re-parse into a full `Message`. Safer
/// than fabricating a question-less query for the response-synthesis paths.
fn formerr(id: u16) -> Message {
    let mut m = Message::new(id, MessageType::Response, OpCode::Query);
    m.metadata.response_code = ResponseCode::FormErr;
    m
}

/// The cheap, allocation-light fields the hot path reads from a query — sourced
/// from either [`wire::parse_query`] or a full `Message`, identically either way.
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
            // `From<u16>` is hickory's own inverse of the encode, so these match
            // the full-parse path's `query_type()` / `query_class()` exactly.
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
