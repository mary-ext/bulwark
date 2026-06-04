//! Whole-request-chain benchmark + profiler.
//!
//! Drives the full engine pipeline (client id → filter → cache → upstream →
//! stats/log) against **real** filter lists (AdGuard SDNS Filter + OISD Big)
//! and an in-process mock UDP upstream, so the numbers reflect a realistic
//! resolver under realistic rule volume — without depending on the public
//! internet at query time.
//!
//! Run with:
//!   cargo run --release --example bench_chain -p bulwark
//!
//! The filter lists are downloaded once into `target/bench-data/` (override the
//! directory with `BENCH_DATA_DIR`). If the network is unavailable, a synthetic
//! fallback list is used so the benchmark still runs.
//!
//! Knobs (env):
//!   BENCH_N                 per-scenario iterations          (default 20000)
//!   BENCH_UPSTREAM_DELAY_US simulated upstream RTT, µs       (default 0)
//!   BENCH_CONCURRENCY       concurrent in-flight queries     (default 64)
//!   BENCH_DATA_DIR          where to cache the lists

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bulwark_config::BlockingMode;
use bulwark_engine::cache::{CachedResponse, DnsCache};
use bulwark_engine::clients::ClientMatcher;
use bulwark_engine::querylog::QueryLog;
use bulwark_engine::stats::Stats;
use bulwark_engine::{Engine, EngineResponse, EngineState};
use bulwark_filter::{ClientInfo, Compiler, FilterEngine};
use bulwark_upstream::{PoolEntry, PoolSettings, QueryKey, UpstreamPool};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

const ADGUARD_URL: &str = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt";
const OISD_URL: &str = "https://big.oisd.nl/";

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Filter list loading (download-once + cache).
// ---------------------------------------------------------------------------

fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("BENCH_DATA_DIR") {
        return PathBuf::from(d);
    }
    // CARGO_MANIFEST_DIR is .../bulwark/server when run via `cargo run`; when run
    // as a bare binary it is unset and cwd is the workspace root.
    let base = std::env::var("CARGO_MANIFEST_DIR")
        .map(|m| PathBuf::from(m).join(".."))
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("target").join("bench-data")
}

async fn fetch_list(url: &str, name: &str) -> Option<String> {
    let dir = data_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(name);
    if let Ok(text) = std::fs::read_to_string(&path) {
        if !text.is_empty() {
            return Some(text);
        }
    }
    eprintln!("  downloading {name} from {url} ...");
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .ok()?
        .get(url)
        .send()
        .await
        .ok()?;
    let text = resp.text().await.ok()?;
    let _ = std::fs::write(&path, &text);
    Some(text)
}

/// Compile the real lists exactly the way the server does (dedup + $badfilter).
async fn build_filter() -> (FilterEngine, Vec<String>) {
    let mut compiler = Compiler::new();
    let mut got_real = false;
    if let Some(text) = fetch_list(ADGUARD_URL, "adguard_sdns.txt").await {
        let s = compiler.add_list(1, "AdGuard SDNS Filter", &text);
        println!("  AdGuard SDNS Filter: {} rules", s.rules);
        got_real = true;
    }
    if let Some(text) = fetch_list(OISD_URL, "oisd_big.txt").await {
        let s = compiler.add_list(2, "OISD Big", &text);
        println!("  OISD Big: {} rules", s.rules);
        got_real = true;
    }
    if !got_real {
        eprintln!("  network unavailable — using synthetic fallback list");
        let mut text = String::new();
        for i in 0..150_000 {
            text.push_str(&format!("||ads{i}.example{}.com^\n", i % 997));
        }
        compiler.add_list(1, "synthetic", &text);
    }
    let t0 = Instant::now();
    let (engine, _stats) = compiler.build();
    println!("  compiled {} rules in {:?}", engine.len(), t0.elapsed());

    // Harvest real blocked domains from the engine's own rule set so the
    // "blocked" workload hits actual list entries.
    let blocked = sample_blocked_domains();
    (engine, blocked)
}

/// Re-read the cached list files and extract plain blockable domains.
fn sample_blocked_domains() -> Vec<String> {
    let dir = data_dir();
    let mut out = Vec::new();
    for name in ["adguard_sdns.txt", "oisd_big.txt"] {
        if let Ok(text) = std::fs::read_to_string(dir.join(name)) {
            for line in text.lines() {
                let line = line.trim();
                if let Some(d) = parse_blockable(line) {
                    // Keep only names the DNS parser accepts as queries.
                    if Name::from_str(&format!("{d}.")).is_ok() {
                        out.push(d);
                        if out.len() >= 50_000 {
                            return out;
                        }
                    }
                }
            }
        }
    }
    if out.is_empty() {
        // Synthetic fallback domains.
        for i in 0..20_000 {
            out.push(format!("ads{i}.example{}.com", i % 997));
        }
    }
    out
}

/// Extract a simple `||domain^` or `0.0.0.0 domain` blockable domain.
fn parse_blockable(line: &str) -> Option<String> {
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
        return None;
    }
    if let Some(rest) = line.strip_prefix("||") {
        let domain = rest.strip_suffix('^').unwrap_or(rest);
        if domain.contains(['*', '/', '$', '~', '|']) || domain.is_empty() {
            return None;
        }
        if domain.contains('.') {
            return Some(domain.to_string());
        }
    } else if let Some(rest) = line
        .strip_prefix("0.0.0.0 ")
        .or_else(|| line.strip_prefix("127.0.0.1 "))
    {
        let domain = rest.trim();
        if domain.contains('.') && !domain.contains(' ') {
            return Some(domain.to_string());
        }
    }
    None
}

/// A handful of real popular domains, used as the "allowed / forwarded" set.
const POPULAR: &[&str] = &[
    "google.com",
    "youtube.com",
    "facebook.com",
    "wikipedia.org",
    "amazon.com",
    "reddit.com",
    "github.com",
    "cloudflare.com",
    "apple.com",
    "microsoft.com",
    "netflix.com",
    "twitch.tv",
    "stackoverflow.com",
    "mozilla.org",
    "rust-lang.org",
    "nytimes.com",
    "bbc.co.uk",
    "spotify.com",
    "wordpress.org",
    "debian.org",
];

// ---------------------------------------------------------------------------
// Mock upstream.
// ---------------------------------------------------------------------------

/// Spawn a mock UDP resolver. Names starting with `nx-` get NXDOMAIN (so the
/// negative-cache path is exercised); everything else gets `A 1.2.3.4`.
async fn mock_upstream(delay: Duration) -> (SocketAddr, Arc<AtomicU64>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let count = Arc::new(AtomicU64::new(0));
    let counter = count.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            counter.fetch_add(1, Ordering::Relaxed);
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let mut resp = query.clone();
            resp.metadata.message_type = MessageType::Response;
            if let Some(q) = query.queries.first() {
                let name = q.name().to_ascii();
                if name.starts_with("nx-") {
                    resp.metadata.response_code = ResponseCode::NXDomain;
                } else {
                    resp.metadata.response_code = ResponseCode::NoError;
                    resp.answers.push(Record::from_rdata(
                        q.name().clone(),
                        300,
                        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
                    ));
                }
            }
            let bytes = resp.to_vec().unwrap();
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let _ = sock.send_to(&bytes, peer).await;
        }
    });
    (addr, count)
}

// ---------------------------------------------------------------------------
// Engine construction.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn build_engine(
    filter: Arc<FilterEngine>,
    upstream: SocketAddr,
    timeout: Duration,
    max_ttl: u32,
    stale_max_age: u32,
    filtering_enabled: bool,
) -> Arc<Engine> {
    let pool = Arc::new(
        UpstreamPool::build(
            &[PoolEntry {
                spec: format!("udp://{upstream}"),
                name: Some("mock".into()),
            }],
            PoolSettings {
                query_timeout: timeout,
                ..Default::default()
            },
        )
        .await
        .unwrap(),
    );
    let state = EngineState {
        filter,
        pool,
        clients: Arc::new(ClientMatcher::default()),
        filtering_enabled,
        blocking_mode: BlockingMode::NxDomain,
        block_v4: Ipv4Addr::UNSPECIFIED,
        block_v6: std::net::Ipv6Addr::UNSPECIFIED,
        blocked_ttl: 10,
    };
    let engine = Engine::new(
        state,
        Arc::new(DnsCache::new(100_000, 0, max_ttl, stale_max_age)),
        Arc::new(QueryLog::new(true)),
        Arc::new(Stats::new(true, 24)),
    );
    attach_drained_sink(&engine);
    engine
}

/// Attach a query-log sink with a background drainer, mirroring production where
/// each logged entry is sent to the writer task. Without this the log's `push`
/// would be a no-op (no sink), under-counting the per-query send cost.
fn attach_drained_sink(engine: &Arc<Engine>) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    engine.log().set_sink(tx);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
}

/// Like `build_engine`, but with independent control over whether the query log
/// and stats recorders are enabled — used to isolate `finalize()`'s cost.
async fn build_engine_obs(
    filter: Arc<FilterEngine>,
    upstream: SocketAddr,
    stats_on: bool,
    log_on: bool,
) -> Arc<Engine> {
    let pool = Arc::new(
        UpstreamPool::build(
            &[PoolEntry {
                spec: format!("udp://{upstream}"),
                name: Some("mock".into()),
            }],
            PoolSettings {
                query_timeout: Duration::from_millis(500),
                ..Default::default()
            },
        )
        .await
        .unwrap(),
    );
    let state = EngineState {
        filter,
        pool,
        clients: Arc::new(ClientMatcher::default()),
        filtering_enabled: true,
        blocking_mode: BlockingMode::NxDomain,
        block_v4: Ipv4Addr::UNSPECIFIED,
        block_v6: std::net::Ipv6Addr::UNSPECIFIED,
        blocked_ttl: 10,
    };
    let engine = Engine::new(
        state,
        Arc::new(DnsCache::new(100_000, 0, 0, 3600)),
        Arc::new(QueryLog::new(log_on)),
        Arc::new(Stats::new(stats_on, 24)),
    );
    if log_on {
        attach_drained_sink(&engine);
    }
    engine
}

fn query(name: &str, rtype: RecordType) -> Message {
    let mut m = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    let mut q = Query::query(Name::from_str(&fqdn).unwrap(), rtype);
    q.set_query_class(DNSClass::IN);
    m.queries.push(q);
    m
}

fn local() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

// ---------------------------------------------------------------------------
// Measurement helpers.
// ---------------------------------------------------------------------------

fn report(label: &str, mut ns: Vec<u64>) {
    if ns.is_empty() {
        println!("  {label:<28} (no samples)");
        return;
    }
    ns.sort_unstable();
    let n = ns.len();
    let sum: u128 = ns.iter().map(|&x| x as u128).sum();
    let mean = sum as f64 / n as f64;
    let pct = |q: f64| ns[(((n as f64) * q) as usize).min(n - 1)];
    println!(
        "  {label:<28} mean={:>9.0}ns  p50={:>9}  p90={:>9}  p99={:>9}  max={:>9}  ({:>9.0} q/s)",
        mean,
        pct(0.50),
        pct(0.90),
        pct(0.99),
        ns[n - 1],
        1e9 / mean,
    );
}

/// Time one async whole-chain scenario over a pre-built batch of queries.
async fn scenario(engine: &Arc<Engine>, label: &str, msgs: Vec<Message>) {
    // Warmup (~10% of the batch).
    let warm = (msgs.len() / 10).max(1);
    for m in msgs.iter().take(warm) {
        let _ = engine.handle(m.clone(), local()).await;
    }
    let mut ns = Vec::with_capacity(msgs.len());
    for m in msgs {
        let t = Instant::now();
        let _ = engine.handle(m, local()).await;
        ns.push(t.elapsed().as_nanos() as u64);
    }
    report(label, ns);
}

fn many(domains: impl Iterator<Item = String>, rtype: RecordType) -> Vec<Message> {
    domains.map(|d| query(&d, rtype)).collect()
}

// ---------------------------------------------------------------------------
// Phase 0: A/B of the optimized hot-path steps (deterministic, low-variance).
//
// Isolates exactly the CPU work changed in `Engine::handle`, so the before/after
// delta is not drowned out by upstream I/O or scheduler noise. Reports best-of-N
// (minimum = least perturbed by background load).
// ---------------------------------------------------------------------------

/// Run `f` `trials` times over `n` iterations; return the best (lowest) ns/op.
fn best_ns_per_op(trials: u32, n: usize, mut f: impl FnMut(usize) -> usize) -> u128 {
    let mut best = u128::MAX;
    for _ in 0..trials {
        let t = Instant::now();
        let mut sink = 0usize;
        for i in 0..n {
            sink += f(i);
        }
        std::hint::black_box(sink);
        best = best.min(t.elapsed().as_nanos() / n as u128);
    }
    best
}

/// Local copy of the engine's new `rcode_label` (private there) for the A/B.
fn rcode_label(code: ResponseCode) -> String {
    let s = match code {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        other => return format!("{other:?}").to_uppercase(),
    };
    s.to_string()
}

fn phase0_ab(blocked: &[String]) {
    println!("\n== Phase 0: optimized hot-path steps, before vs after (best-of-5) ==");
    let n = 1_000_000usize;
    let msgs: Vec<Message> = blocked
        .iter()
        .take(5_000)
        .map(|d| query(d, RecordType::A))
        .collect();

    // --- Name + cache-key derivation, per query ---
    // OLD: lowercase the name for `domain`, then QueryKey::from_message re-walks
    //      the wire name and lowercases it a *second* time.
    let old = best_ns_per_op(5, n, |i| {
        let m = &msgs[i % msgs.len()];
        let q = m.queries.first().unwrap();
        let qname_display = q.name().to_ascii();
        let domain = qname_display.trim_end_matches('.').to_ascii_lowercase();
        let key = QueryKey::from_message(m).unwrap();
        domain.len() + key.name.len()
    });
    // NEW: normalize once; `domain` is a borrow; the key reuses that string.
    let new = best_ns_per_op(5, n, |i| {
        let m = &msgs[i % msgs.len()];
        let q = m.queries.first().unwrap();
        let qname_display = q.name().to_ascii();
        let name_lower = qname_display.to_ascii_lowercase();
        let domain = name_lower.trim_end_matches('.');
        let dlen = domain.len();
        let key = QueryKey {
            name: name_lower,
            rtype: q.query_type(),
            class: q.query_class(),
        };
        dlen + key.name.len()
    });
    println!(
        "  name+key derivation         old={old:>4} ns/op   new={new:>4} ns/op   ({:+.0}%)",
        (new as f64 - old as f64) / old as f64 * 100.0
    );

    // --- Response-code label, per query (runs on every response) ---
    let codes = [
        ResponseCode::NoError,
        ResponseCode::NXDomain,
        ResponseCode::ServFail,
    ];
    let old_r = best_ns_per_op(5, n, |i| {
        let c = codes[i % codes.len()];
        format!("{c:?}").to_uppercase().len()
    });
    let new_r = best_ns_per_op(5, n, |i| rcode_label(codes[i % codes.len()]).len());
    println!(
        "  rcode label                 old={old_r:>4} ns/op   new={new_r:>4} ns/op   ({:+.0}%)",
        (new_r as f64 - old_r as f64) / old_r as f64 * 100.0
    );

    // --- Record-type label, per query (runs on every query: filter + log) ---
    // OLD: RecordType::to_string() heap-allocates. NEW: a borrowed &'static str
    // for the common types.
    let rtypes = [
        RecordType::A,
        RecordType::AAAA,
        RecordType::HTTPS,
        RecordType::TXT,
    ];
    let old_t = best_ns_per_op(5, n, |i| rtypes[i % rtypes.len()].to_string().len());
    let new_t = best_ns_per_op(5, n, |i| rtype_label(rtypes[i % rtypes.len()]).len());
    println!(
        "  rtype label                 old={old_t:>4} ns/op   new={new_t:>4} ns/op   ({:+.0}%)",
        (new_t as f64 - old_t as f64) / old_t as f64 * 100.0
    );
}

/// Local copy of the engine's new `rtype_label` (private there) for the A/B.
fn rtype_label(rt: RecordType) -> &'static str {
    match rt {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::HTTPS => "HTTPS",
        RecordType::TXT => "TXT",
        _ => "OTHER",
    }
}

// ---------------------------------------------------------------------------
// Phase 1: per-stage micro-profile (isolates each step's CPU cost).
// ---------------------------------------------------------------------------

fn phase1_stage_profile(filter: &FilterEngine, blocked: &[String]) {
    println!("\n== Phase 1: per-stage CPU cost (single-threaded, ns/op) ==");
    let n = 500_000usize;
    let ci = ClientInfo::default();
    let matcher = ClientMatcher::default();
    let ip: IpAddr = "192.168.1.50".parse().unwrap();

    // Build a representative set of query names.
    let hits: Vec<&str> = blocked.iter().take(10_000).map(|s| s.as_str()).collect();
    let misses: Vec<String> = (0..10_000)
        .map(|i| format!("node{i}.cdn-{}.example", i % 31))
        .collect();

    // (a) Name normalization as handle() does it (to_ascii + lowercase).
    let names: Vec<Name> = hits
        .iter()
        .map(|h| Name::from_str(&format!("{h}.")).unwrap())
        .collect();
    let t = Instant::now();
    let mut acc = 0usize;
    for i in 0..n {
        let name = &names[i % names.len()];
        let display = name.to_ascii();
        let lower = display.to_ascii_lowercase();
        acc += lower.trim_end_matches('.').len();
    }
    println!(
        "  {:<28} {:>6} ns/op  (sink={acc})",
        "name normalize (ascii+lc)",
        t.elapsed().as_nanos() / n as u128
    );

    // (b) QueryKey::from_message.
    let msgs: Vec<Message> = hits.iter().map(|h| query(h, RecordType::A)).collect();
    let t = Instant::now();
    let mut acc = 0usize;
    for i in 0..n {
        if let Some(k) = QueryKey::from_message(&msgs[i % msgs.len()]) {
            acc += k.name.len();
        }
    }
    println!(
        "  {:<28} {:>6} ns/op  (sink={acc})",
        "QueryKey::from_message",
        t.elapsed().as_nanos() / n as u128
    );

    // (c) Client identification.
    let t = Instant::now();
    let mut acc = 0usize;
    for _ in 0..n {
        acc += matcher.identify(ip).ip.to_string().len();
    }
    println!(
        "  {:<28} {:>6} ns/op  (sink={acc})",
        "clients.identify",
        t.elapsed().as_nanos() / n as u128
    );

    // (d) Filter check — blocked (hits real list rules).
    let t = Instant::now();
    let mut blk = 0u64;
    for i in 0..n {
        if filter.check(hits[i % hits.len()], "A", &ci).is_blocked() {
            blk += 1;
        }
    }
    println!(
        "  {:<28} {:>6} ns/op  (blocked={blk})",
        "filter.check (blocked)",
        t.elapsed().as_nanos() / n as u128
    );

    // (e) Filter check — no match (the common resolver case).
    let t = Instant::now();
    for i in 0..n {
        let _ = filter.check(&misses[i % misses.len()], "A", &ci);
    }
    println!(
        "  {:<28} {:>6} ns/op",
        "filter.check (no match)",
        t.elapsed().as_nanos() / n as u128
    );
}

// ---------------------------------------------------------------------------
// Phase 2: whole-chain latency per scenario.
// ---------------------------------------------------------------------------

async fn phase2_scenarios(
    filter: Arc<FilterEngine>,
    blocked: &[String],
    upstream: SocketAddr,
    n: usize,
) {
    println!("\n== Phase 2: whole-chain latency per scenario ==");

    // Production-like engine: optimistic cache on, generous stale window.
    let engine = build_engine(
        filter.clone(),
        upstream,
        Duration::from_millis(500),
        0,
        3600,
        true,
    )
    .await;

    // Blocked: real list domains -> synthesized NXDOMAIN, never touches upstream.
    let bset: Vec<String> = blocked.iter().cloned().cycle().take(n).collect();
    scenario(&engine, "blocked", many(bset.into_iter(), RecordType::A)).await;

    // Forwarded miss: unique never-seen domains -> mock upstream + cache insert.
    let fwd = (0..n).map(|i| format!("u{i}-{}.bench-fwd.example", rand::random::<u32>()));
    scenario(&engine, "forwarded (miss+insert)", many(fwd, RecordType::A)).await;

    // Cache hit (fresh): warm one domain, then hammer it.
    let _ = engine
        .handle(query("cache-hot.example.", RecordType::A), local())
        .await;
    let hot = (0..n).map(|_| "cache-hot.example".to_string());
    scenario(&engine, "cache hit (fresh)", many(hot, RecordType::A)).await;

    // Allowlisted / popular: forwarded, exercises the full miss-then-cache mix
    // across a small working set (mostly cache hits after warmup).
    let pop = (0..n).map(|i| POPULAR[i % POPULAR.len()].to_string());
    scenario(
        &engine,
        "popular set (warm cache)",
        many(pop, RecordType::A),
    )
    .await;

    // Negative cache: nx- domains -> NXDOMAIN, cached negatively after first.
    let nx = (0..n).map(|i| format!("nx-{}.bench.example", i % 64));
    scenario(
        &engine,
        "negative cache (NXDOMAIN)",
        many(nx, RecordType::A),
    )
    .await;

    // Filtering disabled: skips the filter stage entirely.
    let nofilter = build_engine(
        filter.clone(),
        upstream,
        Duration::from_millis(500),
        0,
        3600,
        false,
    )
    .await;
    let _ = nofilter
        .handle(query("nf-hot.example.", RecordType::A), local())
        .await;
    let nf = (0..n).map(|_| "nf-hot.example".to_string());
    scenario(
        &nofilter,
        "filtering disabled (cache)",
        many(nf, RecordType::A),
    )
    .await;

    // Optimistic stale serve: a dead upstream means background refresh never
    // succeeds, so every lookup serves the stale entry (isolates that path).
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let stale_engine = build_engine(
        filter.clone(),
        dead,
        Duration::from_millis(50),
        1,
        3600,
        true,
    )
    .await;
    // Insert a fresh entry directly, then let it age past its 1s TTL.
    let key = QueryKey::from_message(&query("stale-hot.example.", RecordType::A)).unwrap();
    let mut warm = query("stale-hot.example.", RecordType::A);
    warm.metadata.message_type = MessageType::Response;
    warm.metadata.response_code = ResponseCode::NoError;
    warm.answers.push(Record::from_rdata(
        Name::from_str("stale-hot.example.").unwrap(),
        1,
        RData::A(A(Ipv4Addr::new(9, 9, 9, 9))),
    ));
    stale_engine.cache().insert(key, &warm);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let stale = (0..n.min(5_000)).map(|_| "stale-hot.example".to_string());
    scenario(
        &stale_engine,
        "cache hit (stale+refresh)",
        many(stale, RecordType::A),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Phase 2b: finalize() cost — cache-hit path with observability on vs off.
//
// `finalize()` runs on *every* query and, when stats/log are enabled, builds
// answer summaries, stringifies the client IP, reads the wall clock, locks a
// stats shard, and pushes a log entry. The "fully off" run early-returns before
// any of that, so on - off ≈ the finalize cost paid per cached query in prod.
// ---------------------------------------------------------------------------

async fn phase2b_finalize(filter: Arc<FilterEngine>, upstream: SocketAddr, n: usize) {
    println!("\n== Phase 2b: finalize() cost on the cache-hit path (obs on vs off) ==");

    // stats + log ON (production default).
    let on = build_engine_obs(filter.clone(), upstream, true, true).await;
    let _ = on
        .handle(query("fin-hot.example.", RecordType::A), local())
        .await;
    let hot = (0..n).map(|_| "fin-hot.example".to_string());
    scenario(&on, "cache hit (stats+log on)", many(hot, RecordType::A)).await;

    // stats + log OFF (finalize early-returns the response untouched).
    let off = build_engine_obs(filter.clone(), upstream, false, false).await;
    let _ = off
        .handle(query("fin-hot.example.", RecordType::A), local())
        .await;
    let hot = (0..n).map(|_| "fin-hot.example".to_string());
    scenario(&off, "cache hit (obs off)", many(hot, RecordType::A)).await;

    // stats only / log only, to attribute the cost between the two recorders.
    let stats_only = build_engine_obs(filter.clone(), upstream, true, false).await;
    let _ = stats_only
        .handle(query("fin-hot.example.", RecordType::A), local())
        .await;
    let hot = (0..n).map(|_| "fin-hot.example".to_string());
    scenario(&stats_only, "cache hit (stats only)", many(hot, RecordType::A)).await;

    let log_only = build_engine_obs(filter.clone(), upstream, false, true).await;
    let _ = log_only
        .handle(query("fin-hot.example.", RecordType::A), local())
        .await;
    let hot = (0..n).map(|_| "fin-hot.example".to_string());
    scenario(&log_only, "cache hit (log only)", many(hot, RecordType::A)).await;
}

// ---------------------------------------------------------------------------
// Phase 2c: finalize() component micro-costs (deterministic, best-of-5).
//
// Isolates the individual allocators/syscalls inside finalize()+build() so we
// know which ones are worth eliminating.
// ---------------------------------------------------------------------------

fn phase2c_finalize_components() {
    println!("\n== Phase 2c: finalize() component micro-costs (best-of-5) ==");
    let n = 1_000_000usize;

    // A representative A response: two answer records, like a real reply.
    let name = Name::from_str("cache-hot.example.").unwrap();
    let recs = [
        Record::from_rdata(name.clone(), 300, RData::A(A(Ipv4Addr::new(1, 2, 3, 4)))),
        Record::from_rdata(name.clone(), 300, RData::A(A(Ipv4Addr::new(5, 6, 7, 8)))),
    ];

    // (a) Answer summaries: `resp.answers.iter().map(summarize).collect()`,
    //     where summarize = format!("{} {}", record_type, data).
    let summaries = best_ns_per_op(5, n, |_| {
        let v: Vec<String> = recs
            .iter()
            .map(|r| format!("{} {}", r.record_type(), r.data))
            .collect();
        v.iter().map(|s| s.len()).sum::<usize>()
    });
    println!("  answer summaries (2 recs)   {summaries:>4} ns/op");

    // (b) client_ip.to_string() in LogBuilder::build.
    let ip: IpAddr = "192.168.1.50".parse().unwrap();
    let ip_cost = best_ns_per_op(5, n, |_| ip.to_string().len());
    println!("  client_ip.to_string()       {ip_cost:>4} ns/op");

    // (c) now_ms(): a SystemTime::now() syscall per query.
    let now_cost = best_ns_per_op(5, n, |_| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as usize)
            .unwrap_or(0)
    });
    println!("  now_ms() (SystemTime::now)  {now_cost:>4} ns/op");

    // (d) What a wire-byte cache would replace, per cache hit:
    //   - the Message clone done in adjust_ttls()  (cache hit, in handle)
    //   - the Message::to_vec() re-encode          (server, AFTER handle — not
    //     captured by Phase 2, which times handle() only)
    // vs. what it would cost instead: a flat Vec<u8> clone + in-place TTL patch.
    let mut resp = Message::new(0x1234, MessageType::Response, OpCode::Query);
    let mut q = Query::query(name.clone(), RecordType::A);
    q.set_query_class(DNSClass::IN);
    resp.queries.push(q);
    for r in &recs {
        resp.answers.push(r.clone());
    }
    let clone_cost = best_ns_per_op(5, n, |_| resp.clone().answers.len());
    let encode_cost = best_ns_per_op(5, n, |_| resp.to_vec().map(|v| v.len()).unwrap_or(0));
    let wire = resp.to_vec().unwrap();
    let wireclone_cost = best_ns_per_op(5, n, |_| wire.clone().len());
    println!("  Message::clone (adjust_ttls){clone_cost:>4} ns/op");
    println!("  Message::to_vec (server enc){encode_cost:>4} ns/op");
    println!(
        "  Vec<u8>::clone (wire-byte)   {wireclone_cost:>4} ns/op   (replaces the two above: ~{} ns saved/hit)",
        (clone_cost + encode_cost).saturating_sub(wireclone_cost)
    );
}

// ---------------------------------------------------------------------------
// Phase 2d: query-log build + push cost (deterministic).
//
// Isolates exactly the per-query log work — constructing a QueryLogEntry (its
// string allocations) and handing it to the writer over the unbounded channel
// (a node alloc + atomic enqueue; the entry is moved, not cloned). A background
// task drains the channel so it doesn't grow unbounded, matching production.
// Same-run A/B (build-only vs build+send), so it is immune to the cross-run
// thermal drift that makes Phase 2 means hard to compare.
//
// The writer's own work (the SQLite insert transaction) runs on a background
// task, off the query's hot path entirely, so it is not measured here.
// ---------------------------------------------------------------------------

fn phase2d_log_microbench() {
    println!("\n== Phase 2d: query-log build + channel send (best-of-5) ==");
    let n = 200_000usize;

    // A representative cached A response: one answer record.
    let name = Name::from_str("cache-hot.example.").unwrap();
    let recs = [Record::from_rdata(
        name.clone(),
        300,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    )];
    let ip: IpAddr = "192.168.1.50".parse().unwrap();

    // Build a fresh entry exactly as `finalize()` + `LogBuilder::build()` do:
    // client-IP string, the question string, and the formatted answer summaries
    // are the allocations of interest.
    let make_entry = || QueryLogEntry {
        id: 0,
        time_ms: 1_700_000_000_000,
        client_ip: ip.to_string(),
        question: "cache-hot.example.".to_string(),
        qtype: std::borrow::Cow::Borrowed("A"),
        action: QueryAction::Cached,
        allowlisted: false,
        rcode: std::borrow::Cow::Borrowed("NOERROR"),
        answers: recs
            .iter()
            .map(|r| format!("{} {}", r.record_type(), r.data))
            .collect(),
        elapsed_ms: 0.5,
    };

    // (a) Build the entry only (allocations, no insert).
    let build = best_ns_per_op(5, n, |_| {
        let e = make_entry();
        e.client_ip.len() + e.question.len() + e.answers.iter().map(|s| s.len()).sum::<usize>()
    });

    // (b) Build + send to the writer channel (the real hot-path handoff). A
    // receiver is attached and drained *between* timed trials — outside the
    // timer — so the unbounded channel stays bounded without charging the recv
    // cost to the measurement.
    let log = QueryLog::new(true);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    log.set_sink(tx);
    let mut buildpush = u128::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            log.push(make_entry());
        }
        buildpush = buildpush.min(t.elapsed().as_nanos() / n as u128);
        while rx.try_recv().is_ok() {} // drain (untimed)
    }

    println!("  build entry only            {build:>4} ns/op");
    println!(
        "  build + send (hot path)     {buildpush:>4} ns/op   (channel send alone ~{} ns)",
        buildpush.saturating_sub(build)
    );
}

// ---------------------------------------------------------------------------
// Phase 2e: end-to-end cache hit *including* the wire encode the server does.
//
// Phase 2 times handle() only; the wire-byte cache's biggest win — skipping the
// per-response Message::to_vec re-encode — happens in the server, after handle().
// This phase measures the full client-facing CPU two ways, same run (so it is
// thermal-drift-immune): the real wire-byte path (send bytes as-is) vs. routing
// the response back through a Message + to_vec. NOTE the round-trip arm also
// *decodes* the wire (from_vec) to get a Message, which the pre-wire-byte code
// never did (it held a Message already) — so it OVERSTATES the delta. The clean
// per-hit saving vs. the old code is the Phase 2c figure (~231 ns: the
// adjust_ttls clone + the to_vec re-encode, both now ~0).
// ---------------------------------------------------------------------------

async fn phase2e_e2e(filter: Arc<FilterEngine>, upstream: SocketAddr, n: usize) {
    println!("\n== Phase 2e: end-to-end cache hit incl. wire encode (handle + send-ready) ==");
    let engine = build_engine(filter, upstream, Duration::from_millis(500), 0, 3600, true).await;
    let _ = engine
        .handle(query("e2e-hot.example.", RecordType::A), local())
        .await;

    // Real path: a wire-byte hit is already encoded; send it directly.
    let msgs = many((0..n).map(|_| "e2e-hot.example".to_string()), RecordType::A);
    let warm = (msgs.len() / 10).max(1);
    for m in msgs.iter().take(warm) {
        let _ = engine.handle(m.clone(), local()).await;
    }
    let mut ns = Vec::with_capacity(n);
    for m in msgs {
        let t = Instant::now();
        let resp = engine.handle(m, local()).await;
        let bytes = match resp {
            EngineResponse::Wire(b) => b,
            other => other.into_message().to_vec().unwrap_or_default(),
        };
        std::hint::black_box(bytes.len());
        ns.push(t.elapsed().as_nanos() as u64);
    }
    report("wire-byte (send as-is)", ns);

    // Round-trip through a Message (decode + re-encode). Upper bound; overstates
    // vs. the old code by the decode it adds — see the phase note.
    let msgs = many((0..n).map(|_| "e2e-hot.example".to_string()), RecordType::A);
    let mut ns = Vec::with_capacity(n);
    for m in msgs {
        let t = Instant::now();
        let resp = engine.handle(m, local()).await;
        let bytes = resp.into_message().to_vec().unwrap_or_default();
        std::hint::black_box(bytes.len());
        ns.push(t.elapsed().as_nanos() as u64);
    }
    report("Message round-trip (dec+enc)", ns);
}

// ---------------------------------------------------------------------------
// Phase 3: concurrent throughput + single-flight.
// ---------------------------------------------------------------------------

async fn phase3_concurrency(
    filter: Arc<FilterEngine>,
    blocked: &[String],
    upstream: SocketAddr,
    total: usize,
    concurrency: usize,
) {
    println!("\n== Phase 3: concurrent mixed workload (concurrency={concurrency}) ==");
    let engine = build_engine(filter, upstream, Duration::from_millis(500), 0, 3600, true).await;

    // Realistic mix: ~30% blocked, ~50% repeated popular (cache hits), ~20% unique forward.
    let mut msgs: Vec<Message> = Vec::with_capacity(total);
    for i in 0..total {
        let m = match i % 10 {
            0..=2 => query(&blocked[i % blocked.len()], RecordType::A),
            3..=7 => query(POPULAR[i % POPULAR.len()], RecordType::A),
            _ => query(
                &format!("c{i}-{}.bench-fwd.example", rand::random::<u32>()),
                RecordType::A,
            ),
        };
        msgs.push(m);
    }

    let idx = Arc::new(AtomicUsize::new(0));
    let msgs = Arc::new(msgs);
    let lat = Arc::new(parking_lot::Mutex::new(Vec::<u64>::with_capacity(total)));

    let t0 = Instant::now();
    let mut workers = Vec::new();
    for _ in 0..concurrency {
        let engine = engine.clone();
        let idx = idx.clone();
        let msgs = msgs.clone();
        let lat = lat.clone();
        workers.push(tokio::spawn(async move {
            let mut local_lat = Vec::new();
            loop {
                let i = idx.fetch_add(1, Ordering::Relaxed);
                if i >= msgs.len() {
                    break;
                }
                let t = Instant::now();
                let _ = engine.handle(msgs[i].clone(), local()).await;
                local_lat.push(t.elapsed().as_nanos() as u64);
            }
            lat.lock().extend(local_lat);
        }));
    }
    for w in workers {
        let _ = w.await;
    }
    let elapsed = t0.elapsed();
    let qps = total as f64 / elapsed.as_secs_f64();
    println!("  {total} queries in {elapsed:?}  =>  {qps:.0} q/s aggregate");
    report(
        "per-query latency",
        Arc::try_unwrap(lat).unwrap().into_inner(),
    );

    // Single-flight: fire many identical, never-cached queries at once and
    // confirm the pool coalesces them into one upstream request.
    let (sf_up, sf_count) = mock_upstream(Duration::from_millis(20)).await;
    let sf_engine = build_engine(
        sf_count_filter(),
        sf_up,
        Duration::from_millis(500),
        0,
        0,
        false,
    )
    .await;
    let burst = 200usize;
    let q = query("single-flight.bench.example", RecordType::A);
    let mut tasks = Vec::new();
    for _ in 0..burst {
        let e = sf_engine.clone();
        let q = q.clone();
        tasks.push(tokio::spawn(async move { e.handle(q, local()).await }));
    }
    for t in tasks {
        let _ = t.await;
    }
    println!(
        "  single-flight: {burst} identical concurrent queries -> {} upstream request(s)",
        sf_count.load(Ordering::Relaxed)
    );
}

fn sf_count_filter() -> Arc<FilterEngine> {
    Arc::new(Compiler::new().build().0)
}

// ---------------------------------------------------------------------------
// Phase 4: stats.record() contention — old single global mutex vs new shards.
//
// This isolates the statistics bottleneck from upstream I/O: every query in a
// real resolver calls record(), so its scaling with core count is what matters.
// `OldStats` is a faithful copy of the pre-optimization record() (one mutex,
// string allocations performed *inside* the lock); the new side calls the real
// sharded `bulwark_engine::stats::Stats`.
// ---------------------------------------------------------------------------

use bulwark_engine::querylog::{QueryAction, QueryLogEntry};
use std::collections::HashMap;

fn old_bump(map: &mut HashMap<String, u64>, key: &str, by: u64) {
    if let Some(v) = map.get_mut(key) {
        *v += by;
    } else if map.len() < 50_000 {
        map.insert(key.to_string(), by);
    }
}

#[derive(Default)]
struct OldInner {
    total: u64,
    blocked: u64,
    cached: u64,
    proc_time_sum_ms: f64,
    proc_time_count: u64,
    latency_hist: Vec<u64>,
    domains: HashMap<String, u64>,
    blocked_domains: HashMap<String, u64>,
    clients: HashMap<String, u64>,
    qtypes: HashMap<String, u64>,
    upstreams: HashMap<String, u64>,
    upstream_rtt_sum: HashMap<String, f64>,
    upstream_rtt_count: HashMap<String, u64>,
}

struct OldStats {
    inner: parking_lot::Mutex<OldInner>,
}

impl OldStats {
    fn new() -> Self {
        let inner = OldInner {
            latency_hist: vec![0; 11],
            ..Default::default()
        };
        Self {
            inner: parking_lot::Mutex::new(inner),
        }
    }

    // Mirror of the original record(): single lock, allocations inside it.
    fn record(&self, entry: &QueryLogEntry) {
        let mut s = self.inner.lock();
        s.total += 1;
        let blocked = entry.is_blocked();
        if entry.action == QueryAction::Cached {
            s.cached += 1;
        }
        if blocked {
            s.blocked += 1;
        }
        s.proc_time_sum_ms += entry.elapsed_ms;
        s.proc_time_count += 1;
        let idx = (entry.elapsed_ms as usize).min(10);
        s.latency_hist[idx] += 1;

        let domain = entry.question.trim_end_matches('.').to_string();
        old_bump(&mut s.domains, &domain, 1);
        if blocked {
            old_bump(&mut s.blocked_domains, &domain, 1);
        }
        old_bump(&mut s.clients, &entry.client_ip, 1);
        old_bump(&mut s.qtypes, &entry.qtype, 1);
        if let Some(up) = entry.upstream() {
            old_bump(&mut s.upstreams, up, 1);
            *s.upstream_rtt_sum.entry(up.to_string()).or_insert(0.0) += entry.elapsed_ms;
            *s.upstream_rtt_count.entry(up.to_string()).or_insert(0) += 1;
        }
    }
}

fn entry_for(domain: &str, blocked: bool) -> QueryLogEntry {
    QueryLogEntry {
        id: 0,
        time_ms: 1_700_000_000_000,
        client_ip: "192.168.1.50".into(),
        question: format!("{domain}."),
        qtype: "A".into(),
        action: if blocked {
            QueryAction::Blocked {
                rule: "||ads^".into(),
                list_id: 0,
            }
        } else {
            QueryAction::Forwarded {
                upstream: "mock".into(),
            }
        },
        allowlisted: false,
        rcode: "NOERROR".into(),
        answers: vec![],
        elapsed_ms: 1.5,
    }
}

fn phase4_stats_contention(blocked: &[String]) {
    println!("\n== Phase 4: stats.record() scaling, old single-mutex vs new sharded ==");
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let per_thread = 400_000usize;

    // Shared, pre-built entries (~70% blocked, mirroring a filtering resolver).
    let entries: Arc<Vec<QueryLogEntry>> = Arc::new(
        (0..4096)
            .map(|i| entry_for(&blocked[i % blocked.len()], i % 10 < 7))
            .collect(),
    );

    let thread_counts: Vec<usize> = [1usize, 2, 4, cores]
        .into_iter()
        .filter(|&c| c <= cores)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    println!(
        "  {:<8} {:>14} {:>14} {:>10}",
        "threads", "old (rec/s)", "new (rec/s)", "speedup"
    );
    for &c in &thread_counts {
        let old = Arc::new(OldStats::new());
        let old_rate = run_record_bench(c, per_thread, entries.clone(), {
            let old = old.clone();
            move |e| old.record(e)
        });

        let new = Arc::new(Stats::new(true, 24));
        let new_rate = run_record_bench(c, per_thread, entries.clone(), {
            let new = new.clone();
            move |e| new.record(e, None)
        });

        println!(
            "  {c:<8} {old_rate:>14.0} {new_rate:>14.0} {:>9.1}x",
            new_rate / old_rate.max(1.0)
        );
    }
}

/// Spawn `threads` OS threads, each replaying `per_thread` records, and return
/// aggregate records/second.
fn run_record_bench(
    threads: usize,
    per_thread: usize,
    entries: Arc<Vec<QueryLogEntry>>,
    record: impl Fn(&QueryLogEntry) + Send + Sync + Clone + 'static,
) -> f64 {
    let barrier = Arc::new(std::sync::Barrier::new(threads));
    let mut handles = Vec::new();
    for t in 0..threads {
        let entries = entries.clone();
        let record = record.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut i = t;
            for _ in 0..per_thread {
                record(&entries[i & (entries.len() - 1)]);
                i = i.wrapping_add(1);
            }
        }));
    }
    let start = Instant::now();
    // Threads block on the barrier; start the clock and let them run.
    for h in handles {
        let _ = h.join();
    }
    let elapsed = start.elapsed();
    (threads * per_thread) as f64 / elapsed.as_secs_f64()
}

// ---------------------------------------------------------------------------
// Phase 5: concurrent cache-hit throughput — isolates the cache mutex.
//
// Phase 3's tail is dominated by forwarded queries doing real upstream I/O, so
// it can't show how the cache lock itself scales. Here every operation is a
// warm cache hit (no filter, no upstream, no async), so the only shared state
// is the cache's mutex + the per-hit TTL-rewrite clone. This is where moving
// the clone out of the critical section should show up.
// ---------------------------------------------------------------------------

fn warm_cache(n_keys: usize) -> (Arc<DnsCache>, Arc<Vec<QueryKey>>) {
    let cache = Arc::new(DnsCache::new(100_000, 0, 0, 0));
    let mut keys = Vec::with_capacity(n_keys);
    for i in 0..n_keys {
        let name = format!("hot{i}.bench.example.");
        let mut resp = query(&name, RecordType::A);
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.response_code = ResponseCode::NoError;
        // A couple of answers, like a real A response, so the clone is not free.
        resp.answers.push(Record::from_rdata(
            Name::from_str(&name).unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        resp.answers.push(Record::from_rdata(
            Name::from_str(&name).unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(5, 6, 7, 8))),
        ));
        let key = QueryKey::from_message(&resp).unwrap();
        cache.insert(key.clone(), &resp);
        keys.push(key);
    }
    (cache, Arc::new(keys))
}

fn phase5_cache_contention() {
    println!("\n== Phase 5: concurrent cache-hit throughput (warm keys) ==");
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let per_thread = 2_000_000usize;
    let (cache, keys) = warm_cache(256);
    let mask = keys.len() - 1;

    let thread_counts: Vec<usize> = [1usize, 2, 4, cores]
        .into_iter()
        .filter(|&c| c <= cores)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    println!("  {:<8} {:>16} {:>10}", "threads", "hits/s", "scaling");
    let mut base = 0.0f64;
    for &c in &thread_counts {
        let barrier = Arc::new(std::sync::Barrier::new(c));
        let mut handles = Vec::new();
        for t in 0..c {
            let cache = cache.clone();
            let keys = keys.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let mut i = t;
                let mut sink = 0usize;
                for _ in 0..per_thread {
                    if let Some(hit) = cache.get(&keys[i & mask], 0) {
                        sink += match hit.response {
                            CachedResponse::Wire { bytes, .. } => bytes.len(),
                            CachedResponse::Message(m) => m.answers.len(),
                        };
                    }
                    i = i.wrapping_add(1);
                }
                std::hint::black_box(sink);
            }));
        }
        let start = Instant::now();
        for h in handles {
            let _ = h.join();
        }
        let rate = (c * per_thread) as f64 / start.elapsed().as_secs_f64();
        if c == 1 {
            base = rate;
        }
        println!("  {c:<8} {rate:>16.0} {:>9.1}x", rate / base.max(1.0));
    }
}

// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let n = env_usize("BENCH_N", 20_000);
    let concurrency = env_usize("BENCH_CONCURRENCY", 64);
    let delay = Duration::from_micros(env_usize("BENCH_UPSTREAM_DELAY_US", 0) as u64);

    println!("== Bulwark whole-chain benchmark ==");
    println!("  iterations/scenario={n}  concurrency={concurrency}  upstream_delay={delay:?}");

    println!("\n== Loading filter lists ==");
    let (filter, blocked) = build_filter().await;
    let filter = Arc::new(filter);
    println!("  sampled {} real blockable domains", blocked.len());

    let (upstream, _count) = mock_upstream(delay).await;

    phase0_ab(&blocked);
    phase1_stage_profile(&filter, &blocked);
    phase2_scenarios(filter.clone(), &blocked, upstream, n).await;
    phase2b_finalize(filter.clone(), upstream, n).await;
    phase2c_finalize_components();
    phase2d_log_microbench();
    phase2e_e2e(filter.clone(), upstream, n).await;
    phase3_concurrency(
        filter.clone(),
        &blocked,
        upstream,
        n.max(50_000),
        concurrency,
    )
    .await;
    phase4_stats_contention(&blocked);
    phase5_cache_contention();

    println!("\n== done ==");
}
