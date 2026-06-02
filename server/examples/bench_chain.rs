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
use std::time::{Duration, Instant};

use bulwark_config::BlockingMode;
use bulwark_engine::cache::DnsCache;
use bulwark_engine::clients::ClientMatcher;
use bulwark_engine::querylog::QueryLog;
use bulwark_engine::stats::Stats;
use bulwark_engine::{Engine, EngineState};
use bulwark_filter::{ClientInfo, Compiler, FilterEngine};
use bulwark_upstream::{PoolEntry, PoolSettings, QueryKey, UpstreamPool};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

const ADGUARD_URL: &str =
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt";
const OISD_URL: &str = "https://big.oisd.nl/";

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
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
    } else if let Some(rest) = line.strip_prefix("0.0.0.0 ").or_else(|| line.strip_prefix("127.0.0.1 ")) {
        let domain = rest.trim();
        if domain.contains('.') && !domain.contains(' ') {
            return Some(domain.to_string());
        }
    }
    None
}

/// A handful of real popular domains, used as the "allowed / forwarded" set.
const POPULAR: &[&str] = &[
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com",
    "reddit.com", "github.com", "cloudflare.com", "apple.com", "microsoft.com",
    "netflix.com", "twitch.tv", "stackoverflow.com", "mozilla.org", "rust-lang.org",
    "nytimes.com", "bbc.co.uk", "spotify.com", "wordpress.org", "debian.org",
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
            let Ok(query) = Message::from_vec(&buf[..n]) else { continue };
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
    optimistic: bool,
    max_ttl: u32,
    stale_max_age: u32,
    filtering_enabled: bool,
) -> Arc<Engine> {
    let pool = Arc::new(
        UpstreamPool::build(
            &[PoolEntry { spec: format!("udp://{upstream}"), name: Some("mock".into()) }],
            PoolSettings { query_timeout: timeout, ..Default::default() },
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
    Engine::new(
        state,
        Arc::new(DnsCache::new(100_000, 0, max_ttl, optimistic, stale_max_age)),
        Arc::new(QueryLog::new(10_000, true)),
        Arc::new(Stats::new(true, 24)),
    )
}

fn query(name: &str, rtype: RecordType) -> Message {
    let mut m = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    let fqdn = if name.ends_with('.') { name.to_string() } else { format!("{name}.") };
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
    let msgs: Vec<Message> =
        blocked.iter().take(5_000).map(|d| query(d, RecordType::A)).collect();

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
        let key = QueryKey { name: name_lower, rtype: q.query_type(), class: q.query_class() };
        dlen + key.name.len()
    });
    println!(
        "  name+key derivation         old={old:>4} ns/op   new={new:>4} ns/op   ({:+.0}%)",
        (new as f64 - old as f64) / old as f64 * 100.0
    );

    // --- Response-code label, per query (runs on every response) ---
    let codes = [ResponseCode::NoError, ResponseCode::NXDomain, ResponseCode::ServFail];
    let old_r = best_ns_per_op(5, n, |i| {
        let c = codes[i % codes.len()];
        format!("{c:?}").to_uppercase().len()
    });
    let new_r = best_ns_per_op(5, n, |i| rcode_label(codes[i % codes.len()]).len());
    println!(
        "  rcode label                 old={old_r:>4} ns/op   new={new_r:>4} ns/op   ({:+.0}%)",
        (new_r as f64 - old_r as f64) / old_r as f64 * 100.0
    );
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
    let misses: Vec<String> =
        (0..10_000).map(|i| format!("node{i}.cdn-{}.example", i % 31)).collect();

    // (a) Name normalization as handle() does it (to_ascii + lowercase).
    let names: Vec<Name> = hits.iter().map(|h| Name::from_str(&format!("{h}.")).unwrap()).collect();
    let t = Instant::now();
    let mut acc = 0usize;
    for i in 0..n {
        let name = &names[i % names.len()];
        let display = name.to_ascii();
        let lower = display.to_ascii_lowercase();
        acc += lower.trim_end_matches('.').len();
    }
    println!("  {:<28} {:>6} ns/op  (sink={acc})", "name normalize (ascii+lc)", t.elapsed().as_nanos() / n as u128);

    // (b) QueryKey::from_message.
    let msgs: Vec<Message> = hits.iter().map(|h| query(h, RecordType::A)).collect();
    let t = Instant::now();
    let mut acc = 0usize;
    for i in 0..n {
        if let Some(k) = QueryKey::from_message(&msgs[i % msgs.len()]) {
            acc += k.name.len();
        }
    }
    println!("  {:<28} {:>6} ns/op  (sink={acc})", "QueryKey::from_message", t.elapsed().as_nanos() / n as u128);

    // (c) Client identification.
    let t = Instant::now();
    let mut acc = 0usize;
    for _ in 0..n {
        acc += matcher.identify(ip).ip.to_string().len();
    }
    println!("  {:<28} {:>6} ns/op  (sink={acc})", "clients.identify", t.elapsed().as_nanos() / n as u128);

    // (d) Filter check — blocked (hits real list rules).
    let t = Instant::now();
    let mut blk = 0u64;
    for i in 0..n {
        if filter.check(hits[i % hits.len()], "A", &ci).is_blocked() {
            blk += 1;
        }
    }
    println!("  {:<28} {:>6} ns/op  (blocked={blk})", "filter.check (blocked)", t.elapsed().as_nanos() / n as u128);

    // (e) Filter check — no match (the common resolver case).
    let t = Instant::now();
    for i in 0..n {
        let _ = filter.check(&misses[i % misses.len()], "A", &ci);
    }
    println!("  {:<28} {:>6} ns/op", "filter.check (no match)", t.elapsed().as_nanos() / n as u128);
}

// ---------------------------------------------------------------------------
// Phase 2: whole-chain latency per scenario.
// ---------------------------------------------------------------------------

async fn phase2_scenarios(filter: Arc<FilterEngine>, blocked: &[String], upstream: SocketAddr, n: usize) {
    println!("\n== Phase 2: whole-chain latency per scenario ==");

    // Production-like engine: optimistic cache on, generous stale window.
    let engine = build_engine(filter.clone(), upstream, Duration::from_millis(500), true, 0, 3600, true).await;

    // Blocked: real list domains -> synthesized NXDOMAIN, never touches upstream.
    let bset: Vec<String> = blocked.iter().cloned().cycle().take(n).collect();
    scenario(&engine, "blocked", many(bset.into_iter(), RecordType::A)).await;

    // Forwarded miss: unique never-seen domains -> mock upstream + cache insert.
    let fwd = (0..n).map(|i| format!("u{i}-{}.bench-fwd.example", rand::random::<u32>()));
    scenario(&engine, "forwarded (miss+insert)", many(fwd, RecordType::A)).await;

    // Cache hit (fresh): warm one domain, then hammer it.
    let _ = engine.handle(query("cache-hot.example.", RecordType::A), local()).await;
    let hot = (0..n).map(|_| "cache-hot.example".to_string());
    scenario(&engine, "cache hit (fresh)", many(hot, RecordType::A)).await;

    // Allowlisted / popular: forwarded, exercises the full miss-then-cache mix
    // across a small working set (mostly cache hits after warmup).
    let pop = (0..n).map(|i| POPULAR[i % POPULAR.len()].to_string());
    scenario(&engine, "popular set (warm cache)", many(pop, RecordType::A)).await;

    // Negative cache: nx- domains -> NXDOMAIN, cached negatively after first.
    let nx = (0..n).map(|i| format!("nx-{}.bench.example", i % 64));
    scenario(&engine, "negative cache (NXDOMAIN)", many(nx, RecordType::A)).await;

    // Filtering disabled: skips the filter stage entirely.
    let nofilter = build_engine(filter.clone(), upstream, Duration::from_millis(500), true, 0, 3600, false).await;
    let _ = nofilter.handle(query("nf-hot.example.", RecordType::A), local()).await;
    let nf = (0..n).map(|_| "nf-hot.example".to_string());
    scenario(&nofilter, "filtering disabled (cache)", many(nf, RecordType::A)).await;

    // Optimistic stale serve: a dead upstream means background refresh never
    // succeeds, so every lookup serves the stale entry (isolates that path).
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let stale_engine =
        build_engine(filter.clone(), dead, Duration::from_millis(50), true, 1, 3600, true).await;
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
    scenario(&stale_engine, "cache hit (stale+refresh)", many(stale, RecordType::A)).await;
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
    let engine = build_engine(filter, upstream, Duration::from_millis(500), true, 0, 3600, true).await;

    // Realistic mix: ~30% blocked, ~50% repeated popular (cache hits), ~20% unique forward.
    let mut msgs: Vec<Message> = Vec::with_capacity(total);
    for i in 0..total {
        let m = match i % 10 {
            0 | 1 | 2 => query(&blocked[i % blocked.len()], RecordType::A),
            3..=7 => query(POPULAR[i % POPULAR.len()], RecordType::A),
            _ => query(&format!("c{i}-{}.bench-fwd.example", rand::random::<u32>()), RecordType::A),
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
    report("per-query latency", Arc::try_unwrap(lat).unwrap().into_inner());

    // Single-flight: fire many identical, never-cached queries at once and
    // confirm the pool coalesces them into one upstream request.
    let (sf_up, sf_count) = mock_upstream(Duration::from_millis(20)).await;
    let sf_engine = build_engine(
        sf_count_filter(),
        sf_up,
        Duration::from_millis(500),
        false,
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
    phase3_concurrency(filter.clone(), &blocked, upstream, n.max(50_000), concurrency).await;

    println!("\n== done ==");
}
