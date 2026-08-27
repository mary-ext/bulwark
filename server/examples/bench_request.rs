//! Full request-chain benchmark and profiler.
//!
//! Run with `cargo run --release --example bench_request -p bulwark`.

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bulwark_config::{BlockingMode, ClientConfig};
use bulwark_engine::cache::{CachedResponse, DnsCache};
use bulwark_engine::clients::ClientMatcher;
use bulwark_engine::querylog::QueryLog;
use bulwark_engine::stats::Stats;
use bulwark_engine::{Engine, EngineResponse, EngineState, Ingress};
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

fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("BENCH_DATA_DIR") {
        return PathBuf::from(d);
    }
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
    let blocked = sample_blocked_domains();
    (engine, blocked)
}
fn sample_blocked_domains() -> Vec<String> {
    let dir = data_dir();
    let mut out = Vec::new();
    for name in ["adguard_sdns.txt", "oisd_big.txt"] {
        if let Ok(text) = std::fs::read_to_string(dir.join(name)) {
            for line in text.lines() {
                let line = line.trim();
                if let Some(d) = parse_blockable(line) {
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
        for i in 0..20_000 {
            out.push(format!("ads{i}.example{}.com", i % 997));
        }
    }
    out
}
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
fn sample_clients() -> Vec<ClientConfig> {
    let mut clients: Vec<ClientConfig> = (0..15)
        .map(|i| ClientConfig {
            id: format!("c{i}"),
            name: format!("client-{i}"),
            ids: vec![format!("10.{i}.0.0/16")],
            tags: vec!["lan".into()],
            filtering_enabled: true,
        })
        .collect();
    clients.push(ClientConfig {
        id: "home".into(),
        name: "home-lan".into(),
        ids: vec!["192.168.1.0/24".into()],
        tags: vec!["trusted".into()],
        filtering_enabled: true,
    });
    clients
}
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
        Arc::new(QueryLog::new(true, false)),
        Arc::new(Stats::new(true, 24, false)),
    );
    attach_drained_sink(&engine);
    engine
}
fn attach_drained_sink(engine: &Arc<Engine>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1 << 20);
    engine.log().set_sink(tx);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
}
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
        Arc::new(QueryLog::new(log_on, false)),
        Arc::new(Stats::new(stats_on, 24, false)),
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
fn ingress(m: Message) -> Ingress {
    Ingress::parse(&m.to_vec().unwrap()).expect("query should be decodable")
}

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
async fn scenario(engine: &Arc<Engine>, label: &str, warm: Vec<Ingress>, timed: Vec<Ingress>) {
    for ing in warm {
        let _ = engine.handle(ing, local()).await;
    }
    let mut ns = Vec::with_capacity(timed.len());
    for ing in timed {
        let t = Instant::now();
        let _ = engine.handle(ing, local()).await;
        ns.push(t.elapsed().as_nanos() as u64);
    }
    report(label, ns);
}
fn warm_then_time(msgs: Vec<Ingress>) -> (Vec<Ingress>, Vec<Ingress>) {
    let warm = msgs
        .iter()
        .take((msgs.len() / 10).max(1))
        .cloned()
        .collect();
    (warm, msgs)
}

fn many(domains: impl Iterator<Item = String>, rtype: RecordType) -> Vec<Ingress> {
    domains.map(|d| ingress(query(&d, rtype))).collect()
}
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
    let old = best_ns_per_op(5, n, |i| {
        let m = &msgs[i % msgs.len()];
        let q = m.queries.first().unwrap();
        let qname_display = q.name().to_ascii();
        let domain = qname_display.trim_end_matches('.').to_ascii_lowercase();
        let key = QueryKey::from_message(m).unwrap();
        domain.len() + key.name.len()
    });
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
            dnssec_ok: false,
            checking_disabled: false,
        };
        dlen + key.name.len()
    });
    println!(
        "  name+key derivation         old={old:>4} ns/op   new={new:>4} ns/op   ({:+.0}%)",
        (new as f64 - old as f64) / old as f64 * 100.0
    );
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
fn rtype_label(rt: RecordType) -> &'static str {
    match rt {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::HTTPS => "HTTPS",
        RecordType::TXT => "TXT",
        _ => "OTHER",
    }
}

fn phase1_stage_profile(filter: &FilterEngine, blocked: &[String]) {
    println!("\n== Phase 1: per-stage CPU cost (single-threaded, ns/op) ==");
    let n = 500_000usize;
    let ci = ClientInfo::default();
    let empty_matcher = ClientMatcher::default();
    let populated_matcher = ClientMatcher::build(&sample_clients());
    let ip: IpAddr = "192.168.1.50".parse().unwrap();
    let hits: Vec<&str> = blocked.iter().take(10_000).map(|s| s.as_str()).collect();
    let misses: Vec<String> = (0..10_000)
        .map(|i| format!("node{i}.cdn-{}.example", i % 31))
        .collect();
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
    let t = Instant::now();
    let mut acc = 0usize;
    for _ in 0..n {
        acc += empty_matcher.identify(ip).filtering_enabled as usize;
    }
    println!(
        "  {:<28} {:>6} ns/op  (sink={acc})",
        "clients.identify (no clients)",
        t.elapsed().as_nanos() / n as u128
    );
    let t = Instant::now();
    let mut acc = 0usize;
    for _ in 0..n {
        acc += populated_matcher.identify(ip).filtering_enabled as usize;
    }
    println!(
        "  {:<28} {:>6} ns/op  (sink={acc})",
        "clients.identify (16 CIDRs)",
        t.elapsed().as_nanos() / n as u128
    );
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

async fn phase2_scenarios(
    filter: Arc<FilterEngine>,
    blocked: &[String],
    upstream: SocketAddr,
    n: usize,
) {
    println!("\n== Phase 2: whole-chain latency per scenario ==");
    let engine = build_engine(
        filter.clone(),
        upstream,
        Duration::from_millis(500),
        0,
        3600,
        true,
    )
    .await;
    let bset: Vec<String> = blocked.iter().cloned().cycle().take(n).collect();
    let (warm, timed) = warm_then_time(many(bset.into_iter(), RecordType::A));
    scenario(&engine, "blocked", warm, timed).await;
    let warm_fwd = (0..(n / 10).max(1))
        .map(|i| format!("warm{i}-{}.bench-fwd.example", rand::random::<u32>()));
    let fwd = (0..n).map(|i| format!("u{i}-{}.bench-fwd.example", rand::random::<u32>()));
    scenario(
        &engine,
        "forwarded (miss+insert)",
        many(warm_fwd, RecordType::A),
        many(fwd, RecordType::A),
    )
    .await;
    let _ = engine
        .handle(ingress(query("cache-hot.example.", RecordType::A)), local())
        .await;
    let hot = (0..n).map(|_| "cache-hot.example".to_string());
    scenario(
        &engine,
        "cache hit (fresh)",
        Vec::new(),
        many(hot, RecordType::A),
    )
    .await;
    let pop = (0..n).map(|i| POPULAR[i % POPULAR.len()].to_string());
    let (warm, timed) = warm_then_time(many(pop, RecordType::A));
    scenario(&engine, "popular set (warm cache)", warm, timed).await;
    let nx_warm = (0..64).map(|i| format!("nx-{}.bench.example", i));
    let nx = (0..n).map(|i| format!("nx-{}.bench.example", i % 64));
    scenario(
        &engine,
        "negative cache (NXDOMAIN)",
        many(nx_warm, RecordType::A),
        many(nx, RecordType::A),
    )
    .await;
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
        .handle(ingress(query("nf-hot.example.", RecordType::A)), local())
        .await;
    let nf = (0..n).map(|_| "nf-hot.example".to_string());
    scenario(
        &nofilter,
        "filtering disabled (cache)",
        Vec::new(),
        many(nf, RecordType::A),
    )
    .await;
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
        Vec::new(),
        many(stale, RecordType::A),
    )
    .await;
}

async fn phase2b_finalize(filter: Arc<FilterEngine>, upstream: SocketAddr, n: usize) {
    println!("\n== Phase 2b: finalize() cost on the cache-hit path (obs on vs off) ==");
    let on = build_engine_obs(filter.clone(), upstream, true, true).await;
    let _ = on
        .handle(ingress(query("fin-hot.example.", RecordType::A)), local())
        .await;
    let hot = (0..n).map(|_| "fin-hot.example".to_string());
    scenario(
        &on,
        "cache hit (stats+log on)",
        Vec::new(),
        many(hot, RecordType::A),
    )
    .await;
    let off = build_engine_obs(filter.clone(), upstream, false, false).await;
    let _ = off
        .handle(ingress(query("fin-hot.example.", RecordType::A)), local())
        .await;
    let hot = (0..n).map(|_| "fin-hot.example".to_string());
    scenario(
        &off,
        "cache hit (obs off)",
        Vec::new(),
        many(hot, RecordType::A),
    )
    .await;
    let stats_only = build_engine_obs(filter.clone(), upstream, true, false).await;
    let _ = stats_only
        .handle(ingress(query("fin-hot.example.", RecordType::A)), local())
        .await;
    let hot = (0..n).map(|_| "fin-hot.example".to_string());
    scenario(
        &stats_only,
        "cache hit (stats only)",
        Vec::new(),
        many(hot, RecordType::A),
    )
    .await;

    let log_only = build_engine_obs(filter.clone(), upstream, false, true).await;
    let _ = log_only
        .handle(ingress(query("fin-hot.example.", RecordType::A)), local())
        .await;
    let hot = (0..n).map(|_| "fin-hot.example".to_string());
    scenario(
        &log_only,
        "cache hit (log only)",
        Vec::new(),
        many(hot, RecordType::A),
    )
    .await;
}

fn phase2c_finalize_components() {
    println!("\n== Phase 2c: finalize() component micro-costs (best-of-5) ==");
    let n = 1_000_000usize;
    let name = Name::from_str("cache-hot.example.").unwrap();
    let recs = [
        Record::from_rdata(name.clone(), 300, RData::A(A(Ipv4Addr::new(1, 2, 3, 4)))),
        Record::from_rdata(name.clone(), 300, RData::A(A(Ipv4Addr::new(5, 6, 7, 8)))),
    ];
    let summaries = best_ns_per_op(5, n, |_| {
        let v: Vec<String> = recs
            .iter()
            .map(|r| format!("{} {}", r.record_type(), r.data))
            .collect();
        v.iter().map(|s| s.len()).sum::<usize>()
    });
    println!("  answer summaries (2 recs)   {summaries:>4} ns/op");
    let ip: IpAddr = "192.168.1.50".parse().unwrap();
    let ip_cost = best_ns_per_op(5, n, |_| ip.to_string().len());
    println!("  client_ip.to_string()       {ip_cost:>4} ns/op");
    let now_cost = best_ns_per_op(5, n, |_| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as usize)
            .unwrap_or(0)
    });
    println!("  now_ms() (SystemTime::now)  {now_cost:>4} ns/op");
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

fn phase2d_log_microbench() {
    println!("\n== Phase 2d: query-log build + channel send (best-of-5) ==");
    let n = 200_000usize;
    let name = Name::from_str("cache-hot.example.").unwrap();
    let recs = [Record::from_rdata(
        name.clone(),
        300,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    )];
    let ip: IpAddr = "192.168.1.50".parse().unwrap();
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
    let build = best_ns_per_op(5, n, |_| {
        let e = make_entry();
        e.client_ip.len() + e.question.len() + e.answers.iter().map(|s| s.len()).sum::<usize>()
    });
    let log = QueryLog::new(true, false);
    let (tx, mut rx) = tokio::sync::mpsc::channel(1 << 20);
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

async fn phase2e_e2e(filter: Arc<FilterEngine>, upstream: SocketAddr, n: usize) {
    println!("\n== Phase 2e: end-to-end cache hit incl. wire encode (handle + send-ready) ==");
    let engine = build_engine(filter, upstream, Duration::from_millis(500), 0, 3600, true).await;
    let _ = engine
        .handle(ingress(query("e2e-hot.example.", RecordType::A)), local())
        .await;
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

async fn phase3_concurrency(
    filter: Arc<FilterEngine>,
    blocked: &[String],
    upstream: SocketAddr,
    total: usize,
    concurrency: usize,
) {
    println!("\n== Phase 3: concurrent mixed workload (concurrency={concurrency}) ==");
    let engine = build_engine(filter, upstream, Duration::from_millis(500), 0, 3600, true).await;
    let mut msgs: Vec<Ingress> = Vec::with_capacity(total);
    for i in 0..total {
        let m = match i % 10 {
            0..=2 => query(&blocked[i % blocked.len()], RecordType::A),
            3..=7 => query(POPULAR[i % POPULAR.len()], RecordType::A),
            _ => query(
                &format!("c{i}-{}.bench-fwd.example", rand::random::<u32>()),
                RecordType::A,
            ),
        };
        msgs.push(ingress(m));
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
    let q = ingress(query("single-flight.bench.example", RecordType::A));
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
        answers: std::sync::Arc::from([]),
        elapsed_ms: 1.5,
    }
}

fn phase4_stats_contention(blocked: &[String]) {
    println!("\n== Phase 4: stats.record() scaling, old single-mutex vs new sharded ==");
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let per_thread = 400_000usize;
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

        let new = Arc::new(Stats::new(true, 24, false));
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
    for h in handles {
        let _ = h.join();
    }
    let elapsed = start.elapsed();
    (threads * per_thread) as f64 / elapsed.as_secs_f64()
}

fn warm_cache(n_keys: usize) -> (Arc<DnsCache>, Arc<Vec<QueryKey>>) {
    let cache = Arc::new(DnsCache::new(100_000, 0, 0, 0));
    let mut keys = Vec::with_capacity(n_keys);
    for i in 0..n_keys {
        let name = format!("hot{i}.bench.example.");
        let mut resp = query(&name, RecordType::A);
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.response_code = ResponseCode::NoError;
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
fn parse_ab() {
    use bulwark_engine::wire;

    println!("\n== Ingress parse A/B: Message::from_vec vs wire::parse_query ==");

    let plain = query("cache-hit.example.com.", RecordType::A)
        .to_vec()
        .unwrap();
    let mut m = query("cache-hit.example.com.", RecordType::A);
    let mut e = hickory_proto::op::Edns::new();
    e.set_max_payload(1232);
    e.set_dnssec_ok(true);
    m.set_edns(e);
    let edns = m.to_vec().unwrap();
    let cases = [("no-edns", plain), ("edns+DO", edns)];
    for (label, raw) in &cases {
        let p = wire::parse_query(raw).expect("parse_query");
        let hm = Message::from_vec(raw).unwrap();
        let hq = hm.queries.first().unwrap();
        assert_eq!(p.id, hm.metadata.id);
        assert_eq!(p.qname, hq.name().to_ascii());
        assert_eq!(p.qtype, u16::from(hq.query_type()));
        assert_eq!(p.qclass, u16::from(hq.query_class()));
        assert_eq!(
            p.dnssec_ok,
            hm.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok)
        );
        assert_eq!(p.edns_payload, hm.edns.as_ref().map(|e| e.max_payload()));
        println!("  {label:<8} parser matches hickory");
    }

    for (label, raw) in &cases {
        let fv = best_of_5(|| {
            let m = Message::from_vec(raw).unwrap();
            std::hint::black_box(&m).queries.len()
        });
        let pq = best_of_5(|| {
            let p = wire::parse_query(raw).unwrap();
            std::hint::black_box(&p).qname.len()
        });
        let saved = fv as i128 - pq as i128;
        let pct = (fv as f64 - pq as f64) / fv as f64 * 100.0;
        println!("  {label:<8} from_vec={fv:>4} ns   parse_query={pq:>4} ns   saved={saved:>3} ns ({pct:.0}%)");
    }
}
async fn ingress_ab(n: usize) {
    use bulwark_filter::Compiler;
    println!("\n== Ingress integration A/B: full cache-hit request, Fast vs Full (interleaved) ==");

    let filter = Arc::new(Compiler::new().build().0);
    let (upstream, _count) = mock_upstream(Duration::from_micros(0)).await;
    let engine = build_engine(filter, upstream, Duration::from_millis(500), 0, 3600, true).await;
    let mut q = query("ingress-ab-hot.example.", RecordType::A);
    let mut e = hickory_proto::op::Edns::new();
    e.set_max_payload(1232);
    e.set_dnssec_ok(true);
    q.set_edns(e);
    let raw = q.to_vec().unwrap();
    let _ = engine.handle(Ingress::parse(&raw).unwrap(), local()).await;

    let warm = (n / 10).max(1);
    let mut fast = Vec::with_capacity(n);
    let mut full = Vec::with_capacity(n);
    for i in 0..(n + warm) {
        let t = Instant::now();
        let ing = Ingress::parse(&raw).unwrap();
        let max = ing.udp_max_payload();
        let out = encode_udp_response(engine.handle(ing, local()).await, max);
        let fast_ns = t.elapsed().as_nanos() as u64;
        std::hint::black_box(out.len());
        let t = Instant::now();
        let ing = Ingress::Full(Message::from_vec(&raw).unwrap());
        let max = ing.udp_max_payload();
        let out = encode_udp_response(engine.handle(ing, local()).await, max);
        let full_ns = t.elapsed().as_nanos() as u64;
        std::hint::black_box(out.len());

        if i >= warm {
            fast.push(fast_ns);
            full.push(full_ns);
        }
    }
    let med = |mut v: Vec<u64>| {
        v.sort_unstable();
        v[v.len() / 2]
    };
    let (mf, mu) = (med(fast.clone()), med(full.clone()));
    report("cache hit: Fast (Ingress::parse)", fast);
    report("cache hit: Full (Message::from_vec)", full);
    println!(
        "  => p50 saved = {} ns/req ({:.0}%)",
        mu as i64 - mf as i64,
        (mu as f64 - mf as f64) / mu as f64 * 100.0
    );
}
fn encode_udp_response(resp: EngineResponse, max: usize) -> Vec<u8> {
    match resp {
        EngineResponse::Wire(b) if b.len() <= max => b,
        other => other.into_message().to_vec().unwrap_or_default(),
    }
}
async fn full_request_scenario(engine: &Arc<Engine>, label: &str, pool: Vec<Vec<u8>>) {
    let peer = local();
    let mut ns = Vec::with_capacity(pool.len());
    for raw in &pool {
        let t = Instant::now();
        let ing = Ingress::parse(raw).unwrap();
        let max = ing.udp_max_payload();
        let resp = engine.handle(ing, peer).await;
        let out = encode_udp_response(resp, max);
        ns.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(out.len());
    }
    report(label, ns);
}

async fn phase6_full_request(
    filter: Arc<FilterEngine>,
    blocked: &[String],
    upstream: SocketAddr,
    n: usize,
) {
    println!("\n== Phase 6: full per-request CPU — parse + handle + encode (no socket) ==");
    let engine = build_engine(filter, upstream, Duration::from_millis(500), 0, 3600, true).await;
    let raw = |name: &str| query(name, RecordType::A).to_vec().unwrap();
    let _ = engine
        .handle(ingress(query("req-hot.example.", RecordType::A)), local())
        .await;
    let hit_pool = std::iter::repeat_with(|| raw("req-hot.example."))
        .take(n)
        .collect();
    full_request_scenario(&engine, "cache hit (parse+handle+enc)", hit_pool).await;
    let blk_pool = blocked.iter().cycle().take(n).map(|d| raw(d)).collect();
    full_request_scenario(&engine, "blocked (parse+handle+enc)", blk_pool).await;
    let fwd_pool = (0..n)
        .map(|i| raw(&format!("r{i}-{}.bench-req.example", rand::random::<u32>())))
        .collect();
    full_request_scenario(&engine, "forwarded (parse+handle+enc)", fwd_pool).await;
    let blk_msgs = blocked
        .iter()
        .cycle()
        .take(n)
        .map(|d| ingress(query(d, RecordType::A)))
        .collect();
    handle_only(&engine, "blocked (handle only)", blk_msgs).await;
    let hit_msgs = std::iter::repeat_with(|| ingress(query("req-hot.example.", RecordType::A)))
        .take(n)
        .collect();
    handle_only(&engine, "cache hit (handle only)", hit_msgs).await;
    println!("\n  -- blocked-path decomposition (best-of-5 ns/op) --");
    let blk_bytes = raw(&blocked[0]);
    let parse_ns = best_of_5(|| {
        let m = Message::from_vec(&blk_bytes).unwrap();
        std::hint::black_box(m.queries.len())
    });
    println!(
        "  {:<32} {parse_ns:>6} ns/op",
        "Message::from_vec (request)"
    );
    let blk_resp = engine
        .handle(Ingress::parse(&blk_bytes).unwrap(), local())
        .await
        .into_message();
    let blk_enc_ns = best_of_5(|| blk_resp.to_vec().unwrap().len());
    println!(
        "  {:<32} {blk_enc_ns:>6} ns/op",
        "blocked resp to_vec (SOA)"
    );
    let a_resp = engine
        .handle(ingress(query("req-hot.example.", RecordType::A)), local())
        .await
        .into_message();
    let a_enc_ns = best_of_5(|| a_resp.to_vec().unwrap().len());
    println!("  {:<32} {a_enc_ns:>6} ns/op", "A resp to_vec (contrast)");
    let soa_name_ns = best_of_5(|| {
        let n = Name::from_str("fake-for-negative-caching.bulwark.invalid.").unwrap();
        n.num_labels() as usize
    });
    println!(
        "  {:<32} {soa_name_ns:>6} ns/op  (x2 per block, constant)",
        "Name::from_str (SOA mname)"
    );
}
async fn handle_only(engine: &Arc<Engine>, label: &str, msgs: Vec<Ingress>) {
    let peer = local();
    let mut ns = Vec::with_capacity(msgs.len());
    for ing in msgs {
        let t = Instant::now();
        let resp = engine.handle(ing, peer).await;
        ns.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(matches!(resp, EngineResponse::Wire(_)));
    }
    report(label, ns);
}
fn best_of_5(mut f: impl FnMut() -> usize) -> u128 {
    let iters = 100_000u128;
    let mut best = u128::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        let mut sink = 0usize;
        for _ in 0..iters {
            sink = sink.wrapping_add(f());
        }
        std::hint::black_box(sink);
        best = best.min(t.elapsed().as_nanos() / iters);
    }
    best
}
async fn profile_only(
    filter: Arc<FilterEngine>,
    blocked: &[String],
    upstream: SocketAddr,
    scenario: &str,
) {
    let engine = build_engine(filter, upstream, Duration::from_millis(500), 0, 3600, true).await;
    let raw = |name: &str| query(name, RecordType::A).to_vec().unwrap();
    let iters = env_usize("BENCH_N", 1_500_000);
    let peer = local();
    let _ = engine
        .handle(ingress(query("req-hot.example.", RecordType::A)), peer)
        .await;
    let pool_len = iters.min(100_000);
    let pool: Vec<Vec<u8>> = match scenario {
        "cachehit" => vec![raw("req-hot.example.")],
        "blocked" => (0..pool_len)
            .map(|i| raw(&blocked[i % blocked.len()]))
            .collect(),
        "forwarded" => (0..pool_len)
            .map(|i| raw(&format!("p{i}.bench-prof.example")))
            .collect(),
        other => {
            eprintln!("unknown BENCH_PROFILE='{other}' (use cachehit|blocked|forwarded)");
            return;
        }
    };
    eprintln!("profiling '{scenario}' x{iters} (no socket I/O) ...");
    let t = Instant::now();
    let (mut parse_ns, mut handle_ns, mut enc_ns) = (0u128, 0u128, 0u128);
    let mut sink = 0usize;
    for i in 0..iters {
        let bytes = &pool[i % pool.len()];
        let a = Instant::now();
        let ing = Ingress::parse(bytes).unwrap();
        let max = ing.udp_max_payload();
        let b = Instant::now();
        let resp = engine.handle(ing, peer).await;
        let c = Instant::now();
        let out = encode_udp_response(resp, max);
        let d = Instant::now();
        parse_ns += b.duration_since(a).as_nanos();
        handle_ns += c.duration_since(b).as_nanos();
        enc_ns += d.duration_since(c).as_nanos();
        sink = sink.wrapping_add(out.len());
    }
    let per = |x: u128| x / iters as u128;
    eprintln!(
        "done '{scenario}': {:?} total, {:.0} ns/req, sink={sink}",
        t.elapsed(),
        t.elapsed().as_nanos() as f64 / iters as f64
    );
    eprintln!(
        "  split: parse={} ns  handle={} ns  encode={} ns",
        per(parse_ns),
        per(handle_ns),
        per(enc_ns)
    );
}
fn spawn_listener_baseline(engine: Arc<Engine>, socket: UdpSocket) -> tokio::task::JoinHandle<()> {
    let socket = Arc::new(socket);
    let inflight = Arc::new(tokio::sync::Semaphore::new(1024));
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(ing) = Ingress::parse(&buf[..n]) else {
                continue;
            };
            let Ok(permit) = inflight.clone().acquire_owned().await else {
                return;
            };
            let engine = engine.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let max = ing.udp_max_payload();
                let resp = engine.handle(ing, peer.ip()).await;
                let bytes = encode_udp_response(resp, max);
                if !bytes.is_empty() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            });
        }
    })
}
fn spawn_listener_fastpath(engine: Arc<Engine>, socket: UdpSocket) -> tokio::task::JoinHandle<()> {
    let loops = env_usize("FAST_LOOPS", 1);
    let socket = Arc::new(socket);
    let inflight = Arc::new(tokio::sync::Semaphore::new(1024));
    for _ in 1..loops {
        fastpath_loop(engine.clone(), socket.clone(), inflight.clone());
    }
    fastpath_loop(engine, socket, inflight)
}

fn fastpath_loop(
    engine: Arc<Engine>,
    socket: Arc<UdpSocket>,
    inflight: Arc<tokio::sync::Semaphore>,
) -> tokio::task::JoinHandle<()> {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let waker = Waker::noop();
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(ing) = Ingress::parse(&buf[..n]) else {
                continue;
            };
            let max = ing.udp_max_payload();
            let eng = engine.clone();
            let mut fut: Pin<Box<dyn Future<Output = EngineResponse> + Send>> =
                Box::pin(async move { eng.handle(ing, peer.ip()).await });
            let polled = {
                let mut cx = Context::from_waker(waker);
                fut.as_mut().poll(&mut cx)
            };
            match polled {
                Poll::Ready(resp) => {
                    let bytes = encode_udp_response(resp, max);
                    if !bytes.is_empty() {
                        let _ = socket.send_to(&bytes, peer).await;
                    }
                }
                Poll::Pending => {
                    let Ok(permit) = inflight.clone().acquire_owned().await else {
                        return;
                    };
                    let socket = socket.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let resp = fut.await;
                        let bytes = encode_udp_response(resp, max);
                        if !bytes.is_empty() {
                            let _ = socket.send_to(&bytes, peer).await;
                        }
                    });
                }
            }
        }
    })
}
async fn udp_fast_ab(
    filter: Arc<FilterEngine>,
    upstream: SocketAddr,
    n: usize,
    concurrency: usize,
) {
    let engine = build_engine(filter, upstream, Duration::from_millis(500), 0, 3600, true).await;
    let peer = local();
    let hot = "req-hot.example.";
    let _ = engine
        .handle(ingress(query(hot, RecordType::A)), peer)
        .await;
    let qbytes = query(hot, RecordType::A).to_vec().unwrap();

    let base_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let base_addr = base_sock.local_addr().unwrap();
    let _base = spawn_listener_baseline(engine.clone(), base_sock);
    let fast_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fast_addr = fast_sock.local_addr().unwrap();
    let _fast = spawn_listener_fastpath(engine.clone(), fast_sock);

    println!("\n== UDP fast-path A/B (loopback, warm cache hit) ==");
    println!("  baseline={base_addr}  fastpath={fast_addr}  workload='{hot}'");
    let base_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    base_client.connect(base_addr).await.unwrap();
    let fast_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    fast_client.connect(fast_addr).await.unwrap();
    let mut rbuf = vec![0u8; 4096];
    for _ in 0..2000 {
        base_client.send(&qbytes).await.unwrap();
        base_client.recv(&mut rbuf).await.unwrap();
        fast_client.send(&qbytes).await.unwrap();
        fast_client.recv(&mut rbuf).await.unwrap();
    }
    let mut base_ns = Vec::with_capacity(n);
    let mut fast_ns = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        base_client.send(&qbytes).await.unwrap();
        base_client.recv(&mut rbuf).await.unwrap();
        base_ns.push(t.elapsed().as_nanos() as u64);

        let t = Instant::now();
        fast_client.send(&qbytes).await.unwrap();
        fast_client.recv(&mut rbuf).await.unwrap();
        fast_ns.push(t.elapsed().as_nanos() as u64);
    }
    report("baseline (spawn)  RTT", base_ns);
    report("fastpath (inline) RTT", fast_ns);
    let tput_total = n.max(200_000);
    for (label, addr) in [("baseline", base_addr), ("fastpath", fast_addr)] {
        let per_client = (tput_total / concurrency).max(1);
        let t = Instant::now();
        let mut tasks = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let qb = qbytes.clone();
            tasks.push(tokio::spawn(async move {
                let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                client.connect(addr).await.unwrap();
                let mut rbuf = vec![0u8; 4096];
                for _ in 0..per_client {
                    if client.send(&qb).await.is_err() {
                        break;
                    }
                    let _ = client.recv(&mut rbuf).await;
                }
            }));
        }
        for h in tasks {
            let _ = h.await;
        }
        let elapsed = t.elapsed();
        let total = (per_client * concurrency) as f64;
        println!(
            "  {label:<9} throughput @ {concurrency} clients: {:>10.0} q/s",
            total / elapsed.as_secs_f64()
        );
    }
}
async fn udp_e2e(filter: Arc<FilterEngine>, upstream: SocketAddr, n: usize, concurrency: usize) {
    let engine = build_engine(filter, upstream, Duration::from_millis(500), 0, 3600, true).await;
    let peer = local();
    let hot = "req-hot.example.";
    let _ = engine
        .handle(ingress(query(hot, RecordType::A)), peer)
        .await;
    let qbytes = query(hot, RecordType::A).to_vec().unwrap();

    let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_sock.local_addr().unwrap();
    let _listener = spawn_listener_baseline(engine.clone(), server_sock);

    println!("\n== UDP end-to-end (loopback, warm cache hit) ==");
    println!("  listener at {server_addr}  workload='{hot}' (fresh allowed hit)");
    {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();
        let mut rbuf = vec![0u8; 4096];
        for _ in 0..2000 {
            client.send(&qbytes).await.unwrap();
            let _ = client.recv(&mut rbuf).await.unwrap();
        }
        let mut ns = Vec::with_capacity(n);
        for _ in 0..n {
            let t = Instant::now();
            client.send(&qbytes).await.unwrap();
            let _ = client.recv(&mut rbuf).await.unwrap();
            ns.push(t.elapsed().as_nanos() as u64);
        }
        report("udp closed-loop RTT", ns);
    }
    let tput_total = n.max(200_000);
    let per_client = (tput_total / concurrency).max(1);
    let t = Instant::now();
    let mut tasks = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let qb = qbytes.clone();
        let addr = server_addr;
        tasks.push(tokio::spawn(async move {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.connect(addr).await.unwrap();
            let mut rbuf = vec![0u8; 4096];
            for _ in 0..per_client {
                if client.send(&qb).await.is_err() {
                    break;
                }
                let _ = client.recv(&mut rbuf).await;
            }
        }));
    }
    for h in tasks {
        let _ = h.await;
    }
    let elapsed = t.elapsed();
    let total = (per_client * concurrency) as f64;
    println!(
        "  udp throughput @ {concurrency} clients: {:>10.0} q/s  ({total:.0} queries in {elapsed:?})",
        total / elapsed.as_secs_f64()
    );
}

#[tokio::main]
async fn main() {
    let n = env_usize("BENCH_N", 20_000);
    let concurrency = env_usize("BENCH_CONCURRENCY", 64);
    let delay = Duration::from_micros(env_usize("BENCH_UPSTREAM_DELAY_US", 0) as u64);

    println!("== Bulwark per-request benchmark ==");
    println!("  iterations/scenario={n}  concurrency={concurrency}  upstream_delay={delay:?}");
    if std::env::var("BENCH_PROFILE").as_deref() == Ok("parse") {
        parse_ab();
        return;
    }
    if std::env::var("BENCH_PROFILE").as_deref() == Ok("ingress_ab") {
        ingress_ab(n).await;
        return;
    }

    println!("\n== Loading filter lists ==");
    let (filter, blocked) = build_filter().await;
    let filter = Arc::new(filter);
    println!("  sampled {} real blockable domains", blocked.len());

    let (upstream, _count) = mock_upstream(delay).await;
    if std::env::var("BENCH_PROFILE").as_deref() == Ok("udp_e2e") {
        udp_e2e(filter, upstream, n, concurrency).await;
        return;
    }
    if std::env::var("BENCH_PROFILE").as_deref() == Ok("udp_fast_ab") {
        udp_fast_ab(filter, upstream, n, concurrency).await;
        return;
    }
    if let Ok(scenario) = std::env::var("BENCH_PROFILE") {
        profile_only(filter, &blocked, upstream, &scenario).await;
        return;
    }

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
    phase6_full_request(filter.clone(), &blocked, upstream, n).await;

    println!("\n== done ==");
}
