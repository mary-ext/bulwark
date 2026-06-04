//! Per-transport benchmark + profiler for the upstream layer.
//!
//! `bench_chain` only ever talks to an in-process **UDP** mock, so the encrypted
//! transports (DoT, DoH, DoQ) are never exercised in a controlled benchmark. This
//! example stands up an in-process mock upstream for **every** transport bulwark
//! speaks — plain UDP/TCP, DoT, DoH over HTTP/1.1+HTTP/2, DoH forced over HTTP/3,
//! and DoQ — and drives bulwark's *real* client code against each one.
//!
//! To do that against a local mock (which can only present a self-signed cert) we
//! generate a private CA, register it via `bulwark_upstream::add_trust_root` (the
//! additive, feature-gated `test-trust-roots` hook), and give every mock a leaf
//! cert with an IP SAN for `127.0.0.1`. Certificate verification still runs in
//! full — it just chains to our private CA instead of the public web PKI.
//!
//! For each transport we measure:
//!   * handshake / cold-start cost (first query, incl. TLS/QUIC handshake)
//!   * warm steady-state per-query latency (pool level, unique names)
//!   * concurrent throughput (q/s + percentiles) — exposes the serialized-DoT vs
//!     multiplexed-DoQ/h2/h3 contrast
//!   * whole-chain latency through the full engine with the **real** AdGuard SDNS
//!     + OISD Big filter lists compiled and the cache enabled (forwarded miss)
//!
//! Run with:
//!   cargo run --release --example bench_transports -p bulwark
//!
//! Knobs (env):
//!   BENCH_N                 queries per measurement          (default 5000)
//!   BENCH_UPSTREAM_DELAY_US simulated upstream RTT, µs       (default 0)
//!   BENCH_CONCURRENCY       concurrent in-flight queries     (default 64)
//!   BENCH_TRANSPORTS        comma list to restrict, e.g. "dot,doq"
//!   BENCH_DATA_DIR          where to cache the filter lists

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bulwark_config::BlockingMode;
use bulwark_engine::cache::DnsCache;
use bulwark_engine::clients::ClientMatcher;
use bulwark_engine::querylog::QueryLog;
use bulwark_engine::stats::Stats;
use bulwark_engine::{Engine, EngineState};
use bulwark_filter::{Compiler, FilterEngine};
use bulwark_upstream::{PoolEntry, PoolSettings, UpstreamPool};
use bytes::{Buf, Bytes};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Shared mock answer + DNS helpers.
// ---------------------------------------------------------------------------

/// Build the mock's reply to a query: `nx-*` names get NXDOMAIN (exercises the
/// negative path); everything else gets `A 1.2.3.4`.
fn answer(query: &Message) -> Message {
    let mut resp = query.clone();
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.recursion_available = true;
    if let Some(q) = query.queries.first() {
        if q.name().to_ascii().starts_with("nx-") {
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
    resp
}

/// Decode a wire query, build the answer, re-encode it, applying the RTT delay.
async fn respond(bytes: &[u8], delay: Duration) -> Option<Vec<u8>> {
    let query = Message::from_vec(bytes).ok()?;
    let resp = answer(&query);
    let out = resp.to_vec().ok()?;
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    Some(out)
}

/// Read one 2-byte-length-prefixed DNS message (TCP/DoT/DoQ framing).
async fn read_prefixed<R: AsyncReadExt + Unpin>(r: &mut R) -> Option<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await.ok()?;
    let n = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

/// Write one 2-byte-length-prefixed DNS message. Sends length+body as a single
/// buffer and flushes, which matters over TLS (tokio-rustls buffers writes until
/// flushed, and split small writes otherwise stall on Nagle + delayed-ACK).
async fn write_prefixed<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    let mut framed = Vec::with_capacity(msg.len() + 2);
    framed.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    framed.extend_from_slice(msg);
    w.write_all(&framed).await?;
    w.flush().await
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
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

// ---------------------------------------------------------------------------
// Certificate generation (private CA + leaf with IP SAN 127.0.0.1).
// ---------------------------------------------------------------------------

struct Certs {
    ca_der: CertificateDer<'static>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn generate_certs() -> Certs {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    // CA.
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Bulwark Bench CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Leaf: SANs auto-detected as IP addresses by rcgen's `new`.
    let mut leaf_params =
        CertificateParams::new(vec!["127.0.0.1".to_string(), "::1".to_string()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "bulwark-mock-upstream");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    Certs {
        ca_der: ca_cert.der().clone(),
        chain: vec![leaf_cert.der().clone()],
        key: PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
    }
}

/// A rustls server config presenting our leaf cert, with the given ALPN tokens.
/// `tls13_only` is required for the QUIC-based servers (DoQ, HTTP/3).
fn server_tls(certs: &Certs, alpn: &[&[u8]], tls13_only: bool) -> rustls::ServerConfig {
    let builder = if tls13_only {
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        rustls::ServerConfig::builder()
    };
    let mut cfg = builder
        .with_no_client_auth()
        .with_single_cert(certs.chain.clone(), certs.key.clone_key())
        .expect("server cert");
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    cfg
}

// ---------------------------------------------------------------------------
// Mock upstream servers (one per transport). Each binds 127.0.0.1:0 and returns
// the spec string bulwark should use to reach it.
// ---------------------------------------------------------------------------

async fn mock_udp(delay: Duration) -> String {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            // Handle each datagram in its own task so an upstream-RTT delay does
            // not serialize the recv loop (bulwark sends UDP queries concurrently).
            let data = buf[..n].to_vec();
            let sock = sock.clone();
            tokio::spawn(async move {
                if let Some(out) = respond(&data, delay).await {
                    let _ = sock.send_to(&out, peer).await;
                }
            });
        }
    });
    format!("udp://{addr}")
}

async fn mock_tcp(delay: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            stream.set_nodelay(true).ok();
            tokio::spawn(async move {
                while let Some(msg) = read_prefixed(&mut stream).await {
                    if let Some(out) = respond(&msg, delay).await {
                        if write_prefixed(&mut stream, &out).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
    format!("tcp://{addr}")
}

async fn mock_dot(delay: Duration, certs: &Certs) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls(certs, &[], false)));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tcp.set_nodelay(true).ok();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                while let Some(msg) = read_prefixed(&mut tls).await {
                    if let Some(out) = respond(&msg, delay).await {
                        if write_prefixed(&mut tls, &out).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
    format!("tls://127.0.0.1:{}", addr.port())
}

/// quinn server endpoint with the given ALPN (shared by DoQ and HTTP/3).
fn quic_endpoint(certs: &Certs, alpn: &[&[u8]]) -> (quinn::Endpoint, u16) {
    let tls = server_tls(certs, alpn, true);
    let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("quic server config");
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(qsc));
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
        .expect("quic listen");
    let port = endpoint.local_addr().unwrap().port();
    (endpoint, port)
}

async fn mock_doq(delay: Duration, certs: &Certs) -> String {
    let (endpoint, port) = quic_endpoint(certs, &[b"doq"]);
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                // Each DoQ query is its own bidi stream (RFC 9250).
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    tokio::spawn(async move {
                        let Ok(data) = recv.read_to_end(64 * 1024).await else {
                            return;
                        };
                        if data.len() < 2 {
                            return;
                        }
                        if let Some(out) = respond(&data[2..], delay).await {
                            let _ = send.write_all(&(out.len() as u16).to_be_bytes()).await;
                            let _ = send.write_all(&out).await;
                            let _ = send.finish();
                            // Keep the stream alive until the peer has read.
                            let _ = send.stopped().await;
                        }
                    });
                }
            });
        }
    });
    format!("quic://127.0.0.1:{port}")
}

async fn mock_doh_h12(delay: Duration, certs: &Certs) -> String {
    use http_body_util::BodyExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor =
        tokio_rustls::TlsAcceptor::from(Arc::new(server_tls(certs, &[b"h2", b"http/1.1"], false)));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tcp.set_nodelay(true).ok();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    move |req: http::Request<hyper::body::Incoming>| async move {
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|b| b.to_bytes())
                            .unwrap_or_default();
                        let reply = respond(&body, delay).await.unwrap_or_default();
                        http::Response::builder()
                            .status(200)
                            .header(http::header::CONTENT_TYPE, "application/dns-message")
                            .body(http_body_util::Full::new(Bytes::from(reply)))
                    },
                );
                let io = hyper_util::rt::TokioIo::new(tls);
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, service)
                .await;
            });
        }
    });
    format!("https://127.0.0.1:{}/dns-query", addr.port())
}

async fn mock_doh_h3(delay: Duration, certs: &Certs) -> String {
    let (endpoint, port) = quic_endpoint(certs, &[b"h3"]);
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let Ok(mut h3) =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3.accept().await {
                    tokio::spawn(async move {
                        let Ok((_req, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let mut body = Vec::new();
                        while let Ok(Some(mut chunk)) = stream.recv_data().await {
                            while chunk.has_remaining() {
                                let c = chunk.chunk();
                                body.extend_from_slice(c);
                                let n = c.len();
                                chunk.advance(n);
                            }
                        }
                        let reply = respond(&body, delay).await.unwrap_or_default();
                        let resp = http::Response::builder()
                            .status(200)
                            .header(http::header::CONTENT_TYPE, "application/dns-message")
                            .body(())
                            .unwrap();
                        if stream.send_response(resp).await.is_ok() {
                            let _ = stream.send_data(Bytes::from(reply)).await;
                            let _ = stream.finish().await;
                        }
                    });
                }
            });
        }
    });
    format!("h3://127.0.0.1:{port}/dns-query")
}

// ---------------------------------------------------------------------------
// Filter list loading (download-once + cache; shares bench_chain's directory).
// ---------------------------------------------------------------------------

const ADGUARD_URL: &str = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt";
const OISD_URL: &str = "https://big.oisd.nl/";

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

async fn build_filter() -> FilterEngine {
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
    engine
}

// ---------------------------------------------------------------------------
// Measurement helpers.
// ---------------------------------------------------------------------------

fn report(label: &str, mut ns: Vec<u64>) {
    if ns.is_empty() {
        println!("    {label:<26} (no samples)");
        return;
    }
    ns.sort_unstable();
    let n = ns.len();
    let sum: u128 = ns.iter().map(|&x| x as u128).sum();
    let mean = sum as f64 / n as f64;
    let pct = |q: f64| ns[(((n as f64) * q) as usize).min(n - 1)];
    println!(
        "    {label:<26} mean={:>8.1}µs  p50={:>8.1}  p90={:>8.1}  p99={:>8.1}  max={:>8.1}µs",
        mean / 1000.0,
        pct(0.50) as f64 / 1000.0,
        pct(0.90) as f64 / 1000.0,
        pct(0.99) as f64 / 1000.0,
        ns[n - 1] as f64 / 1000.0,
    );
}

async fn build_pool(spec: &str) -> Arc<UpstreamPool> {
    Arc::new(
        UpstreamPool::build(
            &[PoolEntry {
                spec: spec.to_string(),
                name: Some("mock".into()),
            }],
            PoolSettings {
                query_timeout: Duration::from_secs(5),
                bootstrap: vec![],
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("build pool for {spec}: {e}")),
    )
}

/// Pool-level (transport-only) measurement: handshake, warm latency, throughput.
async fn measure_transport(name: &str, spec: &str, n: usize, concurrency: usize) {
    println!("\n-- {name}  ({spec}) --");
    let pool = build_pool(spec).await;

    // Cold: first query pays the TLS/QUIC handshake + connect.
    let t = Instant::now();
    match pool
        .resolve(&query("cold-start.bench.example", RecordType::A))
        .await
    {
        Ok(_) => println!(
            "    {:<26} {:>8.1}µs",
            "handshake (first query)",
            t.elapsed().as_nanos() as f64 / 1000.0
        ),
        Err(e) => {
            println!("    FAILED: {e}");
            return;
        }
    }

    // Warm: sequential unique names defeat single-flight + any caching, so every
    // query is a real round-trip on the established connection.
    let mut ns = Vec::with_capacity(n);
    for i in 0..n {
        let q = query(
            &format!("w{i}-{}.warm.bench.example", rand::random::<u32>()),
            RecordType::A,
        );
        let t = Instant::now();
        if pool.resolve(&q).await.is_ok() {
            ns.push(t.elapsed().as_nanos() as u64);
        }
    }
    report("warm (sequential)", ns);

    // Concurrent: fire unique queries from `concurrency` workers. DoT serializes
    // over one connection; DoQ/h2/h3 multiplex, so this is where they diverge.
    let idx = Arc::new(AtomicUsize::new(0));
    let lat = Arc::new(parking_lot::Mutex::new(Vec::<u64>::with_capacity(n)));
    let t0 = Instant::now();
    let mut workers = Vec::new();
    for _ in 0..concurrency {
        let pool = pool.clone();
        let idx = idx.clone();
        let lat = lat.clone();
        workers.push(tokio::spawn(async move {
            let mut local_lat = Vec::new();
            loop {
                let i = idx.fetch_add(1, Ordering::Relaxed);
                if i >= n {
                    break;
                }
                let q = query(
                    &format!("c{i}-{}.conc.bench.example", rand::random::<u32>()),
                    RecordType::A,
                );
                let t = Instant::now();
                if pool.resolve(&q).await.is_ok() {
                    local_lat.push(t.elapsed().as_nanos() as u64);
                }
            }
            lat.lock().extend(local_lat);
        }));
    }
    for w in workers {
        let _ = w.await;
    }
    let elapsed = t0.elapsed();
    let lat = Arc::try_unwrap(lat).unwrap().into_inner();
    let qps = lat.len() as f64 / elapsed.as_secs_f64();
    println!(
        "    {:<26} {:>8.0} q/s  (concurrency={concurrency})",
        "throughput", qps
    );
    report("concurrent latency", lat);
}

/// Whole-chain measurement: full engine pipeline (filter + cache + upstream) with
/// the real lists compiled. Forwarded-miss workload, so the transport is on the
/// hot path for every query.
async fn whole_chain(name: &str, spec: &str, filter: Arc<FilterEngine>, n: usize) {
    let pool = build_pool(spec).await;
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
        Arc::new(DnsCache::new(100_000, 0, 3600, 0)),
        Arc::new(QueryLog::new(true, false)),
        Arc::new(Stats::new(true, 24, false)),
    );

    // Warmup.
    for _ in 0..(n / 10).max(1) {
        let _ = engine
            .handle(
                query(
                    &format!("warm-{}.chain.example", rand::random::<u32>()),
                    RecordType::A,
                ),
                local(),
            )
            .await;
    }
    let mut ns = Vec::with_capacity(n);
    for i in 0..n {
        let q = query(
            &format!("u{i}-{}.chain.example", rand::random::<u32>()),
            RecordType::A,
        );
        let t = Instant::now();
        let _ = engine.handle(q, local()).await;
        ns.push(t.elapsed().as_nanos() as u64);
    }
    report(&format!("whole-chain [{name}]"), ns);
}

// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let n = env_usize("BENCH_N", 5_000);
    let concurrency = env_usize("BENCH_CONCURRENCY", 64);
    let delay = Duration::from_micros(env_usize("BENCH_UPSTREAM_DELAY_US", 0) as u64);
    let only: Option<Vec<String>> = std::env::var("BENCH_TRANSPORTS")
        .ok()
        .map(|s| s.split(',').map(|t| t.trim().to_lowercase()).collect());
    let want = |name: &str| only.as_ref().is_none_or(|v| v.iter().any(|t| t == name));

    // Optional tracing (set RUST_LOG, e.g. RUST_LOG=quinn=debug,h3=debug).
    if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    }

    // Install the ring crypto provider for the mock servers' rustls configs.
    let _ = rustls::crypto::ring::default_provider().install_default();

    println!("== Bulwark per-transport benchmark ==");
    println!("  queries/measurement={n}  concurrency={concurrency}  upstream_delay={delay:?}");

    // Private CA -> trust it in bulwark's real client code -> leaf for the mocks.
    let certs = generate_certs();
    bulwark_upstream::add_trust_root(certs.ca_der.clone());

    println!("\n== Loading filter lists ==");
    let filter = Arc::new(build_filter().await);

    // (display name, spec) for each transport, built from its mock's address.
    let mut transports: Vec<(&str, String)> = Vec::new();
    if want("udp") {
        transports.push(("udp ", mock_udp(delay).await));
    }
    if want("tcp") {
        transports.push(("tcp ", mock_tcp(delay).await));
    }
    if want("dot") {
        transports.push(("dot ", mock_dot(delay, &certs).await));
    }
    if want("doh") {
        transports.push(("doh-h2", mock_doh_h12(delay, &certs).await));
    }
    if want("doh3") {
        transports.push(("doh-h3", mock_doh_h3(delay, &certs).await));
    }
    if want("doq") {
        transports.push(("doq ", mock_doq(delay, &certs).await));
    }

    println!("\n== Per-transport: handshake / warm / throughput ==");
    for (name, spec) in &transports {
        measure_transport(name, spec, n, concurrency).await;
    }

    println!("\n== Whole-chain through the engine (filter + cache + upstream) ==");
    for (name, spec) in &transports {
        whole_chain(name, spec, filter.clone(), n).await;
    }

    println!("\n== done ==");
}
