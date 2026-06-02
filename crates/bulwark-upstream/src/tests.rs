//! Integration tests against an in-process mock UDP DNS server. No real network
//! access is required.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

use crate::pool::{PoolEntry, PoolSettings, UpstreamPool};
use crate::spec::UpstreamSpec;
use crate::transport::{decode, encode};

/// A controllable mock DNS server.
struct Mock {
    addr: SocketAddr,
    received: Arc<AtomicU64>,
}

/// Behaviour of the mock for each request.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Answer with the given A record after an optional delay (ms).
    Answer(Ipv4Addr, u64),
    /// Receive but never respond (forces the client to time out).
    Drop,
}

async fn spawn_mock(behaviour: Behaviour) -> Mock {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let received = Arc::new(AtomicU64::new(0));
    let counter = received.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let query = decode(&buf[..n]).unwrap();
            match behaviour {
                Behaviour::Drop => continue,
                Behaviour::Answer(ip, delay) => {
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    let mut resp = query.clone();
                    resp.metadata.message_type = MessageType::Response;
                    resp.metadata.response_code = ResponseCode::NoError;
                    resp.metadata.recursion_available = true;
                    if let Some(q) = query.queries.first() {
                        let rec = Record::from_rdata(q.name().clone(), 60, RData::A(A(ip)));
                        resp.answers.push(rec);
                    }
                    let bytes = encode(&resp).unwrap();
                    let _ = sock.send_to(&bytes, peer).await;
                }
            }
        }
    });
    Mock { addr, received }
}

fn make_query(name: &str) -> Message {
    let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut q = Query::query(Name::from_str(name).unwrap(), RecordType::A);
    q.set_query_class(DNSClass::IN);
    msg.queries.push(q);
    msg
}

fn settings() -> PoolSettings {
    PoolSettings {
        query_timeout: Duration::from_millis(400),
        ewma_alpha: 0.5,
        failure_threshold: 1,
        bootstrap: vec!["127.0.0.1:1".parse().unwrap()],
    }
}

fn entry(addr: SocketAddr) -> PoolEntry {
    PoolEntry {
        spec: format!("udp://{addr}"),
        name: None,
    }
}

#[tokio::test]
async fn resolves_via_udp_and_restores_id() {
    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(1, 2, 3, 4), 0)).await;
    let pool = UpstreamPool::build(&[entry(mock.addr)], settings())
        .await
        .unwrap();

    let resp = pool.resolve(&make_query("example.com.")).await.unwrap();
    assert_eq!(resp.metadata.id, 0x4242);
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(mock.received.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn single_flight_coalesces_identical_queries() {
    // Slow answer so concurrent callers all join the in-flight request.
    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(9, 9, 9, 9), 150)).await;
    let pool = Arc::new(
        UpstreamPool::build(&[entry(mock.addr)], settings())
            .await
            .unwrap(),
    );

    let mut handles = Vec::new();
    for _ in 0..16 {
        let p = pool.clone();
        handles.push(tokio::spawn(async move {
            p.resolve(&make_query("dedup.test.")).await.is_ok()
        }));
    }
    for h in handles {
        assert!(h.await.unwrap());
    }
    // Despite 16 concurrent callers, only ONE request hit the upstream.
    assert_eq!(mock.received.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sequential_failover_to_healthy_upstream() {
    let dead = spawn_mock(Behaviour::Drop).await;
    let good = spawn_mock(Behaviour::Answer(Ipv4Addr::new(5, 5, 5, 5), 0)).await;
    // Dead listed first; the pool must fail over to the good one.
    let pool = UpstreamPool::build(&[entry(dead.addr), entry(good.addr)], settings())
        .await
        .unwrap();

    let resp = pool.resolve(&make_query("failover.test.")).await.unwrap();
    assert_eq!(resp.answers.len(), 1);
    assert!(good.received.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn prefers_fastest_upstream_after_probing() {
    let slow = spawn_mock(Behaviour::Answer(Ipv4Addr::new(1, 1, 1, 1), 120)).await;
    let fast = spawn_mock(Behaviour::Answer(Ipv4Addr::new(2, 2, 2, 2), 0)).await;
    // Slow is listed first, but probing should make the pool prefer the fast one.
    let pool = UpstreamPool::build(&[entry(slow.addr), entry(fast.addr)], settings())
        .await
        .unwrap();

    pool.probe_all().await;
    let baseline_slow = slow.received.load(Ordering::SeqCst);
    let baseline_fast = fast.received.load(Ordering::SeqCst);

    for _ in 0..3 {
        pool.resolve(&make_query("speed.test.")).await.unwrap();
    }

    // The fast upstream should have taken the real queries.
    assert_eq!(slow.received.load(Ordering::SeqCst), baseline_slow);
    assert_eq!(fast.received.load(Ordering::SeqCst), baseline_fast + 3);

    let stats = pool.stats();
    let fast_stat = stats
        .iter()
        .find(|s| s.spec.contains(&fast.addr.to_string()))
        .unwrap();
    assert!(fast_stat.avg_rtt_ms.unwrap() < 50.0);
}

#[tokio::test]
async fn all_upstreams_down_errors() {
    let dead = spawn_mock(Behaviour::Drop).await;
    let pool = UpstreamPool::build(&[entry(dead.addr)], settings())
        .await
        .unwrap();
    let err = pool.resolve(&make_query("nope.test.")).await;
    assert!(err.is_err());
}

#[test]
fn spec_parsing_smoke() {
    assert!(UpstreamSpec::parse("https://dns.google/dns-query").is_ok());
    assert!(UpstreamSpec::parse("garbage://x").is_err());
}

// ---------------------------------------------------------------------------
// Live tests against real public resolvers. Excluded by default; run with
//   cargo test -p bulwark-upstream -- --ignored
// to exercise the encrypted transports end-to-end.
// ---------------------------------------------------------------------------

fn live_settings() -> PoolSettings {
    PoolSettings {
        query_timeout: Duration::from_secs(8),
        ewma_alpha: 0.3,
        failure_threshold: 2,
        bootstrap: vec![],
    }
}

async fn live_resolve(spec: &str) {
    let pool = UpstreamPool::build(
        &[PoolEntry {
            spec: spec.into(),
            name: None,
        }],
        live_settings(),
    )
    .await
    .expect("build pool");
    let resp = pool
        .resolve(&make_query("example.com."))
        .await
        .unwrap_or_else(|e| panic!("{spec} failed: {e}"));
    assert!(
        resp.answers.iter().any(|r| matches!(&r.data, RData::A(_))),
        "{spec} returned no A records"
    );
}

#[tokio::test]
#[ignore]
async fn live_udp() {
    live_resolve("1.1.1.1").await;
}

#[tokio::test]
#[ignore]
async fn live_dot() {
    live_resolve("tls://1.1.1.1").await;
}

#[tokio::test]
#[ignore]
async fn live_doh() {
    live_resolve("https://cloudflare-dns.com/dns-query").await;
}

#[tokio::test]
#[ignore]
async fn live_doq() {
    live_resolve("quic://dns.adguard-dns.com").await;
}
