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
    /// Reply immediately with the given response code and no answer records.
    Code(ResponseCode),
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
                Behaviour::Code(rcode) => {
                    let mut resp = query.clone();
                    resp.metadata.message_type = MessageType::Response;
                    resp.metadata.response_code = rcode;
                    resp.metadata.recursion_available = true;
                    let bytes = encode(&resp).unwrap();
                    let _ = sock.send_to(&bytes, peer).await;
                }
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
    assert_eq!(resp.message.metadata.id, 0x4242);
    assert_eq!(resp.message.answers.len(), 1);
    assert_eq!(resp.upstream, format!("udp://{}", mock.addr));
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
    assert_eq!(resp.message.answers.len(), 1);
    assert!(good.received.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn dead_from_start_upstream_is_demoted() {
    // An upstream that has *never* succeeded must still be marked down and sorted
    // last once it crosses the failure threshold — the bug was that a
    // never-successful upstream (samples == 0) stayed "up" forever and kept being
    // tried first, waiting out its timeout on every query.
    let dead = spawn_mock(Behaviour::Drop).await;
    let good = spawn_mock(Behaviour::Answer(Ipv4Addr::new(4, 4, 4, 4), 0)).await;
    let pool = UpstreamPool::build(&[entry(dead.addr), entry(good.addr)], settings())
        .await
        .unwrap();

    // First query: dead times out, fails over to good.
    let r1 = pool.resolve(&make_query("a.test.")).await.unwrap();
    assert_eq!(r1.upstream, format!("udp://{}", good.addr));

    // Dead is now reported down (previously it showed up because samples == 0).
    let stats = pool.stats();
    let dead_stat = stats
        .iter()
        .find(|s| s.spec.contains(&dead.addr.to_string()))
        .unwrap();
    assert!(!dead_stat.up, "a dead-from-start upstream must be marked down");

    // Subsequent queries skip the demoted upstream entirely.
    let before = dead.received.load(Ordering::SeqCst);
    let r2 = pool.resolve(&make_query("b.test.")).await.unwrap();
    assert_eq!(r2.upstream, format!("udp://{}", good.addr));
    assert_eq!(
        dead.received.load(Ordering::SeqCst),
        before,
        "the demoted upstream should receive no further queries"
    );
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
async fn known_leader_preferred_over_freshly_added_unknown() {
    // A proven, sampled upstream must keep live traffic when a brand-new,
    // never-sampled upstream is added ahead of it on reload. Previously the new
    // upstream sorted as latency 0 ("fastest") and stole the next query — costing
    // a full timeout if it happened to be a black hole.
    let known = spawn_mock(Behaviour::Answer(Ipv4Addr::new(5, 5, 5, 5), 0)).await;
    let old = UpstreamPool::build(&[entry(known.addr)], settings())
        .await
        .unwrap();
    old.resolve(&make_query("warm.test.")).await.unwrap();
    let known_after_warmup = known.received.load(Ordering::SeqCst);

    // Reload: a new upstream is listed FIRST, the known one second. The new pool
    // adopts the known upstream's sampled health; the added one stays unsampled.
    let added = spawn_mock(Behaviour::Answer(Ipv4Addr::new(9, 9, 9, 9), 0)).await;
    let new = UpstreamPool::build(&[entry(added.addr), entry(known.addr)], settings())
        .await
        .unwrap();
    new.adopt_health_from(&old);

    let resp = new.resolve(&make_query("live.test.")).await.unwrap();
    assert_eq!(
        resp.upstream,
        format!("udp://{}", known.addr),
        "a sampled leader must be preferred over an unsampled newcomer"
    );
    assert_eq!(
        added.received.load(Ordering::SeqCst),
        0,
        "the unsampled newcomer must not receive the live query"
    );
    assert_eq!(
        known.received.load(Ordering::SeqCst),
        known_after_warmup + 1
    );
}

/// Poll `cond` until it's true or `timeout` elapses (panicking on timeout).
async fn wait_for(mut cond: impl FnMut() -> bool, timeout: Duration) {
    let start = std::time::Instant::now();
    while !cond() {
        assert!(start.elapsed() < timeout, "condition not met within {timeout:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn per_upstream_probe_fires_once_then_defers() {
    // The pool spawns one probe task per upstream. A never-sampled upstream is
    // due within the (jittered) startup spread, so the task probes it once —
    // then, now healthy, it's deferred a full window and isn't re-probed soon.
    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(8, 8, 8, 8), 0)).await;
    let mut pool = UpstreamPool::build(&[entry(mock.addr)], settings())
        .await
        .unwrap();

    assert_eq!(mock.received.load(Ordering::SeqCst), 0);
    pool.start_probing();

    wait_for(
        || mock.received.load(Ordering::SeqCst) >= 1,
        Duration::from_secs(4),
    )
    .await;
    assert_eq!(
        mock.received.load(Ordering::SeqCst),
        1,
        "a never-sampled upstream is probed once on start"
    );

    // Now healthy → next probe is ~a minute out, so nothing fires meanwhile.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.received.load(Ordering::SeqCst),
        1,
        "a freshly-probed (healthy) upstream is not re-probed within the window"
    );
}

#[tokio::test]
async fn reload_carries_upstream_stats() {
    // Simulate a config reload: build a pool, accumulate some stats, then build a
    // replacement and have it adopt the old pool's health. The unchanged upstream
    // keeps its tallies; a brand-new upstream starts blank.
    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(6, 6, 6, 6), 0)).await;
    let old = UpstreamPool::build(&[entry(mock.addr)], settings())
        .await
        .unwrap();
    old.resolve(&make_query("stats.test.")).await.unwrap();
    let old_stat = old.stats().into_iter().next().unwrap();
    assert_eq!(old_stat.total_queries, 1);

    // New pool: same upstream plus an added one (a different mock address).
    let added = spawn_mock(Behaviour::Answer(Ipv4Addr::new(1, 2, 3, 4), 0)).await;
    let new = UpstreamPool::build(&[entry(mock.addr), entry(added.addr)], settings())
        .await
        .unwrap();
    new.adopt_health_from(&old);

    let stats = new.stats();
    let carried = stats
        .iter()
        .find(|s| s.spec.contains(&mock.addr.to_string()))
        .unwrap();
    assert_eq!(
        carried.total_queries, 1,
        "an unchanged upstream keeps its stats across reload"
    );
    let fresh = stats
        .iter()
        .find(|s| s.spec.contains(&added.addr.to_string()))
        .unwrap();
    assert_eq!(
        fresh.total_queries, 0,
        "a newly added upstream starts with blank stats"
    );
}

#[tokio::test]
async fn reload_matches_upstreams_by_endpoint_not_spelling() {
    // `entry()` spells the upstream `udp://127.0.0.1:PORT`; re-spell it bare on
    // "reload" as `127.0.0.1:PORT`. It's the same endpoint, so stats carry over.
    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(3, 3, 3, 3), 0)).await;
    let old = UpstreamPool::build(&[entry(mock.addr)], settings())
        .await
        .unwrap();
    old.resolve(&make_query("respell.test.")).await.unwrap();

    let bare = PoolEntry {
        spec: mock.addr.to_string(), // no `udp://` scheme
        name: None,
    };
    let new = UpstreamPool::build(&[bare], settings()).await.unwrap();
    new.adopt_health_from(&old);

    assert_eq!(
        new.stats().into_iter().next().unwrap().total_queries,
        1,
        "a re-spelled upstream is recognized as the same and keeps its stats"
    );
}

#[tokio::test]
async fn live_query_defers_the_probe() {
    // A live query refreshes the same health a probe would, so an upstream that
    // just answered a real query has its probe deferred — this is what lets a
    // busy upstream stop being probed entirely.
    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(7, 7, 7, 7), 0)).await;
    let mut pool = UpstreamPool::build(&[entry(mock.addr)], settings())
        .await
        .unwrap();

    pool.resolve(&make_query("fresh.test.")).await.unwrap();
    let after_query = mock.received.load(Ordering::SeqCst);

    pool.start_probing();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.received.load(Ordering::SeqCst),
        after_query,
        "a freshly-used upstream must not be probed"
    );
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

#[tokio::test]
async fn fails_over_past_a_fast_servfail() {
    // A fast SERVFAIL must not satisfy the query: the pool has to fail over to a
    // resolver that actually answers, and the SERVFAIL upstream must not be
    // recorded as a (fast) success that would make it the leader.
    let servfail = spawn_mock(Behaviour::Code(ResponseCode::ServFail)).await;
    let good = spawn_mock(Behaviour::Answer(Ipv4Addr::new(7, 7, 7, 7), 0)).await;
    // SERVFAIL listed first; both unsampled so it's tried first.
    let pool = UpstreamPool::build(&[entry(servfail.addr), entry(good.addr)], settings())
        .await
        .unwrap();

    let resp = pool.resolve(&make_query("sf.test.")).await.unwrap();
    assert_eq!(resp.message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.message.answers.len(), 1);
    assert_eq!(resp.upstream, format!("udp://{}", good.addr));
    assert!(servfail.received.load(Ordering::SeqCst) >= 1);

    // The SERVFAIL upstream stays up (a SERVFAIL is plausibly the query's fault)
    // but never recorded a latency, so it can't have become the leader.
    let sf_stat = pool
        .stats()
        .into_iter()
        .find(|s| s.spec.contains(&servfail.addr.to_string()))
        .unwrap();
    assert!(sf_stat.up, "a SERVFAIL must not mark the upstream down");
    assert!(
        sf_stat.avg_rtt_ms.is_none(),
        "a SERVFAIL must not be recorded as a latency sample"
    );
}

#[tokio::test]
async fn refused_upstream_is_marked_down() {
    // REFUSED is an upstream-level rejection, so unlike SERVFAIL it counts
    // against health (failure_threshold is 1 here) and the pool fails over.
    let refused = spawn_mock(Behaviour::Code(ResponseCode::Refused)).await;
    let good = spawn_mock(Behaviour::Answer(Ipv4Addr::new(8, 8, 8, 8), 0)).await;
    let pool = UpstreamPool::build(&[entry(refused.addr), entry(good.addr)], settings())
        .await
        .unwrap();

    let resp = pool.resolve(&make_query("ref.test.")).await.unwrap();
    assert_eq!(resp.upstream, format!("udp://{}", good.addr));

    let stat = pool
        .stats()
        .into_iter()
        .find(|s| s.spec.contains(&refused.addr.to_string()))
        .unwrap();
    assert!(!stat.up, "a REFUSED upstream must be marked down");
}

#[tokio::test]
async fn all_servfail_returns_the_servfail() {
    // If every upstream SERVFAILs, the client should get that real response
    // rather than an opaque "all upstreams failed" error.
    let servfail = spawn_mock(Behaviour::Code(ResponseCode::ServFail)).await;
    let pool = UpstreamPool::build(&[entry(servfail.addr)], settings())
        .await
        .unwrap();

    let resp = pool.resolve(&make_query("allsf.test.")).await.unwrap();
    assert_eq!(resp.message.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(resp.message.metadata.id, 0x4242, "caller id is restored");
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
        resp.message
            .answers
            .iter()
            .any(|r| matches!(&r.data, RData::A(_))),
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
