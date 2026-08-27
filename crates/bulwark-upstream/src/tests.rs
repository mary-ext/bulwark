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

use tokio::sync::mpsc::Receiver;

use crate::pool::{PoolEntry, PoolSettings, Upstream, UpstreamPool};
use crate::probe_log::{ProbeEvent, ProbeLog, ProbeOutcome};
use crate::spec::UpstreamSpec;
use crate::transport::{decode, encode};
struct Mock {
    addr: SocketAddr,
    received: Arc<AtomicU64>,
}
#[derive(Clone, Copy)]
enum Behaviour {
    Answer(Ipv4Addr, u64),
    Code(ResponseCode),
    Drop,
    SlowFirst(Ipv4Addr, u64),
    ColdShotOnly(Ipv4Addr),
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
            let seen = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let query = decode(&buf[..n]).unwrap();
            let (ip, delay) = match behaviour {
                Behaviour::Drop => continue,
                Behaviour::Code(rcode) => {
                    let mut resp = query.clone();
                    resp.metadata.message_type = MessageType::Response;
                    resp.metadata.response_code = rcode;
                    resp.metadata.recursion_available = true;
                    let bytes = encode(&resp).unwrap();
                    let _ = sock.send_to(&bytes, peer).await;
                    continue;
                }
                Behaviour::Answer(ip, delay) => (ip, delay),
                Behaviour::SlowFirst(ip, delay) => (ip, if seen > 1 { 0 } else { delay }),
                Behaviour::ColdShotOnly(ip) => {
                    if seen.is_multiple_of(2) {
                        continue;
                    }
                    (ip, 0)
                }
            };
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
async fn pool_with_probe_log(addr: SocketAddr) -> (UpstreamPool, Receiver<ProbeEvent>) {
    let mut pool = UpstreamPool::build(&[entry(addr)], settings())
        .await
        .unwrap();
    let probe_log = Arc::new(ProbeLog::new(true));
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    probe_log.set_sink(tx);
    pool.set_probe_log(probe_log);
    (pool, rx)
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
async fn successful_probe_emits_telemetry_event() {
    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(1, 2, 3, 4), 0)).await;
    let (pool, mut rx) = pool_with_probe_log(mock.addr).await;

    pool.probe_all().await;

    let ev = rx.try_recv().expect("a probe event was emitted");
    assert_eq!(ev.outcome, ProbeOutcome::Answer);
    assert_eq!(ev.upstream, format!("udp://{}", mock.addr));
    assert!(ev.rtt_ms.is_some());
    assert!(
        ev.first_rtt_ms.is_some(),
        "both shots answered, so both are recorded"
    );
    assert_eq!(
        mock.received.load(Ordering::SeqCst),
        2,
        "one probe is two queries: warm the connection, then measure on it"
    );
    assert!(
        ev.ewma_ms.is_some(),
        "first successful probe seeds the routing EWMA"
    );
    assert!(ev.up);
    assert_eq!(ev.consecutive_failures, 0);
    assert!(ev.detail.is_none(), "a clean answer carries no detail");
    assert!(
        ev.error_kind.is_none(),
        "a clean answer carries no error kind"
    );
    assert!(ev.live_ewma_ms.is_none(), "no live queries → no live EWMA");
    assert_eq!(ev.live_queries, 0);
    assert!(ev.rank.is_none(), "no selection has run yet");
    assert!(!ev.lead_held);
}

#[tokio::test]
async fn probe_event_captures_live_traffic_and_rank() {
    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(1, 2, 3, 4), 0)).await;
    let (pool, mut rx) = pool_with_probe_log(mock.addr).await;
    pool.resolve(&make_query("a.test.")).await.unwrap();
    pool.probe_all().await;

    let ev = rx.try_recv().expect("a probe event was emitted");
    assert!(
        ev.live_ewma_ms.is_some(),
        "probe captures the live-query EWMA once real traffic has flowed"
    );
    assert_eq!(ev.live_queries, 1);
    assert_eq!(ev.live_failures, 0);
    assert_eq!(ev.rank, Some(0), "the sole upstream ranks first");
    assert!(
        !ev.lead_held,
        "a raw-fastest leader isn't a hysteresis hold"
    );
}

#[tokio::test]
async fn failed_probe_emits_failure_event() {
    let mock = spawn_mock(Behaviour::Drop).await;
    let (pool, mut rx) = pool_with_probe_log(mock.addr).await;

    pool.probe_all().await;

    let ev = rx.try_recv().expect("a probe event was emitted");
    assert_eq!(ev.outcome, ProbeOutcome::Timeout);
    assert!(ev.rtt_ms.is_none(), "a failed probe has no RTT");
    assert!(
        ev.first_rtt_ms.is_none(),
        "the failed shot has no RTT either"
    );
    assert_eq!(
        mock.received.load(Ordering::SeqCst),
        1,
        "a first shot that fails is the whole probe — no second shot is sent"
    );
    assert!(
        ev.ewma_ms.is_none(),
        "no successful probe yet → no routing latency"
    );
    assert!(ev.detail.is_some());
    assert!(!ev.up);
    assert_eq!(ev.consecutive_failures, 1);
}

#[tokio::test]
async fn warm_shot_failure_leaves_liveness_alone() {
    let mock = spawn_mock(Behaviour::ColdShotOnly(Ipv4Addr::new(1, 2, 3, 4))).await;
    let (pool, mut rx) = pool_with_probe_log(mock.addr).await;

    pool.probe_all().await;

    let ev = rx.try_recv().expect("a probe event was emitted");
    assert_eq!(ev.outcome, ProbeOutcome::MeasureFail);
    assert!(
        ev.first_rtt_ms.is_some(),
        "the cold shot answered and proved reachability"
    );
    assert!(ev.rtt_ms.is_none(), "the warm shot produced no sample");
    assert!(
        ev.ewma_ms.is_none(),
        "an unusable cycle must not seed the routing EWMA"
    );
    assert!(ev.up, "a reachable upstream stays up");
    assert_eq!(
        ev.consecutive_failures, 0,
        "the cold shot answered, so nothing counts against liveness"
    );
    assert!(
        ev.detail.is_some(),
        "the warm-shot error is still reported for diagnostics"
    );
}

#[tokio::test]
async fn repeated_warm_shot_failures_never_mark_an_upstream_down() {
    let mock = spawn_mock(Behaviour::ColdShotOnly(Ipv4Addr::new(1, 2, 3, 4))).await;
    let pool = UpstreamPool::build(&[entry(mock.addr)], settings())
        .await
        .unwrap();

    for _ in 0..3 {
        pool.probe_all().await;
    }

    let stat = &pool.stats()[0];
    assert!(stat.up, "warm-shot failures alone never demote an upstream");
    assert!(
        stat.avg_rtt_ms.is_none(),
        "no cycle yielded a usable latency sample"
    );
}

#[tokio::test]
async fn probe_routes_on_the_second_shot_not_the_connection_setup() {
    const SETUP_MS: u64 = 200;
    let mock = spawn_mock(Behaviour::SlowFirst(Ipv4Addr::new(1, 2, 3, 4), SETUP_MS)).await;
    let (pool, mut rx) = pool_with_probe_log(mock.addr).await;

    pool.probe_all().await;

    let ev = rx.try_recv().expect("a probe event was emitted");
    assert_eq!(ev.outcome, ProbeOutcome::Answer);
    let first = ev.first_rtt_ms.expect("the setup shot answered");
    let rtt = ev.rtt_ms.expect("the measured shot answered");
    assert!(
        first >= SETUP_MS as f64,
        "the first shot pays the setup cost: {first}ms"
    );
    assert!(
        rtt < SETUP_MS as f64 / 2.0,
        "the routing figure skips it: {rtt}ms"
    );
    assert_eq!(
        ev.ewma_ms,
        Some(rtt),
        "the first successful probe seeds the routing EWMA from the second shot"
    );
}

#[tokio::test]
async fn udp_socket_idle_closes_then_redials() {
    use crate::plain::UdpTransport;
    use crate::transport::Transport;

    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(1, 2, 3, 4), 0)).await;
    let t = UdpTransport::with_idle_timeout(mock.addr, Duration::from_millis(150));
    let r1 = t.query(&make_query("example.com.")).await.unwrap();
    assert_eq!(r1.answers.len(), 1);
    assert!(
        !t.cached_conn_is_dead().await,
        "socket should be live immediately after a query"
    );
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(
        t.cached_conn_is_dead().await,
        "socket should idle-close after the idle window elapses with no traffic"
    );
    let r2 = t.query(&make_query("example.com.")).await.unwrap();
    assert_eq!(r2.answers.len(), 1);
    assert!(
        !t.cached_conn_is_dead().await,
        "re-dial should install a fresh, live socket"
    );
    assert_eq!(mock.received.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn single_flight_coalesces_identical_queries() {
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
    assert_eq!(mock.received.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sequential_failover_to_healthy_upstream() {
    let dead = spawn_mock(Behaviour::Drop).await;
    let good = spawn_mock(Behaviour::Answer(Ipv4Addr::new(5, 5, 5, 5), 0)).await;
    let pool = UpstreamPool::build(&[entry(dead.addr), entry(good.addr)], settings())
        .await
        .unwrap();

    let resp = pool.resolve(&make_query("failover.test.")).await.unwrap();
    assert_eq!(resp.message.answers.len(), 1);
    assert!(good.received.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn dead_from_start_upstream_is_demoted() {
    let dead = spawn_mock(Behaviour::Drop).await;
    let good = spawn_mock(Behaviour::Answer(Ipv4Addr::new(4, 4, 4, 4), 0)).await;
    let pool = UpstreamPool::build(&[entry(dead.addr), entry(good.addr)], settings())
        .await
        .unwrap();
    let r1 = pool.resolve(&make_query("a.test.")).await.unwrap();
    assert_eq!(r1.upstream, format!("udp://{}", good.addr));
    let stats = pool.stats();
    let dead_stat = stats
        .iter()
        .find(|s| s.spec.contains(&dead.addr.to_string()))
        .unwrap();
    assert!(
        !dead_stat.up,
        "a dead-from-start upstream must be marked down"
    );
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
    let pool = UpstreamPool::build(&[entry(slow.addr), entry(fast.addr)], settings())
        .await
        .unwrap();

    pool.probe_all().await;
    let baseline_slow = slow.received.load(Ordering::SeqCst);
    let baseline_fast = fast.received.load(Ordering::SeqCst);

    for _ in 0..3 {
        pool.resolve(&make_query("speed.test.")).await.unwrap();
    }
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
    let known = spawn_mock(Behaviour::Answer(Ipv4Addr::new(5, 5, 5, 5), 0)).await;
    let old = UpstreamPool::build(&[entry(known.addr)], settings())
        .await
        .unwrap();
    old.probe_all().await;
    let known_after_warmup = known.received.load(Ordering::SeqCst);
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

#[tokio::test]
async fn leadership_is_sticky_within_the_switch_margin() {
    let a = spawn_mock(Behaviour::Answer(Ipv4Addr::new(1, 1, 1, 1), 0)).await;
    let b = spawn_mock(Behaviour::Answer(Ipv4Addr::new(2, 2, 2, 2), 0)).await;
    let pool = UpstreamPool::build(&[entry(a.addr), entry(b.addr)], settings())
        .await
        .unwrap();
    pool.probe_all().await;
    let a_up = pool.upstreams()[0].clone();
    let b_up = pool.upstreams()[1].clone();
    let leads = |pool: &UpstreamPool, who: &Arc<Upstream>| Arc::ptr_eq(&pool.ordered()[0], who);
    a_up.set_routing_latency_for_test(15.0);
    b_up.set_routing_latency_for_test(24.0);
    assert!(leads(&pool, &a_up));
    a_up.set_routing_latency_for_test(24.0);
    b_up.set_routing_latency_for_test(23.0);
    assert!(
        leads(&pool, &a_up),
        "incumbent held while the challenger leads by less than the switch margin"
    );
    a_up.set_routing_latency_for_test(24.0);
    b_up.set_routing_latency_for_test(15.0);
    assert!(
        leads(&pool, &b_up),
        "a challenger past the switch margin takes leadership"
    );
    a_up.set_routing_latency_for_test(14.0);
    b_up.set_routing_latency_for_test(15.0);
    assert!(
        leads(&pool, &b_up),
        "the new incumbent is itself held within the margin"
    );
}

#[tokio::test]
async fn recent_hard_failure_yields_leadership_then_reclaims_on_recovery() {
    let a = spawn_mock(Behaviour::Answer(Ipv4Addr::new(1, 1, 1, 1), 0)).await;
    let b = spawn_mock(Behaviour::Answer(Ipv4Addr::new(2, 2, 2, 2), 0)).await;
    let pool = UpstreamPool::build(&[entry(a.addr), entry(b.addr)], settings())
        .await
        .unwrap();
    pool.probe_all().await;
    let a_up = pool.upstreams()[0].clone();
    let b_up = pool.upstreams()[1].clone();
    let leads = |pool: &UpstreamPool, who: &Arc<Upstream>| Arc::ptr_eq(&pool.ordered()[0], who);
    a_up.set_routing_latency_for_test(15.0);
    b_up.set_routing_latency_for_test(17.0);
    assert!(leads(&pool, &a_up), "clean fast upstream leads");
    a_up.set_recent_failure_for_test();
    b_up.set_routing_latency_for_test(17.0); // re-assert B clean; A stays 15ms
    assert!(
        leads(&pool, &b_up),
        "an upstream on probation must not be held as leader over a clean peer"
    );
    a_up.set_routing_latency_for_test(15.0); // clears consecutive_failures
    assert!(
        leads(&pool, &b_up),
        "a recovered-but-near-tied upstream doesn't reclaim; the incumbent is held"
    );
    a_up.set_routing_latency_for_test(5.0);
    assert!(
        leads(&pool, &a_up),
        "a recovered upstream that clears the switch margin reclaims leadership"
    );
}
async fn wait_for(mut cond: impl FnMut() -> bool, timeout: Duration) {
    let start = std::time::Instant::now();
    while !cond() {
        assert!(
            start.elapsed() < timeout,
            "condition not met within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn per_upstream_probe_fires_once_then_defers() {
    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(8, 8, 8, 8), 0)).await;
    let mut pool = UpstreamPool::build(&[entry(mock.addr)], settings())
        .await
        .unwrap();

    assert_eq!(mock.received.load(Ordering::SeqCst), 0);
    pool.start_probing();

    wait_for(
        || mock.received.load(Ordering::SeqCst) >= 2,
        Duration::from_secs(4),
    )
    .await;
    assert_eq!(
        mock.received.load(Ordering::SeqCst),
        2,
        "a never-sampled upstream is probed once on start (two shots)"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.received.load(Ordering::SeqCst),
        2,
        "a freshly-probed (healthy) upstream is not re-probed within the window"
    );
}

#[tokio::test]
async fn reload_carries_upstream_stats() {
    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(6, 6, 6, 6), 0)).await;
    let old = UpstreamPool::build(&[entry(mock.addr)], settings())
        .await
        .unwrap();
    old.resolve(&make_query("stats.test.")).await.unwrap();
    let old_stat = old.stats().into_iter().next().unwrap();
    assert_eq!(old_stat.total_queries, 1);
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
async fn probing_runs_regardless_of_live_traffic() {
    let mock = spawn_mock(Behaviour::Answer(Ipv4Addr::new(7, 7, 7, 7), 0)).await;
    let mut pool = UpstreamPool::build(&[entry(mock.addr)], settings())
        .await
        .unwrap();

    pool.resolve(&make_query("fresh.test.")).await.unwrap();
    let after_query = mock.received.load(Ordering::SeqCst);

    pool.start_probing();
    wait_for(
        || mock.received.load(Ordering::SeqCst) > after_query,
        Duration::from_secs(4),
    )
    .await;
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
    let servfail = spawn_mock(Behaviour::Code(ResponseCode::ServFail)).await;
    let good = spawn_mock(Behaviour::Answer(Ipv4Addr::new(7, 7, 7, 7), 0)).await;
    let pool = UpstreamPool::build(&[entry(servfail.addr), entry(good.addr)], settings())
        .await
        .unwrap();

    let resp = pool.resolve(&make_query("sf.test.")).await.unwrap();
    assert_eq!(resp.message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.message.answers.len(), 1);
    assert_eq!(resp.upstream, format!("udp://{}", good.addr));
    assert!(servfail.received.load(Ordering::SeqCst) >= 1);
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
