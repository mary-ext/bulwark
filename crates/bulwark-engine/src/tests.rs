//! Engine integration tests: full pipeline (filter → cache → upstream) against
//! an in-process mock UDP upstream.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bulwark_config::BlockingMode;
use bulwark_filter::compile_one;
use bulwark_upstream::{PoolEntry, PoolSettings, UpstreamPool};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

use crate::cache::DnsCache;
use crate::clients::ClientMatcher;
use crate::querylog::{QueryAction, QueryLog};
use crate::stats::Stats;
use crate::{Engine, EngineState, Ingress};

async fn mock_upstream(answer_ip: Ipv4Addr) -> (SocketAddr, Arc<AtomicU64>) {
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
            counter.fetch_add(1, Ordering::SeqCst);
            let query = Message::from_vec(&buf[..n]).unwrap();
            let mut resp = query.clone();
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NoError;
            if let Some(q) = query.queries.first() {
                resp.answers.push(Record::from_rdata(
                    q.name().clone(),
                    300,
                    RData::A(A(answer_ip)),
                ));
            }
            let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    (addr, count)
}

/// A mock upstream that answers every A query with a CNAME chain
/// `<qname> -> <cname_target>` followed by an `A <answer_ip>` for the target,
/// mimicking the CNAME-cloaked responses real trackers return.
async fn mock_upstream_cname(cname_target: &str, answer_ip: Ipv4Addr) -> SocketAddr {
    let target = Name::from_str(cname_target).unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let query = Message::from_vec(&buf[..n]).unwrap();
            let mut resp = query.clone();
            resp.metadata.message_type = MessageType::Response;
            resp.metadata.response_code = ResponseCode::NoError;
            if let Some(q) = query.queries.first() {
                resp.answers.push(Record::from_rdata(
                    q.name().clone(),
                    300,
                    RData::CNAME(hickory_proto::rr::rdata::CNAME(target.clone())),
                ));
                resp.answers.push(Record::from_rdata(
                    target.clone(),
                    300,
                    RData::A(A(answer_ip)),
                ));
            }
            let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    addr
}

async fn make_engine(rules: &str, upstream: SocketAddr) -> Arc<Engine> {
    let filter = Arc::new(compile_one(rules));
    let pool = Arc::new(
        UpstreamPool::build(
            &[PoolEntry {
                spec: format!("udp://{upstream}"),
                name: Some("mock".into()),
            }],
            PoolSettings {
                query_timeout: Duration::from_millis(500),
                bootstrap: vec!["127.0.0.1:1".parse().unwrap()],
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
    Engine::new(
        state,
        Arc::new(DnsCache::new(100, 0, 0, 0)),
        Arc::new(QueryLog::new(true, false)),
        Arc::new(Stats::new(true, 1, false)),
    )
}

fn query(name: &str, rtype: RecordType) -> Message {
    let mut m = Message::new(0xABCD, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    let mut q = Query::query(Name::from_str(name).unwrap(), rtype);
    q.set_query_class(DNSClass::IN);
    m.queries.push(q);
    m
}

fn local() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

/// Encode a query and feed it through the real listener ingress path, so these
/// tests exercise the same `wire::parse_query` fast path production uses.
fn ingest(m: Message) -> Ingress {
    Ingress::parse(&m.to_vec().unwrap()).expect("query should be decodable")
}

#[tokio::test]
async fn forwards_and_caches() {
    let (up, count) = mock_upstream(Ipv4Addr::new(1, 2, 3, 4)).await;
    let engine = make_engine("", up).await;

    let r1 = engine
        .handle(ingest(query("good.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(r1.metadata.response_code, ResponseCode::NoError);
    assert_eq!(r1.answers.len(), 1);
    assert_eq!(r1.metadata.id, 0xABCD);

    // Second identical query should be served from cache (no new upstream hit).
    let r2 = engine
        .handle(ingest(query("good.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(r2.answers.len(), 1);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(engine.cache().hit_count(), 1);
}

#[tokio::test]
async fn cache_hit_serves_patched_wire() {
    let (up, count) = mock_upstream(Ipv4Addr::new(9, 8, 7, 6)).await;
    let engine = make_engine("", up).await;

    // Prime the cache (forwarded, stored as wire bytes with TTL 300).
    let _ = engine
        .handle(ingest(query("hit.com.", RecordType::A)), local())
        .await;

    // Second query with a *different* transaction id -> wire-byte cache hit.
    let mut q = query("hit.com.", RecordType::A);
    q.metadata.id = 0x4242;
    let r = engine.handle(ingest(q), local()).await.into_message();

    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "cache hit must not touch upstream"
    );
    assert_eq!(r.metadata.id, 0x4242, "id must be patched to the new query");
    assert_eq!(r.metadata.message_type, MessageType::Response);
    assert_eq!(r.answers.len(), 1);
    assert!(matches!(&r.answers[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(9, 8, 7, 6)));
    // TTL was rewritten to the remaining lifetime (<= the stored 300, >= 1).
    assert!(r.answers[0].ttl >= 1 && r.answers[0].ttl <= 300);
}

#[tokio::test]
async fn blocks_filtered_domain() {
    let (up, count) = mock_upstream(Ipv4Addr::new(1, 2, 3, 4)).await;
    let engine = make_engine("||ads.example.com^", up).await;

    // Capture what gets handed to the writer for this query.
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    engine.log().set_sink(tx);

    let r = engine
        .handle(ingest(query("ads.example.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    // Blocked queries never touch the upstream.
    assert_eq!(count.load(Ordering::SeqCst), 0);

    let entry = rx.try_recv().expect("blocked query logged");
    assert!(matches!(entry.action, QueryAction::Blocked { .. }));
    assert!(entry.is_blocked());
}

#[tokio::test]
async fn uncloaks_blocked_cname_target() {
    // The query name is clean, but the upstream answer CNAMEs to a blocked
    // tracker. Response-side filtering must catch the target and block.
    let up = mock_upstream_cname("tracker.evil.net.", Ipv4Addr::new(1, 2, 3, 4)).await;
    let engine = make_engine("||tracker.evil.net^", up).await;

    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    engine.log().set_sink(tx);

    let r = engine
        .handle(ingest(query("data.brand.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(
        r.metadata.response_code,
        ResponseCode::NXDomain,
        "a blocked CNAME target should turn the whole response into a block"
    );

    let entry = rx.try_recv().expect("uncloaked query logged");
    assert!(matches!(entry.action, QueryAction::Blocked { .. }));
}

#[tokio::test]
async fn uncloak_block_is_cached() {
    // After uncloaking once, the synthesized block must be cached so the next
    // identical query is served without a second upstream round-trip.
    let up = mock_upstream_cname("tracker.evil.net.", Ipv4Addr::new(1, 2, 3, 4)).await;
    let engine = make_engine("||tracker.evil.net^", up).await;

    let q = || ingest(query("data.brand.com.", RecordType::A));
    let r1 = engine.handle(q(), local()).await.into_message();
    assert_eq!(r1.metadata.response_code, ResponseCode::NXDomain);

    let r2 = engine.handle(q(), local()).await.into_message();
    assert_eq!(r2.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(
        engine.cache().hit_count(),
        1,
        "the second query must hit the cached block, not re-resolve"
    );
}

#[tokio::test]
async fn blocks_response_by_resolved_ip() {
    // The name is clean, but it resolves to a blocked IP. Response-side
    // filtering must catch the A record's address and block.
    let (up, _count) = mock_upstream(Ipv4Addr::new(9, 9, 9, 9)).await;
    let engine = make_engine("||9.9.9.9^", up).await;

    let r = engine
        .handle(ingest(query("sneaky.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(
        r.metadata.response_code,
        ResponseCode::NXDomain,
        "an answer resolving to a blocked IP should be blocked"
    );
}

#[tokio::test]
async fn clean_cname_chain_is_forwarded() {
    // A CNAME chain whose target is *not* blocked must pass through untouched.
    let up = mock_upstream_cname("cdn.good.net.", Ipv4Addr::new(5, 6, 7, 8)).await;
    let engine = make_engine("||tracker.evil.net^", up).await;

    let r = engine
        .handle(ingest(query("www.brand.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    // CNAME + A both present, unmodified.
    assert_eq!(r.answers.len(), 2);
    assert!(r
        .answers
        .iter()
        .any(|a| matches!(&a.data, RData::A(A(ip)) if *ip == Ipv4Addr::new(5, 6, 7, 8))));
}

#[tokio::test]
async fn rewrites_to_custom_ip() {
    let (up, _count) = mock_upstream(Ipv4Addr::new(1, 2, 3, 4)).await;
    let engine = make_engine("||router.lan^$dnsrewrite=10.0.0.1", up).await;

    let r = engine
        .handle(ingest(query("router.lan.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(r.answers.len(), 1);
    assert!(matches!(&r.answers[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(10, 0, 0, 1)));
}

#[tokio::test]
async fn records_statistics() {
    let (up, _) = mock_upstream(Ipv4Addr::new(1, 2, 3, 4)).await;
    let engine = make_engine("||bad.com^", up).await;

    engine
        .handle(ingest(query("bad.com.", RecordType::A)), local())
        .await;
    engine
        .handle(ingest(query("good.com.", RecordType::A)), local())
        .await;

    let snap = engine.stats().snapshot(10, &engine.clients());
    assert_eq!(snap.total, 2);
    assert_eq!(snap.blocked, 1);
    assert!(snap.top_blocked_domains.iter().any(|t| t.name == "bad.com"));
    assert!(snap.top_upstreams.iter().any(|t| t.name == "mock"));
}

#[tokio::test]
async fn servfail_when_no_upstream_answers() {
    // Build an engine whose only upstream is a dead port.
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let engine = make_engine("", dead).await;
    let r = engine
        .handle(ingest(query("anything.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
}
