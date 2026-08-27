//! Engine integration tests: full pipeline (filter → cache → upstream) against
//! an in-process mock UDP upstream.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bulwark_config::{BlockingMode, ClientConfig};
use bulwark_filter::compile_one;
use bulwark_upstream::{PoolEntry, PoolSettings, UpstreamPool};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
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
async fn mock_upstream_https(hints: Vec<Ipv4Addr>) -> SocketAddr {
    use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey, SvcParamValue, SVCB};
    use hickory_proto::rr::rdata::HTTPS;
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
                let svcb = SVCB::new(
                    1,
                    Name::root(),
                    vec![(
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(hints.iter().copied().map(A).collect())),
                    )],
                );
                resp.answers.push(Record::from_rdata(
                    q.name().clone(),
                    300,
                    RData::HTTPS(HTTPS(svcb)),
                ));
            }
            let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    addr
}
async fn mock_upstream_aaaa(answer_ip: Ipv6Addr) -> SocketAddr {
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
                    RData::AAAA(AAAA(answer_ip)),
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
    let _ = engine
        .handle(ingest(query("hit.com.", RecordType::A)), local())
        .await;
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
    assert!(r.answers[0].ttl >= 1 && r.answers[0].ttl <= 300);
}

#[tokio::test]
async fn forwarded_miss_serves_wire_without_reencoding() {
    let (up, _count) = mock_upstream(Ipv4Addr::new(5, 6, 7, 8)).await;
    let engine = make_engine("", up).await;

    let resp = engine
        .handle(ingest(query("fresh.com.", RecordType::A)), local())
        .await;

    let bytes = match &resp {
        crate::EngineResponse::Wire(b) => b.clone(),
        crate::EngineResponse::Message(_) => panic!("forwarded miss should serve wire bytes"),
    };
    let decoded = Message::from_vec(&bytes).expect("served wire decodes");
    assert_eq!(decoded.metadata.id, 0xABCD);
    assert_eq!(decoded.metadata.response_code, ResponseCode::NoError);
    assert_eq!(decoded.answers.len(), 1);
    assert!(
        matches!(&decoded.answers[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(5, 6, 7, 8))
    );
}

#[tokio::test]
async fn blocks_filtered_domain() {
    let (up, count) = mock_upstream(Ipv4Addr::new(1, 2, 3, 4)).await;
    let engine = make_engine("||ads.example.com^", up).await;
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    engine.log().set_sink(tx);

    let r = engine
        .handle(ingest(query("ads.example.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(count.load(Ordering::SeqCst), 0);

    let entry = rx.try_recv().expect("blocked query logged");
    assert!(matches!(entry.action, QueryAction::Blocked { .. }));
    assert!(entry.is_blocked());
}

#[tokio::test]
async fn uncloaks_blocked_cname_target() {
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
async fn blocks_response_on_blocked_https_hint() {
    let up = mock_upstream_https(vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(6, 6, 6, 6)]).await;
    let engine = make_engine("||6.6.6.6^", up).await;

    let r = engine
        .handle(ingest(query("site.com.", RecordType::HTTPS)), local())
        .await
        .into_message();
    assert_eq!(
        r.metadata.response_code,
        ResponseCode::NXDomain,
        "a blocked ipv4hint should block the whole response"
    );
}

#[tokio::test]
async fn aaaa_answer_is_forwarded_untouched() {
    let v6 = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111);
    let up = mock_upstream_aaaa(v6).await;
    let engine = make_engine("||tracker.evil.net^", up).await;

    let r = engine
        .handle(
            ingest(query("ipv6.example.com.", RecordType::AAAA)),
            local(),
        )
        .await
        .into_message();
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert_eq!(r.answers.len(), 1);
    assert!(matches!(&r.answers[0].data, RData::AAAA(AAAA(ip)) if *ip == v6));
}

#[tokio::test]
async fn blocks_response_by_resolved_ipv6() {
    let v6 = Ipv6Addr::new(0x1234, 0, 0, 0, 0, 0, 0, 0xcdef);
    let up = mock_upstream_aaaa(v6).await;
    let engine = make_engine("1234::cdef", up).await;

    let r = engine
        .handle(ingest(query("sneaky6.com.", RecordType::AAAA)), local())
        .await
        .into_message();
    assert_eq!(
        r.metadata.response_code,
        ResponseCode::NXDomain,
        "an answer resolving to a blocked v6 address should be blocked"
    );
}

#[tokio::test]
async fn clean_https_hint_is_forwarded() {
    let up = mock_upstream_https(vec![Ipv4Addr::new(1, 1, 1, 1)]).await;
    let engine = make_engine("||6.6.6.6^", up).await;

    let r = engine
        .handle(ingest(query("site.com.", RecordType::HTTPS)), local())
        .await
        .into_message();
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert_eq!(r.answers.len(), 1, "the HTTPS record should pass through");
    assert!(matches!(&r.answers[0].data, RData::HTTPS(_)));
}

#[tokio::test]
async fn clean_cname_chain_is_forwarded() {
    let up = mock_upstream_cname("cdn.good.net.", Ipv4Addr::new(5, 6, 7, 8)).await;
    let engine = make_engine("||tracker.evil.net^", up).await;

    let r = engine
        .handle(ingest(query("www.brand.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
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
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let engine = make_engine("", dead).await;
    let r = engine
        .handle(ingest(query("anything.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
}
fn state_with(rules: &str, pool: Arc<UpstreamPool>, clients: ClientMatcher) -> EngineState {
    EngineState {
        filter: Arc::new(compile_one(rules)),
        pool,
        clients: Arc::new(clients),
        filtering_enabled: true,
        blocking_mode: BlockingMode::NxDomain,
        block_v4: Ipv4Addr::UNSPECIFIED,
        block_v6: Ipv6Addr::UNSPECIFIED,
        blocked_ttl: 10,
    }
}

#[tokio::test]
async fn reload_unblocks_cached_cloaked_answer() {
    let up = mock_upstream_cname("tracker.evil.net.", Ipv4Addr::new(1, 2, 3, 4)).await;
    let engine = make_engine("||tracker.evil.net^", up).await;

    let r1 = engine
        .handle(ingest(query("data.brand.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(
        r1.metadata.response_code,
        ResponseCode::NXDomain,
        "blocked while the rule is active"
    );
    engine.swap_state(state_with("", engine.pool(), ClientMatcher::default()));

    let r2 = engine
        .handle(ingest(query("data.brand.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(
        r2.metadata.response_code,
        ResponseCode::NoError,
        "the reload must un-block the cached answer"
    );
    assert!(
        r2.answers
            .iter()
            .any(|a| matches!(&a.data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4))),
        "the previously-cloaked raw answer is served straight from cache"
    );
    assert_eq!(
        engine.cache().hit_count(),
        1,
        "served from the cached raw answer, not re-resolved upstream"
    );
}

#[tokio::test]
async fn reload_blocks_cached_clean_answer() {
    let up = mock_upstream_cname("tracker.evil.net.", Ipv4Addr::new(1, 2, 3, 4)).await;
    let engine = make_engine("", up).await; // nothing blocked yet

    let r1 = engine
        .handle(ingest(query("data.brand.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(
        r1.metadata.response_code,
        ResponseCode::NoError,
        "clean while no rule matches"
    );

    engine.swap_state(state_with(
        "||tracker.evil.net^",
        engine.pool(),
        ClientMatcher::default(),
    ));

    let r2 = engine
        .handle(ingest(query("data.brand.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(
        r2.metadata.response_code,
        ResponseCode::NXDomain,
        "the reload must block the now-matching cached answer"
    );
    assert_eq!(
        engine.cache().hit_count(),
        1,
        "decided from the cached raw answer, no re-resolve"
    );
}

#[tokio::test]
async fn unfiltered_client_cache_does_not_leak_to_filtered_client() {
    let up = mock_upstream_cname("tracker.evil.net.", Ipv4Addr::new(1, 2, 3, 4)).await;
    let engine = make_engine("||tracker.evil.net^", up).await;
    let clients = ClientMatcher::build(&[ClientConfig {
        id: "nofilter".into(),
        name: "nofilter".into(),
        ids: vec!["127.0.0.2".into()],
        tags: vec![],
        filtering_enabled: false,
    }]);
    engine.swap_state(state_with("||tracker.evil.net^", engine.pool(), clients));
    let unfiltered: IpAddr = "127.0.0.2".parse().unwrap();
    let rb = engine
        .handle(ingest(query("data.brand.com.", RecordType::A)), unfiltered)
        .await
        .into_message();
    assert_eq!(
        rb.metadata.response_code,
        ResponseCode::NoError,
        "the unfiltered client is not filtered"
    );
    let ra = engine
        .handle(ingest(query("data.brand.com.", RecordType::A)), local())
        .await
        .into_message();
    assert_eq!(
        ra.metadata.response_code,
        ResponseCode::NXDomain,
        "the filtered client must be blocked despite the cached raw answer"
    );
    assert_eq!(
        engine.cache().hit_count(),
        1,
        "the filtered client decided from cache, with no second upstream round-trip"
    );
}
