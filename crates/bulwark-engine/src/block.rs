//! Synthesis of blocked / rewritten / error DNS responses.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use bulwark_config::BlockingMode;
use bulwark_filter::{RewriteData, RewriteRcode};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, PTR, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// Build a response shell echoing the query's id, question, and EDNS.
fn base(query: &Message) -> Message {
    let mut m = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    m.metadata.recursion_desired = query.metadata.recursion_desired;
    m.metadata.recursion_available = true;
    for q in &query.queries {
        m.queries.push(q.clone());
    }
    if let Some(edns) = &query.edns {
        m.set_edns(edns.clone());
    }
    m
}

fn qtype(query: &Message) -> RecordType {
    query
        .queries
        .first()
        .map(|q| q.query_type())
        .unwrap_or(RecordType::A)
}

fn qname(query: &Message) -> Name {
    query
        .queries
        .first()
        .map(|q| q.name().clone())
        .unwrap_or_else(Name::root)
}

/// Push an A/AAAA record matching the query type, or leave NODATA otherwise.
fn push_ip(msg: &mut Message, name: Name, ttl: u32, v4: Ipv4Addr, v6: Ipv6Addr) {
    match qtype_of(&name, msg) {
        RecordType::A => msg
            .answers
            .push(Record::from_rdata(name, ttl, RData::A(A(v4)))),
        RecordType::AAAA => msg
            .answers
            .push(Record::from_rdata(name, ttl, RData::AAAA(AAAA(v6)))),
        // Any other type: NODATA (NOERROR, empty answer).
        _ => {}
    }
}

fn qtype_of(_name: &Name, msg: &Message) -> RecordType {
    msg.queries
        .first()
        .map(|q| q.query_type())
        .unwrap_or(RecordType::A)
}

/// A synthetic SOA for the authority section so clients negative-cache a blocked
/// response for `blocked_ttl` (RFC 2308: the negative TTL is `min(SOA.minimum,
/// record TTL)`). Without it, NXDOMAIN/NODATA blocks aren't cached and the same
/// blocked name is re-queried (and re-logged) on every lookup.
fn negative_soa(name: Name, ttl: u32) -> Record {
    let mname =
        Name::from_str("fake-for-negative-caching.bulwark.invalid.").unwrap_or_else(|_| Name::root());
    let rname = Name::from_str("hostmaster.bulwark.invalid.").unwrap_or_else(|_| Name::root());
    // blocked_ttl is small in practice; clamp to a positive i32 for the
    // refresh/retry/expire fields just in case.
    let secs = ttl.min(i32::MAX as u32) as i32;
    let soa = SOA::new(
        mname,
        rname,
        1,                       // serial
        secs,                    // refresh
        secs,                    // retry
        secs.saturating_mul(10), // expire
        ttl,                     // minimum — drives the negative-cache TTL
    );
    Record::from_rdata(name, ttl, RData::SOA(soa))
}

/// Synthesize a blocked response per the configured [`BlockingMode`].
pub fn block_response(
    query: &Message,
    mode: BlockingMode,
    custom_v4: Ipv4Addr,
    custom_v6: Ipv6Addr,
    ttl: u32,
) -> Message {
    let mut m = base(query);
    let name = qname(query);
    match mode {
        BlockingMode::NxDomain => {
            m.metadata.response_code = ResponseCode::NXDomain;
            m.authorities.push(negative_soa(name, ttl));
        }
        BlockingMode::Refused => m.metadata.response_code = ResponseCode::Refused,
        BlockingMode::NoData => m.authorities.push(negative_soa(name, ttl)), // NOERROR, empty + SOA
        BlockingMode::NullIp => push_ip(
            &mut m,
            name,
            ttl,
            Ipv4Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
        ),
        BlockingMode::CustomIp => push_ip(&mut m, name, ttl, custom_v4, custom_v6),
    }
    m
}

/// The result of synthesizing a rewrite. `Cname` indicates the pipeline should
/// resolve the target and append its addresses.
pub enum Rewritten {
    /// A complete response is ready.
    Done(Message),
    /// A CNAME was inserted; resolve `target` and append A/AAAA answers.
    ResolveCname { message: Message, target: Name },
}

/// Synthesize a response for a `$dnsrewrite` / hosts rewrite.
pub fn rewrite_response(query: &Message, data: &RewriteData, ttl: u32) -> Rewritten {
    let mut m = base(query);
    let name = qname(query);
    let qt = qtype(query);
    match data {
        RewriteData::A(ip) => {
            if qt == RecordType::A {
                m.answers
                    .push(Record::from_rdata(name, ttl, RData::A(A(*ip))));
            }
            Rewritten::Done(m)
        }
        RewriteData::Aaaa(ip) => {
            if qt == RecordType::AAAA {
                m.answers
                    .push(Record::from_rdata(name, ttl, RData::AAAA(AAAA(*ip))));
            }
            Rewritten::Done(m)
        }
        RewriteData::Txt(text) => {
            if qt == RecordType::TXT {
                m.answers.push(Record::from_rdata(
                    name,
                    ttl,
                    RData::TXT(TXT::new(vec![text.clone()])),
                ));
            }
            Rewritten::Done(m)
        }
        RewriteData::Mx {
            preference,
            exchange,
        } => {
            if qt == RecordType::MX {
                let ex = Name::from_str(exchange).unwrap_or_else(|_| Name::root());
                m.answers.push(Record::from_rdata(
                    name,
                    ttl,
                    RData::MX(MX::new(*preference, ex)),
                ));
            }
            Rewritten::Done(m)
        }
        RewriteData::Ptr(target) => {
            if qt == RecordType::PTR {
                let t = Name::from_str(target).unwrap_or_else(|_| Name::root());
                m.answers
                    .push(Record::from_rdata(name, ttl, RData::PTR(PTR(t))));
            }
            Rewritten::Done(m)
        }
        RewriteData::Rcode(rc) => {
            m.metadata.response_code = match rc {
                RewriteRcode::NoError => ResponseCode::NoError,
                RewriteRcode::NxDomain => ResponseCode::NXDomain,
                RewriteRcode::Refused => ResponseCode::Refused,
                RewriteRcode::ServFail => ResponseCode::ServFail,
            };
            Rewritten::Done(m)
        }
        RewriteData::Cname(target) => {
            let target_name = Name::from_str(target).unwrap_or_else(|_| Name::root());
            m.answers.push(Record::from_rdata(
                name,
                ttl,
                RData::CNAME(CNAME(target_name.clone())),
            ));
            if matches!(qt, RecordType::A | RecordType::AAAA) {
                Rewritten::ResolveCname {
                    message: m,
                    target: target_name,
                }
            } else {
                Rewritten::Done(m)
            }
        }
    }
}

/// A simple error response with the given response code.
pub fn error_response(query: &Message, rcode: ResponseCode) -> Message {
    let mut m = base(query);
    m.metadata.response_code = rcode;
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::DNSClass;

    fn query(name: &str, rtype: RecordType) -> Message {
        let mut m = Message::new(7, MessageType::Query, OpCode::Query);
        let mut q = Query::query(Name::from_str(name).unwrap(), rtype);
        q.set_query_class(DNSClass::IN);
        m.queries.push(q);
        m
    }

    #[test]
    fn nxdomain_block() {
        let r = block_response(
            &query("a.com.", RecordType::A),
            BlockingMode::NxDomain,
            Ipv4Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
            10,
        );
        assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(r.metadata.id, 7);
    }

    #[test]
    fn nxdomain_and_nodata_carry_soa_for_negative_caching() {
        for mode in [BlockingMode::NxDomain, BlockingMode::NoData] {
            let r = block_response(
                &query("a.com.", RecordType::A),
                mode,
                Ipv4Addr::UNSPECIFIED,
                Ipv6Addr::UNSPECIFIED,
                42,
            );
            assert_eq!(r.authorities.len(), 1, "{mode:?} should carry an SOA");
            match &r.authorities[0].data {
                RData::SOA(soa) => assert_eq!(
                    soa.minimum, 42,
                    "SOA minimum drives the negative-cache TTL"
                ),
                other => panic!("expected SOA authority, got {other:?}"),
            }
            assert_eq!(r.authorities[0].ttl, 42);
        }
    }

    #[test]
    fn null_ip_block_a() {
        let r = block_response(
            &query("a.com.", RecordType::A),
            BlockingMode::NullIp,
            Ipv4Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
            10,
        );
        assert_eq!(r.answers.len(), 1);
        assert!(matches!(&r.answers[0].data, RData::A(A(ip)) if ip.is_unspecified()));
    }

    #[test]
    fn null_ip_block_aaaa_for_a_query_is_nodata() {
        // A null-IP block for an HTTPS query yields NODATA.
        let r = block_response(
            &query("a.com.", RecordType::HTTPS),
            BlockingMode::NullIp,
            Ipv4Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
            10,
        );
        assert!(r.answers.is_empty());
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    }

    #[test]
    fn rewrite_a() {
        let data = RewriteData::A(Ipv4Addr::new(1, 2, 3, 4));
        match rewrite_response(&query("a.com.", RecordType::A), &data, 30) {
            Rewritten::Done(m) => assert_eq!(m.answers.len(), 1),
            _ => panic!("expected done"),
        }
    }

    #[test]
    fn rewrite_cname_requests_resolution() {
        let data = RewriteData::Cname("target.example.net.".into());
        match rewrite_response(&query("a.com.", RecordType::A), &data, 30) {
            Rewritten::ResolveCname { target, .. } => {
                assert_eq!(target.to_ascii(), "target.example.net.")
            }
            _ => panic!("expected cname resolution"),
        }
    }
}
