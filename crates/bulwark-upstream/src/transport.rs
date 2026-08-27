//! Transport interface and shared wire helpers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use hickory_proto::op::{Edns, Message};
use hickory_proto::rr::{DNSClass, RecordType};
use parking_lot::Mutex as SyncMutex;
use tokio::sync::oneshot;

use crate::error::{Result, UpstreamError};

/// Shared idle timeout for persistent upstream connections.
pub(crate) const UPSTREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// In-flight waiters and connection liveness under one lock.
#[derive(Default)]
pub(crate) struct PendingState {
    pub(crate) map: HashMap<u16, oneshot::Sender<Message>>,
    pub(crate) dead: bool,
}

pub(crate) type Pending = Arc<SyncMutex<PendingState>>;

/// Removes a cancelled in-flight query.
pub(crate) struct PendingGuard {
    pub(crate) pending: Pending,
    pub(crate) id: u16,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.pending.lock().map.remove(&self.id);
    }
}

/// A single upstream transport.
pub trait Transport: Send + Sync {
    /// Sends one query without mutating it.
    fn query<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, Result<Message>>;

    /// Human-readable description for logs.
    fn describe(&self) -> &str;
}

/// The identity of a DNS question, used as the cache & single-flight key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QueryKey {
    /// Lowercased, dot-terminated query name.
    pub name: String,
    pub rtype: RecordType,
    pub class: DNSClass,
    /// EDNS DNSSEC-OK bit.
    pub dnssec_ok: bool,
    /// Header checking-disabled bit.
    pub checking_disabled: bool,
}

impl QueryKey {
    /// Extract the key from the first question of a message.
    pub fn from_message(msg: &Message) -> Option<Self> {
        let q = msg.queries.first()?;
        Some(QueryKey {
            name: q.name().to_ascii().to_ascii_lowercase(),
            rtype: q.query_type(),
            class: q.query_class(),
            dnssec_ok: dnssec_ok(msg),
            checking_disabled: msg.metadata.checking_disabled,
        })
    }
}

/// Whether the message's EDNS OPT record has the DNSSEC-OK (DO) bit set.
pub fn dnssec_ok(msg: &Message) -> bool {
    msg.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok)
}

/// Maximum advertised EDNS UDP payload.
pub(crate) const MAX_UDP_PAYLOAD: u16 = 4096;

/// Drops unkeyed EDNS options and clamps the advertised payload.
pub fn normalize_upstream_edns(msg: &mut Message) {
    let Some(edns) = msg.edns.as_ref() else {
        return;
    };
    let has_options = !edns.options().options.is_empty();
    let over_max = edns.max_payload() > MAX_UDP_PAYLOAD;
    if !has_options && !over_max {
        return;
    }
    let mut clean = Edns::new();
    clean.set_version(edns.version());
    clean.set_max_payload(edns.max_payload().min(MAX_UDP_PAYLOAD));
    clean.set_dnssec_ok(edns.flags().dnssec_ok);
    msg.set_edns(clean);
}

/// Encode a DNS message to wire format.
pub fn encode(msg: &Message) -> Result<Vec<u8>> {
    msg.to_vec()
        .map_err(|e| UpstreamError::Proto(e.to_string()))
}

/// Decode a DNS message from wire format.
pub fn decode(bytes: &[u8]) -> Result<Message> {
    Message::from_vec(bytes).map_err(|e| UpstreamError::Proto(e.to_string()))
}

/// Checks a response id and first question against its query.
pub fn matches_query(query: &Message, response: &Message) -> bool {
    if query.metadata.id != response.metadata.id {
        return false;
    }
    match (query.queries.first(), response.queries.first()) {
        (Some(q), Some(r)) => {
            q.query_type() == r.query_type()
                && q.query_class() == r.query_class()
                && q.name().eq_ignore_root(r.name())
        }
        (Some(_), None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use std::str::FromStr;
    fn query(id: u16, host: &str, fqdn: bool, rtype: RecordType) -> Message {
        let mut name = Name::from_str(host).unwrap();
        name.set_fqdn(fqdn);
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        let mut q = Query::query(name, rtype);
        q.set_query_class(DNSClass::IN);
        msg.queries.push(q);
        msg
    }
    fn wire_roundtrip(msg: &Message) -> Message {
        decode(&encode(msg).unwrap()).unwrap()
    }

    #[test]
    fn bootstrap_relative_query_matches_fqdn_response() {
        let q = query(0x1234, "cloudflare-dns.com", false, RecordType::A);
        assert!(!q.queries[0].name().is_fqdn(), "query should be relative");
        let resp = wire_roundtrip(&q);
        assert!(resp.queries[0].name().is_fqdn(), "wire response is FQDN");
        assert!(matches_query(&q, &resp));
    }

    #[test]
    fn fqdn_query_matches_fqdn_response() {
        let q = query(0x1234, "cloudflare-dns.com", true, RecordType::A);
        let resp = wire_roundtrip(&q);
        assert!(matches_query(&q, &resp));
    }

    #[test]
    fn case_insensitive_name_match() {
        let q = query(0x1234, "Cloudflare-DNS.com", false, RecordType::A);
        let resp = wire_roundtrip(&query(0x1234, "cloudflare-dns.com", true, RecordType::A));
        assert!(matches_query(&q, &resp));
    }

    #[test]
    fn rejects_mismatched_id() {
        let q = query(0x1234, "cloudflare-dns.com", false, RecordType::A);
        let resp = wire_roundtrip(&query(0x5678, "cloudflare-dns.com", true, RecordType::A));
        assert!(!matches_query(&q, &resp));
    }

    #[test]
    fn rejects_mismatched_name() {
        let q = query(0x1234, "cloudflare-dns.com", false, RecordType::A);
        let resp = wire_roundtrip(&query(0x1234, "dns.google", true, RecordType::A));
        assert!(!matches_query(&q, &resp));
    }

    #[test]
    fn normalize_strips_options_but_keeps_do_and_payload() {
        use hickory_proto::op::Edns;
        use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
        use std::net::Ipv4Addr;

        let mut msg = query(1, "a.com", true, RecordType::A);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(true);
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                Ipv4Addr::new(192, 0, 2, 0).into(),
                24,
                0,
            )));
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, vec![1, 2, 3, 4, 5, 6, 7, 8]));
        msg.set_edns(edns);
        assert!(!msg.edns.as_ref().unwrap().options().options.is_empty());

        normalize_upstream_edns(&mut msg);

        let e = msg.edns.as_ref().expect("EDNS envelope is kept");
        assert!(
            e.options().options.is_empty(),
            "client options must be stripped"
        );
        assert!(e.flags().dnssec_ok, "the DO bit must be preserved");
        assert_eq!(e.max_payload(), 1232, "payload size must be preserved");
    }

    #[test]
    fn normalize_is_a_noop_without_edns() {
        let mut msg = query(1, "a.com", true, RecordType::A);
        assert!(msg.edns.is_none());
        normalize_upstream_edns(&mut msg);
        assert!(
            msg.edns.is_none(),
            "a query with no OPT record is untouched"
        );
    }

    #[test]
    fn normalize_clamps_oversized_payload_even_without_options() {
        use hickory_proto::op::Edns;
        let mut msg = query(1, "a.com", true, RecordType::A);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(u16::MAX);
        edns.set_dnssec_ok(true);
        msg.set_edns(edns);

        normalize_upstream_edns(&mut msg);

        let e = msg.edns.as_ref().expect("EDNS envelope is kept");
        assert_eq!(
            e.max_payload(),
            MAX_UDP_PAYLOAD,
            "oversized payload is clamped"
        );
        assert!(e.flags().dnssec_ok, "the DO bit must be preserved");
    }

    #[test]
    fn rejects_mismatched_type() {
        let q = query(0x1234, "cloudflare-dns.com", false, RecordType::A);
        let resp = wire_roundtrip(&query(0x1234, "cloudflare-dns.com", true, RecordType::AAAA));
        assert!(!matches_query(&q, &resp));
    }
}
