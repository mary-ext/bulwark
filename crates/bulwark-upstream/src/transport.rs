//! The [`Transport`] trait and shared query-key / wire helpers.

use futures::future::BoxFuture;
use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, RecordType};

use crate::error::{Result, UpstreamError};

/// A single upstream transport (UDP, TCP, DoT, DoH, or DoQ).
///
/// Implementations send exactly one query and return one response. They do
/// **not** retry across servers — that is the pool's job — but a transport may
/// internally fall back (e.g. UDP → TCP on truncation).
pub trait Transport: Send + Sync {
    /// Send `query` and await the response. The implementation must not mutate
    /// the caller's message; if it needs a different id (e.g. DoQ requires id
    /// 0) it clones internally.
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
    /// EDNS DNSSEC-OK (DO) bit. A DO query gets RRSIGs and can receive different
    /// answers, so it must not share a cache / single-flight entry with a non-DO
    /// query for the same name/type/class — otherwise a DNSSEC response could be
    /// served to a client that didn't ask for one, or a stripped (non-DO)
    /// response to a validating client, breaking validation.
    pub dnssec_ok: bool,
    /// Header CD (checking-disabled) bit. A CD=1 query may receive data a
    /// validating (CD=0) query would not, so it is keyed separately too.
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

/// Encode a DNS message to wire format.
pub fn encode(msg: &Message) -> Result<Vec<u8>> {
    msg.to_vec()
        .map_err(|e| UpstreamError::Proto(e.to_string()))
}

/// Decode a DNS message from wire format.
pub fn decode(bytes: &[u8]) -> Result<Message> {
    Message::from_vec(bytes).map_err(|e| UpstreamError::Proto(e.to_string()))
}

/// Validate that a response plausibly answers a query: matching id and first
/// question. Guards against off-path spoofing on UDP and mismatched demuxing.
pub fn matches_query(query: &Message, response: &Message) -> bool {
    if query.metadata.id != response.metadata.id {
        return false;
    }
    match (query.queries.first(), response.queries.first()) {
        (Some(q), Some(r)) => {
            q.query_type() == r.query_type()
                && q.query_class() == r.query_class()
                // Compare by DNS labels (case-insensitive), ignoring the
                // FQDN/relative distinction. A response decoded off the wire is
                // always FQDN; an internally built query (e.g. the bootstrap
                // resolver) may be relative. `eq_ignore_ascii_case` on
                // `to_ascii()` would treat "a.com" and "a.com." as different and
                // wrongly reject the reply.
                && q.name().eq_ignore_root(r.name())
        }
        // A response with no question section (rare but legal for some errors)
        // is accepted as long as the id matched.
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

    /// Build a query the way the bootstrap resolver does: a dotless host parsed
    /// with `Name::from_str`, then sent over the wire.
    fn query(id: u16, host: &str, fqdn: bool, rtype: RecordType) -> Message {
        let mut name = Name::from_str(host).unwrap();
        name.set_fqdn(fqdn);
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        let mut q = Query::query(name, rtype);
        q.set_query_class(DNSClass::IN);
        msg.queries.push(q);
        msg
    }

    /// Round-trip a message through wire encode/decode. The decoded question is
    /// always FQDN, mirroring a real upstream response.
    fn wire_roundtrip(msg: &Message) -> Message {
        decode(&encode(msg).unwrap()).unwrap()
    }

    #[test]
    fn bootstrap_relative_query_matches_fqdn_response() {
        // Reproduces the bootstrap bug: a relative query name must still match
        // the FQDN question echoed back in the decoded response.
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
    fn rejects_mismatched_type() {
        let q = query(0x1234, "cloudflare-dns.com", false, RecordType::A);
        let resp = wire_roundtrip(&query(0x1234, "cloudflare-dns.com", true, RecordType::AAAA));
        assert!(!matches_query(&q, &resp));
    }
}
