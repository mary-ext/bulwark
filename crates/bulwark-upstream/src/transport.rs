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
}

impl QueryKey {
    /// Extract the key from the first question of a message.
    pub fn from_message(msg: &Message) -> Option<Self> {
        let q = msg.queries.first()?;
        Some(QueryKey {
            name: q.name().to_ascii().to_ascii_lowercase(),
            rtype: q.query_type(),
            class: q.query_class(),
        })
    }
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
                && q.name()
                    .to_ascii()
                    .eq_ignore_ascii_case(&r.name().to_ascii())
        }
        // A response with no question section (rare but legal for some errors)
        // is accepted as long as the id matched.
        (Some(_), None) => true,
        _ => false,
    }
}
