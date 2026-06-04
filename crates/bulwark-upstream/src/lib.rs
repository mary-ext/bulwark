//! Bulwark upstream resolution: plain DNS, DoT, DoH, DoQ transports with
//! single-flight de-duplication and fastest-upstream selection.
//!
//! The [`UpstreamPool`] routes each query to the single best healthy upstream
//! and fails over **sequentially** — it never fans one query out to several
//! upstreams at once. Identical concurrent queries are coalesced so duplicate
//! client traffic doesn't multiply upstream load.

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod doh;
pub mod doq;
pub mod dot;
pub mod error;
pub mod plain;
pub mod pool;
pub mod spec;
pub mod tlsconf;
pub mod transport;

pub use bootstrap::{Bootstrap, SharedBootstrap};
pub use error::{Result, UpstreamError};
pub use pool::{
    test_spec, PoolEntry, PoolSettings, Resolved, Upstream, UpstreamPool, UpstreamStat,
};
pub use spec::{Host, TransportKind, UpstreamSpec};
pub use transport::{dnssec_ok, QueryKey, Transport};

#[cfg(feature = "test-trust-roots")]
pub use tlsconf::test_roots::add_trust_root;

#[cfg(test)]
mod tests;
