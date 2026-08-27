//! DNS upstream transports, pooling, failover, and request coalescing.

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod doh;
pub mod doq;
pub mod dot;
pub mod error;
pub mod plain;
pub mod pool;
pub mod probe_log;
pub mod spec;
pub mod tlsconf;
pub mod transport;

pub use bootstrap::{Bootstrap, SharedBootstrap};
pub use error::{Result, UpstreamError};
pub use pool::{
    test_spec, PoolEntry, PoolSettings, Resolved, Upstream, UpstreamPool, UpstreamStat,
};
pub use probe_log::{ProbeErrorKind, ProbeEvent, ProbeLog, ProbeOutcome};
pub use spec::{Host, TransportKind, UpstreamSpec};
pub use transport::{dnssec_ok, QueryKey, Transport};

#[cfg(feature = "test-trust-roots")]
pub use tlsconf::test_roots::add_trust_root;

#[cfg(test)]
mod tests;
