//! Default-value helper functions for serde `#[serde(default = "...")]`.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{UpstreamConfig, UpstreamsConfig};

pub(crate) fn one() -> u32 {
    1
}
pub(crate) fn five() -> u64 {
    5
}
pub(crate) fn ten() -> u32 {
    10
}
pub(crate) fn sixty() -> u64 {
    60
}
pub(crate) fn btrue() -> bool {
    true
}

pub(crate) fn default_dns_bind() -> Vec<SocketAddr> {
    vec!["0.0.0.0:53".parse().unwrap()]
}

pub(crate) fn default_http_bind() -> SocketAddr {
    "0.0.0.0:3000".parse().unwrap()
}

pub(crate) fn default_upstreams() -> Vec<UpstreamConfig> {
    vec![
        UpstreamConfig {
            spec: "https://dns.quad9.net/dns-query".into(),
            name: Some("Quad9 (DoH)".into()),
            enabled: true,
        },
        UpstreamConfig {
            spec: "1.1.1.1".into(),
            name: Some("Cloudflare".into()),
            enabled: true,
        },
    ]
}

pub(crate) fn default_bootstrap() -> Vec<SocketAddr> {
    vec!["1.1.1.1:53".parse().unwrap(), "9.9.9.9:53".parse().unwrap()]
}

pub(crate) fn default_cache_size() -> usize {
    10_000
}

pub(crate) fn default_max_ttl() -> u32 {
    86_400
}

/// Default serve-stale window: 24h past expiry.
pub(crate) fn default_stale_max_age() -> u32 {
    86_400
}

pub(crate) fn default_log_size() -> usize {
    10_000
}

pub(crate) fn default_stats_days() -> u32 {
    30
}

pub(crate) fn default_log_retention_days() -> u32 {
    7
}

pub(crate) fn default_block_ipv4() -> Ipv4Addr {
    Ipv4Addr::UNSPECIFIED
}

pub(crate) fn default_block_ipv6() -> Ipv6Addr {
    Ipv6Addr::UNSPECIFIED
}

// Used by UpstreamsConfig::default via struct construction; kept for symmetry.
#[allow(dead_code)]
pub(crate) fn default_upstreams_config() -> UpstreamsConfig {
    UpstreamsConfig::default()
}
