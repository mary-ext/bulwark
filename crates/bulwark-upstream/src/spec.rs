//! Parsing of upstream server specifications.
//!
//! Accepted forms (AdGuard-compatible):
//! * `8.8.8.8`, `8.8.8.8:53`            — plain DNS over UDP (TCP fallback)
//! * `udp://1.1.1.1`                     — plain DNS over UDP
//! * `tcp://1.1.1.1`                     — plain DNS over TCP
//! * `tls://dns.google`                  — DNS-over-TLS (default port 853)
//! * `https://dns.google/dns-query`      — DNS-over-HTTPS
//! * `quic://dns.adguard.com`            — DNS-over-QUIC (default port 853)
//!
//! The host may be an IP literal or a hostname; hostnames are resolved via the
//! bootstrap resolver at connection time.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::UpstreamError;

/// The wire protocol used to reach an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

impl TransportKind {
    pub fn default_port(self) -> u16 {
        match self {
            TransportKind::Udp | TransportKind::Tcp => 53,
            TransportKind::Tls | TransportKind::Quic => 853,
            TransportKind::Https => 443,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::Udp => "udp",
            TransportKind::Tcp => "tcp",
            TransportKind::Tls => "tls",
            TransportKind::Https => "https",
            TransportKind::Quic => "quic",
        }
    }
}

/// Where the host part of a spec points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}

impl Host {
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Host::Ip(ip) => Some(*ip),
            Host::Name(_) => None,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Ip(ip) => write!(f, "{ip}"),
            Host::Name(n) => write!(f, "{n}"),
        }
    }
}

/// A fully-parsed upstream specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSpec {
    pub kind: TransportKind,
    pub host: Host,
    pub port: u16,
    /// HTTP path for DoH (e.g. `/dns-query`).
    pub path: String,
    /// The original spec string, used for display.
    pub display: String,
}

impl UpstreamSpec {
    /// Parse a spec string.
    pub fn parse(input: &str) -> Result<Self, UpstreamError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(UpstreamError::InvalidSpec("empty".into()));
        }

        let (kind, rest) = match s.split_once("://") {
            Some(("udp", r)) => (TransportKind::Udp, r),
            Some(("tcp", r)) => (TransportKind::Tcp, r),
            Some(("tls", r)) => (TransportKind::Tls, r),
            Some(("https", r)) => (TransportKind::Https, r),
            Some(("h3", r)) => (TransportKind::Https, r),
            Some(("quic", r)) => (TransportKind::Quic, r),
            Some((scheme, _)) => {
                return Err(UpstreamError::InvalidSpec(format!(
                    "unknown scheme {scheme}"
                )))
            }
            None => (TransportKind::Udp, s),
        };

        // Split off an HTTP path (DoH).
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, format!("/{p}")),
            None => (rest, "/dns-query".to_string()),
        };

        let (host, port) = split_host_port(authority, kind.default_port())?;

        Ok(UpstreamSpec {
            kind,
            host,
            port,
            path,
            display: s.to_string(),
        })
    }

    /// Hostname to use for TLS SNI / HTTP Host. For IP literals this is the IP
    /// string (certificates for public resolvers carry IP SANs).
    pub fn server_name(&self) -> String {
        self.host.to_string()
    }
}

impl fmt::Display for UpstreamSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display)
    }
}

/// Split `host[:port]`, supporting bracketed IPv6 (`[::1]:53`).
fn split_host_port(s: &str, default_port: u16) -> Result<(Host, u16), UpstreamError> {
    if let Some(rest) = s.strip_prefix('[') {
        // Bracketed IPv6.
        let (ip_str, after) = rest
            .split_once(']')
            .ok_or_else(|| UpstreamError::InvalidSpec(format!("unterminated [ in {s}")))?;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| UpstreamError::InvalidSpec(format!("bad IPv6 {ip_str}")))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| UpstreamError::InvalidSpec(format!("bad port {p}")))?,
            None => default_port,
        };
        return Ok((Host::Ip(ip), port));
    }

    // If it parses cleanly as a bare IP (incl. unbracketed IPv6), no port given.
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((Host::Ip(ip), default_port));
    }

    match s.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse()
                .map_err(|_| UpstreamError::InvalidSpec(format!("bad port {p}")))?;
            let host = match h.parse::<IpAddr>() {
                Ok(ip) => Host::Ip(ip),
                Err(_) => Host::Name(h.to_string()),
            };
            Ok((host, port))
        }
        None => Ok((Host::Name(s.to_string()), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_ip() {
        let s = UpstreamSpec::parse("8.8.8.8").unwrap();
        assert_eq!(s.kind, TransportKind::Udp);
        assert_eq!(s.host, Host::Ip("8.8.8.8".parse().unwrap()));
        assert_eq!(s.port, 53);
    }

    #[test]
    fn parse_ip_with_port() {
        let s = UpstreamSpec::parse("8.8.8.8:5353").unwrap();
        assert_eq!(s.port, 5353);
    }

    #[test]
    fn parse_dot() {
        let s = UpstreamSpec::parse("tls://dns.google").unwrap();
        assert_eq!(s.kind, TransportKind::Tls);
        assert_eq!(s.host, Host::Name("dns.google".into()));
        assert_eq!(s.port, 853);
    }

    #[test]
    fn parse_doh_with_path() {
        let s = UpstreamSpec::parse("https://dns.google/dns-query").unwrap();
        assert_eq!(s.kind, TransportKind::Https);
        assert_eq!(s.port, 443);
        assert_eq!(s.path, "/dns-query");
    }

    #[test]
    fn parse_doq() {
        let s = UpstreamSpec::parse("quic://dns.adguard.com").unwrap();
        assert_eq!(s.kind, TransportKind::Quic);
        assert_eq!(s.port, 853);
    }

    #[test]
    fn parse_ipv6_bracketed() {
        let s = UpstreamSpec::parse("[2606:4700:4700::1111]:853").unwrap();
        assert_eq!(s.port, 853);
        assert_eq!(s.host, Host::Ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn parse_ipv6_bare() {
        let s = UpstreamSpec::parse("2606:4700:4700::1111").unwrap();
        assert_eq!(s.host, Host::Ip("2606:4700:4700::1111".parse().unwrap()));
        assert_eq!(s.port, 53);
    }
}
