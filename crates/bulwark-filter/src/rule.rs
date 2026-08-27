//! Filtering rule model.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// What a rule does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Block the query (synthesize a blocked response).
    Block,
    /// Allow / unblock the query (an `@@` exception).
    Allow,
    /// Rewrite the response (`$dnsrewrite=` or a hosts-file IP).
    Rewrite,
}

/// How a rule matches a query name.
#[derive(Debug, Clone)]
pub enum Pattern {
    /// Matches the domain itself and any subdomain (`||example.org^` or a bare
    /// `example.org` line in a blocklist).
    Subdomain(String),
    /// Matches only the exact domain (hosts-file entries, fully-anchored rules).
    Exact(String),
    /// A wildcard pattern compiled to a regex (`*.example.org`, `ads.*`).
    Wildcard(Regex),
    /// A user-supplied regex rule (`/regexp/`).
    Regex(Regex),
}

impl Pattern {
    /// Returns the indexable domain for exact and subdomain patterns.
    pub fn index_key(&self) -> Option<(&str, bool)> {
        match self {
            Pattern::Subdomain(d) => Some((d.as_str(), true)),
            Pattern::Exact(d) => Some((d.as_str(), false)),
            _ => None,
        }
    }
}

/// A DNS record type filter from `$dnstype=A|AAAA` (with optional `~` negation).
#[derive(Debug, Clone, Default)]
pub struct DnsTypeFilter {
    /// Allowed record types (uppercase, e.g. `A`, `AAAA`, `HTTPS`). Empty means
    /// "any".
    pub include: Vec<String>,
    /// Negated record types — the rule applies to everything *except* these.
    pub exclude: Vec<String>,
}

impl DnsTypeFilter {
    /// Does this filter apply to the given (uppercase) record type string?
    pub fn matches(&self, rtype: &str) -> bool {
        if !self.exclude.is_empty() && self.exclude.iter().any(|t| t == rtype) {
            return false;
        }
        if !self.include.is_empty() {
            return self.include.iter().any(|t| t == rtype);
        }
        true
    }
}

/// One entry of a `$client=` or `$ctag=` filter.
#[derive(Debug, Clone)]
pub enum ClientMatch {
    Ip(std::net::IpAddr),
    Net(IpNet),
    Name(String),
}

/// A `$client=` filter (IPs, CIDRs, or client names), with `~` negation.
#[derive(Debug, Clone, Default)]
pub struct ClientFilter {
    pub include: Vec<ClientMatch>,
    pub exclude: Vec<ClientMatch>,
}

/// Information about the client issuing a query, used for `$client`/`$ctag`.
#[derive(Debug, Clone, Default)]
pub struct ClientInfo<'a> {
    pub ip: Option<std::net::IpAddr>,
    pub name: Option<&'a str>,
    pub tags: &'a [String],
}

impl ClientFilter {
    fn entry_matches(m: &ClientMatch, client: &ClientInfo<'_>) -> bool {
        match m {
            ClientMatch::Ip(ip) => client.ip == Some(*ip),
            ClientMatch::Net(net) => client.ip.is_some_and(|ip| net.contains(&ip)),
            ClientMatch::Name(n) => client.name == Some(n.as_str()),
        }
    }

    pub fn matches(&self, client: &ClientInfo<'_>) -> bool {
        if self.exclude.iter().any(|m| Self::entry_matches(m, client)) {
            return false;
        }
        if !self.include.is_empty() {
            return self.include.iter().any(|m| Self::entry_matches(m, client));
        }
        true
    }
}

/// A `$ctag=` filter on client tags, with `~` negation.
#[derive(Debug, Clone, Default)]
pub struct CtagFilter {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl CtagFilter {
    pub fn matches(&self, tags: &[String]) -> bool {
        let has = |t: &String| tags.iter().any(|x| x == t);
        if self.exclude.iter().any(has) {
            return false;
        }
        if !self.include.is_empty() {
            return self.include.iter().any(has);
        }
        true
    }
}

/// The response a `$dnsrewrite` (or hosts IP) produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RewriteData {
    /// Force an IPv4 answer.
    A(Ipv4Addr),
    /// Force an IPv6 answer.
    Aaaa(Ipv6Addr),
    /// Force a CNAME answer (the engine resolves the target).
    Cname(String),
    /// Force a TXT answer.
    Txt(String),
    /// Force an MX answer (`preference exchange`).
    Mx { preference: u16, exchange: String },
    /// Force a PTR answer (a hostname).
    Ptr(String),
    /// Force a specific response code (NXDOMAIN / REFUSED / NOERROR / SERVFAIL).
    Rcode(RewriteRcode),
}

/// Response codes expressible via `$dnsrewrite=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RewriteRcode {
    NoError,
    NxDomain,
    Refused,
    ServFail,
}

/// Optional DNS rule modifiers.
#[derive(Debug, Clone, Default)]
pub struct RuleMods {
    pub important: bool,
    pub dnstype: Option<DnsTypeFilter>,
    pub client: Option<ClientFilter>,
    pub ctag: Option<CtagFilter>,
    /// `$denyallow=` domains excluded from this (blocking) rule.
    pub denyallow: Vec<String>,
    pub rewrite: Option<RewriteData>,
}

impl RuleMods {
    /// Whether no modifier is set.
    pub fn is_empty(&self) -> bool {
        !self.important
            && self.dnstype.is_none()
            && self.client.is_none()
            && self.ctag.is_none()
            && self.denyallow.is_empty()
            && self.rewrite.is_none()
    }
}

/// Filtering rule retained by the compiled engine.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Stable id (index into the engine's rule vector).
    pub id: u32,
    /// The original source line, kept for display & logging.
    pub raw: String,
    pub action: Action,
    pub pattern: Pattern,
    /// Optional DNS modifiers; `None` for the common plain-block rule.
    pub mods: Option<Box<RuleMods>>,
    /// Which loaded list this rule came from.
    pub list_id: u32,
}

/// Rule plus build-only metadata.
#[derive(Debug, Clone)]
pub struct BuildRule {
    pub rule: Rule,
    /// `$badfilter` — this rule disables a matching rule rather than acting.
    pub badfilter: bool,
    /// Canonical signature (pattern + sorted modifiers minus badfilter), used to
    /// pair `$badfilter` rules and de-duplicate.
    pub signature: String,
    /// Safe interior token hashes for the wildcard reverse index.
    pub index_tokens: Vec<u32>,
}

impl Rule {
    /// Priority score used to choose a winner among matching rules. Higher wins:
    /// `$important` adds a large bonus; among equal importance, allow beats
    /// block, and rewrites sit alongside blocks.
    pub fn priority(&self) -> u32 {
        let mut score = match self.action {
            Action::Allow => 2,
            Action::Block | Action::Rewrite => 1,
        };
        if self.mods.as_ref().is_some_and(|m| m.important) {
            score += 100;
        }
        score
    }

    /// The rewrite data, if this is a rewrite rule.
    pub fn rewrite(&self) -> Option<&RewriteData> {
        self.mods.as_ref().and_then(|m| m.rewrite.as_ref())
    }
}
