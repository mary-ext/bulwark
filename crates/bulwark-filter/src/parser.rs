//! Parsing of individual filter-list lines into [`Rule`]s.
//!
//! Supports three line shapes:
//! * **Hosts-file** lines: `0.0.0.0 ads.example.com` (block) or
//!   `1.2.3.4 host.example.com` (rewrite). One line may list several hosts.
//! * **AdBlock-style** DNS rules: `||example.org^`, `@@||example.org^`,
//!   `*.tracker.com`, with the DNS-relevant modifiers
//!   (`$important`, `$badfilter`, `$dnstype`, `$dnsrewrite`, `$client`,
//!   `$ctag`, `$denyallow`).
//! * **Regex** rules: `/^ads?\..*/`.
//!
//! Plain bare-domain lines (`example.org`) are treated as `||example.org^`
//! (block the domain and its subdomains), matching how blocklists are used.

use std::net::IpAddr;

use regex::{Regex, RegexBuilder};

use crate::rule::*;

/// Maximum source length of a `/regex/` rule. Rust's `regex` engine matches in
/// linear time (no catastrophic backtracking), but a pathological source can
/// still blow up *compile* time/memory, so over-long regexes are rejected.
const MAX_REGEX_LEN: usize = 1000;

/// Per-regex compiled-size cap (bytes). Bounds the memory a single rule's
/// compiled program may use, so one hostile list entry can't exhaust memory.
const REGEX_SIZE_LIMIT: usize = 256 * 1024;

/// Compile `src` (which already carries any needed flags like `(?i)`) with the
/// shared size cap, mapping failures to a [`ParseError::Regex`].
fn compile_regex(src: &str) -> Result<Regex, ParseError> {
    RegexBuilder::new(src)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| ParseError::Regex(e.to_string()))
}

/// Outcome of parsing one line.
#[derive(Debug)]
pub enum Parsed {
    /// One or more rules (hosts lines can yield several).
    Rules(Vec<Rule>),
    /// A comment, blank line, or list header — nothing to do.
    Ignored,
    /// A syntactically valid line we intentionally skip (e.g. it carries only
    /// HTTP-only modifiers irrelevant to DNS).
    Unsupported(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid regex rule: {0}")]
    Regex(String),
    #[error("invalid rule: {0}")]
    Invalid(String),
}

/// Hostnames commonly present in hosts files that must never be blocked.
const HOSTS_NOISE: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
];

fn is_blocking_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_loopback(),
    }
}

/// Normalise a domain: lowercase, strip a trailing dot.
fn norm_domain(d: &str) -> String {
    d.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// If `s` is an IP literal — bare (`1.2.3.4`, `1234::cdef`) or bracketed
/// (`[1234::cdef]`) — return its canonical [`IpAddr`] string. IP rules are
/// stored under this canonical key so they match the resolved addresses the
/// response-side filter checks (also via `IpAddr::to_string()`). A bare v6
/// literal is the *only* way to block a v6 address — [`is_dns_hostname`] rejects
/// the colons — matching AdGuard Home, which accepts bare-IP blocklist lines for
/// both families.
fn ip_literal(s: &str) -> Option<String> {
    let bare = s
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(s);
    bare.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// Does `line` carry an AdGuard/ABP **cosmetic** marker — element hiding (`##`,
/// `#@#`), extended-CSS (`#?#`), CSS injection (`#$#`), scriptlets (`#%#`), their
/// `@`-exception variants, or HTML filtering (`$$`, `$@$`)? Such rules act on
/// page content and can never match a DNS hostname, so they're skipped rather
/// than mis-parsed into a bogus domain. The marker shape is `#`, optional `@`,
/// optional one of `? $ %`, then `#`. Mirrors urlfilter's cosmetic-marker set.
fn is_cosmetic(line: &str) -> bool {
    let b = line.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i < n {
        match b[i] {
            b'#' => {
                let mut j = i + 1;
                while j < n && matches!(b[j], b'@' | b'?' | b'$' | b'%') {
                    j += 1;
                }
                if j < n && b[j] == b'#' {
                    return true;
                }
            }
            b'$' if line[i..].starts_with("$$") || line[i..].starts_with("$@$") => {
                return true;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Is `d` a plausible DNS hostname (ASCII labels of letters/digits/`-`/`_`,
/// dot-separated, within length limits)? Used to reject non-DNS junk — URL-path
/// rules, cosmetic selectors, lines with spaces — that would otherwise be stored
/// as a bogus domain pattern. Punycode (`xn--…`) and underscore service labels
/// (`_dmarc`) pass; slashes, spaces, `#`, `:` and empty labels don't.
fn is_dns_hostname(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
}

/// Parse one line into zero or more rules.
pub fn parse_line(line: &str) -> Result<Parsed, ParseError> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(Parsed::Ignored);
    }
    // Comments and AdBlock list headers.
    if line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
        return Ok(Parsed::Ignored);
    }

    // Try hosts-file format first (starts with an IP + whitespace + host(s)).
    if let Some(rules) = try_parse_hosts(line) {
        return Ok(if rules.is_empty() {
            Parsed::Ignored
        } else {
            Parsed::Rules(rules)
        });
    }

    // Cosmetic / HTML-filtering rules act on page content, never on DNS names —
    // skip them rather than mis-parse `example.com##.ad` into a bogus domain.
    // Checked after hosts parsing so a `##`-style inline comment on a hosts line
    // isn't mistaken for a cosmetic marker.
    if is_cosmetic(line) {
        return Ok(Parsed::Unsupported(line.to_string()));
    }

    parse_adblock(line)
}

/// Attempt to parse a hosts-file line. Returns `None` if it is not one.
fn try_parse_hosts(line: &str) -> Option<Vec<Rule>> {
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    let ip: IpAddr = first.parse().ok()?;
    // Collect hostnames until an inline comment begins.
    let mut hosts = Vec::new();
    for tok in parts {
        if tok.starts_with('#') {
            break;
        }
        hosts.push(tok);
    }
    if hosts.is_empty() {
        return None;
    }

    let block = is_blocking_ip(ip);
    let mut rules = Vec::new();
    for host in hosts {
        let domain = norm_domain(host);
        if domain.is_empty() || HOSTS_NOISE.contains(&domain.as_str()) {
            continue;
        }
        let (action, mods) = if block {
            (Action::Block, None)
        } else {
            let rw = match ip {
                IpAddr::V4(v4) => RewriteData::A(v4),
                IpAddr::V6(v6) => RewriteData::Aaaa(v6),
            };
            (
                Action::Rewrite,
                Some(Box::new(RuleMods {
                    rewrite: Some(rw),
                    ..Default::default()
                })),
            )
        };
        rules.push(Rule {
            id: 0,
            raw: format!("{first} {host}"),
            action,
            pattern: Pattern::Exact(domain.clone()),
            mods,
            badfilter: false,
            list_id: 0,
            signature: format!("hosts|{domain}|{}", if block { "block" } else { "rewrite" }),
            index_tokens: Vec::new(),
        });
    }
    Some(rules)
}

/// Split a rule into its pattern part and optional modifier string.
fn split_modifiers(s: &str) -> (&str, Option<&str>) {
    if s.starts_with('/') {
        // Regex rule: `/regex/` or `/regex/$modifiers`.
        if let Some(idx) = s.find("/$") {
            return (&s[..=idx], Some(&s[idx + 2..]));
        }
        return (s, None);
    }
    match s.find('$') {
        Some(idx) => (&s[..idx], Some(&s[idx + 1..])),
        None => (s, None),
    }
}

fn parse_adblock(line: &str) -> Result<Parsed, ParseError> {
    let mut action = Action::Block;
    let mut body = line;
    if let Some(rest) = body.strip_prefix("@@") {
        action = Action::Allow;
        body = rest;
    }

    let (pattern_str, mods_str) = split_modifiers(body);
    let pattern_str = pattern_str.trim();
    if pattern_str.is_empty() {
        return Err(ParseError::Invalid("empty pattern".into()));
    }

    // Build the canonical signature (for $badfilter pairing) before consuming.
    let signature = make_signature(action, pattern_str, mods_str);

    let (pattern, index_tokens) = parse_pattern(pattern_str)?;
    let mut badfilter = false;
    let mut m = RuleMods::default();

    if let Some(mods) = mods_str {
        for tok in mods.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            let (key, value) = match tok.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (tok, None),
            };
            match key {
                "important" => m.important = true,
                "badfilter" => badfilter = true,
                "dnstype" => m.dnstype = Some(parse_dnstype(value.unwrap_or(""))?),
                "client" => m.client = Some(parse_client(value.unwrap_or(""))?),
                "ctag" => m.ctag = Some(parse_ctag(value.unwrap_or(""))?),
                "denyallow" => {
                    let domains: Vec<String> = value
                        .unwrap_or("")
                        .split('|')
                        .filter(|s| !s.is_empty())
                        .map(norm_domain)
                        .collect();
                    // An empty `$denyallow=` would otherwise become a no-op that
                    // silently changes the rule's meaning; reject it instead.
                    if domains.is_empty() {
                        return Err(ParseError::Invalid(
                            "$denyallow requires at least one domain".into(),
                        ));
                    }
                    m.denyallow = domains;
                }
                "dnsrewrite" => {
                    m.rewrite = Some(parse_dnsrewrite(value.unwrap_or(""))?);
                    if action == Action::Block {
                        action = Action::Rewrite;
                    }
                }
                // HTTP/cosmetic-only modifiers are irrelevant to DNS filtering;
                // skip the whole rule rather than match it incorrectly.
                _ => return Ok(Parsed::Unsupported(line.to_string())),
            }
        }
    }

    let rule = Rule {
        id: 0,
        raw: line.to_string(),
        action,
        pattern,
        mods: if m.is_empty() {
            None
        } else {
            Some(Box::new(m))
        },
        badfilter,
        list_id: 0,
        signature,
        index_tokens,
    };

    Ok(Parsed::Rules(vec![rule]))
}

/// Canonical signature: `@@`? + lowercased pattern + sorted modifiers (minus
/// `badfilter`). A `$badfilter` rule shares its signature with the rule it
/// cancels.
fn make_signature(action: Action, pattern: &str, mods: Option<&str>) -> String {
    let prefix = if action == Action::Allow { "@@" } else { "" };
    let mut parts: Vec<String> = mods
        .map(|m| {
            m.split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty() && *s != "badfilter")
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();
    parts.sort();
    format!(
        "{prefix}{}|${}",
        pattern.to_ascii_lowercase(),
        parts.join(",")
    )
}

/// Parse a pattern into a [`Pattern`] plus the safe reverse-index tokens (only
/// non-empty for wildcard patterns).
fn parse_pattern(p: &str) -> Result<(Pattern, Vec<u32>), ParseError> {
    // Regex rule (always falls back to a linear scan — no safe literal tokens).
    if p.starts_with('/') && p.ends_with('/') && p.len() >= 2 {
        let inner = &p[1..p.len() - 1];
        if inner.len() > MAX_REGEX_LEN {
            return Err(ParseError::Regex(format!(
                "regex too long ({} > {MAX_REGEX_LEN} chars)",
                inner.len()
            )));
        }
        let re = compile_regex(&format!("(?i){inner}"))?;
        return Ok((Pattern::Regex(re), Vec::new()));
    }

    let mut s = p;
    let mut subdomain_anchor = false;
    let mut start_anchor = false;
    if let Some(rest) = s.strip_prefix("||") {
        subdomain_anchor = true;
        s = rest;
    } else if let Some(rest) = s.strip_prefix('|') {
        start_anchor = true;
        s = rest;
    }
    let mut end_anchor = false;
    if let Some(rest) = s.strip_suffix('^') {
        end_anchor = true;
        s = rest;
    } else if let Some(rest) = s.strip_suffix('|') {
        end_anchor = true;
        s = rest;
    }
    let s = s.trim_end_matches('^'); // tolerate stray separators

    if s.contains('*') || s.contains('^') {
        let re = build_wildcard_regex(s, subdomain_anchor, start_anchor, end_anchor)?;
        let tokens = crate::token::tokenize_pattern_safe(&s.to_ascii_lowercase());
        return Ok((Pattern::Wildcard(re), tokens));
    }

    // An IP literal (v4 or v6, bare or bracketed) is an exact-host rule, not a
    // domain — block by resolved address, with anchors ignored as meaningless.
    // This must come before `is_dns_hostname`, which rejects the v6 colons.
    if let Some(ip) = ip_literal(s) {
        return Ok((Pattern::Exact(ip), Vec::new()));
    }

    let domain = norm_domain(s);
    if domain.is_empty() {
        return Err(ParseError::Invalid("empty domain".into()));
    }
    if !is_dns_hostname(&domain) {
        return Err(ParseError::Invalid(format!("not a DNS hostname: {domain}")));
    }
    if start_anchor {
        // `|example.com|` — exact host match.
        Ok((Pattern::Exact(domain), Vec::new()))
    } else {
        // `||example.com^` or bare `example.com` — domain + subdomains.
        Ok((Pattern::Subdomain(domain), Vec::new()))
    }
}

/// Convert an AdBlock wildcard pattern into an anchored, case-insensitive regex
/// matched against the (lowercased) query hostname.
fn build_wildcard_regex(
    body: &str,
    subdomain_anchor: bool,
    start_anchor: bool,
    end_anchor: bool,
) -> Result<Regex, ParseError> {
    let mut re = String::from("(?i)");
    if subdomain_anchor {
        // Start of hostname or at a label boundary.
        re.push_str("(?:^|\\.)");
    } else if start_anchor {
        re.push('^');
    }
    for ch in body.chars() {
        match ch {
            '*' => re.push_str(".*"),
            // `^` separator: a domain-name separator or end of string.
            '^' => re.push_str("(?:[^a-z0-9._-]|$)"),
            c if "\\.+?()[]{}|$".contains(c) => {
                re.push('\\');
                re.push(c);
            }
            c => re.push(c),
        }
    }
    if end_anchor {
        re.push('$');
    }
    compile_regex(&re)
}

fn parse_dnstype(value: &str) -> Result<DnsTypeFilter, ParseError> {
    let mut f = DnsTypeFilter::default();
    for t in value.split('|').filter(|s| !s.is_empty()) {
        if let Some(neg) = t.strip_prefix('~') {
            f.exclude.push(neg.to_ascii_uppercase());
        } else {
            f.include.push(t.to_ascii_uppercase());
        }
    }
    // An empty `$dnstype=` (or one with only separators) must not degrade to a
    // match-everything rule; reject it.
    if f.include.is_empty() && f.exclude.is_empty() {
        return Err(ParseError::Invalid(
            "$dnstype requires at least one record type".into(),
        ));
    }
    Ok(f)
}

fn parse_client(value: &str) -> Result<ClientFilter, ParseError> {
    let mut f = ClientFilter::default();
    for raw in value.split('|').filter(|s| !s.is_empty()) {
        let (neg, spec) = match raw.strip_prefix('~') {
            Some(rest) => (true, rest),
            None => (false, raw),
        };
        // Strip surrounding quotes used for names with special chars.
        let spec = spec.trim_matches('"').trim_matches('\'');
        let m = if let Ok(net) = spec.parse::<ipnet::IpNet>() {
            ClientMatch::Net(net)
        } else if let Ok(ip) = spec.parse::<IpAddr>() {
            ClientMatch::Ip(ip)
        } else {
            ClientMatch::Name(spec.to_string())
        };
        if neg {
            f.exclude.push(m);
        } else {
            f.include.push(m);
        }
    }
    if f.include.is_empty() && f.exclude.is_empty() {
        return Err(ParseError::Invalid(
            "$client requires at least one client".into(),
        ));
    }
    Ok(f)
}

fn parse_ctag(value: &str) -> Result<CtagFilter, ParseError> {
    let mut f = CtagFilter::default();
    for t in value.split('|').filter(|s| !s.is_empty()) {
        if let Some(neg) = t.strip_prefix('~') {
            f.exclude.push(neg.to_string());
        } else {
            f.include.push(t.to_string());
        }
    }
    if f.include.is_empty() && f.exclude.is_empty() {
        return Err(ParseError::Invalid(
            "$ctag requires at least one tag".into(),
        ));
    }
    Ok(f)
}

fn parse_dnsrewrite(value: &str) -> Result<RewriteData, ParseError> {
    let v = value.trim();
    // Keyword response codes (short form).
    match v.to_ascii_uppercase().as_str() {
        "NOERROR" => return Ok(RewriteData::Rcode(RewriteRcode::NoError)),
        "NXDOMAIN" => return Ok(RewriteData::Rcode(RewriteRcode::NxDomain)),
        "REFUSED" => return Ok(RewriteData::Rcode(RewriteRcode::Refused)),
        "SERVFAIL" => return Ok(RewriteData::Rcode(RewriteRcode::ServFail)),
        _ => {}
    }
    // Short-form bare IP.
    if let Ok(ip) = v.parse::<IpAddr>() {
        return Ok(ip_rewrite(ip));
    }
    // Full form: `RCODE;TYPE;VALUE` (e.g. `NOERROR;A;1.2.3.4`).
    let segs: Vec<&str> = v.splitn(3, ';').collect();
    if segs.len() == 3 {
        let rtype = segs[1].to_ascii_uppercase();
        let data = segs[2];
        match rtype.as_str() {
            "A" => {
                let ip: std::net::Ipv4Addr = data
                    .parse()
                    .map_err(|_| ParseError::Invalid(format!("bad A in dnsrewrite: {data}")))?;
                return Ok(RewriteData::A(ip));
            }
            "AAAA" => {
                let ip: std::net::Ipv6Addr = data
                    .parse()
                    .map_err(|_| ParseError::Invalid(format!("bad AAAA in dnsrewrite: {data}")))?;
                return Ok(RewriteData::Aaaa(ip));
            }
            "CNAME" => return Ok(RewriteData::Cname(norm_domain(data))),
            "TXT" => return Ok(RewriteData::Txt(data.trim_matches('"').to_string())),
            "PTR" => return Ok(RewriteData::Ptr(norm_domain(data))),
            "MX" => {
                // `<preference> <exchange>`, e.g. `10 mail.example.com`.
                let mut it = data.split_whitespace();
                let preference: u16 = it
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| ParseError::Invalid(format!("bad MX in dnsrewrite: {data}")))?;
                let exchange = it
                    .next()
                    .ok_or_else(|| ParseError::Invalid(format!("bad MX in dnsrewrite: {data}")))?;
                return Ok(RewriteData::Mx {
                    preference,
                    exchange: norm_domain(exchange),
                });
            }
            _ => {}
        }
    }
    // Bare CNAME target (a hostname).
    if v.contains('.') && !v.contains(';') {
        return Ok(RewriteData::Cname(norm_domain(v)));
    }
    Err(ParseError::Invalid(format!(
        "unsupported dnsrewrite: {value}"
    )))
}

fn ip_rewrite(ip: IpAddr) -> RewriteData {
    match ip {
        IpAddr::V4(v4) => RewriteData::A(v4),
        IpAddr::V6(v6) => RewriteData::Aaaa(v6),
    }
}
