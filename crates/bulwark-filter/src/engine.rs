//! The compiled matching engine.
//!
//! Rules are bucketed for fast lookup: exact and subdomain rules go into hash
//! maps keyed by domain, while wildcard/regex rules are scanned linearly (they
//! are rare in practice). A query checks the exact map, walks domain suffixes
//! against the subdomain map, then scans the regex bucket, and finally chooses a
//! winner by AdGuard-compatible priority.

use std::collections::HashMap;

use crate::rule::{Action, ClientInfo, Pattern, RewriteData, Rule};

/// Where a matching rule came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchInfo {
    pub rule: String,
    pub list_id: u32,
    pub rule_id: u32,
}

/// The outcome of matching a query against the rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Not filtered. `rule` is `Some` when an explicit `@@` exception matched.
    Allow { rule: Option<MatchInfo> },
    /// The query should be blocked.
    Block(MatchInfo),
    /// The response should be rewritten.
    Rewrite { info: MatchInfo, data: RewriteData },
}

impl Verdict {
    pub fn is_blocked(&self) -> bool {
        matches!(self, Verdict::Block(_))
    }
}

/// A compiled, read-only set of filtering rules.
#[derive(Debug, Default)]
pub struct FilterEngine {
    rules: Vec<Rule>,
    /// domain -> rule ids (matches domain + subdomains).
    subdomain: HashMap<String, Vec<u32>, ahash::RandomState>,
    /// domain -> rule ids (exact match only).
    exact: HashMap<String, Vec<u32>, ahash::RandomState>,
    /// Wildcard + regex rule ids, scanned for every query.
    scan: Vec<u32>,
}

/// Returns true if `domain` equals `base` or is a subdomain of it.
fn is_subdomain_of(domain: &str, base: &str) -> bool {
    domain == base
        || (domain.len() > base.len()
            && domain.ends_with(base)
            && domain.as_bytes()[domain.len() - base.len() - 1] == b'.')
}

impl FilterEngine {
    /// Build an engine from already-prepared rules (ids reassigned here). Rules
    /// disabled by a `$badfilter` should be filtered out by the caller; see
    /// [`crate::list::Compiler`].
    pub fn from_rules(mut rules: Vec<Rule>) -> Self {
        let hasher = ahash::RandomState::new();
        let mut subdomain: HashMap<String, Vec<u32>, ahash::RandomState> =
            HashMap::with_hasher(hasher.clone());
        let mut exact: HashMap<String, Vec<u32>, ahash::RandomState> = HashMap::with_hasher(hasher);
        let mut scan = Vec::new();

        for (i, rule) in rules.iter_mut().enumerate() {
            let id = i as u32;
            rule.id = id;
            match &rule.pattern {
                Pattern::Subdomain(d) => subdomain.entry(d.clone()).or_default().push(id),
                Pattern::Exact(d) => exact.entry(d.clone()).or_default().push(id),
                Pattern::Wildcard(_) | Pattern::Regex(_) => scan.push(id),
            }
        }

        FilterEngine {
            rules,
            subdomain,
            exact,
            scan,
        }
    }

    /// Number of active rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    fn collect_candidates(&self, domain: &str, out: &mut Vec<u32>) {
        if let Some(ids) = self.exact.get(domain) {
            out.extend_from_slice(ids);
        }
        let mut hay = domain;
        loop {
            if let Some(ids) = self.subdomain.get(hay) {
                out.extend_from_slice(ids);
            }
            match hay.find('.') {
                Some(i) => hay = &hay[i + 1..],
                None => break,
            }
        }
        for &id in &self.scan {
            let matched = match &self.rules[id as usize].pattern {
                Pattern::Wildcard(re) | Pattern::Regex(re) => re.is_match(domain),
                _ => false,
            };
            if matched {
                out.push(id);
            }
        }
    }

    /// Is `rule` applicable to this query (modifiers, client, denyallow)?
    fn applicable(&self, rule: &Rule, domain: &str, rtype: &str, client: &ClientInfo<'_>) -> bool {
        if let Some(f) = &rule.dnstype {
            if !f.matches(rtype) {
                return false;
            }
        }
        if let Some(f) = &rule.client {
            if !f.matches(client) {
                return false;
            }
        }
        if let Some(f) = &rule.ctag {
            if !f.matches(client.tags) {
                return false;
            }
        }
        // `$denyallow`: the (blocking) rule does *not* apply to these domains.
        if matches!(rule.action, Action::Block | Action::Rewrite)
            && rule
                .denyallow
                .iter()
                .any(|base| is_subdomain_of(domain, base))
        {
            return false;
        }
        true
    }

    /// Match a query. `domain` is normalised (lowercased, no trailing dot);
    /// `rtype` is the uppercase record type (e.g. `"A"`, `"AAAA"`).
    pub fn check(&self, domain: &str, rtype: &str, client: &ClientInfo<'_>) -> Verdict {
        let domain_owned;
        let domain = if domain.bytes().any(|b| b.is_ascii_uppercase()) || domain.ends_with('.') {
            domain_owned = domain.trim_end_matches('.').to_ascii_lowercase();
            domain_owned.as_str()
        } else {
            domain
        };

        let mut candidates = Vec::new();
        self.collect_candidates(domain, &mut candidates);

        let mut best: Option<&Rule> = None;
        for &id in &candidates {
            let rule = &self.rules[id as usize];
            if !self.applicable(rule, domain, rtype, client) {
                continue;
            }
            match best {
                Some(b) if rule.priority() <= b.priority() => {}
                _ => best = Some(rule),
            }
        }

        match best {
            None => Verdict::Allow { rule: None },
            Some(rule) => {
                let info = MatchInfo {
                    rule: rule.raw.clone(),
                    list_id: rule.list_id,
                    rule_id: rule.id,
                };
                match rule.action {
                    Action::Allow => Verdict::Allow { rule: Some(info) },
                    Action::Block => Verdict::Block(info),
                    Action::Rewrite => Verdict::Rewrite {
                        info,
                        data: rule
                            .rewrite
                            .clone()
                            .expect("rewrite rule must carry rewrite data"),
                    },
                }
            }
        }
    }
}
