//! The compiled matching engine.
//!
//! Rules are bucketed for fast lookup: exact and subdomain rules go into hash
//! maps keyed by domain, while wildcard/regex rules are scanned linearly (they
//! are rare in practice). A query checks the exact map, walks domain suffixes
//! against the subdomain map, then scans the regex bucket, and finally chooses a
//! winner by AdGuard-compatible priority.

use std::collections::HashMap;

use crate::rule::{Action, ClientInfo, Pattern, RewriteData, Rule};

/// A pass-through hasher for keys that are *already* well-distributed hashes.
/// `scan_index` is keyed by FNV-1a token hashes (see [`crate::token`]), so
/// running them through a general-purpose hasher again is wasted work on every
/// probe; this just forwards the `u32`.
#[derive(Default)]
struct IdentityHasher(u64);

impl std::hash::Hasher for IdentityHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.0 = i as u64;
    }
    fn write(&mut self, bytes: &[u8]) {
        // The map only ever uses `u32` keys (which route through `write_u32`);
        // this arm exists only to satisfy the trait.
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ b as u64;
        }
    }
}

type BuildIdentityHasher = std::hash::BuildHasherDefault<IdentityHasher>;

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
    /// Reverse index: token hash -> wildcard rule ids bucketed under that token.
    /// Only queries sharing a token need check these rules. Keyed by an FNV token
    /// hash, so it uses an identity hasher (no re-hashing on probe).
    scan_index: HashMap<u32, Vec<u32>, BuildIdentityHasher>,
    /// Wildcard rules without a safe token + all regex rules: checked for every
    /// query (kept small in practice). They're grouped into bounded-size
    /// `RegexSet` chunks so matching is a handful of fused DFA passes rather than
    /// an O(rules) sweep of individual `.is_match` calls — even for a list with
    /// thousands of tokenless regexes. Each chunk's `Vec<u32>` holds the rule ids
    /// parallel to that set's patterns, preserving attribution. A chunk that
    /// can't build within the size limit degrades to per-rule scanning for *just
    /// that chunk* (collected into `fallback_individual`), logged so it isn't
    /// silent.
    fallback_sets: Vec<(regex::RegexSet, Vec<u32>)>,
    fallback_individual: Vec<u32>,
    /// True if any rule carries a `$client=` or `$ctag=` modifier, i.e. its
    /// verdict can depend on *which* client is asking. Consumers (the response
    /// cache) use this to decide whether a per-domain verdict can be memoised
    /// globally or must be recomputed per client. See [`Self::content_hash`].
    has_client_dependent_rules: bool,
    /// A stable hash of the rule set's *content* (each rule's source line, list,
    /// and action). Two engines built from the same rules — in the same process
    /// or across a no-op reload — produce the same value; any rule add/remove/edit
    /// changes it. The response cache stamps memoised verdicts with this value and
    /// treats a mismatch as "recompute", so a filter change transparently
    /// invalidates stale verdicts. Deterministic (fixed-key hasher), so it is not
    /// perturbed by per-process hash randomisation.
    content_hash: u64,
}

/// Fallback rules are grouped into `RegexSet` chunks of at most this many
/// patterns, so each set stays within its size limit and matching stays a
/// bounded number of fused passes.
const FALLBACK_CHUNK: usize = 256;

/// Compiled-size cap for each fallback `RegexSet` chunk (bytes).
const FALLBACK_REGEXSET_SIZE_LIMIT: usize = 16 * 1024 * 1024;

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
        let mut scan_index: HashMap<u32, Vec<u32>, BuildIdentityHasher> = HashMap::default();
        let mut scan_fallback = Vec::new();
        let mut scan_rules: Vec<u32> = Vec::new();

        for (i, rule) in rules.iter_mut().enumerate() {
            let id = i as u32;
            rule.id = id;
            match &rule.pattern {
                Pattern::Subdomain(d) => subdomain.entry(d.clone()).or_default().push(id),
                Pattern::Exact(d) => exact.entry(d.clone()).or_default().push(id),
                Pattern::Wildcard(_) | Pattern::Regex(_) => scan_rules.push(id),
            }
        }

        // Count token frequency across scan rules so each rule can be bucketed
        // under its *rarest* token, minimizing candidate set sizes.
        let mut token_freq: HashMap<u32, u32, ahash::RandomState> = HashMap::default();
        for &id in &scan_rules {
            for &t in &rules[id as usize].index_tokens {
                *token_freq.entry(t).or_default() += 1;
            }
        }
        for &id in &scan_rules {
            let best = rules[id as usize]
                .index_tokens
                .iter()
                .min_by_key(|t| token_freq.get(t).copied().unwrap_or(0))
                .copied();
            match best {
                Some(tok) => scan_index.entry(tok).or_default().push(id),
                None => scan_fallback.push(id),
            }
        }

        // Group the fallback rules into bounded RegexSet chunks (adblock-rust-style
        // fusion, but each set tells us *which* rule matched so we keep per-rule
        // attribution). Chunking bounds each set's compiled size and guarantees
        // matching never degrades to an O(rules) per-query sweep.
        let mut fallback_sets: Vec<(regex::RegexSet, Vec<u32>)> = Vec::new();
        let mut fallback_individual: Vec<u32> = Vec::new();
        for chunk in scan_fallback.chunks(FALLBACK_CHUNK) {
            let mut pats: Vec<&str> = Vec::with_capacity(chunk.len());
            let mut ids: Vec<u32> = Vec::with_capacity(chunk.len());
            for &id in chunk {
                if let Pattern::Wildcard(re) | Pattern::Regex(re) = &rules[id as usize].pattern {
                    pats.push(re.as_str());
                    ids.push(id);
                }
            }
            if pats.is_empty() {
                continue;
            }
            match regex::RegexSetBuilder::new(&pats)
                .size_limit(FALLBACK_REGEXSET_SIZE_LIMIT)
                .build()
            {
                Ok(set) => fallback_sets.push((set, ids)),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        rules = ids.len(),
                        "filter fallback RegexSet chunk exceeded its size limit; \
                         scanning those rules individually"
                    );
                    fallback_individual.extend_from_slice(&ids);
                }
            }
        }

        // Whether any rule's outcome can vary by client. Computed before we drop
        // build-time fields (it reads only `mods`, which is retained).
        let has_client_dependent_rules = rules.iter().any(|r| {
            r.mods
                .as_ref()
                .is_some_and(|m| m.client.is_some() || m.ctag.is_some())
        });

        // A deterministic content hash over the retained rule fields. `DefaultHasher`
        // has fixed keys, so the same rules always hash the same — even across a
        // reload that rebuilds the engine — while any rule change shifts it.
        let content_hash = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            for r in &rules {
                r.raw.hash(&mut h);
                r.list_id.hash(&mut h);
                (r.action as u8).hash(&mut h);
            }
            h.finish()
        };

        // The signature strings and index tokens are only needed during
        // compilation; drop them to save memory on large rule sets.
        for rule in rules.iter_mut() {
            rule.signature = String::new();
            rule.signature.shrink_to_fit();
            rule.index_tokens = Vec::new();
        }

        FilterEngine {
            rules,
            subdomain,
            exact,
            scan_index,
            fallback_sets,
            fallback_individual,
            has_client_dependent_rules,
            content_hash,
        }
    }

    /// Whether any rule's verdict can depend on the querying client (`$client=`
    /// or `$ctag=`). When false, a response-side verdict is identical for every
    /// client and may be memoised globally; when true it must be recomputed per
    /// client. See the field docs on [`FilterEngine`].
    pub fn has_client_dependent_rules(&self) -> bool {
        self.has_client_dependent_rules
    }

    /// A stable hash of the rule set's content, used as a generation stamp for
    /// memoised response verdicts. See the field docs on [`FilterEngine`].
    pub fn content_hash(&self) -> u64 {
        self.content_hash
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

        // Wildcard/regex rules: always-checked fallback + token-indexed.
        let check = |id: u32, out: &mut Vec<u32>| {
            let matched = match &self.rules[id as usize].pattern {
                Pattern::Wildcard(re) | Pattern::Regex(re) => re.is_match(domain),
                _ => false,
            };
            if matched {
                out.push(id);
            }
        };
        // Fallback: a few fused RegexSet passes (one per chunk) instead of N
        // individual matches, plus any chunk that couldn't build, scanned per-rule.
        for (set, ids) in &self.fallback_sets {
            for idx in set.matches(domain) {
                out.push(ids[idx]);
            }
        }
        for &id in &self.fallback_individual {
            check(id, out);
        }
        if !self.scan_index.is_empty() {
            // Reuse a per-thread token buffer so the common query path doesn't
            // allocate a fresh Vec on every lookup.
            thread_local! {
                static TOKENS: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
            }
            TOKENS.with(|cell| {
                let mut tokens = cell.borrow_mut();
                crate::token::tokenize_query_into(domain, &mut tokens);
                for &tok in tokens.iter() {
                    if let Some(ids) = self.scan_index.get(&tok) {
                        for &id in ids {
                            check(id, out);
                        }
                    }
                }
            });
        }
    }

    /// Is `rule` applicable to this query (modifiers, client, denyallow)?
    fn applicable(&self, rule: &Rule, domain: &str, rtype: &str, client: &ClientInfo<'_>) -> bool {
        // Plain rules (no modifiers) always apply — the common, fast path.
        let Some(m) = &rule.mods else {
            return true;
        };
        if let Some(f) = &m.dnstype {
            if !f.matches(rtype) {
                return false;
            }
        }
        if let Some(f) = &m.client {
            if !f.matches(client) {
                return false;
            }
        }
        if let Some(f) = &m.ctag {
            if !f.matches(client.tags) {
                return false;
            }
        }
        // `$denyallow`: the (blocking) rule does *not* apply to these domains.
        if matches!(rule.action, Action::Block | Action::Rewrite)
            && m.denyallow.iter().any(|base| is_subdomain_of(domain, base))
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

        // Reuse a per-thread scratch buffer to avoid allocating on every query.
        thread_local! {
            static CANDIDATES: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
        }

        let best_id = CANDIDATES.with(|cell| {
            let mut candidates = cell.borrow_mut();
            candidates.clear();
            self.collect_candidates(domain, &mut candidates);

            let mut best: Option<u32> = None;
            let mut best_prio = 0u32;
            for &id in candidates.iter() {
                let rule = &self.rules[id as usize];
                if !self.applicable(rule, domain, rtype, client) {
                    continue;
                }
                let prio = rule.priority();
                if best.is_none() || prio > best_prio {
                    best = Some(id);
                    best_prio = prio;
                }
            }
            best
        });

        match best_id.map(|id| &self.rules[id as usize]) {
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
                            .rewrite()
                            .cloned()
                            .expect("rewrite rule must carry rewrite data"),
                    },
                }
            }
        }
    }
}
