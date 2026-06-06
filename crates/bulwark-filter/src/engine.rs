//! The compiled matching engine.
//!
//! The engine is **span-backed**: rather than keeping a parsed `Rule` struct per
//! line (each pulling several heap allocations and storing the domain up to three
//! times), it concatenates the kept source lines and the normalised domains into
//! two flat arenas and represents every rule as a fixed [`RuleRecord`] of `u32`
//! offsets. Lookup is by domain *hash*, not by domain string: exact and
//! subdomain rules live in `HashMap<u64, Range>` indices whose values point into
//! flat hit vectors, so there are no per-domain string keys and no per-entry
//! `Vec`. A query hashes the name (and each suffix), probes the maps, and
//! *verifies* each candidate's stored domain span against the query to reject the
//! rare hash collision — correctness comes from the span check, never the hash.
//! Wildcard/regex rules are bucketed by token (see [`crate::token`]) and scanned
//! via fused `RegexSet`s exactly as before, their compiled programs held in a
//! side arena.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use crate::rule::{Action, BuildRule, ClientInfo, Pattern, RewriteData, RuleMods, Rule};

/// A pass-through hasher for keys that are *already* well-distributed hashes
/// (FNV token hashes for `scan_index`, FNV-1a domain hashes for the domain
/// indices). Running them through a general-purpose hasher again is wasted work
/// on every probe; this just forwards the integer.
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
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0 = i;
    }
    fn write(&mut self, bytes: &[u8]) {
        // The maps only ever use integer keys (routed through `write_u32`/
        // `write_u64`); this arm exists only to satisfy the trait.
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ b as u64;
        }
    }
}

type BuildIdentityHasher = std::hash::BuildHasherDefault<IdentityHasher>;

/// Sentinel for "no modifier cluster" in [`RuleRecord::mods_idx`].
const NO_MODS: u32 = u32::MAX;

/// Rule kinds, stored as a `u8` tag on each record.
mod kind {
    pub const EXACT: u8 = 0;
    pub const SUBDOMAIN: u8 = 1;
    pub const WILDCARD: u8 = 2;
    pub const REGEX: u8 = 3;
}

/// A compiled rule, as a fixed-size record of offsets into the engine's arenas.
/// No heap allocation of its own; the common plain-block rule is fully described
/// by this ~28-byte record plus its slices of the shared text arenas.
#[derive(Debug, Clone)]
struct RuleRecord {
    /// Span of the original source line in `raw_arena` (for display / logging).
    raw_start: u32,
    raw_len: u32,
    /// For exact/subdomain rules: span start of the normalised domain in
    /// `domain_arena`. For wildcard/regex rules: index into `regexes`.
    dom_or_re: u32,
    /// For exact/subdomain rules: domain byte length. Zero for wildcard/regex.
    dom_len: u32,
    /// Which loaded list this rule came from.
    list_id: u32,
    /// Index into `mods`, or [`NO_MODS`].
    mods_idx: u32,
    action: Action,
    /// One of the [`kind`] tags.
    kind: u8,
}

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

/// A hash-keyed domain index: `domain hash -> (start, len)` range into a flat
/// hit vector of rule ids. Replaces a `HashMap<String, Vec<u32>>`, dropping the
/// per-domain key string and the per-entry `Vec` allocation.
#[derive(Debug, Default)]
struct DomainIndex {
    map: HashMap<u64, (u32, u32), BuildIdentityHasher>,
    hits: Vec<u32>,
}

impl DomainIndex {
    /// Build from `(hash, rule_id)` pairs. Pairs sharing a hash are grouped into
    /// one contiguous run in `hits`.
    fn build(mut pairs: Vec<(u64, u32)>) -> Self {
        pairs.sort_unstable_by_key(|p| p.0);
        let mut map: HashMap<u64, (u32, u32), BuildIdentityHasher> =
            HashMap::with_capacity_and_hasher(pairs.len(), BuildIdentityHasher::default());
        let mut hits: Vec<u32> = Vec::with_capacity(pairs.len());
        let mut i = 0;
        while i < pairs.len() {
            let h = pairs[i].0;
            let start = hits.len() as u32;
            while i < pairs.len() && pairs[i].0 == h {
                hits.push(pairs[i].1);
                i += 1;
            }
            map.insert(h, (start, hits.len() as u32 - start));
        }
        map.shrink_to_fit();
        hits.shrink_to_fit();
        DomainIndex { map, hits }
    }

    #[inline]
    fn get(&self, hash: u64) -> &[u32] {
        match self.map.get(&hash) {
            Some(&(start, len)) => &self.hits[start as usize..(start + len) as usize],
            None => &[],
        }
    }

    fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }
}

/// A compiled, read-only set of filtering rules.
#[derive(Debug, Default)]
pub struct FilterEngine {
    /// Fixed-size rule records (no per-rule heap allocation).
    rules: Vec<RuleRecord>,
    /// All kept source lines, concatenated. `RuleRecord::raw_*` index into this.
    raw_arena: Box<str>,
    /// All normalised exact/subdomain domains, concatenated. The domain indices'
    /// span verification and `MatchInfo` both read from here.
    domain_arena: Box<str>,
    /// Modifier clusters, referenced by `RuleRecord::mods_idx`. Plain rules carry
    /// no modifiers, so this stays small in practice.
    mods: Vec<RuleMods>,
    /// Compiled wildcard/regex programs, referenced by `RuleRecord::dom_or_re`.
    regexes: Vec<regex::Regex>,
    /// Hasher used to turn a domain (or query suffix) into the `u64` key for the
    /// exact/subdomain indices. Stored so build and query hash identically; a
    /// fast (ahash) hash matters because every query hashes the name and each of
    /// its suffixes. The 64-bit output is well-distributed, so the indices key it
    /// through an identity hasher.
    dhash: ahash::RandomState,
    /// Exact-match domain index (`hosts` entries, fully-anchored rules).
    exact: DomainIndex,
    /// Subdomain-match domain index (`||domain^`, bare domains) — matches the
    /// domain and any subdomain.
    subdomain: DomainIndex,
    /// Reverse index: token hash -> wildcard rule ids bucketed under that token.
    scan_index: HashMap<u32, Vec<u32>, BuildIdentityHasher>,
    /// Tokenless wildcard rules + all regex rules, grouped into bounded-size
    /// fused `RegexSet` chunks (each chunk's `Vec<u32>` parallels its patterns,
    /// preserving attribution). A chunk that can't build within the size limit
    /// degrades to per-rule scanning in `fallback_individual`.
    fallback_sets: Vec<(regex::RegexSet, Vec<u32>)>,
    fallback_individual: Vec<u32>,
    /// True if any rule carries a `$client=` or `$ctag=` modifier, i.e. its
    /// verdict can depend on *which* client is asking.
    has_client_dependent_rules: bool,
    /// A stable hash of the rule set's *content*. See the field's prior docs:
    /// deterministic across reloads, perturbed by any rule add/remove/edit, used
    /// by the response cache to invalidate memoised verdicts.
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
    /// Build an engine from already-prepared rules (ids are the record index).
    /// Rules disabled by a `$badfilter` should be filtered out by the caller; see
    /// [`crate::list::Compiler`]. The build-time [`BuildRule`] data is consumed
    /// here and replaced by the compact span-backed representation.
    pub fn from_rules(rules: Vec<BuildRule>) -> Self {
        let mut raw_arena = String::new();
        let mut domain_arena = String::new();
        let mut records: Vec<RuleRecord> = Vec::with_capacity(rules.len());
        let mut mods: Vec<RuleMods> = Vec::new();
        let mut regexes: Vec<regex::Regex> = Vec::new();

        let dhash = ahash::RandomState::new();
        let mut exact_pairs: Vec<(u64, u32)> = Vec::new();
        let mut sub_pairs: Vec<(u64, u32)> = Vec::new();
        // (rule id, safe interior tokens) for wildcard/regex rules only.
        let mut scan_meta: Vec<(u32, Vec<u32>)> = Vec::new();

        let mut has_client_dependent_rules = false;

        // Deterministic content hash over the retained rule fields (fixed-key
        // `DefaultHasher`, so the same rules always hash the same across reloads).
        let mut ch = std::collections::hash_map::DefaultHasher::new();

        for (i, br) in rules.into_iter().enumerate() {
            let id = i as u32;
            let BuildRule {
                rule, index_tokens, ..
            } = br;
            let Rule {
                raw,
                action,
                pattern,
                mods: rule_mods,
                list_id,
                ..
            } = rule;

            raw.hash(&mut ch);
            list_id.hash(&mut ch);
            (action as u8).hash(&mut ch);

            let raw_start = raw_arena.len() as u32;
            let raw_len = raw.len() as u32;
            raw_arena.push_str(&raw);

            let mods_idx = match rule_mods {
                Some(m) => {
                    if m.client.is_some() || m.ctag.is_some() {
                        has_client_dependent_rules = true;
                    }
                    let idx = mods.len() as u32;
                    mods.push(*m);
                    idx
                }
                None => NO_MODS,
            };

            let (kind, dom_or_re, dom_len) = match pattern {
                Pattern::Exact(d) => {
                    let start = domain_arena.len() as u32;
                    let len = d.len() as u32;
                    exact_pairs.push((dhash.hash_one(d.as_str()), id));
                    domain_arena.push_str(&d);
                    (kind::EXACT, start, len)
                }
                Pattern::Subdomain(d) => {
                    let start = domain_arena.len() as u32;
                    let len = d.len() as u32;
                    sub_pairs.push((dhash.hash_one(d.as_str()), id));
                    domain_arena.push_str(&d);
                    (kind::SUBDOMAIN, start, len)
                }
                Pattern::Wildcard(re) => {
                    let idx = regexes.len() as u32;
                    regexes.push(re);
                    scan_meta.push((id, index_tokens));
                    (kind::WILDCARD, idx, 0)
                }
                Pattern::Regex(re) => {
                    let idx = regexes.len() as u32;
                    regexes.push(re);
                    scan_meta.push((id, index_tokens));
                    (kind::REGEX, idx, 0)
                }
            };

            records.push(RuleRecord {
                raw_start,
                raw_len,
                dom_or_re,
                dom_len,
                list_id,
                mods_idx,
                action,
                kind,
            });
        }
        let content_hash = ch.finish();

        // Bucket each wildcard/regex rule under its *rarest* token, falling back
        // to the always-scanned set for tokenless rules.
        let mut token_freq: HashMap<u32, u32, ahash::RandomState> = HashMap::default();
        for (_, toks) in &scan_meta {
            for &t in toks {
                *token_freq.entry(t).or_default() += 1;
            }
        }
        let mut scan_index: HashMap<u32, Vec<u32>, BuildIdentityHasher> = HashMap::default();
        let mut scan_fallback: Vec<u32> = Vec::new();
        for (id, toks) in &scan_meta {
            let best = toks
                .iter()
                .min_by_key(|t| token_freq.get(t).copied().unwrap_or(0))
                .copied();
            match best {
                Some(tok) => scan_index.entry(tok).or_default().push(*id),
                None => scan_fallback.push(*id),
            }
        }

        // Group the fallback rules into bounded fused `RegexSet` chunks.
        let mut fallback_sets: Vec<(regex::RegexSet, Vec<u32>)> = Vec::new();
        let mut fallback_individual: Vec<u32> = Vec::new();
        for chunk in scan_fallback.chunks(FALLBACK_CHUNK) {
            let mut pats: Vec<&str> = Vec::with_capacity(chunk.len());
            let mut ids: Vec<u32> = Vec::with_capacity(chunk.len());
            for &id in chunk {
                let r = &records[id as usize];
                if r.kind == kind::WILDCARD || r.kind == kind::REGEX {
                    pats.push(regexes[r.dom_or_re as usize].as_str());
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

        let exact = DomainIndex::build(exact_pairs);
        let subdomain = DomainIndex::build(sub_pairs);

        records.shrink_to_fit();
        mods.shrink_to_fit();
        regexes.shrink_to_fit();

        FilterEngine {
            rules: records,
            raw_arena: raw_arena.into_boxed_str(),
            domain_arena: domain_arena.into_boxed_str(),
            mods,
            regexes,
            dhash,
            exact,
            subdomain,
            scan_index,
            fallback_sets,
            fallback_individual,
            has_client_dependent_rules,
            content_hash,
        }
    }

    /// The original source line of a record (for `MatchInfo` / display).
    #[inline]
    fn raw(&self, r: &RuleRecord) -> &str {
        &self.raw_arena[r.raw_start as usize..(r.raw_start + r.raw_len) as usize]
    }

    /// The normalised domain of an exact/subdomain record.
    #[inline]
    fn domain(&self, r: &RuleRecord) -> &str {
        &self.domain_arena[r.dom_or_re as usize..(r.dom_or_re + r.dom_len) as usize]
    }

    /// The modifier cluster of a record, if any.
    #[inline]
    fn mods_of(&self, r: &RuleRecord) -> Option<&RuleMods> {
        (r.mods_idx != NO_MODS).then(|| &self.mods[r.mods_idx as usize])
    }

    /// Confirm a hash-bucket candidate genuinely matches `domain`, rejecting the
    /// rare 64-bit hash collision. Exact rules must equal the domain; subdomain
    /// rules must be a suffix of it; wildcard/regex rules were already confirmed
    /// by their regex match when collected.
    #[inline]
    fn domain_matches(&self, r: &RuleRecord, domain: &str) -> bool {
        match r.kind {
            kind::EXACT => self.domain(r) == domain,
            kind::SUBDOMAIN => is_subdomain_of(domain, self.domain(r)),
            _ => true,
        }
    }

    /// Priority score (higher wins): `$important` adds a large bonus; among equal
    /// importance allow beats block, and rewrites sit alongside blocks.
    #[inline]
    fn priority(&self, r: &RuleRecord) -> u32 {
        let mut score = match r.action {
            Action::Allow => 2,
            Action::Block | Action::Rewrite => 1,
        };
        if self.mods_of(r).is_some_and(|m| m.important) {
            score += 100;
        }
        score
    }

    /// Whether any rule's verdict can depend on the querying client (`$client=`
    /// or `$ctag=`).
    pub fn has_client_dependent_rules(&self) -> bool {
        self.has_client_dependent_rules
    }

    /// A stable hash of the rule set's content, used as a generation stamp for
    /// memoised response verdicts.
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

    /// Approximate retained-heap breakdown, in bytes, for tuning. Counts the
    /// large flat allocations (records, arenas, index tables + hit vectors); the
    /// long tail (mods/regex heap, scan index) is lumped under `other`. Intended
    /// for the `memprobe` example, not production use.
    #[doc(hidden)]
    pub fn mem_report(&self) -> [(&'static str, usize); 5] {
        let rec = self.rules.capacity() * std::mem::size_of::<RuleRecord>();
        let raw = self.raw_arena.len();
        let dom = self.domain_arena.len();
        let entry = std::mem::size_of::<(u64, (u32, u32))>();
        let index = (self.exact.map.capacity() + self.subdomain.map.capacity()) * entry
            + (self.exact.hits.capacity() + self.subdomain.hits.capacity()) * 4;
        let other = self.mods.capacity() * std::mem::size_of::<RuleMods>()
            + self.regexes.capacity() * std::mem::size_of::<regex::Regex>();
        [
            ("records", rec),
            ("raw_arena", raw),
            ("domain_arena", dom),
            ("index", index),
            ("other", other),
        ]
    }

    fn collect_candidates(&self, domain: &str, out: &mut Vec<u32>) {
        // Exact and subdomain rules are gathered by domain hash. We push the raw
        // bucket hits *without* verifying the span here — verification (which
        // needs to load the rule record) is folded into the winner-selection loop
        // in `check`, which loads the record anyway, so a candidate costs only one
        // record load instead of two. The hash narrows the set; the span check in
        // `check` rejects the (astronomically rare) collision.
        if !self.exact.is_empty() {
            out.extend_from_slice(self.exact.get(self.dhash.hash_one(domain)));
        }
        if !self.subdomain.is_empty() {
            let mut hay = domain;
            loop {
                out.extend_from_slice(self.subdomain.get(self.dhash.hash_one(hay)));
                match hay.find('.') {
                    Some(i) => hay = &hay[i + 1..],
                    None => break,
                }
            }
        }

        // Wildcard/regex rules: always-checked fallback + token-indexed.
        let check = |id: u32, out: &mut Vec<u32>| {
            let r = &self.rules[id as usize];
            if (r.kind == kind::WILDCARD || r.kind == kind::REGEX)
                && self.regexes[r.dom_or_re as usize].is_match(domain)
            {
                out.push(id);
            }
        };
        for (set, ids) in &self.fallback_sets {
            for idx in set.matches(domain) {
                out.push(ids[idx]);
            }
        }
        for &id in &self.fallback_individual {
            check(id, out);
        }
        if !self.scan_index.is_empty() {
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

    /// Is `r` applicable to this query (modifiers, client, denyallow)?
    fn applicable(&self, r: &RuleRecord, domain: &str, rtype: &str, client: &ClientInfo<'_>) -> bool {
        // Plain rules (no modifiers) always apply — the common, fast path.
        let Some(m) = self.mods_of(r) else {
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
        if matches!(r.action, Action::Block | Action::Rewrite)
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
                let r = &self.rules[id as usize];
                if !self.domain_matches(r, domain) || !self.applicable(r, domain, rtype, client) {
                    continue;
                }
                let prio = self.priority(r);
                if best.is_none() || prio > best_prio {
                    best = Some(id);
                    best_prio = prio;
                }
            }
            best
        });

        match best_id {
            None => Verdict::Allow { rule: None },
            Some(id) => {
                let r = &self.rules[id as usize];
                let info = MatchInfo {
                    rule: self.raw(r).to_string(),
                    list_id: r.list_id,
                    rule_id: id,
                };
                match r.action {
                    Action::Allow => Verdict::Allow { rule: Some(info) },
                    Action::Block => Verdict::Block(info),
                    Action::Rewrite => Verdict::Rewrite {
                        info,
                        data: self
                            .mods_of(r)
                            .and_then(|m| m.rewrite.clone())
                            .expect("rewrite rule must carry rewrite data"),
                    },
                }
            }
        }
    }
}
