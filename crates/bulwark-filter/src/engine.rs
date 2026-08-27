//! Span-backed compiled filtering engine.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use crate::rule::{Action, BuildRule, ClientInfo, Pattern, RewriteData, Rule, RuleMods};

/// Pass-through hasher for pre-hashed integer keys.
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

/// Fixed-size rule record indexing shared arenas.
#[derive(Debug, Clone)]
struct RuleRecord {
    /// Source-line offset in `raw_arena`.
    raw_start: u32,
    /// For exact/subdomain rules: span start of the normalised domain in
    /// `domain_arena`. For wildcard/regex rules: index into `regexes`.
    dom_or_re: u32,
    /// Index into `mods`, or [`NO_MODS`].
    mods_idx: u32,
    /// Source-line length, saturated at `u16::MAX`.
    raw_len: u16,
    /// Which loaded list this rule came from.
    list_id: u16,
    /// Domain length, or zero for wildcard/regex rules.
    dom_len: u8,
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

/// Maps domain hashes to ranges in a flat rule-id vector.
#[derive(Debug, Default)]
struct DomainIndex {
    map: HashMap<u64, (u32, u32), BuildIdentityHasher>,
    hits: Vec<u32>,
}

impl DomainIndex {
    /// Groups `(hash, rule_id)` pairs into contiguous hit ranges.
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

/// Token-indexed and fallback wildcard/regex scans.
#[derive(Debug, Default)]
struct ScanGroup {
    scan_index: HashMap<u32, Vec<u32>, BuildIdentityHasher>,
    fallback_sets: Vec<(regex::RegexSet, Vec<u32>)>,
    fallback_individual: Vec<u32>,
}

impl ScanGroup {
    fn is_empty(&self) -> bool {
        self.scan_index.is_empty()
            && self.fallback_sets.is_empty()
            && self.fallback_individual.is_empty()
    }

    fn rule_count(&self) -> usize {
        self.scan_index.values().map(|v| v.len()).sum::<usize>()
            + self
                .fallback_sets
                .iter()
                .map(|(_, ids)| ids.len())
                .sum::<usize>()
            + self.fallback_individual.len()
    }
}

/// Builds a scan group using each rule's rarest safe token.
fn build_scan_group(
    meta: Vec<(u32, Vec<u32>)>,
    records: &[RuleRecord],
    regexes: &[regex::Regex],
    token_index: bool,
) -> ScanGroup {
    let mut scan_index: HashMap<u32, Vec<u32>, BuildIdentityHasher> = HashMap::default();
    let mut scan_fallback: Vec<u32> = Vec::new();
    if token_index {
        let mut token_freq: HashMap<u32, u32, ahash::RandomState> = HashMap::default();
        for (_, toks) in &meta {
            for &t in toks {
                *token_freq.entry(t).or_default() += 1;
            }
        }
        for (id, toks) in &meta {
            let best = toks
                .iter()
                .min_by_key(|t| token_freq.get(t).copied().unwrap_or(0))
                .copied();
            match best {
                Some(tok) => scan_index.entry(tok).or_default().push(*id),
                None => scan_fallback.push(*id),
            }
        }
    } else {
        scan_fallback.extend(meta.iter().map(|(id, _)| *id));
    }

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

    ScanGroup {
        scan_index,
        fallback_sets,
        fallback_individual,
    }
}

/// A compiled, read-only set of filtering rules.
#[derive(Debug, Default)]
pub struct FilterEngine {
    rules: Vec<RuleRecord>,
    /// All kept source lines, concatenated. `RuleRecord::raw_*` index into this.
    raw_arena: Box<str>,
    /// Concatenated normalized domains.
    domain_arena: Box<str>,
    /// Modifier clusters referenced by rule records.
    mods: Vec<RuleMods>,
    /// Compiled wildcard/regex programs, referenced by `RuleRecord::dom_or_re`.
    regexes: Vec<regex::Regex>,
    /// Shared domain hasher for build and lookup.
    dhash: ahash::RandomState,
    /// Exact-match domain index (`hosts` entries, fully-anchored rules).
    exact: DomainIndex,
    /// Subdomain-match domain index (`||domain^`, bare domains) — matches the
    /// domain and any subdomain.
    subdomain: DomainIndex,
    /// Wildcard/regex rules that can override domain matches.
    override_scan: ScanGroup,
    /// Plain wildcard/regex blocks scanned after higher-priority rules.
    block_scan: ScanGroup,
    /// Whether any verdict depends on the client.
    has_client_dependent_rules: bool,
    /// Stable rule-set content hash.
    content_hash: u64,
}

/// Maximum patterns per fallback `RegexSet`.
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
    /// Builds an engine from rules prepared by [`crate::list::Compiler`].
    pub fn from_rules(rules: Vec<BuildRule>) -> Self {
        let mut raw_arena = String::new();
        let mut domain_arena = String::new();
        let mut records: Vec<RuleRecord> = Vec::with_capacity(rules.len());
        let mut mods: Vec<RuleMods> = Vec::new();
        let mut regexes: Vec<regex::Regex> = Vec::new();

        let dhash = ahash::RandomState::new();
        let mut exact_pairs: Vec<(u64, u32)> = Vec::new();
        let mut sub_pairs: Vec<(u64, u32)> = Vec::new();
        let mut override_meta: Vec<(u32, Vec<u32>)> = Vec::new();
        let mut block_meta: Vec<(u32, Vec<u32>)> = Vec::new();

        let mut has_client_dependent_rules = false;

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
            let raw_len = raw.len().min(u16::MAX as usize) as u16;
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

            // A wildcard/regex rule "overrides" if its priority can exceed a
            // plain domain block — i.e. it is an allow (`@@`) or `$important`.
            let override_capable = action == Action::Allow
                || (mods_idx != NO_MODS && mods[mods_idx as usize].important);

            let (kind, dom_or_re, dom_len) = match pattern {
                Pattern::Exact(d) => {
                    debug_assert!(d.len() <= u8::MAX as usize, "DNS name exceeds 255 bytes");
                    let start = domain_arena.len() as u32;
                    let len = d.len() as u8;
                    exact_pairs.push((dhash.hash_one(d.as_str()), id));
                    domain_arena.push_str(&d);
                    (kind::EXACT, start, len)
                }
                Pattern::Subdomain(d) => {
                    debug_assert!(d.len() <= u8::MAX as usize, "DNS name exceeds 255 bytes");
                    let start = domain_arena.len() as u32;
                    let len = d.len() as u8;
                    sub_pairs.push((dhash.hash_one(d.as_str()), id));
                    domain_arena.push_str(&d);
                    (kind::SUBDOMAIN, start, len)
                }
                Pattern::Wildcard(re) => {
                    let idx = regexes.len() as u32;
                    regexes.push(re);
                    let meta = if override_capable {
                        &mut override_meta
                    } else {
                        &mut block_meta
                    };
                    meta.push((id, index_tokens));
                    (kind::WILDCARD, idx, 0)
                }
                Pattern::Regex(re) => {
                    let idx = regexes.len() as u32;
                    regexes.push(re);
                    let meta = if override_capable {
                        &mut override_meta
                    } else {
                        &mut block_meta
                    };
                    meta.push((id, index_tokens));
                    (kind::REGEX, idx, 0)
                }
            };

            records.push(RuleRecord {
                raw_start,
                raw_len,
                dom_or_re,
                dom_len,
                list_id: list_id as u16,
                mods_idx,
                action,
                kind,
            });
        }
        let content_hash = ch.finish();

        let override_scan = build_scan_group(override_meta, &records, &regexes, false);
        let block_scan = build_scan_group(block_meta, &records, &regexes, true);

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
            override_scan,
            block_scan,
            has_client_dependent_rules,
            content_hash,
        }
    }

    /// The original source line of a record (for `MatchInfo` / display).
    #[inline]
    fn raw(&self, r: &RuleRecord) -> &str {
        &self.raw_arena[r.raw_start as usize..r.raw_start as usize + r.raw_len as usize]
    }

    /// The normalised domain of an exact/subdomain record.
    #[inline]
    fn domain(&self, r: &RuleRecord) -> &str {
        &self.domain_arena[r.dom_or_re as usize..r.dom_or_re as usize + r.dom_len as usize]
    }

    /// The modifier cluster of a record, if any.
    #[inline]
    fn mods_of(&self, r: &RuleRecord) -> Option<&RuleMods> {
        (r.mods_idx != NO_MODS).then(|| &self.mods[r.mods_idx as usize])
    }

    /// Verifies a hash-bucket candidate against its stored domain.
    #[inline]
    fn domain_matches(&self, r: &RuleRecord, domain: &str) -> bool {
        match r.kind {
            kind::EXACT => self.domain(r) == domain,
            kind::SUBDOMAIN => is_subdomain_of(domain, self.domain(r)),
            _ => true,
        }
    }

    /// Returns the rule's winner-selection priority.
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

    /// Whether any verdict can depend on the client.
    pub fn has_client_dependent_rules(&self) -> bool {
        self.has_client_dependent_rules
    }

    /// Stable rule-set generation hash.
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

    /// Approximate retained-heap breakdown for tuning.
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

    /// Wildcard/regex scan sizes for tuning.
    #[doc(hidden)]
    pub fn scan_report(&self) -> [(&'static str, usize); 2] {
        [
            ("override_rules", self.override_scan.rule_count()),
            ("block_rules", self.block_scan.rule_count()),
        ]
    }

    /// Collects exact and subdomain candidates by hash.
    fn collect_domain(&self, domain: &str, out: &mut Vec<u32>) {
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
    }

    /// Collects matching wildcard and regex rules.
    fn scan_group(&self, group: &ScanGroup, domain: &str, tokens: &[u32], out: &mut Vec<u32>) {
        let check = |id: u32, out: &mut Vec<u32>| {
            let r = &self.rules[id as usize];
            if (r.kind == kind::WILDCARD || r.kind == kind::REGEX)
                && self.regexes[r.dom_or_re as usize].is_match(domain)
            {
                out.push(id);
            }
        };
        for (set, ids) in &group.fallback_sets {
            for idx in set.matches(domain) {
                out.push(ids[idx]);
            }
        }
        for &id in &group.fallback_individual {
            check(id, out);
        }
        if !group.scan_index.is_empty() {
            for &tok in tokens {
                if let Some(ids) = group.scan_index.get(&tok) {
                    for &id in ids {
                        check(id, out);
                    }
                }
            }
        }
    }

    /// Updates the highest-priority applicable candidate.
    fn consider(
        &self,
        ids: &[u32],
        domain: &str,
        rtype: &str,
        client: &ClientInfo<'_>,
        best: &mut Option<u32>,
        best_prio: &mut u32,
    ) {
        for &id in ids {
            let r = &self.rules[id as usize];
            if !self.domain_matches(r, domain) || !self.applicable(r, domain, rtype, client) {
                continue;
            }
            let prio = self.priority(r);
            if best.is_none() || prio > *best_prio {
                *best = Some(id);
                *best_prio = prio;
            }
        }
    }

    /// Checks rule modifiers against a query.
    fn applicable(
        &self,
        r: &RuleRecord,
        domain: &str,
        rtype: &str,
        client: &ClientInfo<'_>,
    ) -> bool {
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

        thread_local! {
            static CANDIDATES: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
            static TOKENS: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
        }

        let best_id = CANDIDATES.with(|ccell| {
            TOKENS.with(|tcell| {
                let mut candidates = ccell.borrow_mut();
                let mut best: Option<u32> = None;
                let mut best_prio = 0u32;

                candidates.clear();
                self.collect_domain(domain, &mut candidates);
                self.scan_group(&self.override_scan, domain, &[], &mut candidates);
                self.consider(
                    &candidates,
                    domain,
                    rtype,
                    client,
                    &mut best,
                    &mut best_prio,
                );

                if best.is_none() && !self.block_scan.is_empty() {
                    let mut tokens = tcell.borrow_mut();
                    tokens.clear();
                    if !self.block_scan.scan_index.is_empty() {
                        crate::token::for_each_query_token(domain, |t| tokens.push(t));
                    }
                    candidates.clear();
                    self.scan_group(&self.block_scan, domain, &tokens, &mut candidates);
                    self.consider(
                        &candidates,
                        domain,
                        rtype,
                        client,
                        &mut best,
                        &mut best_prio,
                    );
                }
                best
            })
        });

        match best_id {
            None => Verdict::Allow { rule: None },
            Some(id) => {
                let r = &self.rules[id as usize];
                let info = MatchInfo {
                    rule: self.raw(r).to_string(),
                    list_id: r.list_id as u32,
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
