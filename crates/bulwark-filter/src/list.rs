//! Loading and compiling filter lists into a [`FilterEngine`].

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::engine::FilterEngine;
use crate::parser::{parse_line, Parsed};
use crate::rule::{Action, BuildRule, Pattern};

/// Per-list statistics gathered while compiling.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListStats {
    pub list_id: u32,
    pub name: String,
    /// Total non-empty, non-comment lines that produced rules.
    pub rules: usize,
    /// Lines skipped because they carried only unsupported (HTTP) modifiers.
    pub unsupported: usize,
    /// Lines that failed to parse.
    pub errors: usize,
}

/// Accumulates rules from one or more lists, resolves `$badfilter`, and builds a
/// [`FilterEngine`].
#[derive(Default)]
pub struct Compiler {
    rules: Vec<BuildRule>,
    badfilter_sigs: HashSet<String>,
    stats: Vec<ListStats>,
}

impl Compiler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse and add every line of `text` as belonging to list `list_id`.
    pub fn add_list(&mut self, list_id: u32, name: &str, text: &str) -> ListStats {
        let mut stats = ListStats {
            list_id,
            name: name.to_string(),
            ..Default::default()
        };
        for line in text.lines() {
            match parse_line(line) {
                Ok(Parsed::Rules(rules)) => {
                    for mut rule in rules {
                        rule.rule.list_id = list_id;
                        if rule.badfilter {
                            self.badfilter_sigs.insert(rule.signature.clone());
                            // A badfilter rule only disables others; it is not
                            // itself a matchable rule.
                            continue;
                        }
                        stats.rules += 1;
                        self.rules.push(rule);
                    }
                }
                Ok(Parsed::Ignored) => {}
                Ok(Parsed::Unsupported(_)) => stats.unsupported += 1,
                Err(_) => stats.errors += 1,
            }
        }
        self.stats.push(stats.clone());
        stats
    }

    /// Consume the compiler, producing the engine and the gathered stats.
    ///
    /// Rules cancelled by `$badfilter` are dropped, and exact-duplicate rules
    /// (same signature — pattern + modifiers + action) are de-duplicated, which
    /// matters a lot for overlapping blocklists. The first occurrence wins (so
    /// its source list keeps the attribution).
    pub fn build(self) -> (FilterEngine, Vec<ListStats>) {
        let Compiler {
            rules,
            badfilter_sigs,
            stats,
        } = self;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut active: Vec<BuildRule> = rules
            .into_iter()
            .filter(|r| !badfilter_sigs.contains(&r.signature))
            .filter(|r| seen.insert(r.signature.clone()))
            .collect();
        prune_redundant(&mut active);
        (FilterEngine::from_rules(active), stats)
    }
}

/// Drop plain block rules already covered by a broader plain `||ancestor^`
/// subdomain block — e.g. `||ads.doubleclick.net^` (or a hosts entry for the
/// same host) when `||doubleclick.net^` is also blocked. Real merged blocklists
/// carry a meaningful fraction of these.
///
/// Soundness: a rule is removed only when it is a **plain** (unmodified) `Block`
/// *and* a plain **subdomain** `Block` exists for a strict ancestor (for an
/// exact/hosts rule, also the same domain). The surviving subdomain rule matches
/// the removed rule's domain and every subdomain of it, with the same action and
/// no client/type narrowing, so the verdict is identical for every query and
/// client. Anything that could differ — exceptions (`@@`), `$important`,
/// rewrites, `$client`/`$ctag`/`$dnstype`/`$denyallow`, and the subsuming
/// subdomain rules themselves — is never removed. The only observable change is
/// that a removed rule's query-log attribution shifts to the broader survivor.
fn prune_redundant(active: &mut Vec<BuildRule>) {
    // Subsumers: the domains of plain subdomain Block rules.
    let subsumers: HashSet<&str> = active
        .iter()
        .filter_map(|br| {
            if br.rule.action == Action::Block && br.rule.mods.is_none() {
                if let Pattern::Subdomain(d) = &br.rule.pattern {
                    return Some(d.as_str());
                }
            }
            None
        })
        .collect();
    if subsumers.is_empty() {
        return;
    }
    // Mask first (borrows `active` immutably via `subsumers`), then prune.
    let keep: Vec<bool> = active.iter().map(|br| !is_redundant(br, &subsumers)).collect();
    drop(subsumers);
    let mut i = 0;
    active.retain(|_| {
        let k = keep[i];
        i += 1;
        k
    });
}

/// Is this a plain Block rule whose domain is already covered by a subsuming
/// subdomain block in `subsumers`? Exact rules also test their own domain (a
/// subdomain block of `d` covers the exact host `d`); subdomain rules test only
/// strict ancestors (an equal-domain duplicate would already be deduped).
fn is_redundant(br: &BuildRule, subsumers: &HashSet<&str>) -> bool {
    if br.rule.action != Action::Block || br.rule.mods.is_some() {
        return false;
    }
    let (d, include_self) = match &br.rule.pattern {
        Pattern::Subdomain(d) => (d.as_str(), false),
        Pattern::Exact(d) => (d.as_str(), true),
        _ => return false,
    };
    if include_self && subsumers.contains(d) {
        return true;
    }
    let mut rest = d;
    while let Some(idx) = rest.find('.') {
        rest = &rest[idx + 1..];
        if subsumers.contains(rest) {
            return true;
        }
    }
    false
}

/// Convenience: compile a single list's text into an engine.
pub fn compile_one(text: &str) -> FilterEngine {
    let mut c = Compiler::new();
    c.add_list(0, "inline", text);
    c.build().0
}
