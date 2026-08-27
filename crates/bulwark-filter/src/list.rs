//! Filter-list compilation.

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

    /// Builds an engine after applying `$badfilter` and deduplication.
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

/// Removes plain blocks covered by an unmodified ancestor subdomain block.
fn prune_redundant(active: &mut Vec<BuildRule>) {
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
    let keep: Vec<bool> = active
        .iter()
        .map(|br| !is_redundant(br, &subsumers))
        .collect();
    drop(subsumers);
    let mut i = 0;
    active.retain(|_| {
        let k = keep[i];
        i += 1;
        k
    });
}

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
