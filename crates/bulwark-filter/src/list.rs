//! Loading and compiling filter lists into a [`FilterEngine`].

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::engine::FilterEngine;
use crate::parser::{parse_line, Parsed};
use crate::rule::BuildRule;

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
        let active: Vec<BuildRule> = rules
            .into_iter()
            .filter(|r| !badfilter_sigs.contains(&r.signature))
            .filter(|r| seen.insert(r.signature.clone()))
            .collect();
        (FilterEngine::from_rules(active), stats)
    }
}

/// Convenience: compile a single list's text into an engine.
pub fn compile_one(text: &str) -> FilterEngine {
    let mut c = Compiler::new();
    c.add_list(0, "inline", text);
    c.build().0
}
