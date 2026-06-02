//! Bulwark filtering engine: parses host-file lists and the DNS-relevant subset
//! of AdGuard rule syntax, then matches DNS queries against them.
//!
//! # Overview
//!
//! ```
//! use bulwark_filter::{compile_one, ClientInfo, Verdict};
//!
//! let engine = compile_one("||ads.example.com^\n@@||good.ads.example.com^");
//! let client = ClientInfo::default();
//!
//! assert!(engine.check("ads.example.com", "A", &client).is_blocked());
//! assert!(engine.check("x.ads.example.com", "A", &client).is_blocked());
//! // The exception un-blocks a specific subdomain.
//! assert!(!engine.check("good.ads.example.com", "A", &client).is_blocked());
//! ```

#![forbid(unsafe_code)]

pub mod engine;
pub mod list;
pub mod parser;
pub mod rule;

pub use engine::{FilterEngine, MatchInfo, Verdict};
pub use list::{compile_one, Compiler, ListStats};
pub use parser::{parse_line, ParseError, Parsed};
pub use rule::{
    Action, ClientInfo, ClientMatch, DnsTypeFilter, Pattern, RewriteData, RewriteRcode, Rule,
};

#[cfg(test)]
mod tests;
