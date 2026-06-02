//! Bulwark filtering engine: parses host-file lists and the DNS-relevant subset
//! of AdGuard rule syntax, then matches DNS queries against them.

#![forbid(unsafe_code)]
