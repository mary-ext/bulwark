//! Bulwark engine: the DNS query-processing pipeline tying together filtering,
//! caching, upstream resolution, client identification, query logging, and
//! statistics, plus the UDP/TCP DNS server.

#![forbid(unsafe_code)]
