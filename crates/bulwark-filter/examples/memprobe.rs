//! Combined memory + match-throughput harness for the filter engine.
//!
//! Builds a synthetic AdGuard-style blocklist and reports both the retained
//! heap per rule and the match latency for a hit/miss query mix, so a memory
//! refactor can be gated on *measured* throughput, not just bytes saved.
//!
//! Usage: `cargo run --release --example memprobe -p bulwark-filter [N] [ITERS]`

use std::hint::black_box;
use std::time::Instant;

use bulwark_filter::engine::FilterEngine;
use bulwark_filter::list::Compiler;
use bulwark_filter::rule::{ClientInfo, Rule};

fn rss_kb() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0);
        }
    }
    0
}

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let iters: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(5_000_000);

    println!("size_of::<Rule>()    = {} bytes", std::mem::size_of::<Rule>());

    // Synthetic blocklist of plain ||domain^ rules with realistic ~30-char
    // domains (the overwhelmingly common blocklist shape).
    let mut text = String::new();
    for i in 0..n {
        text.push_str(&format!("||tracker{i:07}.ads-cdn-segment.example.com^\n"));
    }
    let text_bytes = text.len();

    let before = rss_kb();
    let mut c = Compiler::new();
    c.add_list(0, "synthetic", &text);
    let (engine, _stats): (FilterEngine, _) = c.build();
    drop(text);
    let after = rss_kb();

    println!("rules                = {}", engine.len());
    println!("source text          = {:.1} MiB", text_bytes as f64 / 1048576.0);
    println!("RSS before build     = {:.1} MiB", before as f64 / 1024.0);
    println!("RSS after build      = {:.1} MiB", after as f64 / 1024.0);
    println!(
        "retained / rule      = {:.0} bytes",
        (after.saturating_sub(before)) as f64 * 1024.0 / n as f64
    );

    // Pre-generate a query pool (half guaranteed hits — a subdomain of a real
    // blocked domain — half guaranteed misses) so the timed loop measures
    // matching, not `format!` allocation. Built after the RSS snapshot so it
    // doesn't pollute the per-rule figure.
    const POOL: usize = 4096;
    let queries: Vec<String> = (0..POOL)
        .map(|j| {
            let idx = (j * 7919) % n;
            if j & 1 == 0 {
                format!("sub.tracker{idx:07}.ads-cdn-segment.example.com")
            } else {
                format!("host{idx:07}.legit-service.example.org")
            }
        })
        .collect();

    // A cheap LCG strides across the pool so we're not hammering one hot line.
    let client = ClientInfo::default();
    let mut hits = 0u64;
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let t0 = Instant::now();
    for _ in 0..iters {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let q = &queries[(state >> 40) as usize % POOL];
        let v = engine.check(q, "A", &client);
        if v.is_blocked() {
            hits += 1;
        }
        black_box(&v);
    }
    let elapsed = t0.elapsed();
    let per = elapsed.as_nanos() as f64 / iters as f64;
    println!("---- throughput ----");
    println!("queries              = {iters} ({hits} blocked)");
    println!("ns / query           = {per:.1}");
    println!("Mqueries / sec       = {:.2}", 1000.0 / per);

    black_box(&engine);
}
