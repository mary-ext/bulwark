//! Throwaway-ish micro-benchmark for the filter engine at scale.
//!
//! Run with: `cargo run --release --example bench_filter -p bulwark`

use std::time::Instant;

use bulwark_filter::{compile_one, ClientInfo};

fn main() {
    // ~200k mixed rules: mostly ||domain^ and hosts, a few thousand wildcards.
    let mut text = String::new();
    for i in 0..180_000 {
        text.push_str(&format!("||ads{i}.example{}.com^\n", i % 997));
    }
    for i in 0..15_000 {
        text.push_str(&format!("0.0.0.0 tracker{i}.net\n"));
    }
    for i in 0..5_000 {
        text.push_str(&format!("||*.cdn{i}.evil.io^\n"));
    }

    let t0 = Instant::now();
    let engine = compile_one(&text);
    println!("rules={} build={:?}", engine.len(), t0.elapsed());

    let ci = ClientInfo::default();
    let n = 1_000_000u32;

    // Matching queries (block).
    let t1 = Instant::now();
    let mut hits = 0u64;
    for i in 0..n {
        let host = format!("ads{}.example{}.com", i % 180_000, (i % 180_000) % 997);
        if engine.check(&host, "A", &ci).is_blocked() {
            hits += 1;
        }
    }
    let d = t1.elapsed();
    println!("match:    {n} lookups hits={hits} {d:?} ({:?}/q)", d / n);

    // Non-matching queries (the overwhelmingly common case for a resolver).
    let t2 = Instant::now();
    for i in 0..n {
        let host = format!("legit{}.good-domain.example", i);
        let _ = engine.check(&host, "A", &ci);
    }
    let d2 = t2.elapsed();
    println!("nomatch:  {n} lookups {d2:?} ({:?}/q)", d2 / n);
}
