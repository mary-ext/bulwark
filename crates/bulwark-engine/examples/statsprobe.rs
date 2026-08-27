//! Stats-subsystem retained-heap probe.
//!
//! Run with `cargo run --release --example statsprobe -p bulwark-engine [DISTINCT] [LEGACY_CAP]`.

use std::collections::HashMap;

use bulwark_engine::clients::ClientMatcher;
use bulwark_engine::querylog::{QueryAction, QueryLogEntry};
use bulwark_engine::stats::Stats;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn allocated() -> usize {
    use tikv_jemalloc_ctl::{epoch, stats};
    epoch::advance().unwrap();
    stats::allocated::read().unwrap()
}

fn entry(question: &str, client_ip: &str, action: QueryAction) -> QueryLogEntry {
    QueryLogEntry {
        question: question.to_string(),
        client_ip: client_ip.to_string(),
        action,
        elapsed_ms: 1.0,
        ..QueryLogEntry::empty()
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let distinct: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let legacy_cap: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(50_000);
    let base = allocated();
    let stats = Stats::new(true, 30, false);
    for i in 0..distinct {
        let q = format!("name{i}.example.com.");
        let client = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        let action = if i % 5 == 0 {
            QueryAction::Blocked {
                rule: "||ads^".into(),
                list_id: 0,
            }
        } else {
            QueryAction::Forwarded {
                upstream: "1.1.1.1".into(),
            }
        };
        stats.record(&entry(&q, &client, action), Some(1.0));
    }
    let new_retained = allocated().saturating_sub(base);
    let snap = stats.snapshot(20, &ClientMatcher::default());
    std::hint::black_box(&snap);
    let base2 = allocated();
    let mut resolved: HashMap<String, u64> = HashMap::new();
    let mut blocked: HashMap<String, u64> = HashMap::new();
    for i in 0..legacy_cap {
        resolved.insert(format!("name{i}.example.com."), 1);
        blocked.insert(format!("blk{i}.example.com."), 1);
    }
    let legacy_retained = allocated().saturating_sub(base2);
    std::hint::black_box((&resolved, &blocked));

    let mb = |b: usize| b as f64 / (1024.0 * 1024.0);
    println!("statsprobe (jemalloc retained heap)");
    println!("  stream:            {distinct} distinct domains + clients");
    println!(
        "  NEW bounded stats: {:>8.2} MiB  (top_resolved={}, top_clients={})",
        mb(new_retained),
        snap.top_resolved_domains.len(),
        snap.top_clients.len(),
    );
    println!(
        "  OLD domain maps:   {:>8.2} MiB  (2 × {legacy_cap} distinct keys)",
        mb(legacy_retained),
    );
    if new_retained > 0 {
        println!(
            "  domain-map ratio:  {:>8.1}×  smaller (new total vs old two domain maps alone)",
            legacy_retained as f64 / new_retained as f64,
        );
    }
}
