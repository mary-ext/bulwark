//! Combined memory + match-throughput harness for the filter engine.
//!
//! Reports retained heap per rule (broken down by component) and match latency
//! for a hit/miss query mix, so an engine change is gated on *measured* bytes
//! and queries/sec, not estimates.
//!
//! Synthetic list (default): `cargo run --release --example memprobe -p bulwark-filter [N] [ITERS]`
//! Real lists:               `LISTS=a.txt,b.txt cargo run --release --example memprobe -p bulwark-filter [ITERS]`
//!
//! Run under the same allocator + decay as prod for a true-retained figure:
//! `_RJEM_MALLOC_CONF=dirty_decay_ms:0,muzzy_decay_ms:0`.

use std::hint::black_box;
use std::net::IpAddr;
use std::time::Instant;

use bulwark_filter::engine::FilterEngine;
use bulwark_filter::list::Compiler;
use bulwark_filter::rule::{ClientInfo, Rule};

// Match the server's allocator (see server/src/main.rs) so RSS reflects prod.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn rss_kb() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Best-effort domain extraction from a list line, for building the hit
/// workload. Returns `None` for comments, exceptions, and anything that isn't a
/// plain `||domain^` / bare-domain / hosts entry.
fn sample_domain(line: &str) -> Option<String> {
    let l = line.trim();
    if l.is_empty() || l.starts_with('!') || l.starts_with('#') || l.starts_with('[') {
        return None;
    }
    // hosts: "ip domain ..."
    if let Some((first, rest)) = l.split_once(char::is_whitespace) {
        if first.parse::<IpAddr>().is_ok() {
            let host = rest.split_whitespace().next()?;
            if host.starts_with('#') {
                return None;
            }
            return clean(host);
        }
    }
    // adblock ||domain^ / bare domain (skip exceptions and modified rules)
    if l.starts_with("@@") {
        return None;
    }
    let mut s = l.strip_prefix("||").unwrap_or(l);
    if let Some(i) = s.find('$') {
        s = &s[..i];
    }
    let s = s.trim_end_matches('^').trim_end_matches('|');
    clean(s)
}

fn clean(s: &str) -> Option<String> {
    let s = s.trim_end_matches('.');
    if s.is_empty() || s.contains('/') || s.contains('*') || s.contains(':') || !s.contains('.') {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

fn main() {
    // BGTHREAD=1 verifies the exact runtime ctl the server uses to purge.
    if std::env::var("BGTHREAD").is_ok() {
        tikv_jemalloc_ctl::background_thread::write(true).expect("enable background_thread");
    }
    let mut args = std::env::args().skip(1);

    // Real-list mode if LISTS is set; otherwise a synthetic list of N rules.
    let (texts, iters): (Vec<(String, String)>, usize) = match std::env::var("LISTS") {
        Ok(paths) => {
            let iters = args.next().and_then(|s| s.parse().ok()).unwrap_or(5_000_000);
            let v = paths
                .split(',')
                .map(|p| (p.to_string(), std::fs::read_to_string(p).expect("read list")))
                .collect();
            (v, iters)
        }
        Err(_) => {
            let n: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
            let iters: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(5_000_000);
            let mut text = String::with_capacity(n * 46);
            for i in 0..n {
                text.push_str(&format!("||tracker{i:07}.ads-cdn-segment.example.com^\n"));
            }
            (vec![("synthetic".to_string(), text)], iters)
        }
    };

    println!("size_of::<Rule>()    = {} bytes", std::mem::size_of::<Rule>());
    let text_bytes: usize = texts.iter().map(|(_, t)| t.len()).sum();

    let before = rss_kb();
    let mut c = Compiler::new();
    for (i, (name, t)) in texts.iter().enumerate() {
        c.add_list(i as u32, name, t);
    }
    let (engine, _stats): (FilterEngine, _) = c.build();

    // Sample real blocked domains for the hit workload before dropping the text.
    const POOL: usize = 4096;
    let mut samples: Vec<String> = Vec::new();
    'outer: for (_, t) in &texts {
        for line in t.lines() {
            if let Some(d) = sample_domain(line) {
                samples.push(d);
                if samples.len() >= POOL / 2 {
                    break 'outer;
                }
            }
        }
    }
    drop(texts);
    let after = rss_kb();

    // Optional settle: sleep so jemalloc's decay / background_thread can return
    // the dirty pages left by the build, exposing how much of `after` is
    // allocator retention vs true live heap. `SETTLE_SECS=N` to enable.
    let settled = match std::env::var("SETTLE_SECS").ok().and_then(|s| s.parse().ok()) {
        Some(secs) if secs > 0 => {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            Some(rss_kb())
        }
        _ => None,
    };

    let n = engine.len().max(1);
    println!("rules                = {}", engine.len());
    println!("source text          = {:.1} MiB", text_bytes as f64 / 1048576.0);
    println!("RSS before build     = {:.1} MiB", before as f64 / 1024.0);
    println!("RSS after build      = {:.1} MiB", after as f64 / 1024.0);
    if let Some(s) = settled {
        println!("RSS settled          = {:.1} MiB", s as f64 / 1024.0);
    }
    println!(
        "retained / rule      = {:.0} bytes",
        (after.saturating_sub(before)) as f64 * 1024.0 / n as f64
    );
    println!("---- composition (B/rule) ----");
    for (label, bytes) in engine.mem_report() {
        println!("  {label:14} = {:.1}", bytes as f64 / n as f64);
    }
    println!("---- scan structure (rule counts) ----");
    for (label, count) in engine.scan_report() {
        println!("  {label:20} = {count}");
    }

    // Query pool: interleave real blocked domains (hits) with synthetic misses.
    // Falls back to synthetic hits if no domains were sampled.
    let queries: Vec<String> = (0..POOL)
        .map(|j| {
            if j & 1 == 0 && !samples.is_empty() {
                samples[(j / 2) % samples.len()].clone()
            } else if j & 1 == 0 {
                format!("sub.tracker{:07}.ads-cdn-segment.example.com", j % n)
            } else {
                format!("host{j:07}.legit-service-{j}.example.org")
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
