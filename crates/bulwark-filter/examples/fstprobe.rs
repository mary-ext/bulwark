//! FST domain-index size and throughput experiment.
//!
//! Run with `LISTS=a.txt[,b.txt] cargo run --release --example fstprobe -p bulwark-filter [ITERS]`.

use std::collections::HashMap;
use std::hint::black_box;
use std::net::IpAddr;
use std::time::Instant;

use fst::raw::{Fst, Output};

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
fn extract(line: &str) -> Option<String> {
    let l = line.trim();
    if l.is_empty() || l.starts_with('!') || l.starts_with('#') || l.starts_with('[') {
        return None;
    }
    if let Some((first, rest)) = l.split_once(char::is_whitespace) {
        if first.parse::<IpAddr>().is_ok() {
            let host = rest.split_whitespace().next()?;
            return clean(host);
        }
    }
    if l.starts_with("@@") {
        return None;
    }
    let mut s = l.strip_prefix("||").unwrap_or(l);
    if let Some(i) = s.find('$') {
        s = &s[..i];
    }
    clean(s.trim_end_matches('^').trim_end_matches('|'))
}

fn clean(s: &str) -> Option<String> {
    let s = s.trim_end_matches('.');
    if s.is_empty() || s.contains('/') || s.contains('*') || s.contains(':') || !s.contains('.') {
        return None;
    }
    Some(s.to_ascii_lowercase())
}
fn rev_labels(d: &str) -> String {
    let mut parts: Vec<&str> = d.split('.').collect();
    parts.reverse();
    parts.join(".")
}
fn fst_match(fst: &Fst<Vec<u8>>, q: &str, out: &mut Vec<u64>) {
    let rq = rev_labels(q);
    let bytes = rq.as_bytes();
    let mut node = fst.root();
    let mut acc = Output::zero();
    for &b in bytes {
        if b == b'.' && node.is_final() {
            out.push(acc.cat(node.final_output()).value());
        }
        match node.find_input(b) {
            Some(i) => {
                let t = node.transition(i);
                acc = acc.cat(t.out);
                node = fst.node(t.addr);
            }
            None => return,
        }
    }
    if node.is_final() {
        out.push(acc.cat(node.final_output()).value()); // full exact match
    }
}

fn main() {
    let iters: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000_000);
    let paths = std::env::var("LISTS").expect("set LISTS=path[,path]");
    let mut set: Vec<String> = Vec::new();
    for p in paths.split(',') {
        let text = std::fs::read_to_string(p).expect("read list");
        for line in text.lines() {
            if let Some(d) = extract(line) {
                set.push(d);
            }
        }
    }
    set.sort();
    set.dedup();
    let n = set.len();
    println!("domains              = {n}");
    let hasher = ahash::RandomState::new();
    let mut dom_text = String::new();
    let mut spans: Vec<(u32, u8)> = Vec::with_capacity(n);
    let mut pairs: Vec<(u64, u32)> = Vec::with_capacity(n);
    for (i, d) in set.iter().enumerate() {
        spans.push((dom_text.len() as u32, d.len() as u8));
        dom_text.push_str(d);
        pairs.push((hasher.hash_one(d.as_str()), i as u32));
    }
    pairs.sort_unstable_by_key(|p| p.0);
    let mut map: HashMap<u64, (u32, u32)> = HashMap::with_capacity(n);
    let mut hits: Vec<u32> = Vec::with_capacity(n);
    let mut i = 0;
    while i < pairs.len() {
        let h = pairs[i].0;
        let start = hits.len() as u32;
        while i < pairs.len() && pairs[i].0 == h {
            hits.push(pairs[i].1);
            i += 1;
        }
        map.insert(h, (start, hits.len() as u32 - start));
    }
    let hashmap_bytes = dom_text.len()
        + map.capacity() * std::mem::size_of::<(u64, (u32, u32))>()
        + hits.capacity() * 4
        + spans.capacity() * std::mem::size_of::<(u32, u8)>();
    let mut keyed: Vec<(String, u64)> = set
        .iter()
        .enumerate()
        .map(|(i, d)| (rev_labels(d), i as u64))
        .collect();
    keyed.sort();
    keyed.dedup_by(|a, b| a.0 == b.0); // FST needs unique sorted keys
    let mut builder = fst::MapBuilder::memory();
    for (k, v) in &keyed {
        builder.insert(k, *v).unwrap();
    }
    let fst_map = builder.into_map();
    let fst = fst_map.as_fst();
    let fst_bytes = fst.as_bytes().len();

    println!("---- size ----");
    println!(
        "hashmap (text+idx)   = {hashmap_bytes} B  ({:.1} B/rule)",
        hashmap_bytes as f64 / n as f64
    );
    println!(
        "fst                  = {fst_bytes} B  ({:.1} B/rule, {:.2}x smaller)",
        fst_bytes as f64 / n as f64,
        hashmap_bytes as f64 / fst_bytes as f64
    );
    const POOL: usize = 4096;
    let queries: Vec<String> = (0..POOL)
        .map(|j| {
            let d = &set[(j * 7919) % n];
            if j & 1 == 0 {
                format!("sub.{d}") // subdomain hit
            } else {
                format!("nx{j}.legit-service-{j}.example.org") // miss
            }
        })
        .collect();
    let hashmap_lookup = |q: &str, out: &mut Vec<u32>| {
        let mut hay = q;
        loop {
            if let Some(&(s, l)) = map.get(&hasher.hash_one(hay)) {
                for &id in &hits[s as usize..(s + l) as usize] {
                    let (st, ln) = spans[id as usize];
                    if &dom_text[st as usize..st as usize + ln as usize] == hay {
                        out.push(id);
                    }
                }
            }
            match hay.find('.') {
                Some(k) => hay = &hay[k + 1..],
                None => break,
            }
        }
    };

    let bench = |name: &str, f: &dyn Fn(&str, &mut Vec<u64>)| {
        let mut scratch = Vec::new();
        let mut found = 0u64;
        let mut st: u64 = 0x9e37_79b9_7f4a_7c15;
        let t0 = Instant::now();
        for _ in 0..iters {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let q = &queries[(st >> 40) as usize % POOL];
            scratch.clear();
            f(q, &mut scratch);
            found += scratch.len() as u64;
            black_box(&scratch);
        }
        let per = t0.elapsed().as_nanos() as f64 / iters as f64;
        println!("  {name:18} = {per:5.1} ns/lookup  ({found} hits)");
    };

    println!("---- throughput ----");
    bench("hashmap walk", &|q, out| {
        let mut v: Vec<u32> = Vec::new();
        hashmap_lookup(q, &mut v);
        out.extend(v.into_iter().map(u64::from));
    });
    bench("fst walk", &|q, out| fst_match(fst, q, out));
}
