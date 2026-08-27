use bulwark_filter::{compile_one, ClientInfo};
use std::time::Instant;
fn main() {
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
    let build = t0.elapsed();
    println!("rules={} build={:?}", engine.len(), build);
    let ci = ClientInfo::default();
    let t1 = Instant::now();
    let n = 500_000u32;
    let mut hits = 0u64;
    for i in 0..n {
        let host = format!("ads{}.example{}.com", i % 180_000, (i % 180_000) % 997);
        if engine.check(&host, "A", &ci).is_blocked() {
            hits += 1;
        }
    }
    let look = t1.elapsed();
    println!(
        "lookups={} hits={} total={:?} per_query={:?}",
        n,
        hits,
        look,
        look / n
    );
}
