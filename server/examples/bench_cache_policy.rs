//! Cache **eviction-policy** prototype + hit-rate benchmark.
//!
//! The production `DnsCache` is LRU-bounded. A recurring question is whether it
//! should instead be MRU, or some recency+frequency *mixture*. Eviction policy
//! only governs *which entry is dropped when the cache is full* — it is entirely
//! independent of TTL/serve-stale (those decide freshness, not residency). So we
//! isolate the question here: replay synthetic access streams through several
//! policies at a fixed capacity and compare **hit rate** (the metric that
//! actually drives upstream load).
//!
//! Run with:
//!   cargo run --release --example bench_cache_policy -p bulwark
//!
//! Knobs (env):
//!   CACHE_ACCESSES   accesses replayed per (workload, policy)   (default 2_000_000)
//!   CACHE_UNIVERSE   number of distinct domains in the universe (default 100_000)
//!   CACHE_ZIPF_S     Zipfian skew for the "realistic DNS" stream (default 1.0)
//!   CACHE_SEED       RNG seed (deterministic, comparable runs)   (default 0x5757)
//!
//! Policies compared:
//!   LRU       — evict least-recently-used (the current production policy).
//!   MRU       — evict most-recently-used (the proposed alternative).
//!   SLRU      — segmented LRU: a probation + a protected segment. A recency
//!               *and* frequency mixture — an entry must be re-referenced to earn
//!               a slot in the protected segment, so one-off lookups can't evict
//!               proven-popular names. This is the "mixture" worth considering.
//!   W-TinyLFU — LRU main store fronted by a frequency-sketch admission filter:
//!               a candidate is only admitted over the LRU victim if it has been
//!               seen at least as often. State-of-the-art for skewed workloads.
//!
//! Workloads:
//!   zipf(s)   — Zipfian popularity. This is what real resolver traffic looks
//!               like (a few very hot names + a long tail). LRU's home turf.
//!   uniform   — every domain equally likely ("hit it with random requests").
//!               No locality at all; the worst case for *any* policy.
//!   scan-loop — repeatedly sweep a working set larger than the cache. The one
//!               and only pattern where MRU beats LRU; included for honesty.

use std::collections::{BTreeMap, HashMap, VecDeque};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// ---------------------------------------------------------------------------
// Policy trait. `access` returns true on a hit; the cache is mutated to reflect
// the access (recency bump on hit, admit/evict on miss).
// ---------------------------------------------------------------------------

trait Policy {
    fn access(&mut self, key: u32) -> bool;
}

// ---------------------------------------------------------------------------
// Recency-ordered cache: one structure parameterized by which end it evicts.
// A logical clock + a BTreeMap recency index gives O(log n) access/evict and
// makes LRU vs MRU a single boolean.
// ---------------------------------------------------------------------------

struct Recency {
    cap: usize,
    clock: u64,
    map: HashMap<u32, u64>,    // key -> last-use tick
    order: BTreeMap<u64, u32>, // tick -> key (ordered by recency)
    evict_mru: bool,
}

impl Recency {
    fn new(cap: usize, evict_mru: bool) -> Self {
        Self {
            cap: cap.max(1),
            clock: 0,
            map: HashMap::with_capacity(cap * 2),
            order: BTreeMap::new(),
            evict_mru,
        }
    }
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }
}

impl Policy for Recency {
    fn access(&mut self, key: u32) -> bool {
        if let Some(&old) = self.map.get(&key) {
            self.order.remove(&old);
            let t = self.tick();
            self.order.insert(t, key);
            self.map.insert(key, t);
            return true;
        }
        if self.map.len() >= self.cap {
            // Evict from the chosen end of the recency order.
            let victim_tick = if self.evict_mru {
                *self.order.keys().next_back().unwrap()
            } else {
                *self.order.keys().next().unwrap()
            };
            let victim = self.order.remove(&victim_tick).unwrap();
            self.map.remove(&victim);
        }
        let t = self.tick();
        self.order.insert(t, key);
        self.map.insert(key, t);
        false
    }
}

// ---------------------------------------------------------------------------
// Segmented LRU (SLRU): probation (newcomers) + protected (proven). A miss lands
// in probation; a *second* reference promotes to protected. When protected is
// full the promotion demotes protected's LRU back to probation. This is the
// recency+frequency "mixture": a single one-off lookup can never displace a name
// that has demonstrated repeat demand.
// ---------------------------------------------------------------------------

struct Slru {
    prot_cap: usize,
    prob_cap: usize,
    protected: LruList,
    probation: LruList,
}

impl Slru {
    fn new(cap: usize, protected_frac: f64) -> Self {
        let prot = ((cap as f64 * protected_frac) as usize).clamp(1, cap.saturating_sub(1).max(1));
        let prob = cap.saturating_sub(prot).max(1);
        Self {
            prot_cap: prot,
            prob_cap: prob,
            protected: LruList::new(prot),
            probation: LruList::new(prob),
        }
    }
}

impl Policy for Slru {
    fn access(&mut self, key: u32) -> bool {
        if self.protected.touch(key) {
            return true; // hot stays hot
        }
        if self.probation.remove(key) {
            // Promote into protected; demote protected's LRU if it overflows.
            if self.protected.len() >= self.prot_cap {
                if let Some(demoted) = self.protected.pop_lru() {
                    if self.probation.len() >= self.prob_cap {
                        self.probation.pop_lru();
                    }
                    self.probation.push_mru(demoted);
                }
            }
            self.protected.push_mru(key);
            return true;
        }
        // Miss: admit into probation.
        if self.probation.len() >= self.prob_cap {
            self.probation.pop_lru();
        }
        self.probation.push_mru(key);
        false
    }
}

/// Minimal LRU list backed by a VecDeque for order + HashMap for membership.
/// Capacity is enforced by the owning SLRU. Order ops are amortized; fine for a
/// single-threaded sim.
struct LruList {
    order: VecDeque<u32>, // front = LRU, back = MRU
    set: HashMap<u32, ()>,
}

impl LruList {
    fn new(cap: usize) -> Self {
        Self {
            order: VecDeque::with_capacity(cap + 1),
            set: HashMap::with_capacity(cap * 2),
        }
    }
    fn len(&self) -> usize {
        self.set.len()
    }
    fn contains(&self, key: u32) -> bool {
        self.set.contains_key(&key)
    }
    /// Bump to MRU if present; returns whether it was a hit.
    fn touch(&mut self, key: u32) -> bool {
        if !self.contains(key) {
            return false;
        }
        if let Some(pos) = self.order.iter().position(|&k| k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
        true
    }
    fn remove(&mut self, key: u32) -> bool {
        if self.set.remove(&key).is_none() {
            return false;
        }
        if let Some(pos) = self.order.iter().position(|&k| k == key) {
            self.order.remove(pos);
        }
        true
    }
    fn push_mru(&mut self, key: u32) {
        self.set.insert(key, ());
        self.order.push_back(key);
    }
    fn pop_lru(&mut self) -> Option<u32> {
        let k = self.order.pop_front()?;
        self.set.remove(&k);
        Some(k)
    }
}

// ---------------------------------------------------------------------------
// W-TinyLFU-lite: LRU main store + a count-min frequency sketch as an admission
// filter. On a miss against a full cache, the incoming key is only admitted if
// its estimated frequency is >= the LRU victim's. Counts are aged (halved) every
// `sample` accesses so the filter tracks *recent* popularity, not all-time.
// ---------------------------------------------------------------------------

struct TinyLfu {
    main: Recency, // LRU main store
    sketch: CountMin,
    sample: u64,
    seen: u64,
}

impl TinyLfu {
    fn new(cap: usize) -> Self {
        Self {
            main: Recency::new(cap, false),
            sketch: CountMin::new(cap * 8),
            sample: (cap as u64 * 10).max(1),
            seen: 0,
        }
    }
    fn bump(&mut self, key: u32) {
        self.sketch.add(key);
        self.seen += 1;
        if self.seen >= self.sample {
            self.sketch.halve();
            self.seen = 0;
        }
    }
}

impl Policy for TinyLfu {
    fn access(&mut self, key: u32) -> bool {
        self.bump(key);
        if self.main.map.contains_key(&key) {
            // Hit: just refresh recency.
            self.main.access(key);
            return true;
        }
        // Miss. If there's room, admit unconditionally.
        if self.main.map.len() < self.main.cap {
            self.main.access(key);
            return false;
        }
        // Full: admit only if the candidate is at least as frequent as the LRU
        // victim. TinyLFU's key idea — protect the cache from one-hit wonders.
        let victim_tick = *self.main.order.keys().next().unwrap();
        let victim = *self.main.order.get(&victim_tick).unwrap();
        if self.sketch.est(key) >= self.sketch.est(victim) {
            self.main.access(key); // evicts the LRU victim, inserts candidate
        }
        // else: reject the candidate, leave the cache untouched.
        false
    }
}

/// 4-row count-min sketch with saturating u16 counters.
struct CountMin {
    width: usize,
    rows: [Vec<u16>; 4],
    seeds: [u64; 4],
}

impl CountMin {
    fn new(width: usize) -> Self {
        let w = width.next_power_of_two().max(16);
        Self {
            width: w,
            rows: [vec![0; w], vec![0; w], vec![0; w], vec![0; w]],
            seeds: [
                0x9E3779B97F4A7C15,
                0xC2B2AE3D27D4EB4F,
                0x165667B19E3779F9,
                0xD6E8FEB86659FD93,
            ],
        }
    }
    fn idx(&self, key: u32, seed: u64) -> usize {
        // Fibonacci-hash style mix.
        let mut h = (key as u64).wrapping_add(seed);
        h ^= h >> 33;
        h = h.wrapping_mul(0xFF51AFD7ED558CCD);
        h ^= h >> 33;
        (h as usize) & (self.width - 1)
    }
    fn add(&mut self, key: u32) {
        for r in 0..4 {
            let i = self.idx(key, self.seeds[r]);
            let c = &mut self.rows[r][i];
            *c = c.saturating_add(1);
        }
    }
    fn est(&self, key: u32) -> u16 {
        let mut m = u16::MAX;
        for r in 0..4 {
            let i = self.idx(key, self.seeds[r]);
            m = m.min(self.rows[r][i]);
        }
        m
    }
    fn halve(&mut self) {
        for row in &mut self.rows {
            for c in row.iter_mut() {
                *c >>= 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Workload generators. Each returns an iterator-like closure producing the next
// key; we precompute into a Vec for replay so every policy sees the *same*
// stream (apples-to-apples).
// ---------------------------------------------------------------------------

/// Zipfian sampler via a precomputed normalized CDF + binary search.
struct Zipf {
    cdf: Vec<f64>,
}

impl Zipf {
    fn new(n: usize, s: f64) -> Self {
        let mut cdf = Vec::with_capacity(n);
        let mut acc = 0.0f64;
        for k in 1..=n {
            acc += 1.0 / (k as f64).powf(s);
            cdf.push(acc);
        }
        let total = acc;
        for v in &mut cdf {
            *v /= total;
        }
        Self { cdf }
    }
    fn sample(&self, u: f64) -> u32 {
        // First index whose cumulative prob exceeds u. rank 0 == hottest.
        self.cdf.partition_point(|&c| c < u) as u32
    }
}

fn gen_zipf(rng: &mut StdRng, universe: usize, s: f64, n: usize) -> Vec<u32> {
    let z = Zipf::new(universe, s);
    (0..n).map(|_| z.sample(rng.random::<f64>())).collect()
}

fn gen_uniform(rng: &mut StdRng, universe: usize, n: usize) -> Vec<u32> {
    (0..n).map(|_| rng.random_range(0..universe as u32)).collect()
}

/// Repeatedly sweep `working_set` distinct keys in order. Classic LRU pathology
/// (and MRU's one winning case) when working_set > cache capacity.
fn gen_scan(working_set: usize, n: usize) -> Vec<u32> {
    (0..n).map(|i| (i % working_set) as u32).collect()
}

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok().or_else(|| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok()))
        .unwrap_or(default)
}

fn build_policies(cap: usize) -> Vec<Box<dyn Policy>> {
    vec![
        Box::new(Recency::new(cap, false)),
        Box::new(Recency::new(cap, true)),
        Box::new(Slru::new(cap, 0.8)),
        Box::new(TinyLfu::new(cap)),
    ]
}

fn hit_rate(policy: &mut dyn Policy, stream: &[u32]) -> f64 {
    let mut hits = 0u64;
    for &k in stream {
        if policy.access(k) {
            hits += 1;
        }
    }
    hits as f64 / stream.len() as f64 * 100.0
}

fn run_workload(title: &str, note: &str, stream: &[u32], universe: usize, ratios: &[f64]) {
    println!("\n== {title} ==");
    println!("  {note}");
    println!(
        "  {:>10}  {:>8}  {:>8}  {:>8}  {:>10}",
        "cache", "LRU", "MRU", "SLRU", "W-TinyLFU"
    );
    for &r in ratios {
        let cap = ((universe as f64) * r).round() as usize;
        let cap = cap.max(1);
        let mut policies = build_policies(cap);
        let mut rates = Vec::new();
        for p in policies.iter_mut() {
            rates.push(hit_rate(p.as_mut(), stream));
        }
        println!(
            "  {:>9}({:>3.0}%) {:>7.2}% {:>7.2}% {:>7.2}% {:>9.2}%",
            cap,
            r * 100.0,
            rates[0],
            rates[1],
            rates[2],
            rates[3],
        );
    }
}

fn main() {
    let accesses = env_usize("CACHE_ACCESSES", 2_000_000);
    let universe = env_usize("CACHE_UNIVERSE", 100_000);
    let zipf_s = env_f64("CACHE_ZIPF_S", 1.0);
    let seed = env_u64("CACHE_SEED", 0x5757);

    println!("== Bulwark cache eviction-policy benchmark ==");
    println!(
        "  accesses/run={accesses}  universe={universe}  zipf_s={zipf_s}  seed={seed:#x}"
    );
    println!("  metric = hit rate (higher is better); each column is a policy.");

    let mut rng = StdRng::seed_from_u64(seed);

    // Cache-size ratios relative to the universe (tiny -> roomy).
    let ratios = [0.005f64, 0.01, 0.05, 0.10, 0.25];

    // (1) Realistic DNS: Zipfian popularity.
    let zipf = gen_zipf(&mut rng, universe, zipf_s, accesses);
    run_workload(
        "Workload: zipf (realistic DNS traffic)",
        "A few very hot names + a long tail. This is what resolvers actually see.",
        &zipf,
        universe,
        &ratios,
    );

    // (2) Uniform random — "hit it with random requests".
    let uniform = gen_uniform(&mut rng, universe, accesses);
    run_workload(
        "Workload: uniform random (no locality)",
        "Every domain equally likely. Worst case for any policy; pure capacity.",
        &uniform,
        universe,
        &ratios,
    );

    // (3) Sequential scan-loop — MRU's one winning pattern, for honesty.
    // Working set deliberately a touch larger than the largest cache tested.
    let working_set = ((universe as f64) * 0.30) as usize;
    let scan = gen_scan(working_set, accesses);
    run_workload(
        "Workload: scan-loop (cyclic sweep > cache)",
        &format!(
            "Repeatedly sweep {working_set} keys in order. The ONE case MRU wins \
             (LRU evicts each key right before it's needed again)."
        ),
        &scan,
        universe,
        &ratios,
    );

    println!("\n== done ==");
    println!(
        "  Takeaway: on realistic (zipf) and random traffic LRU/SLRU/W-TinyLFU\n  \
         dominate; MRU only wins on cyclic scans, which DNS traffic is not."
    );
}
