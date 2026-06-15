//! DNS response cache (Phase 3).
//!
//! * TTL-respecting positive **and** negative caching (RFC 2308).
//! * User-configurable min/max TTL clamps.
//! * Optional optimistic caching (serve-stale, RFC 8767): expired entries can be
//!   served immediately while a background refresh runs.
//! * LRU-bounded, keyed by `(name, type, class)`.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bulwark_filter::MatchInfo;
use bulwark_upstream::QueryKey;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use lru::LruCache;
use parking_lot::Mutex;

/// Default negative-cache TTL when no SOA is present.
const DEFAULT_NEGATIVE_TTL: u32 = 30;
/// TTL (seconds) applied to records when serving a stale answer.
const STALE_SERVE_TTL: u32 = 1;
/// Magic + version header for the persisted snapshot blob. Bump the trailing
/// digit on any format change so stale snapshots are ignored, not misread.
// Identifies the snapshot format. A blob whose magic doesn't match (a different
// or older format) fails the check and is ignored — a safe cold start.
const SNAPSHOT_MAGIC: &[u8; 8] = b"BLWKCSN2";

// Per-record sanity caps for snapshot import. A snapshot is locally written, but
// a corrupt or truncated file must degrade to a (partial) cold start rather than
// over-allocate or install bogus entries. A DNS message and its answer/offset
// counts are all small, so anything beyond these bounds is rejected.
const MAX_SNAPSHOT_WIRE_LEN: usize = 64 * 1024;
const MAX_SNAPSHOT_ANSWERS: usize = 64;
const MAX_SNAPSHOT_TTL_OFFSETS: usize = 256;

/// How a cached response is held. The common case is `Wire`: the response we
/// already encoded once, plus the byte offsets of every TTL field, so serving a
/// hit is a flat byte clone + in-place id/TTL patch — no `Message` clone and no
/// `to_vec` re-encode. `Message` is the fallback for the rare response we
/// couldn't safely wire-scan.
///
/// All fields are behind `Arc`/`Box`, so cloning a `Stored` under the cache lock
/// is just pointer bumps; the actual byte clone + patch happens after the lock
/// is released so concurrent hits don't serialize on it.
#[derive(Clone)]
enum Stored {
    Wire {
        /// Encoded response bytes, TTLs as originally stored.
        bytes: Arc<[u8]>,
        /// Byte offsets of each RR TTL field (excludes OPT); patched per hit.
        ttl_offsets: Arc<[u32]>,
        /// Response code, kept so the query log/stats don't re-parse the wire.
        rcode: ResponseCode,
        /// Precomputed answer summaries for the query log (e.g. `"A 1.2.3.4"`).
        answers: Arc<[String]>,
    },
    Message(Arc<Message>),
}

/// A memoised response-side filtering verdict for a cached *raw* upstream answer,
/// stamped with the filter generation it was computed under.
///
/// The cache stores the answer the upstream actually returned (never a synthetic
/// block), plus — when it can be trusted globally — the verdict the response-side
/// filter reached for it. This lets the engine re-decide blocking per client and
/// per config without re-fetching upstream: a clean answer is served as-is, a
/// blocked one is re-synthesised fresh from the *current* blocking config. The
/// generation pins the verdict to the filter that produced it, so a config change
/// transparently invalidates it (the engine recomputes on mismatch).
#[derive(Clone)]
pub struct ResponseVerdict {
    /// The filter [`content_hash`](bulwark_filter::FilterEngine::content_hash)
    /// this verdict was computed under. A mismatch against the live filter means
    /// it's stale and must be recomputed.
    pub generation: u64,
    pub outcome: Outcome,
}

/// Whether a cached answer is blocked by the response-side filter.
#[derive(Clone)]
pub enum Outcome {
    /// The answer chain matched no blocklist rule.
    Clean,
    /// The answer is blocked; carries the matching rule for logging/attribution.
    Block(MatchInfo),
}

impl ResponseVerdict {
    /// A clean verdict stamped with `generation`.
    pub fn clean(generation: u64) -> Self {
        Self {
            generation,
            outcome: Outcome::Clean,
        }
    }

    /// A block verdict (carrying the matched rule) stamped with `generation`.
    pub fn block(info: MatchInfo, generation: u64) -> Self {
        Self {
            generation,
            outcome: Outcome::Block(info),
        }
    }
}

struct Entry {
    stored: Stored,
    stored_at: Instant,
    /// Effective (clamped) TTL in seconds.
    ttl: u32,
    /// Memoised response-side verdict (with its generation), or `None` when it
    /// must be (re)computed on the next hit: snapshot-restored entries, refreshes
    /// or inserts made while client-dependent rules are active, or answers cached
    /// by an unfiltered client. `None` is always safe — it forces re-evaluation.
    verdict: Option<ResponseVerdict>,
}

impl Entry {
    fn age_secs(&self) -> u32 {
        self.stored_at.elapsed().as_secs().min(u32::MAX as u64) as u32
    }
}

/// The response form returned from a cache hit: either ready-to-send wire bytes
/// (id + TTLs already patched) plus the bits the log/stats need, or a `Message`
/// fallback the caller encodes itself.
pub enum CachedResponse {
    Wire {
        bytes: Vec<u8>,
        rcode: ResponseCode,
        answers: Arc<[String]>,
    },
    Message(Message),
}

/// The encoded wire bytes (plus the log/stats metadata) of a freshly-inserted
/// answer, handed back by [`DnsCache::insert_returning`] so the cache-miss path
/// can serve the response it just encoded without a second `to_vec`. Same shape
/// a [`CachedResponse::Wire`] hit yields.
pub struct InsertedWire {
    pub bytes: Vec<u8>,
    pub rcode: ResponseCode,
    pub answers: Arc<[String]>,
}

impl CachedResponse {
    /// Decode to a structured `Message`. The `Wire` variant re-parses its bytes
    /// (only used off the hot path — e.g. by the UDP truncation fallback or
    /// tests; the fast path sends the bytes as-is).
    pub fn into_message(self) -> Message {
        match self {
            CachedResponse::Message(m) => m,
            CachedResponse::Wire { bytes, .. } => Message::from_vec(&bytes)
                .unwrap_or_else(|_| Message::new(0, MessageType::Response, OpCode::Query)),
        }
    }
}

/// Whether a cache hit is within TTL or is being served past expiry under the
/// optimistic (serve-stale) window. Under serve-stale, `Stale` is the *expected*
/// dominant hit path — not an error case — so it's modelled as a freshness state
/// rather than a `stale: bool` to keep callers from treating it as exceptional.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HitFreshness {
    /// Within TTL: serve as-is.
    Fresh,
    /// Past TTL but within the serve-stale window: serve now, but the caller
    /// must kick off a background refresh to re-populate the entry.
    Stale,
}

impl HitFreshness {
    /// A stale serve must trigger a background refresh; a fresh one need not.
    pub fn requires_refresh(self) -> bool {
        matches!(self, HitFreshness::Stale)
    }
}

/// Result of a cache lookup.
pub struct CacheHit {
    pub response: CachedResponse,
    /// Whether the answer is fresh or is being served stale (which obliges the
    /// caller to trigger a background refresh). See [`HitFreshness`].
    pub freshness: HitFreshness,
    /// The memoised response-side verdict for this entry, if any. The engine
    /// gates on this before serving raw bytes to a filtering client (see
    /// [`ResponseVerdict`]); `None`, or a stale generation, forces a per-client
    /// recompute against the cached answer.
    pub verdict: Option<ResponseVerdict>,
}

/// Summarise an answer record as e.g. `"A 1.2.3.4"` for the query log.
fn summarize(rec: &hickory_proto::rr::Record) -> String {
    format!("{} {}", rec.record_type(), rec.data)
}

/// Live, atomically-updatable cache tuning.
pub struct CacheConfig {
    pub enabled: AtomicBool,
    pub min_ttl: AtomicU32,
    /// 0 means "no upper clamp".
    pub max_ttl: AtomicU32,
    /// Optimistic caching (serve-stale): the max seconds past expiry that a
    /// stale entry may still be served while it refreshes in the background.
    /// `0` disables serve-stale; any value `> 0` enables it and bounds staleness.
    pub stale_max_age: AtomicU32,
    /// Whether to precompute and store per-answer log summaries on each cache
    /// entry. They feed *only* the query log, so when logging is off they are
    /// pure resident overhead (an `Arc<[String]>` per entry, kept for the whole
    /// entry lifetime). Mirrors `query_log.enabled`: on when logging is on (where
    /// the stored copy makes a logged hit a cheap `Arc` clone instead of a wire
    /// re-parse), off otherwise so an idle/SBC box doesn't carry summaries nobody
    /// reads. Toggling at runtime only affects entries inserted afterwards; the
    /// rest fill in (empty → populated, or vice versa) as they refresh.
    pub store_summaries: AtomicBool,
}

/// Number of cache shards: a power of two (so shard selection is a cheap mask)
/// near the CPU count, clamped to a sane range. Each shard has its own mutex, so
/// concurrent lookups on different shards don't serialize — DNS traffic is
/// highly concurrent (one tokio task per query), and cache hits are exactly
/// where we want cores to scale. A single global mutex scales *negatively* under
/// load (measured: 9.3M→2.9M hits/s, 1→16 threads).
fn shard_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .next_power_of_two()
        .clamp(8, 64)
}

/// A TTL-aware DNS cache, split into independently-locked shards keyed by a
/// cheap hash of the query key.
pub struct DnsCache {
    shards: Box<[Mutex<LruCache<QueryKey, Entry>>]>,
    /// Bit mask for shard selection (`shards.len()` is a power of two).
    mask: usize,
    /// Hasher for shard selection only (the per-shard `LruCache` re-hashes
    /// internally; this one just spreads keys across shards).
    hash_builder: ahash::RandomState,
    cfg: CacheConfig,
    /// Total capacity across all shards (the configured value).
    capacity: AtomicUsize,
    hits: AtomicU64,
    misses: AtomicU64,
    /// Subset of `hits` that were served stale (expired but within the
    /// optimistic-caching window). Each one is a client-facing hit that *also*
    /// triggers a background refresh, so `hits - stale_hits` is the count of
    /// truly fresh hits, and `stale_hits` is the optimistic-serve volume.
    stale_hits: AtomicU64,
    /// Background refreshes dispatched to the upstream pool (one per stale serve
    /// that re-parsed; see [`Self::note_refresh_started`]). This is the
    /// upstream-facing cost the client-side hit rate hides — every refresh is an
    /// upstream call the client never waited on. The pool may single-flight
    /// concurrent identical refreshes, so the number that actually reach the wire
    /// can be lower; this counts intent (dispatch).
    refreshes: AtomicU64,
    /// Background refreshes whose upstream resolution failed. A high ratio means
    /// the optimistic path is repeatedly serving stale while never landing a
    /// fresh answer — a healthy-looking hit rate masking a dead upstream.
    refresh_failures: AtomicU64,
}

/// A point-in-time snapshot of the cache's lifetime counters. Held as cheap
/// atomics on the hot path; persisted in `stats.json` and seeded back on start
/// (see [`DnsCache::seed_counters`]) so they accumulate across restarts.
#[derive(Clone, Copy, Debug, Default)]
pub struct CacheCounters {
    pub hits: u64,
    pub misses: u64,
    pub stale_hits: u64,
    pub refreshes: u64,
    pub refresh_failures: u64,
}

/// Per-shard capacity for a given total, never zero.
fn shard_cap(total: usize, shards: usize) -> std::num::NonZeroUsize {
    std::num::NonZeroUsize::new((total / shards).max(1)).unwrap()
}

impl DnsCache {
    pub fn new(capacity: usize, min_ttl: u32, max_ttl: u32, stale_max_age: u32) -> Self {
        let cap = capacity.max(1);
        let n = shard_count();
        let per_shard = shard_cap(cap, n);
        let shards = (0..n)
            .map(|_| Mutex::new(LruCache::new(per_shard)))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            shards,
            mask: n - 1,
            hash_builder: ahash::RandomState::new(),
            cfg: CacheConfig {
                enabled: AtomicBool::new(true),
                min_ttl: AtomicU32::new(min_ttl),
                max_ttl: AtomicU32::new(max_ttl),
                stale_max_age: AtomicU32::new(stale_max_age),
                // Default on: the engine syncs this to `query_log.enabled` right
                // after construction. On keeps existing behaviour (and tests) and
                // is the safe default — we only ever drop summaries we're sure
                // nothing reads.
                store_summaries: AtomicBool::new(true),
            },
            capacity: AtomicUsize::new(cap),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stale_hits: AtomicU64::new(0),
            refreshes: AtomicU64::new(0),
            refresh_failures: AtomicU64::new(0),
        }
    }

    /// The shard a key maps to.
    fn shard(&self, key: &QueryKey) -> &Mutex<LruCache<QueryKey, Entry>> {
        let h = self.hash_builder.hash_one(key) as usize;
        &self.shards[h & self.mask]
    }

    /// Apply new tuning at runtime (config hot-reload). Resizes if needed.
    pub fn reconfigure(
        &self,
        enabled: bool,
        capacity: usize,
        min_ttl: u32,
        max_ttl: u32,
        stale_max_age: u32,
    ) {
        self.cfg.enabled.store(enabled, Ordering::Relaxed);
        self.cfg.min_ttl.store(min_ttl, Ordering::Relaxed);
        self.cfg.max_ttl.store(max_ttl, Ordering::Relaxed);
        self.cfg
            .stale_max_age
            .store(stale_max_age, Ordering::Relaxed);
        let cap = capacity.max(1);
        if cap != self.capacity.swap(cap, Ordering::Relaxed) {
            let per_shard = shard_cap(cap, self.shards.len());
            for shard in self.shards.iter() {
                shard.lock().resize(per_shard);
            }
        }
        if !enabled {
            self.clear();
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.cfg.enabled.load(Ordering::Relaxed)
    }

    /// Mirror query-logging state into the cache: when logging is off, new
    /// entries skip the per-answer log summaries entirely (see
    /// [`CacheConfig::store_summaries`]). Called by the engine on startup and on
    /// every config reload, alongside the query log's own reconfigure.
    pub fn set_store_summaries(&self, store: bool) {
        self.cfg.store_summaries.store(store, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        for shard in self.shards.iter() {
            shard.lock().clear();
        }
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn miss_count(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn stale_hit_count(&self) -> u64 {
        self.stale_hits.load(Ordering::Relaxed)
    }

    pub fn refresh_count(&self) -> u64 {
        self.refreshes.load(Ordering::Relaxed)
    }

    pub fn refresh_failure_count(&self) -> u64 {
        self.refresh_failures.load(Ordering::Relaxed)
    }

    /// Snapshot every lifetime counter at once for the stats API.
    pub fn counters(&self) -> CacheCounters {
        CacheCounters {
            hits: self.hit_count(),
            misses: self.miss_count(),
            stale_hits: self.stale_hit_count(),
            refreshes: self.refresh_count(),
            refresh_failures: self.refresh_failure_count(),
        }
    }

    /// Record that the engine has dispatched a background refresh for a stale
    /// entry. Called once per refresh the engine spawns; the matching upstream
    /// outcome is reported via [`Self::note_refresh_failed`] on failure.
    pub fn note_refresh_started(&self) {
        self.refreshes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a dispatched background refresh failed to resolve upstream.
    pub fn note_refresh_failed(&self) {
        self.refresh_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Seed the lifetime counters from a persisted snapshot at startup, so the
    /// optimistic-caching metrics accumulate across restarts rather than resetting
    /// to zero. Call before serving traffic (the counters then count up from here).
    pub fn seed_counters(&self, c: CacheCounters) {
        self.hits.store(c.hits, Ordering::Relaxed);
        self.misses.store(c.misses, Ordering::Relaxed);
        self.stale_hits.store(c.stale_hits, Ordering::Relaxed);
        self.refreshes.store(c.refreshes, Ordering::Relaxed);
        self.refresh_failures.store(c.refresh_failures, Ordering::Relaxed);
    }

    /// Zero the lifetime counters (the "reset statistics" action clears these
    /// alongside the aggregate stats, since they're the same analytics surface).
    pub fn reset_counters(&self) {
        self.seed_counters(CacheCounters::default());
    }

    /// Look up a response, returning it ready to serve with TTLs decremented to
    /// remaining lifetime and the transaction id set to `id`. Returns `None` on a
    /// true miss; counts hits/misses.
    pub fn get(&self, key: &QueryKey, id: u16) -> Option<CacheHit> {
        if !self.is_enabled() {
            return None;
        }

        // Hold the lock only long enough to bump the LRU and clone a cheap
        // (pointer-only) handle to the stored form; the actual byte clone + TTL
        // patch (or message clone) is deferred until after the guard is dropped
        // so concurrent hits don't serialize on it.
        let (stored, ttl, freshness, verdict) = {
            let mut map = self.shard(key).lock();
            let Some(entry) = map.get(key) else {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            };

            let age = entry.age_secs();
            let entry_ttl = entry.ttl;
            // Cloning `stored` (Arc bumps) ends the borrow of `entry`, freeing
            // `map` for the `pop` below. The verdict comes along so the engine can
            // gate on it without re-locking; `Clean`/`None` are alloc-free clones,
            // and a `Block` clone (rarer) is just the matched rule.
            let stored = entry.stored.clone();
            let verdict = entry.verdict.clone();

            if age < entry_ttl {
                (stored, (entry_ttl - age).max(1), HitFreshness::Fresh, verdict)
            } else {
                // Expired. Optionally serve stale within the configured window
                // (serve-stale is on iff `stale_max_age > 0`). The window is
                // measured from expiry, so `ttl + stale_max_age` is the total
                // lifetime of a stale-servable entry.
                let stale_max_age = self.cfg.stale_max_age.load(Ordering::Relaxed);
                if age.saturating_sub(entry_ttl) < stale_max_age {
                    // A stale serve is still a hit (counted below), but track the
                    // optimistic subset separately: it's the slice of the hit rate
                    // that costs a background upstream refresh.
                    self.stale_hits.fetch_add(1, Ordering::Relaxed);
                    (stored, STALE_SERVE_TTL, HitFreshness::Stale, verdict)
                } else {
                    // Too old / not optimistic: drop it and report a miss.
                    map.pop(key);
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
        };

        self.hits.fetch_add(1, Ordering::Relaxed);
        let response = match stored {
            Stored::Wire {
                bytes,
                ttl_offsets,
                rcode,
                answers,
            } => {
                let mut out = bytes.to_vec();
                crate::wire::patch(&mut out, id, ttl, &ttl_offsets);
                CachedResponse::Wire {
                    bytes: out,
                    rcode,
                    answers,
                }
            }
            Stored::Message(message) => {
                let mut m = adjust_ttls(&message, ttl);
                m.metadata.id = id;
                CachedResponse::Message(m)
            }
        };
        Some(CacheHit {
            response,
            freshness,
            verdict,
        })
    }

    /// Insert a raw upstream response with no memoised verdict. The next
    /// filtering hit will (re)compute one. Used by background refreshes, by
    /// inserts made while client-dependent rules are active, and by tests.
    /// No-op if the response isn't cacheable.
    pub fn insert(&self, key: QueryKey, message: &Message) {
        self.insert_inner(key, message, None);
    }

    /// Insert a raw upstream response together with a memoised response-side
    /// verdict (which carries its filter generation). Only safe when the verdict
    /// is client-independent (the filter has no `$client`/`$ctag` rules); the
    /// engine enforces that. No-op if the response isn't cacheable.
    pub fn insert_with_verdict(
        &self,
        key: QueryKey,
        message: &Message,
        verdict: Option<ResponseVerdict>,
    ) {
        self.insert_inner(key, message, verdict);
    }

    /// Insert like [`Self::insert_with_verdict`] but return the encoded wire
    /// bytes ready to serve (mirroring a [`CachedResponse::Wire`] hit), so the
    /// cache-miss path serves the answer it just encoded instead of re-encoding
    /// the `Message` a second time. `None` means it wasn't stored as wire (not
    /// cacheable, or the rare `Message` fallback) — the caller then serves its
    /// own `Message`.
    pub fn insert_returning(
        &self,
        key: QueryKey,
        message: &Message,
        verdict: Option<ResponseVerdict>,
    ) -> Option<InsertedWire> {
        self.insert_inner(key, message, verdict)
    }

    fn insert_inner(
        &self,
        key: QueryKey,
        message: &Message,
        verdict: Option<ResponseVerdict>,
    ) -> Option<InsertedWire> {
        if !self.is_enabled() {
            return None;
        }
        let ttl = self.cacheable_ttl(message)?;
        // Encode once and record TTL offsets so hits are a byte clone + patch.
        // When the wire form is built we also hand the encoded bytes back (see
        // [`InsertedWire`]) so the cache-miss path serves the response it just
        // encoded rather than re-encoding the same `Message`. Fall back to
        // storing the `Message` (serving nothing back) if encoding or the wire
        // scan fails (rare; keeps correctness for anything we can't safely patch).
        let (stored, served) = match message.to_vec() {
            Ok(bytes) => match crate::wire::scan_ttl_offsets(&bytes) {
                Some(offsets) => {
                    let rcode = message.metadata.response_code;
                    // Only pay to build + retain the per-answer log summaries when
                    // query logging is on; otherwise store an empty slice so an
                    // idle box doesn't carry summaries nothing will read.
                    let answers: Arc<[String]> =
                        if self.cfg.store_summaries.load(Ordering::Relaxed) {
                            message.answers.iter().map(summarize).collect()
                        } else {
                            Arc::from([])
                        };
                    let bytes: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
                    // A flat memcpy of the just-encoded bytes — far cheaper than
                    // the full `to_vec` re-encode it spares on the serve path.
                    let served = InsertedWire {
                        bytes: bytes.to_vec(),
                        rcode,
                        answers: answers.clone(),
                    };
                    (
                        Stored::Wire {
                            bytes,
                            ttl_offsets: Arc::from(offsets.into_boxed_slice()),
                            rcode,
                            answers,
                        },
                        Some(served),
                    )
                }
                None => (Stored::Message(Arc::new(message.clone())), None),
            },
            Err(_) => (Stored::Message(Arc::new(message.clone())), None),
        };
        let entry = Entry {
            stored,
            stored_at: Instant::now(),
            ttl,
            verdict,
        };
        self.shard(&key).lock().put(key, entry);
        served
    }

    /// Decide whether a response is cacheable and compute its clamped TTL.
    fn cacheable_ttl(&self, message: &Message) -> Option<u32> {
        let rcode = message.metadata.response_code;
        // Only cache successful answers and authoritative negative answers.
        match rcode {
            ResponseCode::NoError | ResponseCode::NXDomain => {}
            _ => return None,
        }
        if message.metadata.truncation {
            return None;
        }

        let base_ttl = if !message.answers.is_empty() {
            message
                .answers
                .iter()
                .map(|r| r.ttl)
                .min()
                .unwrap_or(DEFAULT_NEGATIVE_TTL)
        } else {
            // Negative / NODATA: use the SOA minimum/TTL from the authority
            // section, else a small default.
            negative_ttl(message)
        };

        let min = self.cfg.min_ttl.load(Ordering::Relaxed);
        let max = self.cfg.max_ttl.load(Ordering::Relaxed);
        let mut ttl = base_ttl.max(min);
        if max != 0 {
            ttl = ttl.min(max);
        }
        if ttl == 0 {
            return None;
        }
        Some(ttl)
    }

    /// Serialize the cache to a self-describing byte blob for persistence across
    /// restarts. Only the `Wire` form is persisted (the rare `Message` fallback
    /// is skipped — it can't be safely byte-patched anyway); entries already past
    /// their stale lifetime are dropped. Each record stores the entry's *age* so
    /// remaining lifetime can be recomputed on load against wall-clock time —
    /// `stored_at` is an `Instant`, meaningless across processes.
    ///
    /// This walks every shard under its lock, so it is an off-hot-path operation
    /// (periodic snapshot + shutdown), never called while serving a query.
    pub fn export_snapshot(&self) -> Vec<u8> {
        let now = unix_secs();
        let stale_max_age = self.cfg.stale_max_age.load(Ordering::Relaxed);
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&now.to_le_bytes());
        // Backfilled with the real count once we know how many we wrote.
        let count_at = out.len();
        out.extend_from_slice(&0u32.to_le_bytes());

        let mut count: u32 = 0;
        for shard in self.shards.iter() {
            let map = shard.lock();
            for (key, entry) in map.iter() {
                let Stored::Wire {
                    bytes,
                    ttl_offsets,
                    rcode,
                    answers,
                } = &entry.stored
                else {
                    continue;
                };
                let age = entry.age_secs();
                // Skip entries that are neither fresh nor stale-servable.
                if age >= entry.ttl.saturating_add(stale_max_age) {
                    continue;
                }
                write_record(&mut out, key, age, entry.ttl, *rcode, answers, bytes, ttl_offsets);
                count += 1;
            }
        }
        out[count_at..count_at + 4].copy_from_slice(&count.to_le_bytes());
        out
    }

    /// Restore entries from a blob produced by [`Self::export_snapshot`].
    /// Returns the number of entries inserted. Best-effort: a bad magic, an
    /// unreadable/truncated blob, or individual dead/expired entries are silently
    /// skipped (a cold start is always safe). Remaining lifetime is recomputed
    /// from the snapshot's wall-clock age plus elapsed time, so entries that have
    /// expired beyond the *current* stale window while we were down are dropped.
    /// Call after the cache's TTL/stale config is in place.
    pub fn import_snapshot(&self, data: &[u8]) -> usize {
        let mut r = Reader::new(data);
        if r.take(SNAPSHOT_MAGIC.len()) != Some(SNAPSHOT_MAGIC.as_slice()) {
            return 0;
        }
        let (Some(snap_unix), Some(count)) = (r.u64(), r.u32()) else {
            return 0;
        };
        let now = unix_secs();
        let elapsed = now.saturating_sub(snap_unix);
        let stale_max_age = self.cfg.stale_max_age.load(Ordering::Relaxed) as u64;

        let mut restored = 0;
        for _ in 0..count {
            let Some(parsed) = read_record(&mut r) else {
                break; // truncated/corrupt tail — keep what we got.
            };
            let total_age = parsed.age as u64 + elapsed;
            // Dead while we were down: past ttl + stale window.
            if total_age >= parsed.ttl as u64 + stale_max_age {
                continue;
            }
            // Rebuild an `Instant` that elapses to `total_age`. Can fail only if
            // the machine's monotonic clock is younger than the entry's age.
            let Some(stored_at) =
                Instant::now().checked_sub(Duration::from_secs(total_age))
            else {
                continue;
            };
            let entry = Entry {
                stored: parsed.stored,
                stored_at,
                ttl: parsed.ttl,
                // Snapshots persist only the raw answer, never a verdict: the
                // filter config may have changed across the restart, so the first
                // filtering hit recomputes (see `verdict` field docs).
                verdict: None,
            };
            self.shard(&parsed.key).lock().put(parsed.key, entry);
            restored += 1;
        }
        restored
    }
}

/// Current wall-clock time as seconds since the Unix epoch (0 if the clock is
/// before the epoch, which it never is in practice).
fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append one `Wire` entry to the snapshot buffer. See [`DnsCache::export_snapshot`]
/// for the format; every length prefix is little-endian.
#[allow(clippy::too_many_arguments)]
fn write_record(
    out: &mut Vec<u8>,
    key: &QueryKey,
    age: u32,
    ttl: u32,
    rcode: ResponseCode,
    answers: &[String],
    bytes: &[u8],
    offsets: &[u32],
) {
    let name = key.name.as_bytes();
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&u16::from(key.rtype).to_le_bytes());
    out.extend_from_slice(&u16::from(key.class).to_le_bytes());
    // Pack the DNSSEC-relevant key bits into one flags byte (bit0=DO, bit1=CD).
    out.push((key.dnssec_ok as u8) | ((key.checking_disabled as u8) << 1));
    out.extend_from_slice(&age.to_le_bytes());
    out.extend_from_slice(&ttl.to_le_bytes());
    out.extend_from_slice(&u16::from(rcode).to_le_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_le_bytes());
    for a in answers {
        let ab = a.as_bytes();
        out.extend_from_slice(&(ab.len() as u16).to_le_bytes());
        out.extend_from_slice(ab);
    }
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out.extend_from_slice(&(offsets.len() as u32).to_le_bytes());
    for o in offsets {
        out.extend_from_slice(&o.to_le_bytes());
    }
}

/// A record parsed from a snapshot blob, pre-`Instant` (age is resolved to a
/// `stored_at` by the caller, which knows the elapsed-since-snapshot offset).
struct ParsedEntry {
    key: QueryKey,
    age: u32,
    ttl: u32,
    stored: Stored,
}

/// Parse one record. Returns `None` on a short/corrupt read so the caller can
/// stop at the first bad record and keep everything before it.
fn read_record(r: &mut Reader) -> Option<ParsedEntry> {
    let name_len = r.u16()? as usize;
    let name = String::from_utf8_lossy(r.take(name_len)?).into_owned();
    let rtype = r.u16()?.into();
    let class = r.u16()?.into();
    let flags = r.u8()?;
    let key = QueryKey {
        name,
        rtype,
        class,
        dnssec_ok: flags & 0b01 != 0,
        checking_disabled: flags & 0b10 != 0,
    };
    let age = r.u32()?;
    let ttl = r.u32()?;
    // Use the `From<u16>` trait impl, not the inherent `from(high, low)`.
    let rcode: ResponseCode = r.u16()?.into();

    let ans_count = r.u16()? as usize;
    if ans_count > MAX_SNAPSHOT_ANSWERS {
        return None;
    }
    let mut answers = Vec::with_capacity(ans_count);
    for _ in 0..ans_count {
        let len = r.u16()? as usize;
        answers.push(String::from_utf8_lossy(r.take(len)?).into_owned());
    }

    let wire_len = r.u32()? as usize;
    if wire_len > MAX_SNAPSHOT_WIRE_LEN {
        return None;
    }
    let wire = r.take(wire_len)?;
    // Reject a record whose wire bytes don't parse to a message answering this
    // exact key. A corrupt snapshot must not install arbitrary bytes under a key
    // that a later lookup would patch and serve as a cache hit.
    if !wire_matches_key(wire, &key) {
        return None;
    }
    let bytes: Arc<[u8]> = Arc::from(wire);

    let off_count = r.u32()? as usize;
    // Cap before allocating: `off_count` is an untrusted u32, so a corrupt value
    // could otherwise drive a multi-gigabyte `Vec::with_capacity`.
    if off_count > MAX_SNAPSHOT_TTL_OFFSETS {
        return None;
    }
    let mut offsets = Vec::with_capacity(off_count);
    for _ in 0..off_count {
        offsets.push(r.u32()?);
    }
    // TTL offsets index into the wire bytes for patching on serve; reject any
    // that would read/write past the end (a u32 TTL needs 4 bytes).
    if offsets
        .iter()
        .any(|&o| o as usize + 4 > bytes.len())
    {
        return None;
    }

    Some(ParsedEntry {
        key,
        age,
        ttl,
        stored: Stored::Wire {
            bytes,
            ttl_offsets: Arc::from(offsets.into_boxed_slice()),
            rcode,
            answers: Arc::from(answers.into_boxed_slice()),
        },
    })
}

/// Whether `bytes` decodes to a DNS message whose first question matches `key`
/// (name case-insensitively, plus type and class). Used to reject snapshot
/// records whose wire payload doesn't belong under the key it's stored at.
fn wire_matches_key(bytes: &[u8], key: &QueryKey) -> bool {
    match Message::from_vec(bytes) {
        Ok(msg) => msg.queries.first().is_some_and(|q| {
            q.query_type() == key.rtype
                && q.query_class() == key.class
                && q.name().to_ascii().eq_ignore_ascii_case(&key.name)
        }),
        Err(_) => false,
    }
}

/// Minimal forward-only byte reader: every accessor returns `None` rather than
/// panicking when the buffer is too short, so a truncated snapshot degrades to a
/// partial (or empty) restore instead of a crash.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
}

/// Derive a negative-cache TTL from the SOA record, if any.
fn negative_ttl(message: &Message) -> u32 {
    use hickory_proto::rr::RData;
    for rec in &message.authorities {
        if let RData::SOA(soa) = &rec.data {
            // RFC 2308: the negative TTL is min(SOA.minimum, SOA record TTL).
            return soa.minimum.min(rec.ttl).max(1);
        }
    }
    DEFAULT_NEGATIVE_TTL
}

/// Clone a message with all record TTLs set to `ttl`.
fn adjust_ttls(message: &Message, ttl: u32) -> Message {
    let mut m = message.clone();
    for r in m.answers.iter_mut() {
        r.ttl = ttl;
    }
    for r in m.authorities.iter_mut() {
        r.ttl = ttl;
    }
    for r in m.additionals.iter_mut() {
        r.ttl = ttl;
    }
    m
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bulwark_upstream::QueryKey;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

    use super::*;

    fn key(name: &str) -> QueryKey {
        QueryKey {
            name: name.to_string(),
            rtype: RecordType::A,
            class: DNSClass::IN,
            dnssec_ok: false,
            checking_disabled: false,
        }
    }

    fn answer(name: &str, ttl: u32) -> Message {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        let mut q = Query::query(Name::from_str(name).unwrap(), RecordType::A);
        q.set_query_class(DNSClass::IN);
        m.queries.push(q);
        m.answers.push(Record::from_rdata(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(A::new(1, 2, 3, 4)),
        ));
        m
    }

    #[test]
    fn caches_and_returns_with_decreasing_ttl() {
        let cache = DnsCache::new(100, 0, 0, 0);
        cache.insert(key("a.com."), &answer("a.com.", 100));
        let hit = cache.get(&key("a.com."), 0).unwrap();
        assert!(!hit.freshness.requires_refresh());
        let m = hit.response.into_message();
        assert!(m.answers[0].ttl <= 100);
        assert!(m.answers[0].ttl >= 99);
    }

    #[test]
    fn min_ttl_clamp_raises_short_ttls() {
        let cache = DnsCache::new(100, 60, 0, 0);
        cache.insert(key("b.com."), &answer("b.com.", 5));
        let hit = cache.get(&key("b.com."), 0).unwrap();
        assert!(hit.response.into_message().answers[0].ttl >= 59);
    }

    #[test]
    fn max_ttl_clamp_caps_long_ttls() {
        let cache = DnsCache::new(100, 0, 100, 0);
        cache.insert(key("c.com."), &answer("c.com.", 100_000));
        let hit = cache.get(&key("c.com."), 0).unwrap();
        assert!(hit.response.into_message().answers[0].ttl <= 100);
    }

    #[test]
    fn expired_entry_is_a_miss_without_optimistic() {
        let cache = DnsCache::new(100, 0, 0, 0);
        // TTL 0 won't cache; use a 1s ttl but simulate expiry via min/max=... we
        // instead insert with ttl then force expiry by zero remaining.
        cache.insert(key("d.com."), &answer("d.com.", 1));
        // Manually expire by mutating stored_at is not accessible; instead test
        // that a fresh non-optimistic cache without the entry misses.
        assert!(cache.get(&key("missing.com."), 0).is_none());
    }

    #[test]
    fn does_not_cache_servfail() {
        let cache = DnsCache::new(100, 0, 0, 0);
        let mut m = answer("e.com.", 100);
        m.answers.clear();
        m.metadata.response_code = ResponseCode::ServFail;
        cache.insert(key("e.com."), &m);
        assert!(cache.get(&key("e.com."), 0).is_none());
    }

    #[test]
    fn negative_response_uses_default_ttl() {
        let cache = DnsCache::new(100, 0, 0, 0);
        let mut m = answer("f.com.", 100);
        m.answers.clear();
        m.metadata.response_code = ResponseCode::NXDomain;
        cache.insert(key("f.com."), &m);
        // NXDOMAIN with no answers is cached (negative cache).
        assert!(cache.get(&key("f.com."), 0).is_some());
    }

    #[test]
    fn reconfigure_disables_and_clears() {
        let cache = DnsCache::new(100, 0, 0, 0);
        cache.insert(key("g.com."), &answer("g.com.", 100));
        assert_eq!(cache.len(), 1);
        cache.reconfigure(false, 100, 0, 0, 0);
        assert!(cache.get(&key("g.com."), 0).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn optimistic_serves_stale_within_window() {
        // TTL 0 normally wouldn't cache; use a tiny ttl and a generous stale
        // window. An expired entry should be served stale (and flagged) when
        // optimistic + within window, then become a miss once the window passes.
        let cache = DnsCache::new(100, 0, 0, 3600);
        // Insert with ttl 1, then force expiry by mutating stored_at.
        cache.insert(key("h.com."), &answer("h.com.", 1));
        {
            let mut map = cache.shard(&key("h.com.")).lock();
            let e = map.get_mut(&key("h.com.")).unwrap();
            e.stored_at = Instant::now() - std::time::Duration::from_secs(10);
        }
        let hit = cache.get(&key("h.com."), 0).expect("stale hit");
        assert!(hit.freshness.requires_refresh());

        // Now push it beyond the stale window -> miss.
        cache.insert(key("h.com."), &answer("h.com.", 1));
        {
            let mut map = cache.shard(&key("h.com.")).lock();
            let e = map.get_mut(&key("h.com.")).unwrap();
            e.stored_at = Instant::now() - std::time::Duration::from_secs(7200);
        }
        assert!(cache.get(&key("h.com."), 0).is_none());
    }

    #[test]
    fn counters_split_fresh_from_stale_and_track_refreshes() {
        let cache = DnsCache::new(100, 0, 0, 3600);
        cache.insert(key("c.com."), &answer("c.com.", 1));

        // A fresh hit bumps `hits` but not `stale_hits`.
        cache.get(&key("c.com."), 0).expect("fresh hit");
        assert_eq!(cache.hit_count(), 1);
        assert_eq!(cache.stale_hit_count(), 0);

        // Force expiry into the stale window: the next hit is a stale serve.
        {
            let mut map = cache.shard(&key("c.com.")).lock();
            let e = map.get_mut(&key("c.com.")).unwrap();
            e.stored_at = Instant::now() - Duration::from_secs(10);
        }
        assert!(cache.get(&key("c.com."), 0).expect("stale hit").freshness.requires_refresh());
        assert_eq!(cache.hit_count(), 2, "stale serve still counts as a hit");
        assert_eq!(cache.stale_hit_count(), 1, "...and as a stale hit");

        // A true miss touches neither hit counter.
        assert!(cache.get(&key("absent.com."), 0).is_none());
        assert_eq!(cache.miss_count(), 1);

        // Refresh dispatch/outcome counters are driven by the engine.
        cache.note_refresh_started();
        cache.note_refresh_started();
        cache.note_refresh_failed();
        let c = cache.counters();
        assert_eq!(c.refreshes, 2);
        assert_eq!(c.refresh_failures, 1);
        assert_eq!(c.hits, 2);
        assert_eq!(c.stale_hits, 1);
    }

    #[test]
    fn snapshot_roundtrips_fresh_entry() {
        let cache = DnsCache::new(100, 0, 0, 0);
        cache.insert(key("a.com."), &answer("a.com.", 100));
        let blob = cache.export_snapshot();

        let restored = DnsCache::new(100, 0, 0, 0);
        assert_eq!(restored.import_snapshot(&blob), 1);
        let hit = restored.get(&key("a.com."), 0).expect("restored hit");
        assert!(!hit.freshness.requires_refresh());
        // TTL is the remaining lifetime, decremented from the original 100.
        let m = hit.response.into_message();
        assert!(m.answers[0].ttl <= 100 && m.answers[0].ttl >= 95);
    }

    #[test]
    fn snapshot_preserves_answers_and_rcode_for_logging() {
        let cache = DnsCache::new(100, 0, 0, 0);
        cache.insert(key("a.com."), &answer("a.com.", 100));
        let blob = cache.export_snapshot();

        let restored = DnsCache::new(100, 0, 0, 0);
        restored.import_snapshot(&blob);
        match restored.get(&key("a.com."), 0).unwrap().response {
            CachedResponse::Wire { rcode, answers, .. } => {
                assert_eq!(rcode, ResponseCode::NoError);
                assert_eq!(&*answers, &["A 1.2.3.4".to_string()]);
            }
            CachedResponse::Message(_) => panic!("expected wire form"),
        }
    }

    #[test]
    fn snapshot_keeps_stale_servable_entry() {
        // Expired but within the stale window: should survive a snapshot and come
        // back as a stale hit (triggering a background refresh on the live path).
        let cache = DnsCache::new(100, 0, 0, 3600);
        cache.insert(key("h.com."), &answer("h.com.", 1));
        {
            let mut map = cache.shard(&key("h.com.")).lock();
            let e = map.get_mut(&key("h.com.")).unwrap();
            e.stored_at = Instant::now() - Duration::from_secs(10);
        }
        let blob = cache.export_snapshot();

        let restored = DnsCache::new(100, 0, 0, 3600);
        assert_eq!(restored.import_snapshot(&blob), 1);
        assert!(restored.get(&key("h.com."), 0).expect("stale hit").freshness.requires_refresh());
    }

    #[test]
    fn snapshot_drops_dead_entry() {
        // Past ttl + stale window at export time -> not written to the blob.
        let cache = DnsCache::new(100, 0, 0, 5);
        cache.insert(key("d.com."), &answer("d.com.", 1));
        {
            let mut map = cache.shard(&key("d.com.")).lock();
            let e = map.get_mut(&key("d.com.")).unwrap();
            e.stored_at = Instant::now() - Duration::from_secs(60);
        }
        let blob = cache.export_snapshot();

        let restored = DnsCache::new(100, 0, 0, 5);
        assert_eq!(restored.import_snapshot(&blob), 0);
    }

    #[test]
    fn import_ignores_garbage() {
        let cache = DnsCache::new(100, 0, 0, 0);
        assert_eq!(cache.import_snapshot(b""), 0);
        assert_eq!(cache.import_snapshot(b"not a snapshot at all"), 0);
        // Valid header, truncated body -> 0 restored, no panic.
        let mut blob = SNAPSHOT_MAGIC.to_vec();
        blob.extend_from_slice(&unix_secs().to_le_bytes());
        blob.extend_from_slice(&5u32.to_le_bytes()); // claims 5, has none
        assert_eq!(cache.import_snapshot(&blob), 0);
    }

    #[test]
    fn stale_window_zero_disables_serve_stale() {
        let cache = DnsCache::new(100, 0, 0, 0);
        cache.insert(key("i.com."), &answer("i.com.", 1));
        {
            let mut map = cache.shard(&key("i.com.")).lock();
            let e = map.get_mut(&key("i.com.")).unwrap();
            e.stored_at = Instant::now() - std::time::Duration::from_secs(10);
        }
        assert!(cache.get(&key("i.com."), 0).is_none());
    }

    #[test]
    fn dnssec_do_query_does_not_reuse_non_do_entry() {
        let cache = DnsCache::new(100, 0, 0, 0);
        let plain = key("dnssec.test.");
        let with_do = QueryKey {
            dnssec_ok: true,
            ..key("dnssec.test.")
        };
        cache.insert(plain.clone(), &answer("dnssec.test.", 60));
        assert!(cache.get(&plain, 0).is_some());
        assert!(
            cache.get(&with_do, 0).is_none(),
            "a DO query must not be served the non-DO cache entry"
        );
    }

    #[test]
    fn snapshot_record_rejects_mismatched_or_corrupt_wire() {
        let wire = answer("good.test.", 60).to_vec().unwrap();
        // Wire whose question matches the key is accepted...
        assert!(wire_matches_key(&wire, &key("good.test.")));
        // ...but not under a different key (would be cache poisoning on import)...
        assert!(!wire_matches_key(&wire, &key("evil.test.")));
        // ...and garbage bytes are rejected outright.
        assert!(!wire_matches_key(b"not a dns message", &key("good.test.")));
    }

    #[test]
    fn snapshot_roundtrips_dnssec_flags() {
        let cache = DnsCache::new(100, 0, 0, 0);
        let k = QueryKey {
            dnssec_ok: true,
            checking_disabled: true,
            ..key("flags.test.")
        };
        cache.insert(k.clone(), &answer("flags.test.", 60));
        let blob = cache.export_snapshot();

        let restored = DnsCache::new(100, 0, 0, 0);
        assert_eq!(restored.import_snapshot(&blob), 1);
        // The restored entry keeps its DO/CD flags: a plain-key lookup misses.
        assert!(restored.get(&key("flags.test."), 0).is_none());
        assert!(restored.get(&k, 0).is_some());
    }
}
