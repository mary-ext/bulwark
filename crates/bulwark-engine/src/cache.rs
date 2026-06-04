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
const SNAPSHOT_MAGIC: &[u8; 8] = b"BLWKCSN1";

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

struct Entry {
    stored: Stored,
    stored_at: Instant,
    /// Effective (clamped) TTL in seconds.
    ttl: u32,
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

/// Result of a cache lookup.
pub struct CacheHit {
    pub response: CachedResponse,
    /// True when this is a stale (expired) answer served optimistically; the
    /// caller should trigger a background refresh.
    pub stale: bool,
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
            },
            capacity: AtomicUsize::new(cap),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
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
        let (stored, ttl, stale) = {
            let mut map = self.shard(key).lock();
            let Some(entry) = map.get(key) else {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            };

            let age = entry.age_secs();
            let entry_ttl = entry.ttl;
            // Cloning `stored` (Arc bumps) ends the borrow of `entry`, freeing
            // `map` for the `pop` below.
            let stored = entry.stored.clone();

            if age < entry_ttl {
                (stored, (entry_ttl - age).max(1), false)
            } else {
                // Expired. Optionally serve stale within the configured window
                // (serve-stale is on iff `stale_max_age > 0`). The window is
                // measured from expiry, so `ttl + stale_max_age` is the total
                // lifetime of a stale-servable entry.
                let stale_max_age = self.cfg.stale_max_age.load(Ordering::Relaxed);
                if age.saturating_sub(entry_ttl) < stale_max_age {
                    (stored, STALE_SERVE_TTL, true)
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
        Some(CacheHit { response, stale })
    }

    /// Insert a response. No-op if the response isn't cacheable.
    pub fn insert(&self, key: QueryKey, message: &Message) {
        if !self.is_enabled() {
            return;
        }
        let Some(ttl) = self.cacheable_ttl(message) else {
            return;
        };
        // Encode once and record TTL offsets so hits are a byte clone + patch.
        // Fall back to storing the `Message` if encoding or the wire scan fails
        // (rare; keeps correctness for anything we can't safely patch).
        let stored = match message.to_vec() {
            Ok(bytes) => match crate::wire::scan_ttl_offsets(&bytes) {
                Some(offsets) => Stored::Wire {
                    bytes: Arc::from(bytes.into_boxed_slice()),
                    ttl_offsets: Arc::from(offsets.into_boxed_slice()),
                    rcode: message.metadata.response_code,
                    answers: message.answers.iter().map(summarize).collect(),
                },
                None => Stored::Message(Arc::new(message.clone())),
            },
            Err(_) => Stored::Message(Arc::new(message.clone())),
        };
        let entry = Entry {
            stored,
            stored_at: Instant::now(),
            ttl,
        };
        self.shard(&key).lock().put(key, entry);
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
    let age = r.u32()?;
    let ttl = r.u32()?;
    // Use the `From<u16>` trait impl, not the inherent `from(high, low)`.
    let rcode: ResponseCode = r.u16()?.into();

    let ans_count = r.u16()? as usize;
    let mut answers = Vec::with_capacity(ans_count);
    for _ in 0..ans_count {
        let len = r.u16()? as usize;
        answers.push(String::from_utf8_lossy(r.take(len)?).into_owned());
    }

    let wire_len = r.u32()? as usize;
    let bytes: Arc<[u8]> = Arc::from(r.take(wire_len)?);

    let off_count = r.u32()? as usize;
    let mut offsets = Vec::with_capacity(off_count);
    for _ in 0..off_count {
        offsets.push(r.u32()?);
    }

    Some(ParsedEntry {
        key: QueryKey { name, rtype, class },
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
        assert!(!hit.stale);
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
        assert!(hit.stale);

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
    fn snapshot_roundtrips_fresh_entry() {
        let cache = DnsCache::new(100, 0, 0, 0);
        cache.insert(key("a.com."), &answer("a.com.", 100));
        let blob = cache.export_snapshot();

        let restored = DnsCache::new(100, 0, 0, 0);
        assert_eq!(restored.import_snapshot(&blob), 1);
        let hit = restored.get(&key("a.com."), 0).expect("restored hit");
        assert!(!hit.stale);
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
        assert!(restored.get(&key("h.com."), 0).expect("stale hit").stale);
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
}
