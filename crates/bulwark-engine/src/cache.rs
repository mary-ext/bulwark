//! Sharded, TTL-aware DNS response cache with optional serve-stale.

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
/// Snapshot format marker. Change the suffix on format changes.
const SNAPSHOT_MAGIC: &[u8; 8] = b"BLWKCSN2";

// Bounds allocations from corrupt snapshots.
const MAX_SNAPSHOT_WIRE_LEN: usize = 64 * 1024;
const MAX_SNAPSHOT_ANSWERS: usize = 64;
const MAX_SNAPSHOT_TTL_OFFSETS: usize = 256;

/// Encoded responses are patched in place; unscannable responses use `Message`.
#[derive(Clone)]
enum Stored {
    Wire {
        bytes: Arc<[u8]>,
        /// Byte offsets of each RR TTL field (excludes OPT); patched per hit.
        ttl_offsets: Arc<[u32]>,
        rcode: ResponseCode,
        /// Precomputed answer summaries for the query log (e.g. `"A 1.2.3.4"`).
        answers: Arc<[String]>,
    },
    Message(Arc<Message>),
}

/// Response-filter verdict keyed to a filter generation.
#[derive(Clone)]
pub struct ResponseVerdict {
    /// Filter [`content_hash`](bulwark_filter::FilterEngine::content_hash).
    pub generation: u64,
    pub outcome: Outcome,
}

/// Whether a cached answer is blocked by the response-side filter.
#[derive(Clone)]
pub enum Outcome {
    Clean,
    /// The answer is blocked; carries the matching rule for logging/attribution.
    Block(MatchInfo),
}

impl ResponseVerdict {
    pub fn clean(generation: u64) -> Self {
        Self {
            generation,
            outcome: Outcome::Clean,
        }
    }

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
    /// `None` forces response filtering on the next hit.
    verdict: Option<ResponseVerdict>,
}

impl Entry {
    fn age_secs(&self) -> u32 {
        self.stored_at.elapsed().as_secs().min(u32::MAX as u64) as u32
    }
}

/// Response returned by a cache hit.
pub enum CachedResponse {
    Wire {
        bytes: Vec<u8>,
        rcode: ResponseCode,
        answers: Arc<[String]>,
    },
    Message(Message),
}

/// Encoded response returned while inserting a cache miss.
pub struct InsertedWire {
    pub bytes: Vec<u8>,
    pub rcode: ResponseCode,
    pub answers: Arc<[String]>,
}

impl CachedResponse {
    /// Decodes the cached response.
    pub fn into_message(self) -> Message {
        match self {
            CachedResponse::Message(m) => m,
            CachedResponse::Wire { bytes, .. } => Message::from_vec(&bytes)
                .unwrap_or_else(|_| Message::new(0, MessageType::Response, OpCode::Query)),
        }
    }
}

/// Freshness of a cache hit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HitFreshness {
    Fresh,
    /// Past TTL but within the serve-stale window: serve now, but the caller
    /// must kick off a background refresh to re-populate the entry.
    Stale,
}

impl HitFreshness {
    /// Whether the entry requires a background refresh.
    pub fn requires_refresh(self) -> bool {
        matches!(self, HitFreshness::Stale)
    }
}

/// Result of a cache lookup.
pub struct CacheHit {
    pub response: CachedResponse,
    pub freshness: HitFreshness,
    /// Cached response-filter verdict, if reusable.
    pub verdict: Option<ResponseVerdict>,
}

fn summarize(rec: &hickory_proto::rr::Record) -> String {
    format!("{} {}", rec.record_type(), rec.data)
}

/// Live, atomically-updatable cache tuning.
pub struct CacheConfig {
    pub enabled: AtomicBool,
    pub min_ttl: AtomicU32,
    /// 0 means "no upper clamp".
    pub max_ttl: AtomicU32,
    /// Serve-stale window; 0 disables it.
    pub stale_max_age: AtomicU32,
    /// Stores answer summaries for query logging.
    pub store_summaries: AtomicBool,
}

/// Selects a power-of-two shard count near the CPU count.
fn shard_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .next_power_of_two()
        .clamp(8, 64)
}

/// Sharded TTL-aware DNS cache.
pub struct DnsCache {
    shards: Box<[Mutex<LruCache<QueryKey, Entry>>]>,
    /// Bit mask for shard selection (`shards.len()` is a power of two).
    mask: usize,
    /// Hasher used only for shard selection.
    hash_builder: ahash::RandomState,
    cfg: CacheConfig,
    /// Total capacity across all shards (the configured value).
    capacity: AtomicUsize,
    hits: AtomicU64,
    misses: AtomicU64,
    /// Hits served within the stale window.
    stale_hits: AtomicU64,
    /// Background refreshes dispatched for stale hits.
    refreshes: AtomicU64,
    /// Failed background refreshes.
    refresh_failures: AtomicU64,
}

/// Snapshot of lifetime cache counters.
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

    /// Enables answer summaries for newly inserted entries.
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

    /// Returns all lifetime counters.
    pub fn counters(&self) -> CacheCounters {
        CacheCounters {
            hits: self.hit_count(),
            misses: self.miss_count(),
            stale_hits: self.stale_hit_count(),
            refreshes: self.refresh_count(),
            refresh_failures: self.refresh_failure_count(),
        }
    }

    /// Records a dispatched background refresh.
    pub fn note_refresh_started(&self) {
        self.refreshes.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a failed background refresh.
    pub fn note_refresh_failed(&self) {
        self.refresh_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Restores lifetime counters.
    pub fn seed_counters(&self, c: CacheCounters) {
        self.hits.store(c.hits, Ordering::Relaxed);
        self.misses.store(c.misses, Ordering::Relaxed);
        self.stale_hits.store(c.stale_hits, Ordering::Relaxed);
        self.refreshes.store(c.refreshes, Ordering::Relaxed);
        self.refresh_failures
            .store(c.refresh_failures, Ordering::Relaxed);
    }

    /// Resets lifetime counters.
    pub fn reset_counters(&self) {
        self.seed_counters(CacheCounters::default());
    }

    /// Returns a response with its remaining TTL and transaction id patched.
    pub fn get(&self, key: &QueryKey, id: u16) -> Option<CacheHit> {
        if !self.is_enabled() {
            return None;
        }

        // Clone shared state before patching bytes outside the shard lock.
        let (stored, ttl, freshness, verdict) = {
            let mut map = self.shard(key).lock();
            let Some(entry) = map.get(key) else {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            };

            let age = entry.age_secs();
            let entry_ttl = entry.ttl;
            let stored = entry.stored.clone();
            let verdict = entry.verdict.clone();

            if age < entry_ttl {
                (
                    stored,
                    (entry_ttl - age).max(1),
                    HitFreshness::Fresh,
                    verdict,
                )
            } else {
                let stale_max_age = self.cfg.stale_max_age.load(Ordering::Relaxed);
                if age.saturating_sub(entry_ttl) < stale_max_age {
                    self.stale_hits.fetch_add(1, Ordering::Relaxed);
                    (stored, STALE_SERVE_TTL, HitFreshness::Stale, verdict)
                } else {
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

    /// Inserts a raw response without a cached filter verdict.
    pub fn insert(&self, key: QueryKey, message: &Message) {
        self.insert_inner(key, message, None);
    }

    /// Inserts a raw response and client-independent filter verdict.
    pub fn insert_with_verdict(
        &self,
        key: QueryKey,
        message: &Message,
        verdict: Option<ResponseVerdict>,
    ) {
        self.insert_inner(key, message, verdict);
    }

    /// Inserts a response and returns its encoded wire form when available.
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
        // Unscannable responses fall back to structured storage.
        let (stored, served) = match message.to_vec() {
            Ok(bytes) => match crate::wire::scan_ttl_offsets(&bytes) {
                Some(offsets) => {
                    let rcode = message.metadata.response_code;
                    let answers: Arc<[String]> = if self.cfg.store_summaries.load(Ordering::Relaxed)
                    {
                        message.answers.iter().map(summarize).collect()
                    } else {
                        Arc::from([])
                    };
                    let bytes: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
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

    /// Returns the clamped TTL for a cacheable response.
    fn cacheable_ttl(&self, message: &Message) -> Option<u32> {
        let rcode = message.metadata.response_code;
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

    /// Serializes live wire entries for restart persistence.
    pub fn export_snapshot(&self) -> Vec<u8> {
        let now = unix_secs();
        let stale_max_age = self.cfg.stale_max_age.load(Ordering::Relaxed);
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&now.to_le_bytes());
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
                if age >= entry.ttl.saturating_add(stale_max_age) {
                    continue;
                }
                write_record(
                    &mut out,
                    key,
                    age,
                    entry.ttl,
                    *rcode,
                    answers,
                    bytes,
                    ttl_offsets,
                );
                count += 1;
            }
        }
        out[count_at..count_at + 4].copy_from_slice(&count.to_le_bytes());
        out
    }

    /// Restores live entries from an exported snapshot.
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
            if total_age >= parsed.ttl as u64 + stale_max_age {
                continue;
            }
            let Some(stored_at) = Instant::now().checked_sub(Duration::from_secs(total_age)) else {
                continue;
            };
            let entry = Entry {
                stored: parsed.stored,
                stored_at,
                ttl: parsed.ttl,
                // Filter generations do not survive restarts.
                verdict: None,
            };
            self.shard(&parsed.key).lock().put(parsed.key, entry);
            restored += 1;
        }
        restored
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Appends a wire entry using little-endian length prefixes.
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

struct ParsedEntry {
    key: QueryKey,
    age: u32,
    ttl: u32,
    stored: Stored,
}

/// Parses one snapshot record.
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
    // Do not install bytes under a mismatched cache key.
    if !wire_matches_key(wire, &key) {
        return None;
    }
    let bytes: Arc<[u8]> = Arc::from(wire);

    let off_count = r.u32()? as usize;
    if off_count > MAX_SNAPSHOT_TTL_OFFSETS {
        return None;
    }
    let mut offsets = Vec::with_capacity(off_count);
    for _ in 0..off_count {
        offsets.push(r.u32()?);
    }
    if offsets.iter().any(|&o| o as usize + 4 > bytes.len()) {
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

/// Checks that snapshot wire bytes answer their stored key.
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

/// Bounds-checked forward-only byte reader.
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

/// Derives a negative-cache TTL from an SOA.
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
        cache.insert(key("d.com."), &answer("d.com.", 1));
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
        let cache = DnsCache::new(100, 0, 0, 3600);
        cache.insert(key("h.com."), &answer("h.com.", 1));
        {
            let mut map = cache.shard(&key("h.com.")).lock();
            let e = map.get_mut(&key("h.com.")).unwrap();
            e.stored_at = Instant::now() - std::time::Duration::from_secs(10);
        }
        let hit = cache.get(&key("h.com."), 0).expect("stale hit");
        assert!(hit.freshness.requires_refresh());

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

        cache.get(&key("c.com."), 0).expect("fresh hit");
        assert_eq!(cache.hit_count(), 1);
        assert_eq!(cache.stale_hit_count(), 0);

        {
            let mut map = cache.shard(&key("c.com.")).lock();
            let e = map.get_mut(&key("c.com.")).unwrap();
            e.stored_at = Instant::now() - Duration::from_secs(10);
        }
        assert!(cache
            .get(&key("c.com."), 0)
            .expect("stale hit")
            .freshness
            .requires_refresh());
        assert_eq!(cache.hit_count(), 2, "stale serve still counts as a hit");
        assert_eq!(cache.stale_hit_count(), 1, "...and as a stale hit");

        assert!(cache.get(&key("absent.com."), 0).is_none());
        assert_eq!(cache.miss_count(), 1);

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
        assert!(restored
            .get(&key("h.com."), 0)
            .expect("stale hit")
            .freshness
            .requires_refresh());
    }

    #[test]
    fn snapshot_drops_dead_entry() {
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
        assert!(wire_matches_key(&wire, &key("good.test.")));
        assert!(!wire_matches_key(&wire, &key("evil.test.")));
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
        assert!(restored.get(&key("flags.test."), 0).is_none());
        assert!(restored.get(&k, 0).is_some());
    }
}
