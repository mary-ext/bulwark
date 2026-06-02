# Bulwark — Implementation Notes

A running log of interesting design decisions, gotchas, and references. Newest
notes appended under each section as work proceeds.

## References

- AdGuard DNS filtering rule syntax:
  https://adguard.com/kb/general/ad-filtering/create-own-filters/
- AdGuard Home rule priority & `$dnsrewrite`, `$dnstype`, `$client`,
  `$denyallow`, `$badfilter`, `$important`.
- RFC 1035 (DNS), RFC 2308 (negative caching), RFC 6891 (EDNS0),
  RFC 7858 (DoT), RFC 8484 (DoH), RFC 9250 (DoQ).

## Toolchain / environment

- Rust 1.94.1, Node 22, pnpm 10. 4 vCPU / 15 GB.
- `hickory-proto` chosen for DNS message types + wire codec; we build our own
  resolver/server orchestration on top for full control over single-flight and
  fastest-upstream selection.

### Politeness clarification (from user)

"No parallel requests" = do **not** send the same query to several/all
upstreams simultaneously (AdGuard's "parallel requests" / "fastest IP" racing
modes). Bulwark instead keeps per-upstream latency stats (from real traffic +
polite background probes) and routes each query to the single best healthy
upstream, falling over to the next one **sequentially** only on failure. We
*also* keep single-flight coalescing of identical in-flight client queries —
that's an orthogonal optimisation that further reduces upstream load.

- reqwest 0.13 renamed TLS features: use `rustls` + `webpki-roots` (not the old
  `rustls-tls`).

---

## Allow/Block from the query log (round 4)

Added a per-row overflow menu (⋯) in the Query Log with "Allow this domain" /
"Block this domain". Matches AdGuard Home's behaviour exactly (verified in
`AdGuardHome client/src/actions/index.tsx::toggleBlocking`): block adds
`||domain^$important`, allow adds `@@||domain^$important`. The `$important` is
what lets a UI unblock override even an important block from a subscribed list
(our priorities: important-allow 102 > important-block 101). Backed by a new
idempotent `POST /api/filters/rule {rule}` that appends one line to the custom
rules. Verified: a list-blocked domain flips to `allow` after the action.

Final adblock-rust skim: the only unadopted idea is `RegexManager` (lazy-compile
+ discard infrequently-used regexes to cap memory when there are *many* regex
rules) — geared at browser extensions; negligible for DNS (mostly plain
`||domain^`/hosts, few `/regex/`), so intentionally skipped. Everything else of
value (tokenized reverse index, RegexSet fallback, de-dup, compact memory) is in.

## AdGuard Home rule-parity check (round 3)

Cloned AdGuardHome + AdguardTeam/urlfilter (its rule parser) to `/tmp` and
compared. urlfilter's option table shows the DNS-relevant modifiers are:
`important, badfilter, dnstype, dnsrewrite, denyallow, ctag, client` — **all of
which Bulwark supports** (`$important` = priority +100; `@@` exceptions =
unblocking; both confirmed). The rest in urlfilter's table are HTTP/cosmetic
(`script`, `image`, `third-party`, `elemhide`, `domain`, …) and irrelevant to
DNS — we skip those rules as `Unsupported` rather than mis-match them.

`$dnsrewrite`: AGH's `dnsrewrite.go` handles RCODEs + A/AAAA/CNAME/TXT/MX/PTR/
HTTPS/SVCB/SRV. We had A/AAAA/CNAME + RCODEs; **added TXT, MX, PTR** (parse +
response synthesis in `block.rs`). Left HTTPS/SVCB/SRV out for now — their
parameterised values (SvcParams, target/port/priority) are involved and rarely
used for a DNS filter; the parser reports them as unsupported rather than
guessing.

## Follow-up enhancements (round 2)

- **Query-log list attribution**: each entry already carried the matching `rule`
  text + `list_id`; the query-log API now resolves `list_id → list name`
  (id 0 = "Custom rules") and the UI shows a **List** column. A block is one
  winning rule from one list (after de-dup, the first list that defined it), so
  we attribute to that — no ambiguous "blocked by N lists".
- **Serialized snapshots — decided against.** adblock-rust serializes (its
  `.dat` = magic+version+seahash+flatbuffer) mainly for *instant client cold
  start* (browser extension / mobile re-parsing 100k+ network+cosmetic rules on
  every launch) and as a zero-copy in-memory layout. Bulwark is a long-running
  server; measured build is ~0.68s for 200k rules (incl. 5k regex compiles),
  amortised over days of uptime — so a snapshot is low ROI. We borrowed the part
  that *does* help a server (memory compactness) instead.
- **Hot-path + memory optimization** (the part of adblock's design worth taking):
  - `Rule`'s modifier cluster (`dnstype/client/ctag/denyallow/rewrite/important`)
    is boxed into `Option<Box<RuleMods>>`. The overwhelming majority of blocklist
    rules carry no modifiers, so the common rule shrinks to id/raw/action/
    pattern/list_id + a null pointer; `applicable()` early-returns on `None`.
  - Build-only `signature` strings and `index_tokens` are dropped after the
    engine is built.
  - `check()` uses a per-thread reusable scratch buffer for candidate ids, so
    steady-state lookups don't allocate.
  - Measured: 200k rules, **~0.34µs/query non-matching, ~0.65µs/query matching**
    (incl. the bench's own per-iteration string alloc). See
    `server/examples/bench_filter.rs`.

## Follow-up enhancements (round 1)

- **Configurable optimistic-cache retention**: the serve-stale window was a
  hard-coded 30h constant; it's now `cache.optimistic_max_age_secs` (default
  24h), plumbed through `DnsCache` as an atomic and editable in Settings. It
  bounds *staleness* (how long past expiry a stale answer may be served); total
  memory is independently bounded by the LRU `size`. `0` disables serve-stale.
- **Query log** already covers the asks: searchable by domain substring and by
  client (IP **or** name), blocked-only filter, and each entry records the
  action (blocked/cached/forwarded/rewritten/error), the upstream that answered
  (or `cache`), the matched rule, rcode, answers, and processing time — verified
  live.
- **Second adblock-rust pass**:
  - *Compile-time de-duplication* of identical rules by signature (huge for
    overlapping blocklists; first occurrence keeps attribution).
  - *`RegexSet` fallback*: the always-checked wildcard/regex fallback bucket is
    now matched with a single `regex::RegexSet` pass that reports *which*
    patterns matched — so we keep per-rule attribution while turning N regex
    evals into one (adblock fuses into an alternation but loses attribution; the
    `RegexSet` gives us both). Falls back to per-rule checks if the set can't
    build.
  - Dropped the compile-only `signature` strings from rules after build to cut
    memory on large lists.

## Phase 1 — filter engine — DONE

Design:
- `rule.rs` — `Rule`, `Pattern` (Subdomain / Exact / Wildcard / Regex), action
  (Block/Allow/Rewrite), and the DNS modifier types (`$dnstype`, `$client`,
  `$ctag`, `$denyallow`, `$dnsrewrite`, `$important`, `$badfilter`).
- `parser.rs` — one entry point `parse_line`. Detects hosts-file lines (IP +
  hostnames; `0.0.0.0`/`127.0.0.1`/`::`/`::1` → block, other IP → rewrite),
  AdBlock rules, and `/regex/` rules. Hosts "noise" names (localhost, ip6-*,
  broadcasthost) are skipped so we never blackhole loopback.
- `engine.rs` — `FilterEngine`. Exact + subdomain rules bucket into ahash maps;
  wildcard/regex scanned linearly. Lookup walks domain suffixes for subdomain
  rules. Winner chosen by `priority()` score.
- `list.rs` — `Compiler` accumulates rules across lists, collects `$badfilter`
  signatures, and drops cancelled rules at `build()`.

Decisions / faithful-to-AdGuard choices:
- **Bare domain** (`example.org`) ⇒ treated as `||example.org^` (domain +
  subdomains), which is what blocklists expect.
- **Hosts entries** are *exact* (no subdomain match), matching /etc/hosts
  semantics — blocklists list each subdomain explicitly.
- **Priority**: `score = (allow?2:1) + (important?100:0)`; highest wins ⇒
  important > exception > block, and allow beats block at equal importance.
- **`$badfilter`** pairs by a canonical signature (`@@`? + lowercased pattern +
  sorted modifiers minus `badfilter`), so it cancels exactly the twin rule.
- **`$denyallow`** makes a blocking rule *not* apply to the listed domains.
- **Unsupported (HTTP-only) modifiers** (`$third-party`, `$script`, …) ⇒ the
  whole rule is skipped (counted as `unsupported`) rather than mis-matched.
- 50k-rule build + 10k lookups complete in well under the 2s test budget.

## Phase 2 — upstream — DONE

Modules: `spec` (parse `udp/tcp/tls/https/quic://`), `transport` (trait +
`QueryKey` + wire codec), `plain` (UDP w/ TCP-on-truncation, TCP), `dot`,
`doh`, `doq`, `bootstrap`, `tlsconf`, `pool`.

Key decisions:
- **Transport trait** returns `BoxFuture` so the pool can hold heterogeneous
  `Box<dyn Transport>`. UDP binds an ephemeral socket per query (simple,
  stateless; cache + single-flight keep volume low). DoT keeps one persistent
  TLS connection, serialised by a `tokio::Mutex` (reconnects on error). DoH uses
  `reqwest` (HTTP/2 keep-alive) with the host pinned to bootstrap-resolved IPs so
  it never loops through Bulwark itself. DoQ opens one bi-stream per query over a
  reused QUIC connection (id forced to 0 per RFC 9250).
- **Bootstrap**: resolves DoT/DoH/DoQ hostnames via plain-DNS to well-known
  servers (default 1.1.1.1/8.8.8.8) so encrypted upstreams referenced by name
  don't depend on (and can't loop through) Bulwark.
- **Single-flight**: `futures::Shared` future keyed by `QueryKey` in a mutexed
  map; the first caller is "leader" and removes the entry on completion, others
  await the shared result. Verified: 16 concurrent identical queries → 1 upstream
  request.
- **Fastest upstream + sequential failover**: per-upstream EWMA latency + health;
  `ordered()` sorts healthy-first then by latency; `resolve_sequential` tries one
  at a time. Never parallel — satisfies the politeness requirement. Verified by
  tests (prefers fast upstream after probing; fails over past a dead one).
- **Background probing**: `probe_all()` sends `NS .` to each upstream once,
  sequentially, refreshing latency/health. Server schedules it on a timer.
- rustls crypto provider (ring) installed once via `OnceLock`.

Environment note: this dev sandbox routes outbound HTTPS through a proxy
(`CLAUDE_CODE_PROXY_RESOLVES_HOSTS`) and blocks direct TCP/QUIC to :443/:853, so
the `#[ignore]`d live DoT/DoH/DoQ tests time out *here*; `live_udp` passes. The
transports are written to spec and should work wherever direct egress exists
(the intended Tailscale deployment). Fixed a real bug: DoH must negotiate h2 via
ALPN, not `http2_prior_knowledge()` (that's for cleartext h2c).

## Phase 3 — cache — DONE

`DnsCache` (in engine crate): LRU (`lru` crate) keyed by `QueryKey`. Stores the
full response + `stored_at` + clamped `ttl`. On `get`, adjusts record TTLs to
the remaining lifetime. Positive + negative caching (NXDOMAIN/NODATA via SOA
minimum per RFC 2308). Tuning (enabled, size, min/max TTL clamp, optimistic) is
held in atomics and `reconfigure`d live. Optimistic mode serves stale within a
window and the *engine* spawns a single background refresh (pool single-flight
keeps it to one upstream request). Doesn't cache SERVFAIL/REFUSED/truncated.

## Phase 4 — engine — DONE

`Engine` holds hot-swappable `EngineState` (filter + pool + client map +
filtering knobs) in an `ArcSwap`; cache/log/stats are persistent `Arc`s so a
config reload never drops accumulated data. `handle()` pipeline:
client-identify → filter (block/rewrite/allow) → cache → upstream → finalize
(record stats + push log). CNAME rewrites resolve the target via the pool and
append answers. Blocking modes: NXDOMAIN / NODATA / REFUSED / null-IP /
custom-IP (per query type). `server.rs` runs UDP (per-query task, EDNS-aware
truncation with TC bit) and TCP (length-prefixed, pipelined, idle timeout).

### Persistence design (per user request: separate retention for logs & stats)

- **Query log**: in-memory ring for fast browsing + an optional async *sink*
  (`set_sink`) so the server can append entries to disk and `preload` recent
  ones on startup. Retention (`query_log.retention_days`) is independent.
- **Stats**: serializable inner state with `export()`/`import()`; the server
  snapshots it periodically and on shutdown, and the time-series honours
  `stats.retention_days` (separate from the log). Both have `persist` toggles.
- Actual file I/O lives in the server (Phase 6), which owns the data dir.

## Phase 5 — config — DONE

`bulwark-config`: one `Config` root with `server / upstreams / cache /
filtering / clients / query_log / stats / auth` sections, all `#[serde(default)]`
so partial YAML works. Durations stored as `*_secs`/`*_days` for simple
UI/JSON editing. Atomic save (temp + rename), validation, schema version.
Password stored as an Argon2 hash (set by the server during the setup flow).

## Phase 6 — server — DONE

`server/` binary. Modules: `app` (state + config→engine build/apply, hot-reload),
`auth` (Argon2 hashing + in-memory sessions), `persist` (query-log JSONL
append/load/prune + stats snapshot), `api` (Axum REST), `assets` (embedded SPA),
`main` (wiring + background tasks + graceful shutdown).

- **Config apply** rebuilds the hot-swappable `EngineState` and reconfigures
  cache/log/stats in place — no traffic dropped, accumulated data kept.
- **Auth**: setup flow creates the admin (Argon2id); login issues an HttpOnly
  session cookie; a middleware gates all `/api/*` except status/setup/login.
  Salt generated from `rand` bytes via `SaltString::encode_b64` (avoids a
  rand_core version clash with password_hash).
- **Persistence**: query log appended to `querylog.jsonl` by a background writer
  fed via the log's sink; preloaded + pruned on startup; hourly pruner honours
  `query_log.retention_days`. Stats snapshotted to `stats.json` every 60s and on
  shutdown; restored on startup; `stats.retention_days` bounds the series.
- **Background tasks**: upstream probe loop (interval from config), stats
  snapshotter, query-log pruner.
- DNS bind failure (e.g. needing root for :53) is non-fatal — the web UI still
  starts so the user can reconfigure. `BULWARK_DNS_BIND` / `BULWARK_HTTP_BIND`
  env overrides ease testing on unprivileged ports.

Verified end-to-end (server on :15353/:13000): setup, real resolution via
upstream failover, custom-rule + hosts-list blocking → NXDOMAIN, check tool,
upstream test, live stats, query log, auth 401 gating, and persistence across a
restart.

API surface: `/api/status|setup|login|logout`, `/api/config` (+ section PUTs
`upstreams|cache|filtering|server|querylog|stats`), `/api/filters` (+ `custom`,
`check`, `lists` CRUD + `refresh`), `/api/clients`, `/api/stats` (+ `reset`),
`/api/querylog` (GET/DELETE), `/api/upstreams` (+ `test`).

## Phase 7 — web UI — DONE

Svelte 5 (runes) + Vite + TypeScript SPA in `web/`, built to `web/dist` and
embedded via `rust-embed`. Charts use **Chart.js** (per request — more reliable
than hand-rolled SVG). Hash-based routing; a typed `api.ts` client; a toast
store; dark theme in `app.css`.

Views: Login/Setup, Dashboard (stat cards + time-series line, top
domains/blocked/clients bars, qtype doughnut, latency histogram; 5s polling),
Query Log (filter/search/paginate, live toggle), Filters (lists CRUD + refresh,
custom-rules editor, check-a-domain tool), Upstreams (live status/RTT table +
chart, add/remove/test, settings), Clients (named IP/CIDR + tags + per-client
filtering), Settings (filtering/cache/querylog/stats/server sections).

Gotchas:
- `web/dist` is committed (un-ignored) so `cargo build` embeds a working UI with
  no Node needed. `pnpm build` regenerates it.
- Asset route `/assets/{*path}` captures the path *after* `/assets/`; the
  handler re-prepends `assets/` to match embed keys (rust-embed keys are
  relative to the dist root). Verified JS/CSS serve with correct content types.
- esbuild's pnpm build script is allow-listed via `pnpm.onlyBuiltDependencies`.
- Test-harness notes: foreground `sleep` is blocked (use `curl --retry`);
  `pkill -f target/debug/bulwark` matches the shell's own command line and kills
  it — use `pkill -x bulwark`.

## Phase 9 — filtering optimization (from adblock-rust) — DONE

Studied Brave's `adblock-rust` (cloned to /tmp): it tokenizes filters and the
request, bucketing each filter under one rare token in a reverse index, then
only checks candidates that share a token with the request.

Applied the idea to our **wildcard/regex bucket** (previously scanned linearly
for every query; exact/subdomain were already O(labels) via hash maps):
- New `token` module: FNV-1a hashing; `tokenize_query` (all alphanumeric runs
  ≥3 chars of the query name) and `tokenize_pattern_safe` (only **interior**
  literal runs — bounded by real separators, never a `*` edge — so any matching
  domain is guaranteed to contain them as complete tokens).
- Each wildcard rule carries `index_tokens`; at build time we bucket it under
  its **rarest** token (`scan_index: token → rule ids`). Wildcard rules with no
  safe token and **all regex rules** go to `scan_fallback` (always scanned), so
  correctness is never sacrificed for speed.
- Lookup tokenizes the query once and only regex-checks the rarest-token bucket
  plus the (small) fallback list.

Result: 20k wildcard rules, 5k lookups complete well under budget; a linear
scan would be ~20k regex evals per query. Correctness covered by
`wildcard_reverse_index_correctness` (mixed wildcard + regex, positive &
negative) and the existing AdGuard-semantics tests — all green.

Future ideas not yet taken from adblock-rust: flatbuffer/compact rule layout for
very large lists, and compile-time rule de-duplication/fusing.
