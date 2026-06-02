# Bulwark — Implementation Plan

Bulwark is a self-hosted, network-wide DNS filtering resolver written in Rust —
an alternative to AdGuard Home. It is intended to run as a DNS resolver inside a
Tailscale tailnet: it hosts **plain DNS** (UDP/TCP) for clients, and forwards to
configurable upstreams over plain DNS, **DoH**, **DoT**, or **DoQ**.

This document is the living plan. It is updated as work progresses. Interesting
implementation details and decisions live in [`NOTES.md`](./NOTES.md).

## Status legend

- [ ] not started
- [~] in progress
- [x] done & tested

---

## Goals (from the brief)

1. Configurable entirely through a web UI.
2. Configurable upstream DNS servers: plain DNS, DoH, DoT, DoQ.
3. We only *host* plain DNS for now (Tailscale resolver use case).
4. Use the fastest upstream where possible.
5. Be polite to the user's internet and to upstreams:
   - **Never fan a single query out to several/all upstreams at once.** For a
     given query we pick the *one* best upstream and send it there; on failure
     we fail over to the next **sequentially**, never racing them in parallel.
     (This rules out AdGuard's "parallel requests" mode by design.)
   - Additionally, identical concurrent in-flight queries are coalesced
     (single-flight) so duplicate client traffic doesn't multiply upstream load.
   - Reasonable *background* polling of upstreams (latency probing) is allowed,
     rate-limited and spread out.
6. Configurable blocking filter lists.
7. Support **host-file** lists and the **DNS-relevant subset of AdGuard rule
   syntax**.
8. Assign human-friendly **names to clients**.
9. **Statistics**: total queries, blocked count, processing time, top queried
   domains, top blocked domains, top clients, upstream response-time stats, most
   queried upstreams.
10. **Query log** browsing.
11. Custom user filtering rules.

## Non-goals (for now)

- Hosting DoH/DoT/DoQ *server* endpoints (we only host plain DNS).
- DHCP server, per-client encryption, mobile config — out of scope.

---

## Architecture

A Cargo workspace of focused, independently-testable crates, plus a single
server binary and a web UI.

```
bulwark/
├── Cargo.toml                 # workspace
├── crates/
│   ├── bulwark-filter/        # rule parsing + matching engine
│   ├── bulwark-upstream/      # upstream transports + fastest selection + single-flight
│   ├── bulwark-config/        # config model, defaults, persistence (shared types)
│   └── bulwark-engine/        # DNS server + cache + query log + stats + clients
├── server/                    # bulwark binary: Axum REST API + embeds web UI + runs engine
├── web/                       # Svelte + Vite front-end (built into server/ at compile time)
└── docs/                      # PLAN.md, NOTES.md
```

Dependency direction (no cycles):

```
filter   config
   \      /  \
    \    /    \
   engine      \
      \         \
       \         \
        server (binary) ── upstream
            └── web (embedded assets)
engine also depends on upstream + filter + config
```

### Core building blocks

- **DNS message types & wire codec**: `hickory-proto` — battle-tested, runtime
  independent. We build our own orchestration on top.
- **Async runtime**: `tokio`.
- **Web**: `axum` + `tower-http`, assets embedded via `rust-embed`.
- **TLS**: `rustls` (DoT/DoQ/DoH).
- **QUIC**: `quinn` (DoQ).
- **HTTP client**: `reqwest` (DoH).
- **Serialization**: `serde` + `serde_json`; config persisted as YAML
  (`serde_yaml`-compatible) so it is human-editable too.

---

## Phases

### Phase 0 — Scaffolding & docs  `[x]`
- [x] Inspect environment, confirm toolchain & network.
- [x] Workspace `Cargo.toml`, `.gitignore`, crate skeletons.
- [x] `docs/PLAN.md` + `docs/NOTES.md`.
- [x] Commit.

### Phase 1 — `bulwark-filter`  `[x]` — DONE
The filtering engine. Pure, no I/O, fully unit-tested.
- [x] Rule model: blocking, exception, hosts, rewrite, with modifiers.
- [x] Parsers:
  - [x] Hosts-file format (`0.0.0.0 domain`, `127.0.0.1 domain`, IP rewrites).
  - [x] Plain domain lists (`domain` per line).
  - [x] AdBlock-style: `||domain^`, `@@||domain^`, `|`, `*`, `^`, comments.
  - [x] Regex rules `/regex/`.
  - [x] Modifiers: `$important`, `$badfilter`, `$dnstype`, `$dnsrewrite`,
        `$client`, `$denyallow`, `$ctag`.
- [x] Matcher with AdGuard-compatible priority:
      `$important` > exception (`@@`) > basic; `$badfilter` cancels; `$denyallow`
      and `$client`/`$ctag` scoping.
- [x] Fast lookup structure (hash sets for plain domains, suffix matching, regex
      bucket) so 100k+ rules match in microseconds.
- [x] Filter list manager: load from text, merge multiple lists, stats per list.
- [x] Extensive unit tests + criterion-style sanity benches (in tests).

### Phase 2 — `bulwark-upstream`  `[x]`
Upstream resolution layer.
- [x] Transport trait `Upstream { resolve(query) -> Response }`.
- [x] Plain DNS over UDP (+ TCP fallback on truncation).
- [x] DoT (DNS-over-TLS, RFC 7858) via tokio-rustls.
- [x] DoH (RFC 8484, POST `application/dns-message`) via reqwest.
- [x] DoQ (DNS-over-QUIC, RFC 9250) via quinn.
- [x] URL/spec parser: `8.8.8.8`, `tls://…`, `https://…/dns-query`, `quic://…`,
      `udp://`, with `#name` labels.
- [x] **Single-flight**: coalesce identical concurrent in-flight queries so we
      never send duplicate parallel requests upstream.
- [x] **Fastest upstream**: maintain EWMA latency per upstream from real traffic
      + a polite background health/latency probe; route to the best healthy one,
      with failover.
- [x] Tests with a local mock UDP DNS server; failover, dedup, selection.

### Phase 3 — caching  `[x]` (in `bulwark-engine`)
- [x] TTL-respecting positive & negative cache (RFC 2308).
- [x] **User-configurable minimum & maximum TTL** clamps (override upstream TTLs
      within `[min_ttl, max_ttl]`), settable from the web UI.
- [x] **Optional optimistic caching** (serve-stale, RFC 8767): a config toggle;
      when on, expired entries are served immediately while a single polite,
      de-duplicated background refresh is kicked off.
- [x] Cache enable/disable toggle and configurable cache size.
- [x] Cache keyed by (name, qtype, qclass); LRU bound.
- [x] Tests.

### Phase 4 — `bulwark-engine`  `[x]`
The query-processing pipeline & observability.
- [x] DNS server: UDP + TCP listeners (tokio), proper truncation/EDNS handling.
- [x] Pipeline: parse → identify client → filter → cache → upstream → log+stats.
- [x] Client identification & naming (by IP / CIDR → name + tags).
- [x] Query log (ring buffer + optional persistence) with filtering/paging.
- [x] Statistics aggregator (counters, top-N via count-min/heaps, latency
      histograms, per-upstream stats, time-bucketed series for charts).
- [x] Blocking response synthesis (NXDOMAIN / 0.0.0.0 / custom IP / NODATA).
- [x] Hot-reload of config/filters without dropping traffic.
- [x] Integration tests against the mock upstream.

### Phase 5 — `bulwark-config`  `[x]`
- [x] Strongly-typed config (server, upstreams, filtering, clients, lists, UI).
- [x] Sensible defaults; load/save YAML; atomic writes; schema versioning.
- [x] Validation with helpful errors.
- [x] Tests.

### Phase 6 — `server` binary + REST API  `[x]`
- [x] Axum app: config CRUD, filter lists CRUD + refresh, clients CRUD,
      custom rules, stats endpoints, query-log endpoint, control (test upstream).
- [x] Wires engine + config + filter manager; applies hot-reload on change.
- [x] Background tasks: list refresh scheduler, latency probes, stats rollup.
- [x] Auth (session cookie + password) — basic but real.
- [x] Embeds the built web UI via `rust-embed`; serves SPA.
- [x] Graceful shutdown, structured logging (`tracing`).

### Phase 7 — Web UI  `[x]`
- [x] Svelte + Vite + TS SPA.
- [x] Dashboard (stats, charts), Query Log, Filters (lists + custom rules),
      Upstreams, Clients, Settings, Login.
- [x] Talks to REST API; live-ish updates via polling (polite).
- [x] `pnpm build` → static assets embedded in the binary.

### Phase 8 — Integration, polish, docs  `[x]`
- [x] End-to-end smoke test (spin server, real query through dig/hickory).
- [x] README with quick start, Tailscale notes, config reference.
- [x] Final pass: clippy, fmt, deny warnings where reasonable.

---

## Testing strategy

- Every core crate has unit tests; `cargo test --workspace` is the gate.
- `bulwark-upstream` and `bulwark-engine` test against an in-process mock UDP
  DNS server so no real network is needed in CI.
- A scripted end-to-end check runs the server and queries it.

## Politeness invariants (must always hold)

- **One upstream per query.** A query is sent to a single chosen upstream; on
  failure/timeout we try the next upstream **sequentially**. We never fan a
  single query out to multiple upstreams concurrently ("parallel requests"
  mode is intentionally not implemented).
- At most **one** in-flight upstream request per `(name,type,class)` key
  (single-flight); concurrent callers await the shared result.
- Background probing is rate-limited and spread out; never a thundering herd.
- Cache + serve-stale minimise upstream load; respect TTLs.
