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

## Phase 2 — upstream

## Phase 3 — cache

## Phase 4 — engine

## Phase 5 — config

## Phase 6 — server

## Phase 7 — web UI
