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

## Phase 1 — filter engine

(notes added during implementation)

## Phase 2 — upstream

## Phase 3 — cache

## Phase 4 — engine

## Phase 5 — config

## Phase 6 — server

## Phase 7 — web UI
