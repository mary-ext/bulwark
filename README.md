# Bulwark

**Bulwark** is a self-hosted, network-wide DNS filtering resolver written in
Rust — an alternative to AdGuard Home, designed to run as a DNS resolver inside
a [Tailscale](https://tailscale.com) tailnet. It serves **plain DNS** (UDP/TCP)
to your devices and forwards upstream over plain DNS, **DoH**, **DoT**, or
**DoQ**, while blocking ads/trackers and giving you a full web UI with stats and
query logs.

> Status: feature-complete across the planned phases. See
> [`docs/PLAN.md`](docs/PLAN.md) for the roadmap and
> [`docs/NOTES.md`](docs/NOTES.md) for design notes.

## Features

- **Web UI for everything** — dashboard, query log, filters, upstreams, clients,
  and settings. No config-file editing required (though the YAML is there if you
  want it).
- **Encrypted upstreams** — plain DNS, DNS-over-TLS (RFC 7858),
  DNS-over-HTTPS (RFC 8484), and DNS-over-QUIC (RFC 9250).
- **Polite by design**
  - A query goes to the **single fastest healthy upstream**, failing over
    **sequentially** — never fanned out to several upstreams at once.
  - Identical in-flight queries are **coalesced** (single-flight).
  - Latency is tracked from real traffic plus a gentle background probe.
- **Caching** — TTL-respecting positive & negative cache, configurable min/max
  TTL clamps, and optional **optimistic caching** (serve-stale with a single
  background refresh and a **configurable bound on staleness**).
- **Filtering** — host-file lists and the DNS-relevant subset of **AdGuard rule
  syntax** (`||domain^`, `@@` exceptions, wildcards, `/regex/`, and the
  `$important`, `$badfilter`, `$dnstype`, `$dnsrewrite`, `$client`, `$ctag`,
  `$denyallow` modifiers). Write your own custom rules too.
- **Client naming** — map IPs/CIDRs to friendly names and tags; toggle filtering
  per client.
- **Observability** — total/blocked/cached counters, top queried & blocked
  domains, top clients, per-upstream response times, processing-time histogram,
  and an hourly time series. Browse and search the **query log**.
- **Persistence** — query log and statistics are persisted to disk with
  **independent, configurable retention**.

## Architecture

A Cargo workspace of focused, independently-tested crates:

| Crate | Responsibility |
|-------|----------------|
| `bulwark-filter` | Rule parsing (AdGuard subset + hosts) and fast matching |
| `bulwark-upstream` | UDP/TCP/DoT/DoH/DoQ transports, fastest-upstream selection, single-flight, bootstrap |
| `bulwark-config` | Typed config model, defaults, YAML persistence, validation |
| `bulwark-engine` | DNS server (UDP/TCP), cache, client matcher, query log, stats, pipeline |
| `bulwark` (`server/`) | Axum REST API + embedded web UI, wiring, background tasks |
| `web/` | Svelte + Vite + Chart.js front-end (built into the binary) |

## Quick start

### Build

The web UI is embedded into the binary at compile time, but the **web build and
the Rust build are decoupled**: `cargo build` only embeds whatever is already in
`web/dist` — it never runs `pnpm`. Build the front-end first, then the binary:

```sh
cd web && pnpm install && pnpm build && cd ..
cargo build --release
```

Or, with [`just`](https://github.com/casey/just): `just install && just dist`.

The built bundle (`web/dist`) is generated, **not** committed. If you build
without a Node toolchain (or before building the UI), the server still compiles
and runs — it just serves a small "UI not built" placeholder, and `cargo` prints
a warning. Iterate on the UI live with `cd web && pnpm dev` (it proxies `/api` to
a running server on `:3000`); in that mode you don't need the embedded bundle at
all.

> **Why decoupled?** The front-end's API client is generated from an OpenAPI
> spec that the server emits. If `cargo build` also drove `pnpm build`, building
> the server would require the web bundle, which would require the spec, which
> would require building the server — a cycle. Keeping the steps separate makes
> the pipeline a straight line: spec → client codegen → `pnpm build` →
> `cargo build`.

### Run

```sh
./target/release/bulwark
```

On first run it creates `./data/config.yaml` and listens on:

- **DNS**: `0.0.0.0:53` (UDP + TCP)
- **Web UI**: `http://0.0.0.0:3000`

Open the web UI, create your admin account, and you're set.

> **Binding to port 53** needs privileges. Either run as root, or grant the
> capability once:
>
> ```sh
> sudo setcap 'cap_net_bind_service=+ep' ./target/release/bulwark
> ```
>
> For local testing on unprivileged ports, override the binds:
>
> ```sh
> BULWARK_DNS_BIND=127.0.0.1:5353 BULWARK_HTTP_BIND=127.0.0.1:3000 ./target/debug/bulwark
> ```
>
> If the DNS bind fails, the web UI still starts so you can reconfigure.

### Use it as your Tailscale resolver

1. Run Bulwark on a machine in your tailnet and note its Tailscale IP
   (e.g. `100.x.y.z`).
2. In the [Tailscale admin console](https://login.tailscale.com/admin/dns),
   under **Nameservers**, add `100.x.y.z` as a **global nameserver** (optionally
   enable **Override local DNS**), or add it as a split-DNS resolver for
   specific domains.
3. (Recommended) Set Bulwark's `dns_bind` to its Tailscale IP, e.g.
   `100.x.y.z:53`, so it only answers tailnet clients. Each device then shows up
   in the query log by its tailnet IP — name them on the **Clients** page.

## Configuration

Everything is editable from the web UI. The underlying file lives at
`$BULWARK_DATA_DIR/config.yaml` (default `./data/config.yaml`).

### Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `BULWARK_DATA_DIR` | `./data` | Config, filter lists, query log, and stats |
| `BULWARK_DNS_BIND` | — | Override DNS listen address (testing) |
| `BULWARK_HTTP_BIND` | — | Override web UI listen address (testing) |
| `BULWARK_LOG` | `info` | `tracing` filter (e.g. `bulwark=debug`) |

### Upstream spec formats

| Form | Protocol |
|------|----------|
| `1.1.1.1`, `8.8.8.8:53` | Plain DNS over UDP (TCP fallback on truncation) |
| `udp://1.1.1.1` / `tcp://1.1.1.1` | Plain DNS, forced transport |
| `tls://dns.google` | DNS-over-TLS (port 853) |
| `https://dns.quad9.net/dns-query` | DNS-over-HTTPS |
| `quic://dns.adguard-dns.com` | DNS-over-QUIC (port 853) |

Hostnames for encrypted upstreams are resolved via the **bootstrap** servers
(plain DNS, configurable) so they never loop back through Bulwark.

### Filtering rules

Bulwark understands:

- **Hosts files**: `0.0.0.0 ads.example.com` (block), `1.2.3.4 host.lan` (rewrite).
- **Bare domains**: `doubleclick.net` (blocks the domain and subdomains).
- **AdBlock-style**: `||ads.example.com^`, `@@||allow.example.com^`,
  `*.tracker.com`, `/^ads?\d*\./`.
- **Modifiers**: `$important`, `$badfilter`, `$dnstype=A|AAAA`,
  `$dnsrewrite=…`, `$client=10.0.0.0/24|laptop`, `$ctag=device_kids`,
  `$denyallow=good.example.com`.
- **`$dnsrewrite`** supports response-code keywords (`NOERROR`, `NXDOMAIN`,
  `REFUSED`, `SERVFAIL`), short-form IPs (`1.2.3.4`, `::1`), and full-form
  `RCODE;TYPE;VALUE` for `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `PTR`.

Rule priority follows AdGuard: `$important` > `@@` exceptions > basic rules;
`$badfilter` cancels a matching rule; `$denyallow` carves out exceptions.

### AdGuard Home parity

Bulwark supports AdGuard Home's **complete DNS-relevant modifier set**
(`$important`, `$badfilter`, `$dnstype`, `$dnsrewrite`, `$denyallow`, `$ctag`,
`$client`) and all DNS rule forms (adblock-style, hosts, bare domains,
wildcards, `/regex/`, and `@@` exceptions). The only intentional gaps are
`$dnsrewrite` to the exotic record types `HTTPS`/`SVCB`/`SRV` (rare; their
parameterised values aren't synthesised yet) and HTTP/cosmetic-only modifiers
(`$script`, `$third-party`, element hiding, …), which are irrelevant to DNS and
are safely skipped rather than mis-applied.

## Development

```sh
cargo test --workspace     # all unit + integration tests
cargo clippy --workspace
cargo fmt --all

# Live UI dev against a running server (proxies /api to :3000):
cd web && pnpm dev
```

Network-dependent upstream tests are `#[ignore]`d by default:

```sh
cargo test -p bulwark-upstream -- --ignored   # exercises live DoT/DoH/DoQ/UDP
```

## License

MIT. Bulwark studies concepts from projects like Brave's `adblock-rust` but does
not copy their code.
