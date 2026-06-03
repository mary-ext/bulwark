/**
 * Bulwark API
 * 0.1.0
 * DO NOT MODIFY - This file has been generated using oazapfts.
 * See https://www.npmjs.com/package/oazapfts
 */
import * as Oazapfts from "@oazapfts/runtime";
import * as QS from "@oazapfts/runtime/query";
export const defaults: Oazapfts.Defaults<Oazapfts.CustomHeaders> = {
    headers: {},
    baseUrl: "/"
};
const oazapfts = Oazapfts.runtime(defaults);
export const servers = {};
export type ClientConfig = {
    /** Whether filtering applies to this client. */
    filtering_enabled?: boolean;
    /** Identifiers: IP addresses or CIDR ranges. */
    ids?: string[];
    name: string;
    tags?: string[];
};
export type ErrorResponse = {
    error: string;
};
export type OkResponse = {
    ok: boolean;
};
export type AuthConfig = {
    /** Argon2 password hash; `None` until the admin sets a password (setup flow). */
    password_hash?: string | null;
    /** Admin username. */
    username?: string;
};
export type CacheConfig = {
    enabled?: boolean;
    /** Clamp upper bound for TTLs (seconds); 0 means "no upper clamp". */
    max_ttl_secs?: number;
    /** Clamp lower bound for TTLs (seconds). */
    min_ttl_secs?: number;
    /** Optimistic caching (serve-stale): the maximum number of seconds **past
    expiry** that a stale entry may be served immediately while a fresh
    resolve runs in the background. `0` disables serve-stale entirely; any
    value `> 0` enables it and bounds how stale an answer can be (entries are
    never served unbounded). */
    optimistic_max_age_secs?: number;
    /** Maximum number of cached entries. */
    size?: number;
};
export type BlockingMode = "nx_domain" | "null_ip" | "custom_ip" | "refused" | "no_data";
export type FilterListConfig = {
    enabled?: boolean;
    id: number;
    last_updated?: number | null;
    name: string;
    /** Cached metadata (updated by the server; persisted for the UI). */
    rule_count?: number;
    /** Remote URL to fetch; if absent the list is managed purely in the UI. */
    url?: string | null;
};
export type FilteringConfig = {
    /** TTL (seconds) for synthesized blocked responses. */
    blocked_ttl_secs?: number;
    blocking_mode?: BlockingMode;
    custom_block_ipv4?: string;
    custom_block_ipv6?: string;
    /** User-authored custom rules (one rule per line). */
    custom_rules?: string;
    enabled?: boolean;
    lists?: FilterListConfig[];
};
export type QueryLogConfig = {
    /** Whether to anonymize client IPs (drop last octet / suffix). */
    anonymize?: boolean;
    enabled?: boolean;
    /** Persist the query log to disk so it survives restarts. */
    persist?: boolean;
    /** How many days of query log to retain on disk (independent of `stats`).
    0 keeps only the in-memory `size` window. */
    retention_days?: number;
    /** Number of recent entries kept in memory for fast browsing. */
    size?: number;
};
export type ServerConfig = {
    /** Addresses to serve plain DNS on (UDP + TCP). */
    dns_bind?: string[];
    /** Address to serve the web UI + API on. */
    http_bind?: string;
    /** Per-client query rate limit (queries/sec); 0 disables. */
    ratelimit?: number;
};
export type StatsConfig = {
    enabled?: boolean;
    /** Persist statistics to disk so they survive restarts. */
    persist?: boolean;
    /** How many days of time-bucketed statistics history to keep (independent of
    the query-log retention). */
    retention_days?: number;
};
export type UpstreamsConfig = {
    /** Plain-DNS bootstrap servers for resolving DoT/DoH/DoQ hostnames. */
    bootstrap?: string[];
    /** Interval between background latency probes (seconds); 0 disables probing. */
    probe_interval_secs?: number;
    /** Freeform upstream list: one spec per line. Lines starting with `#` are
    comments and blank lines are ignored — both are preserved verbatim so
    you can annotate and toggle entries by commenting them out. e.g.
    `https://cloudflare-dns.com/dns-query`, `tls://one.one.one.one`. */
    servers?: string;
    /** Per-attempt query timeout (seconds). */
    timeout_secs?: number;
};
export type Config = {
    auth?: AuthConfig;
    cache?: CacheConfig;
    clients?: ClientConfig[];
    filtering?: FilteringConfig;
    query_log?: QueryLogConfig;
    server?: ServerConfig;
    stats?: StatsConfig;
    upstreams?: UpstreamsConfig;
    version?: number;
};
export type FilteringSettings = {
    blocked_ttl_secs: number;
    blocking_mode: BlockingMode;
    custom_block_ipv4: string;
    custom_block_ipv6: string;
    enabled: boolean;
};
export type ServerUpdateResponse = {
    ok: boolean;
    restart_required: boolean;
};
export type FiltersResponse = {
    blocking_mode: BlockingMode;
    custom_rules: string;
    enabled: boolean;
    lists: FilterListConfig[];
};
export type CheckRequest = {
    domain: string;
    qtype?: string | null;
};
export type CheckResponse = {
    /** One of `allow`, `block`, or `rewrite`. */
    action: string;
    /** The filter list responsible (absent for allow verdicts). */
    list_id?: number | null;
    /** The matching rule text, if any. */
    rule?: string | null;
};
export type CustomRules = {
    rules: string;
};
export type NewList = {
    /** Optional inline content (when no URL is given). */
    content?: string | null;
    enabled?: boolean;
    name: string;
    url?: string | null;
};
export type AddListResponse = {
    /** The id assigned to the new list. */
    id: number;
    ok: boolean;
};
export type ListUpdate = {
    enabled?: boolean | null;
    name?: string | null;
    url?: string | null;
};
export type AddRule = {
    /** A single rule line to append to the custom rules, e.g. `@@||example.com^`
    or `||ads.example.com^`. Used by the query-log "allow/block" actions. */
    rule: string;
};
export type AddRuleResponse = {
    /** `false` when the rule already existed (the append was a no-op). */
    added: boolean;
    ok: boolean;
    /** The (trimmed) rule that was processed. */
    rule: string;
};
export type Credentials = {
    password: string;
    username: string;
};
export type LogEntryView = {
    /** One of `forwarded`, `cached`, `blocked`, `rewritten`, or `error`. */
    action: string;
    /** True if an `@@` exception allowed an otherwise-blocked query. */
    allowlisted: boolean;
    /** Short summary of answer records (e.g. `["A 1.2.3.4"]`). */
    answers: string[];
    client_ip: string;
    client_name?: string | null;
    elapsed_ms: number;
    id: number;
    /** Filter list id responsible (blocked/rewritten queries only). */
    list_id?: number | null;
    /** Friendly name of the filter list responsible (absent unless the query was
    blocked or rewritten by a known list; id 0 is the user's custom rules). */
    list_name?: string | null;
    qtype: string;
    question: string;
    rcode: string;
    /** Matching rule text (blocked/rewritten queries only). */
    rule?: string | null;
    /** Unix epoch milliseconds. */
    time_ms: number;
    /** Upstream that answered (forwarded queries only). */
    upstream?: string | null;
};
export type QueryLogResponse = {
    entries: LogEntryView[];
    /** Total entries currently held (before paging, after filtering). */
    total: number;
};
export type TopEntryDto = {
    count: number;
    name: string;
};
export type SeriesPointDto = {
    blocked: number;
    cached: number;
    hour: number;
    total: number;
};
export type LatencyPercentilesDto = {
    p50: number;
    p90: number;
    p99: number;
};
export type StatsResponse = {
    avg_processing_ms: number;
    block_rate: number;
    blocked: number;
    cache_hits: number;
    cache_misses: number;
    cache_size: number;
    cached: number;
    errors: number;
    latency_buckets: string[];
    latency_hist: number[];
    qtypes: TopEntryDto[];
    rewritten: number;
    series: SeriesPointDto[];
    top_blocked_domains: TopEntryDto[];
    top_clients: TopEntryDto[];
    top_domains: TopEntryDto[];
    top_upstreams: TopEntryDto[];
    total: number;
    upstream_avg_rtt_ms: {
        [key: string]: number;
    };
    upstream_latency_pct: {
        [key: string]: LatencyPercentilesDto;
    };
};
export type StatusResponse = {
    /** Whether the current request carries a valid session. */
    authed: boolean;
    /** DNS listen addresses (host:port). */
    dns_bind: string[];
    /** Whether the initial admin account still needs to be created. */
    setup_needed: boolean;
    version: string;
};
export type TransportKindDto = "udp" | "tcp" | "tls" | "https" | "quic";
export type UpstreamStatDto = {
    avg_rtt_ms?: number | null;
    kind: TransportKindDto;
    last_error?: string | null;
    last_rtt_ms?: number | null;
    name: string;
    spec: string;
    total_failures: number;
    total_queries: number;
    up: boolean;
};
export type TestUpstream = {
    spec: string;
};
export type TestResult = {
    error?: string | null;
    ok: boolean;
    rtt_ms?: number | null;
};
export function getClients(opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: ClientConfig[];
    } | {
        status: 401;
        data: ErrorResponse;
    }>("/api/clients", {
        ...opts
    });
}
export function putClients(body: ClientConfig[], opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/clients", oazapfts.json({
        ...opts,
        method: "PUT",
        body
    }));
}
export function getConfig(opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: Config;
    } | {
        status: 401;
        data: ErrorResponse;
    }>("/api/config", {
        ...opts
    });
}
export function putCache(cacheConfig: CacheConfig, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/config/cache", oazapfts.json({
        ...opts,
        method: "PUT",
        body: cacheConfig
    }));
}
export function putFiltering(filteringSettings: FilteringSettings, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/config/filtering", oazapfts.json({
        ...opts,
        method: "PUT",
        body: filteringSettings
    }));
}
export function putQuerylog(queryLogConfig: QueryLogConfig, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/config/querylog", oazapfts.json({
        ...opts,
        method: "PUT",
        body: queryLogConfig
    }));
}
export function putServer(serverConfig: ServerConfig, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: ServerUpdateResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/config/server", oazapfts.json({
        ...opts,
        method: "PUT",
        body: serverConfig
    }));
}
export function putStatsCfg(statsConfig: StatsConfig, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/config/stats", oazapfts.json({
        ...opts,
        method: "PUT",
        body: statsConfig
    }));
}
export function putUpstreams(upstreamsConfig: UpstreamsConfig, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/config/upstreams", oazapfts.json({
        ...opts,
        method: "PUT",
        body: upstreamsConfig
    }));
}
export function getFilters(opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: FiltersResponse;
    } | {
        status: 401;
        data: ErrorResponse;
    }>("/api/filters", {
        ...opts
    });
}
export function checkDomain(checkRequest: CheckRequest, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: CheckResponse;
    } | {
        status: 401;
        data: ErrorResponse;
    }>("/api/filters/check", oazapfts.json({
        ...opts,
        method: "POST",
        body: checkRequest
    }));
}
export function putCustomRules(customRules: CustomRules, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/filters/custom", oazapfts.json({
        ...opts,
        method: "PUT",
        body: customRules
    }));
}
export function addList(newList: NewList, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: AddListResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/filters/lists", oazapfts.json({
        ...opts,
        method: "POST",
        body: newList
    }));
}
export function updateList(id: number, listUpdate: ListUpdate, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 404;
        data: ErrorResponse;
    }>(`/api/filters/lists/${encodeURIComponent(id)}`, oazapfts.json({
        ...opts,
        method: "PUT",
        body: listUpdate
    }));
}
export function deleteList(id: number, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 404;
        data: ErrorResponse;
    }>(`/api/filters/lists/${encodeURIComponent(id)}`, {
        ...opts,
        method: "DELETE"
    });
}
export function refreshList(id: number, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    } | {
        status: 404;
        data: ErrorResponse;
    }>(`/api/filters/lists/${encodeURIComponent(id)}/refresh`, {
        ...opts,
        method: "POST"
    });
}
export function addCustomRule(addRule: AddRule, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: AddRuleResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/filters/rule", oazapfts.json({
        ...opts,
        method: "POST",
        body: addRule
    }));
}
export function login(credentials: Credentials, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 401;
        data: ErrorResponse;
    }>("/api/login", oazapfts.json({
        ...opts,
        method: "POST",
        body: credentials
    }));
}
export function logout(opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    }>("/api/logout", {
        ...opts,
        method: "POST"
    });
}
export function getQuerylog({ search, client, blockedOnly, offset, limit }: {
    search?: string;
    client?: string;
    blockedOnly?: boolean;
    offset?: number;
    limit?: number;
} = {}, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: QueryLogResponse;
    } | {
        status: 401;
        data: ErrorResponse;
    }>(`/api/querylog${QS.query(QS.explode({
        search,
        client,
        blocked_only: blockedOnly,
        offset,
        limit
    }))}`, {
        ...opts
    });
}
export function clearQuerylog(opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 401;
        data: ErrorResponse;
    }>("/api/querylog", {
        ...opts,
        method: "DELETE"
    });
}
export function setup(credentials: Credentials, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/setup", oazapfts.json({
        ...opts,
        method: "POST",
        body: credentials
    }));
}
export function getStats({ top }: {
    top?: number;
} = {}, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: StatsResponse;
    } | {
        status: 401;
        data: ErrorResponse;
    }>(`/api/stats${QS.query(QS.explode({
        top
    }))}`, {
        ...opts
    });
}
export function resetStats(opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 401;
        data: ErrorResponse;
    }>("/api/stats/reset", {
        ...opts,
        method: "POST"
    });
}
export function status(opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: StatusResponse;
    }>("/api/status", {
        ...opts
    });
}
export function getUpstreams(opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: UpstreamStatDto[];
    } | {
        status: 401;
        data: ErrorResponse;
    }>("/api/upstreams", {
        ...opts
    });
}
export function testUpstream(testUpstream: TestUpstream, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: TestResult;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/upstreams/test", oazapfts.json({
        ...opts,
        method: "POST",
        body: testUpstream
    }));
}
