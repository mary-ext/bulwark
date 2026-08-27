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
    /** Stable, server-assigned identifier. Used as the resource key in the API. */
    id?: string;
    /** Identifiers: IP addresses or CIDR ranges. */
    ids?: string[];
    name: string;
    tags?: string[];
};
export type ErrorResponse = {
    error: string;
};
export type ClientInput = {
    filtering_enabled?: boolean;
    ids?: string[];
    name: string;
    tags?: string[];
};
export type OkResponse = {
    ok: boolean;
};
export type AuthConfig = {
    /** Argon2 password hash; absent until setup completes. */
    password_hash?: string | null;
    /** Base64url HMAC secret for session JWTs. */
    session_secret?: string | null;
    /** Admin username. */
    username?: string;
};
export type CacheConfig = {
    enabled?: boolean;
    /** Clamp upper bound for TTLs (seconds); 0 means "no upper clamp". */
    max_ttl_secs?: number;
    /** Clamp lower bound for TTLs (seconds). */
    min_ttl_secs?: number;
    /** Maximum age past expiry for serve-stale; 0 disables it. */
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
export type PrivacyConfig = {
    /** Omits client IPs from query logs and statistics. */
    anonymize_client_ips?: boolean;
};
export type QueryLogConfig = {
    enabled?: boolean;
    /** Persist the query log to disk so it survives restarts. When off, the log
    is kept in an in-memory database for the lifetime of the process. */
    persist?: boolean;
    /** How many days of query log to retain (independent of `stats`). Entries
    older than this are pruned periodically. 0 disables time-based pruning
    (the log is kept indefinitely). */
    retention_days?: number;
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
export type UpstreamLogConfig = {
    /** Enables probe telemetry at runtime. */
    enabled?: boolean;
    /** Persists telemetry across restarts. Applied at startup. */
    persist?: boolean;
    /** Retention in days; 0 disables time-based pruning. */
    retention_days?: number;
};
export type UpstreamsConfig = {
    /** Plain-DNS bootstrap servers for resolving DoT/DoH/DoQ hostnames. */
    bootstrap?: string[];
    /** Upstream specs, one per line. Blank and `#`-prefixed lines are ignored. */
    servers?: string;
    /** Per-attempt query timeout (seconds). */
    timeout_secs?: number;
};
export type Config = {
    auth?: AuthConfig;
    cache?: CacheConfig;
    clients?: ClientConfig[];
    filtering?: FilteringConfig;
    privacy?: PrivacyConfig;
    query_log?: QueryLogConfig;
    server?: ServerConfig;
    stats?: StatsConfig;
    upstream_log?: UpstreamLogConfig;
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
    /** The filter list responsible, present whenever a rule matched
    (`Custom rules` for user-written rules). */
    list_name?: string | null;
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
    /** Matching filter-list name. */
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
    /** Total entries matching the filter (across all pages), for pagination. */
    total: number;
};
export type SeriesPointDto = {
    blocked: number;
    cached: number;
    hour: number;
    total: number;
};
export type TopEntryDto = {
    count: number;
    name: string;
};
export type LatencyPercentilesDto = {
    p50: number;
    p90: number;
    p99: number;
};
export type StatsResponse = {
    block_rate: number;
    blocked: number;
    /** Lifetime fresh and stale cache hits. */
    cache_hits: number;
    /** Cache lookups that found nothing servable and went upstream. */
    cache_misses: number;
    /** Background refreshes that failed to resolve upstream. */
    cache_refresh_failures: number;
    /** Background refreshes dispatched upstream. */
    cache_refreshes: number;
    cache_size: number;
    /** Stale hits that triggered background refreshes. */
    cache_stale_hits: number;
    cached: number;
    errors: number;
    p95_processing_ms: number;
    rewritten: number;
    series: SeriesPointDto[];
    top_blocked_domains: TopEntryDto[];
    top_clients: TopEntryDto[];
    top_resolved_domains: TopEntryDto[];
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
export function postClient(clientInput: ClientInput, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: ClientConfig;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/clients", oazapfts.json({
        ...opts,
        method: "POST",
        body: clientInput
    }));
}
export function putClient(id: string, clientInput: ClientInput, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    } | {
        status: 404;
        data: ErrorResponse;
    }>(`/api/clients/${encodeURIComponent(id)}`, oazapfts.json({
        ...opts,
        method: "PUT",
        body: clientInput
    }));
}
export function deleteClient(id: string, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 404;
        data: ErrorResponse;
    }>(`/api/clients/${encodeURIComponent(id)}`, {
        ...opts,
        method: "DELETE"
    });
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
export function putPrivacy(privacyConfig: PrivacyConfig, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/config/privacy", oazapfts.json({
        ...opts,
        method: "PUT",
        body: privacyConfig
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
export function putUpstreamLog(upstreamLogConfig: UpstreamLogConfig, opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 400;
        data: ErrorResponse;
    }>("/api/config/upstreamlog", oazapfts.json({
        ...opts,
        method: "PUT",
        body: upstreamLogConfig
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
export function clearUpstreamLog(opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: OkResponse;
    } | {
        status: 401;
        data: ErrorResponse;
    }>("/api/upstreamlog", {
        ...opts,
        method: "DELETE"
    });
}
export function exportUpstreamLog(opts?: Oazapfts.RequestOpts) {
    return oazapfts.fetchJson<{
        status: 200;
        data: Blob;
    } | {
        status: 401;
        data: ErrorResponse;
    }>("/api/upstreamlog/export", {
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
