// Typed REST client for the Bulwark API.

export interface Status {
  setup_needed: boolean;
  authed: boolean;
  version: string;
  dns_bind: string[];
}

export interface UpstreamCfg {
  spec: string;
  name?: string | null;
  enabled: boolean;
}

export interface UpstreamsCfg {
  servers: UpstreamCfg[];
  bootstrap: string[];
  timeout_secs: number;
  probe_interval_secs: number;
}

export interface CacheCfg {
  enabled: boolean;
  size: number;
  min_ttl_secs: number;
  max_ttl_secs: number;
  optimistic: boolean;
  optimistic_max_age_secs: number;
}

export type BlockingMode = "nx_domain" | "null_ip" | "custom_ip" | "refused" | "no_data";

export interface FilterList {
  id: number;
  name: string;
  url?: string | null;
  enabled: boolean;
  rule_count: number;
  last_updated?: number | null;
}

export interface ServerCfg {
  dns_bind: string[];
  http_bind: string;
  ratelimit: number;
}

export interface QueryLogCfg {
  enabled: boolean;
  size: number;
  persist: boolean;
  retention_days: number;
  anonymize: boolean;
}

export interface StatsCfg {
  enabled: boolean;
  persist: boolean;
  retention_days: number;
}

export interface ClientCfg {
  name: string;
  ids: string[];
  tags: string[];
  filtering_enabled: boolean;
}

export interface TopEntry {
  name: string;
  count: number;
}

export interface SeriesPoint {
  hour: number;
  total: number;
  blocked: number;
  cached: number;
}

export interface StatsSummary {
  total: number;
  blocked: number;
  cached: number;
  rewritten: number;
  errors: number;
  block_rate: number;
  avg_processing_ms: number;
  latency_buckets: string[];
  latency_hist: number[];
  top_domains: TopEntry[];
  top_blocked_domains: TopEntry[];
  top_clients: TopEntry[];
  top_upstreams: TopEntry[];
  qtypes: TopEntry[];
  upstream_avg_rtt_ms: Record<string, number>;
  series: SeriesPoint[];
  cache_hits: number;
  cache_misses: number;
  cache_size: number;
}

export interface LogEntry {
  id: number;
  time_ms: number;
  client_ip: string;
  client_name?: string | null;
  question: string;
  qtype: string;
  action: string;
  allowlisted: boolean;
  rcode: string;
  answers: string[];
  rule?: string | null;
  list_id?: number | null;
  list_name?: string | null;
  upstream?: string | null;
  elapsed_ms: number;
}

export interface UpstreamStat {
  spec: string;
  name: string;
  kind: string;
  up: boolean;
  avg_rtt_ms?: number | null;
  last_rtt_ms?: number | null;
  total_queries: number;
  total_failures: number;
  last_error?: string | null;
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { "content-type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) throw new ApiError("unauthorized", 401);
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new ApiError(data.error ?? res.statusText, res.status);
  return data as T;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

export const api = {
  status: () => req<Status>("GET", "/api/status"),
  setup: (username: string, password: string) =>
    req("POST", "/api/setup", { username, password }),
  login: (username: string, password: string) =>
    req("POST", "/api/login", { username, password }),
  logout: () => req("POST", "/api/logout"),

  getConfig: () => req<any>("GET", "/api/config"),
  putUpstreams: (c: UpstreamsCfg) => req("PUT", "/api/config/upstreams", c),
  putCache: (c: CacheCfg) => req("PUT", "/api/config/cache", c),
  putFiltering: (c: {
    enabled: boolean;
    blocking_mode: BlockingMode;
    custom_block_ipv4: string;
    custom_block_ipv6: string;
    blocked_ttl_secs: number;
  }) => req("PUT", "/api/config/filtering", c),
  putServer: (c: ServerCfg) => req<any>("PUT", "/api/config/server", c),
  putQuerylog: (c: QueryLogCfg) => req("PUT", "/api/config/querylog", c),
  putStatsCfg: (c: StatsCfg) => req("PUT", "/api/config/stats", c),

  getFilters: () =>
    req<{
      lists: FilterList[];
      custom_rules: string;
      enabled: boolean;
      blocking_mode: BlockingMode;
    }>("GET", "/api/filters"),
  putCustomRules: (rules: string) => req("PUT", "/api/filters/custom", { rules }),
  addRule: (rule: string) => req<{ added: boolean }>("POST", "/api/filters/rule", { rule }),
  checkDomain: (domain: string, qtype?: string) =>
    req<{ action: string; rule?: string; list_id?: number }>("POST", "/api/filters/check", {
      domain,
      qtype,
    }),
  addList: (l: { name: string; url?: string; enabled: boolean; content?: string }) =>
    req<{ id: number }>("POST", "/api/filters/lists", l),
  updateList: (id: number, u: { name?: string; url?: string; enabled?: boolean }) =>
    req("PUT", `/api/filters/lists/${id}`, u),
  deleteList: (id: number) => req("DELETE", `/api/filters/lists/${id}`),
  refreshList: (id: number) => req("POST", `/api/filters/lists/${id}/refresh`),

  getClients: () => req<ClientCfg[]>("GET", "/api/clients"),
  putClients: (clients: ClientCfg[]) => req("PUT", "/api/clients", clients),

  getStats: (top = 15) => req<StatsSummary>("GET", `/api/stats?top=${top}`),
  resetStats: () => req("POST", "/api/stats/reset"),

  getQuerylog: (params: {
    search?: string;
    client?: string;
    blocked_only?: boolean;
    offset?: number;
    limit?: number;
  }) => {
    const q = new URLSearchParams();
    if (params.search) q.set("search", params.search);
    if (params.client) q.set("client", params.client);
    if (params.blocked_only) q.set("blocked_only", "true");
    if (params.offset) q.set("offset", String(params.offset));
    if (params.limit) q.set("limit", String(params.limit));
    return req<{ entries: LogEntry[]; total: number }>("GET", `/api/querylog?${q}`);
  },
  clearQuerylog: () => req("DELETE", "/api/querylog"),

  getUpstreams: () => req<UpstreamStat[]>("GET", "/api/upstreams"),
  testUpstream: (spec: string) =>
    req<{ ok: boolean; rtt_ms?: number; error?: string }>("POST", "/api/upstreams/test", {
      spec,
    }),
};
