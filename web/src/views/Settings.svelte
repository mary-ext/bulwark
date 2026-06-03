<script lang="ts">
  import * as api from "../api/generated";
  import { ok } from "@oazapfts/runtime";
  import type {
    CacheConfig,
    QueryLogConfig,
    StatsConfig,
    ServerConfig,
    BlockingMode,
  } from "../api/generated";
  import { errMsg } from "../lib/errors";
  import { toaster } from "../lib/toast.svelte";

  let loaded = $state(false);

  let filtering = $state({
    enabled: true,
    blocking_mode: "nx_domain" as BlockingMode,
    custom_block_ipv4: "0.0.0.0",
    custom_block_ipv6: "::",
    blocked_ttl_secs: 10,
  });
  let cache = $state<Required<CacheConfig> | null>(null);
  let querylog = $state<Required<QueryLogConfig> | null>(null);
  let stats = $state<Required<StatsConfig> | null>(null);
  let server = $state<Required<ServerConfig> | null>(null);

  async function load() {
    const c = await ok(api.getConfig());
    filtering = {
      enabled: c.filtering?.enabled ?? true,
      blocking_mode: c.filtering?.blocking_mode ?? "nx_domain",
      custom_block_ipv4: c.filtering?.custom_block_ipv4 ?? "0.0.0.0",
      custom_block_ipv6: c.filtering?.custom_block_ipv6 ?? "::",
      blocked_ttl_secs: c.filtering?.blocked_ttl_secs ?? 10,
    };
    cache = (c.cache ?? null) as Required<CacheConfig> | null;
    querylog = (c.query_log ?? null) as Required<QueryLogConfig> | null;
    stats = (c.stats ?? null) as Required<StatsConfig> | null;
    server = (c.server ?? null) as Required<ServerConfig> | null;
    loaded = true;
  }

  $effect(() => {
    load();
  });

  async function run(fn: () => Promise<unknown>, okMsg: string) {
    try {
      await fn();
      toaster.show(okMsg);
    } catch (e) {
      toaster.show(errMsg(e, "Save failed"), true);
    }
  }

  const blockingModes: { v: BlockingMode; l: string }[] = [
    { v: "nx_domain", l: "NXDOMAIN" },
    { v: "null_ip", l: "Null IP (0.0.0.0 / ::)" },
    { v: "custom_ip", l: "Custom IP" },
    { v: "refused", l: "REFUSED" },
    { v: "no_data", l: "NODATA" },
  ];
</script>

<h1 class="page-title">Settings</h1>

{#if loaded}
  <div class="grid cols-2">
    <!-- Filtering -->
    <div class="card">
      <h3 style="margin-top:0">Filtering</h3>
      <div class="field row" style="justify-content:space-between">
        <label style="margin:0">Enable filtering</label>
        <label class="switch"><input type="checkbox" bind:checked={filtering.enabled} /><span class="slider"></span></label>
      </div>
      <div class="field">
        <label for="bm">Blocking mode</label>
        <select id="bm" bind:value={filtering.blocking_mode}>
          {#each blockingModes as m}<option value={m.v}>{m.l}</option>{/each}
        </select>
      </div>
      {#if filtering.blocking_mode === "custom_ip"}
        <div class="grid cols-2">
          <div class="field"><label>Block IPv4</label><input class="mono" bind:value={filtering.custom_block_ipv4} /></div>
          <div class="field"><label>Block IPv6</label><input class="mono" bind:value={filtering.custom_block_ipv6} /></div>
        </div>
      {/if}
      <div class="field">
        <label for="bt">Blocked response TTL (s)</label>
        <input id="bt" type="number" min="0" bind:value={filtering.blocked_ttl_secs} />
      </div>
      <button class="primary" onclick={() => run(() => ok(api.putFiltering(filtering)), "Filtering saved")}>Save</button>
    </div>

    <!-- Cache -->
    <div class="card">
      <h3 style="margin-top:0">Cache</h3>
      {#if cache}
        <div class="field row" style="justify-content:space-between">
          <label style="margin:0">Enable cache</label>
          <label class="switch"><input type="checkbox" bind:checked={cache.enabled} /><span class="slider"></span></label>
        </div>
        <div class="field row" style="justify-content:space-between">
          <label style="margin:0" title="Serve stale answers while refreshing in the background">Optimistic caching</label>
          <label class="switch">
            <input
              type="checkbox"
              checked={cache.optimistic_max_age_secs > 0}
              onchange={(e) => (cache!.optimistic_max_age_secs = e.currentTarget.checked ? 86400 : 0)}
            />
            <span class="slider"></span>
          </label>
        </div>
        {#if cache.optimistic_max_age_secs > 0}
          <div class="field">
            <label for="sa">Max serve-stale age (s past expiry)</label>
            <input id="sa" type="number" min="1" bind:value={cache.optimistic_max_age_secs} />
            <p class="muted" style="font-size:0.78rem;margin:0.3rem 0 0">
              Bounds how stale an answer can be; turn the toggle off to disable serve-stale.
            </p>
          </div>
        {/if}
        <div class="field"><label for="cs">Max entries</label><input id="cs" type="number" min="1" bind:value={cache.size} /></div>
        <div class="grid cols-2">
          <div class="field"><label>Min TTL (s)</label><input type="number" min="0" bind:value={cache.min_ttl_secs} /></div>
          <div class="field"><label>Max TTL (s, 0 = none)</label><input type="number" min="0" bind:value={cache.max_ttl_secs} /></div>
        </div>
        <button class="primary" onclick={() => cache && run(() => ok(api.putCache(cache!)), "Cache saved")}>Save</button>
      {/if}
    </div>

    <!-- Query log -->
    <div class="card">
      <h3 style="margin-top:0">Query log</h3>
      {#if querylog}
        <div class="field row" style="justify-content:space-between">
          <label style="margin:0">Enable query log</label>
          <label class="switch"><input type="checkbox" bind:checked={querylog.enabled} /><span class="slider"></span></label>
        </div>
        <div class="field row" style="justify-content:space-between">
          <label style="margin:0">Persist to disk</label>
          <label class="switch"><input type="checkbox" bind:checked={querylog.persist} /><span class="slider"></span></label>
        </div>
        <div class="field row" style="justify-content:space-between">
          <label style="margin:0">Anonymize client IPs</label>
          <label class="switch"><input type="checkbox" bind:checked={querylog.anonymize} /><span class="slider"></span></label>
        </div>
        <div class="grid cols-2">
          <div class="field"><label>In-memory entries</label><input type="number" min="1" bind:value={querylog.size} /></div>
          <div class="field"><label>Retention (days)</label><input type="number" min="0" bind:value={querylog.retention_days} /></div>
        </div>
        <button class="primary" onclick={() => querylog && run(() => ok(api.putQuerylog(querylog!)), "Query log saved")}>Save</button>
      {/if}
    </div>

    <!-- Stats -->
    <div class="card">
      <h3 style="margin-top:0">Statistics</h3>
      {#if stats}
        <div class="field row" style="justify-content:space-between">
          <label style="margin:0">Enable statistics</label>
          <label class="switch"><input type="checkbox" bind:checked={stats.enabled} /><span class="slider"></span></label>
        </div>
        <div class="field row" style="justify-content:space-between">
          <label style="margin:0">Persist to disk</label>
          <label class="switch"><input type="checkbox" bind:checked={stats.persist} /><span class="slider"></span></label>
        </div>
        <div class="field"><label>Retention (days)</label><input type="number" min="1" bind:value={stats.retention_days} /></div>
        <p class="muted" style="font-size:0.8rem">Query log and statistics retention are independent.</p>
        <button class="primary" onclick={() => stats && run(() => ok(api.putStatsCfg(stats!)), "Statistics saved")}>Save</button>
      {/if}
    </div>

    <!-- Server -->
    <div class="card" style="grid-column:1/-1">
      <h3 style="margin-top:0">Server <span class="muted" style="font-size:0.8rem">(changes to binds need a restart)</span></h3>
      {#if server}
        <div class="grid cols-3">
          <div class="field">
            <label>DNS bind (comma-separated)</label>
            <input class="mono" value={server.dns_bind.join(", ")}
              onchange={(e) => server && (server.dns_bind = (e.target as HTMLInputElement).value.split(",").map((s) => s.trim()).filter(Boolean))} />
          </div>
          <div class="field"><label>HTTP bind</label><input class="mono" bind:value={server.http_bind} /></div>
          <div class="field"><label>Rate limit (qps/client, 0 = off)</label><input type="number" min="0" bind:value={server.ratelimit} /></div>
        </div>
        <button class="primary" onclick={() => server && run(() => ok(api.putServer(server!)), "Server settings saved (restart to apply binds)")}>Save</button>
      {/if}
    </div>
  </div>
{:else}
  <p class="muted">Loading…</p>
{/if}
