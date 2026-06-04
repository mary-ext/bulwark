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
  import { parseList } from "../lib/format";
  import { toaster } from "../lib/toast.svelte";
  import Field from "../components/Field.svelte";
  import Select from "../components/Select.svelte";
  import SwitchRow from "../components/SwitchRow.svelte";
  import ConfirmDialog from "../components/ConfirmDialog.svelte";

  let loaded = $state(false);
  let confirmClearLog = $state(false);
  let confirmResetStats = $state(false);

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

  function clearLog() {
    run(() => ok(api.clearQuerylog()), "Query log cleared");
  }

  function resetStats() {
    run(() => ok(api.resetStats()), "Statistics cleared");
  }

  const blockingModes: { value: BlockingMode; label: string }[] = [
    { value: "nx_domain", label: "NXDOMAIN" },
    { value: "null_ip", label: "Null IP (0.0.0.0 / ::)" },
    { value: "custom_ip", label: "Custom IP" },
    { value: "refused", label: "REFUSED" },
    { value: "no_data", label: "NODATA" },
  ];
</script>

<div class="page-head">
  <h1 class="page-title">Settings</h1>
</div>

{#if loaded}
  <div class="grid cols-2">
    <!-- Filtering -->
    <section class="card">
      <div class="card-title">Filtering</div>
      <div class="stack">
        <SwitchRow bind:checked={filtering.enabled} label="Enable filtering" />
        <Field label="Blocking mode" htmlFor="bm">
          <Select id="bm" bind:value={filtering.blocking_mode} items={blockingModes} />
        </Field>
        {#if filtering.blocking_mode === "custom_ip"}
          <div class="grid cols-2">
            <Field label="Block IPv4" htmlFor="f-block4">
              <input id="f-block4" class="mono" bind:value={filtering.custom_block_ipv4} />
            </Field>
            <Field label="Block IPv6" htmlFor="f-block6">
              <input id="f-block6" class="mono" bind:value={filtering.custom_block_ipv6} />
            </Field>
          </div>
        {/if}
        <Field label="Blocked response TTL (s)" htmlFor="bt">
          <input id="bt" type="number" min="0" bind:value={filtering.blocked_ttl_secs} />
        </Field>
        <div>
          <button
            class="btn btn-primary"
            onclick={() => run(() => ok(api.putFiltering(filtering)), "Filtering saved")}
          >
            Save
          </button>
        </div>
      </div>
    </section>

    <!-- Cache -->
    {#if cache}
      <section class="card">
        <div class="card-title">Cache</div>
        <div class="stack">
          <SwitchRow bind:checked={cache.enabled} label="Enable cache" />
          <SwitchRow
            checked={cache.optimistic_max_age_secs > 0}
            label="Optimistic caching"
            hint="Serve stale answers while refreshing in the background."
            onCheckedChange={(v) => cache && (cache.optimistic_max_age_secs = v ? 86400 : 0)}
          />
          {#if cache.optimistic_max_age_secs > 0}
            <Field
              label="Max serve-stale age (s past expiry)"
              htmlFor="sa"
              hint="Bounds how stale an answer can be; turn the toggle off to disable serve-stale."
            >
              <input id="sa" type="number" min="1" bind:value={cache.optimistic_max_age_secs} />
            </Field>
          {/if}
          <Field label="Max entries" htmlFor="cs">
            <input id="cs" type="number" min="1" bind:value={cache.size} />
          </Field>
          <div class="grid cols-2">
            <Field label="Min TTL (s)" htmlFor="c-minttl">
              <input id="c-minttl" type="number" min="0" bind:value={cache.min_ttl_secs} />
            </Field>
            <Field label="Max TTL (s, 0 = none)" htmlFor="c-maxttl">
              <input id="c-maxttl" type="number" min="0" bind:value={cache.max_ttl_secs} />
            </Field>
          </div>
          <div>
            <button
              class="btn btn-primary"
              onclick={() => cache && run(() => ok(api.putCache(cache!)), "Cache saved")}
            >
              Save
            </button>
          </div>
        </div>
      </section>
    {/if}

    <!-- Query log -->
    {#if querylog}
      <section class="card">
        <div class="card-title">Query log</div>
        <div class="stack">
          <SwitchRow bind:checked={querylog.enabled} label="Enable query log" />
          <SwitchRow bind:checked={querylog.persist} label="Persist to disk" />
          <SwitchRow bind:checked={querylog.anonymize} label="Anonymize client IPs" />
          <Field
            label="Retention (days)"
            htmlFor="q-retention"
            hint="Entries older than this are pruned. 0 keeps them indefinitely."
          >
            <input id="q-retention" type="number" min="0" bind:value={querylog.retention_days} />
          </Field>
          <div class="btn-row">
            <button
              class="btn btn-primary"
              onclick={() => querylog && run(() => ok(api.putQuerylog(querylog!)), "Query log saved")}
            >
              Save
            </button>
            <button class="btn btn-danger" onclick={() => (confirmClearLog = true)}>
              Clear log
            </button>
          </div>
        </div>
      </section>
    {/if}

    <!-- Stats -->
    {#if stats}
      <section class="card">
        <div class="card-title">Statistics</div>
        <div class="stack">
          <SwitchRow bind:checked={stats.enabled} label="Enable statistics" />
          <SwitchRow bind:checked={stats.persist} label="Persist to disk" />
          <Field
            label="Retention (days)"
            htmlFor="s-retention"
            hint="Query log and statistics retention are independent."
          >
            <input id="s-retention" type="number" min="1" bind:value={stats.retention_days} />
          </Field>
          <div class="btn-row">
            <button
              class="btn btn-primary"
              onclick={() => stats && run(() => ok(api.putStatsCfg(stats!)), "Statistics saved")}
            >
              Save
            </button>
            <button class="btn btn-danger" onclick={() => (confirmResetStats = true)}>
              Clear statistics
            </button>
          </div>
        </div>
      </section>
    {/if}

    <!-- Server -->
    {#if server}
      <section class="card" style="grid-column:1/-1">
        <div class="card-title">
          Server
          <span class="muted" style="font-weight:400;font-size:0.8rem"
            >(changes to binds need a restart)</span
          >
        </div>
        <div class="grid cols-3">
          <Field label="DNS bind (comma-separated)" htmlFor="sv-dns">
            <input
              id="sv-dns"
              class="mono"
              value={server.dns_bind.join(", ")}
              onchange={(e) =>
                server && (server.dns_bind = parseList((e.target as HTMLInputElement).value))}
            />
          </Field>
          <Field label="HTTP bind" htmlFor="sv-http">
            <input id="sv-http" class="mono" bind:value={server.http_bind} />
          </Field>
          <Field label="Rate limit (qps/client, 0 = off)" htmlFor="sv-ratelimit">
            <input id="sv-ratelimit" type="number" min="0" bind:value={server.ratelimit} />
          </Field>
        </div>
        <div style="margin-top:var(--sp-4)">
          <button
            class="btn btn-primary"
            onclick={() =>
              server &&
              run(() => ok(api.putServer(server!)), "Server settings saved (restart to apply binds)")}
          >
            Save
          </button>
        </div>
      </section>
    {/if}
  </div>
{:else}
  <p class="muted">Loading…</p>
{/if}

<ConfirmDialog
  bind:open={confirmClearLog}
  title="Clear query log?"
  message="This empties the in-memory query log. Persisted history on disk is not affected."
  confirmLabel="Clear log"
  danger
  onConfirm={clearLog}
/>

<ConfirmDialog
  bind:open={confirmResetStats}
  title="Clear statistics?"
  message="This resets all collected statistics counters and top-domain tallies. This cannot be undone."
  confirmLabel="Clear statistics"
  danger
  onConfirm={resetStats}
/>

<style>
  .btn-row {
    display: flex;
    gap: var(--sp-3);
  }
</style>
