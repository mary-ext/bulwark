<script lang="ts">
  import * as api from "../api/generated";
  import { ok } from "@oazapfts/runtime";
  import type { UpstreamStatDto, UpstreamsConfig } from "../api/generated";
  import { isStatus, errMsg } from "../lib/errors";
  import { toaster } from "../lib/toast.svelte";
  import { duration, num, parseList } from "../lib/format";
  import Icon from "../components/Icon.svelte";
  import Field from "../components/Field.svelte";
  import ResponsiveTable from "../components/ResponsiveTable.svelte";

  type UpstreamsCfg = Required<UpstreamsConfig>;

  let stats = $state<UpstreamStatDto[]>([]);
  let cfg = $state<UpstreamsCfg | null>(null);

  let testing = $state<string | null>(null);
  let saving = $state(false);
  let loading = $state(false);

  async function loadStats() {
    loading = true;
    try {
      stats = await ok(api.getUpstreams());
    } catch (e) {
      if (!isStatus(e, 401)) toaster.show("Failed to load upstreams", true);
    } finally {
      loading = false;
    }
  }

  async function loadCfg() {
    try {
      const c = await ok(api.getConfig());
      cfg = (c.upstreams ?? null) as UpstreamsCfg | null;
    } catch (e) {
      if (!isStatus(e, 401)) toaster.show("Failed to load upstreams config", true);
    }
  }

  // Load once on mount — no background polling.
  $effect(() => {
    loadStats();
    loadCfg();
  });

  async function save() {
    if (!cfg) return;
    saving = true;
    try {
      await ok(api.putUpstreams(cfg));
      toaster.show("Upstreams saved");
      await Promise.all([loadCfg(), loadStats()]);
    } catch (e) {
      toaster.show(errMsg(e, "Save failed"), true);
    } finally {
      saving = false;
    }
  }

  async function testSpec(spec: string) {
    testing = spec;
    try {
      const r = await ok(api.testUpstream({ spec }));
      if (r.ok) toaster.show(`OK — ${duration(r.rtt_ms)}`);
      else toaster.show(`Failed: ${r.error}`, true);
    } finally {
      testing = null;
    }
  }
</script>

<div class="page-head">
  <h1 class="page-title">Upstreams</h1>
  <span class="spacer"></span>
  <button class="btn btn-sm" onclick={loadStats} disabled={loading}>
    <Icon name="refresh" size={15} /> Refresh
  </button>
</div>

<section class="card" style="padding:0;overflow:hidden">
  <ResponsiveTable items={stats} key={(s) => s.name}>
    {#snippet head()}
      <tr>
        <th></th><th>Name</th><th>Type</th>
        <th class="num">avg</th>
        <th class="num">queries</th><th class="num">fails</th><th></th>
      </tr>
    {/snippet}
    {#snippet row(s)}
      <tr class="hoverable">
        <td>
          <span
            class="dot"
            class:up={s.up}
            class:down={!s.up}
            title={s.last_error ? `down — ${s.last_error}` : s.up ? "up" : "down"}
          ></span>
        </td>
        <td class="mono up-name" title={s.last_error ?? s.spec}>{s.name}</td>
        <td><span class="tag">{s.kind.toUpperCase()}</span></td>
        <td class="num">{duration(s.avg_rtt_ms)}</td>
        <td class="num">{num(s.total_queries)}</td>
        <td class="num" class:bad={s.total_failures > 0}>{num(s.total_failures)}</td>
        <td style="text-align:right">
          <button class="btn btn-sm" onclick={() => testSpec(s.spec)} disabled={testing === s.spec}>
            {testing === s.spec ? "…" : "Test"}
          </button>
        </td>
      </tr>
    {/snippet}
    {#snippet card(s)}
      <div class="up-card">
        <div class="up-head">
          <span class="dot" class:up={s.up} class:down={!s.up}></span>
          <span class="mono up-name" title={s.spec}>{s.name}</span>
          <span class="tag">{s.kind.toUpperCase()}</span>
          <span class="spacer"></span>
          <button class="btn btn-sm" onclick={() => testSpec(s.spec)} disabled={testing === s.spec}>
            {testing === s.spec ? "…" : "Test"}
          </button>
        </div>
        {#if s.last_error}<div class="up-error" title={s.last_error}>{s.last_error}</div>{/if}
        <div class="up-metrics muted">
          <span>avg {duration(s.avg_rtt_ms)}</span>
          <span>{num(s.total_queries)} q</span>
          <span class:bad={s.total_failures > 0}>{num(s.total_failures)} fail</span>
        </div>
      </div>
    {/snippet}
    {#snippet empty()}No upstreams configured.{/snippet}
  </ResponsiveTable>
</section>

{#if cfg}
  <section class="card" style="margin-top:var(--sp-4)">
    <div class="card-title">Configured upstreams</div>
    <p class="muted hint">
      One upstream per line. Each query goes to the single fastest healthy upstream, failing over
      sequentially — never fanned out in parallel. Supports plain DNS, <code>tls://</code>,
      <code>https://…/dns-query</code>, and <code>quic://</code>. Lines starting with
      <code>#</code> are comments (preserved on save).
    </p>
    <textarea
      bind:value={cfg.servers}
      rows="8"
      class="mono"
      spellcheck="false"
      placeholder={"# Cloudflare\nhttps://cloudflare-dns.com/dns-query\n#tls://one.one.one.one"}
    ></textarea>

    <div class="grid cols-3" style="margin-top:var(--sp-4)">
      <Field label="Query timeout (s)" htmlFor="to">
        <input id="to" type="number" bind:value={cfg.timeout_secs} min="1" />
      </Field>
      <Field label="Probe interval (s)" htmlFor="pi">
        <input id="pi" type="number" bind:value={cfg.probe_interval_secs} min="0" />
      </Field>
      <Field label="Bootstrap servers" htmlFor="bs">
        <input
          id="bs"
          class="mono"
          value={cfg.bootstrap.join(", ")}
          onchange={(e) => cfg && (cfg.bootstrap = parseList((e.target as HTMLInputElement).value))}
        />
      </Field>
    </div>

    <div style="margin-top:var(--sp-4)">
      <button class="btn btn-primary" onclick={save} disabled={saving}>
        {saving ? "Saving…" : "Save settings"}
      </button>
    </div>
  </section>
{/if}

<style>
  .dot {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .dot.up {
    background: var(--good);
    box-shadow: 0 0 0 3px var(--good-bg);
  }
  .dot.down {
    background: var(--bad);
    box-shadow: 0 0 0 3px var(--bad-bg);
  }
  .up-name {
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-weight: 500;
  }
  .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  td.num {
    font-family: var(--font-mono);
  }
  td.bad,
  .up-metrics .bad {
    color: var(--bad-fg);
  }
  .hint {
    margin: 0 0 var(--sp-3);
    font-size: 0.82rem;
  }

  /* Mobile card */
  .up-card {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    padding: 0.8rem 0.85rem;
    border-bottom: 1px solid var(--border);
  }
  .up-head {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
  }
  .up-error {
    font-size: 0.78rem;
    color: var(--bad-fg);
    background: var(--bad-bg);
    border: 1px solid var(--bad-border);
    border-radius: var(--radius-sm);
    padding: 0.3rem 0.5rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .up-metrics {
    display: flex;
    flex-wrap: wrap;
    gap: 4px var(--sp-3);
    font-size: 0.8rem;
  }
</style>
