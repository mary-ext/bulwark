<script lang="ts">
  import * as api from "../api/generated";
  import { ok } from "@oazapfts/runtime";
  import type {
    UpstreamStatDto,
    UpstreamsConfig,
    LatencyPercentilesDto,
  } from "../api/generated";
  import { isStatus, errMsg } from "../lib/errors";
  import { toaster } from "../lib/toast.svelte";
  import { ms, num } from "../lib/format";
  import Chart from "../lib/Chart.svelte";
  import type { ChartConfiguration } from "chart.js/auto";

  // The server always returns fully-populated config; treat it as required here.
  type UpstreamsCfg = Required<UpstreamsConfig>;

  let stats = $state<UpstreamStatDto[]>([]);
  let pct = $state<Record<string, LatencyPercentilesDto>>({});
  let cfg = $state<UpstreamsCfg | null>(null);

  let testing = $state(false);
  let saving = $state(false);

  async function loadStats() {
    try {
      const [up, summary] = await Promise.all([ok(api.getUpstreams()), ok(api.getStats())]);
      stats = up;
      pct = summary.upstream_latency_pct ?? {};
    } catch (e) {
      if (!isStatus(e, 401)) toaster.show("Failed to load upstreams", true);
    }
  }

  async function loadCfg() {
    const c = await ok(api.getConfig());
    cfg = (c.upstreams ?? null) as UpstreamsCfg | null;
  }

  $effect(() => {
    loadStats();
    loadCfg();
    const t = setInterval(loadStats, 5000);
    return () => clearInterval(t);
  });

  async function save() {
    if (!cfg) return;
    saving = true;
    try {
      await ok(api.putUpstreams(cfg));
      toaster.show("Upstreams saved");
      // Reflect the server-normalized text (trimmed lines, collapsed blanks)
      // back into the editor.
      await Promise.all([loadCfg(), loadStats()]);
    } catch (e) {
      toaster.show(errMsg(e, "Save failed"), true);
    } finally {
      saving = false;
    }
  }

  async function testSpec(spec: string) {
    testing = true;
    try {
      const r = await ok(api.testUpstream({ spec }));
      if (r.ok) toaster.show(`OK — ${r.rtt_ms?.toFixed(1)} ms`);
      else toaster.show(`Failed: ${r.error}`, true);
    } finally {
      testing = false;
    }
  }

  const rttConfig = $derived<ChartConfiguration>({
    type: "bar",
    data: {
      labels: stats.map((s) => s.name),
      datasets: [
        {
          label: "Avg RTT (ms)",
          data: stats.map((s) => s.avg_rtt_ms ?? 0),
          backgroundColor: stats.map((s) => (s.up ? "#4f8cff" : "#f85149")),
          borderRadius: 4,
        },
      ],
    },
    options: { plugins: { legend: { display: false } }, scales: { x: { grid: { display: false } } } },
  });
</script>

<h1 class="page-title">Upstreams</h1>

<div class="card">
  <h3 style="margin-top:0">Status & latency</h3>
  <table>
    <thead>
      <tr><th>Name</th><th>Type</th><th>Status</th><th>Avg RTT</th><th>Last</th><th>p50</th><th>p90</th><th>p99</th><th>Queries</th><th>Fails</th><th></th></tr>
    </thead>
    <tbody>
      {#each stats as s}
        <tr>
          <td class="mono" title={s.spec}>{s.name}</td>
          <td><span class="tag">{s.kind.toUpperCase()}</span></td>
          <td><span class="badge {s.up ? 'up' : 'down'}">{s.up ? "up" : "down"}</span></td>
          <td>{ms(s.avg_rtt_ms)}</td>
          <td class="muted">{ms(s.last_rtt_ms)}</td>
          <td class="muted">{ms(pct[s.name]?.p50)}</td>
          <td class="muted">{ms(pct[s.name]?.p90)}</td>
          <td class="muted">{ms(pct[s.name]?.p99)}</td>
          <td>{num(s.total_queries)}</td>
          <td class="muted">{num(s.total_failures)}</td>
          <td style="text-align:right"><button onclick={() => testSpec(s.spec)} disabled={testing}>Test</button></td>
        </tr>
      {/each}
      {#if stats.length === 0}
        <tr><td colspan="11" class="muted" style="text-align:center;padding:1.5rem">No upstreams configured.</td></tr>
      {/if}
    </tbody>
  </table>
  {#if stats.length}
    <div class="chart-box" style="height:200px;margin-top:1rem"><Chart config={rttConfig} /></div>
  {/if}
</div>

{#if cfg}
  <div class="card" style="margin-top:1rem">
    <h3 style="margin-top:0">Configured upstreams</h3>
    <p class="muted" style="margin-top:0">
      One upstream per line. Each query goes to the single fastest healthy
      upstream, failing over sequentially — never fanned out in parallel.
      Supports plain DNS, <code>tls://</code>, <code>https://…/dns-query</code>,
      and <code>quic://</code>. Lines starting with <code>#</code> are comments
      (preserved on save) — handy for labelling or disabling an entry.
    </p>
    <textarea bind:value={cfg.servers} rows="8" class="mono" spellcheck="false"
      placeholder={"# Cloudflare\nhttps://cloudflare-dns.com/dns-query\n#tls://one.one.one.one"}></textarea>

    <div class="grid cols-3" style="margin-top:1rem">
      <div class="field">
        <label for="to">Query timeout (s)</label>
        <input id="to" type="number" bind:value={cfg.timeout_secs} min="1" />
      </div>
      <div class="field">
        <label for="pi">Probe interval (s)</label>
        <input id="pi" type="number" bind:value={cfg.probe_interval_secs} min="0" />
      </div>
      <div class="field">
        <label for="bs">Bootstrap servers</label>
        <input id="bs" class="mono" value={cfg.bootstrap.join(", ")}
          onchange={(e) => cfg && (cfg.bootstrap = (e.target as HTMLInputElement).value.split(",").map((s) => s.trim()).filter(Boolean))} />
      </div>
    </div>

    <button class="primary" onclick={save} disabled={saving}>{saving ? "Saving…" : "Save settings"}</button>
  </div>
{/if}
