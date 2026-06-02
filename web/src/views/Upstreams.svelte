<script lang="ts">
  import { api, type UpstreamStat, type UpstreamsCfg, type UpstreamCfg } from "../lib/api";
  import { toaster } from "../lib/toast.svelte";
  import { ms, num } from "../lib/format";
  import Chart from "../lib/Chart.svelte";
  import type { ChartConfiguration } from "chart.js/auto";

  let stats = $state<UpstreamStat[]>([]);
  let cfg = $state<UpstreamsCfg | null>(null);

  // Add form
  let newSpec = $state("");
  let newName = $state("");
  let testing = $state(false);
  let saving = $state(false);

  async function loadStats() {
    try {
      stats = await api.getUpstreams();
    } catch (e: any) {
      if (e.status !== 401) toaster.show("Failed to load upstreams", true);
    }
  }

  async function loadCfg() {
    const c = await api.getConfig();
    cfg = c.upstreams;
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
      await api.putUpstreams(cfg);
      toaster.show("Upstreams saved");
      await loadStats();
    } catch (e: any) {
      toaster.show(e.message ?? "Save failed", true);
    } finally {
      saving = false;
    }
  }

  async function addUpstream() {
    if (!cfg || !newSpec.trim()) return;
    cfg.servers.push({ spec: newSpec.trim(), name: newName.trim() || null, enabled: true } as UpstreamCfg);
    newSpec = "";
    newName = "";
    await save();
  }

  function removeUpstream(i: number) {
    if (!cfg) return;
    cfg.servers.splice(i, 1);
    save();
  }

  async function testSpec(spec: string) {
    testing = true;
    try {
      const r = await api.testUpstream(spec);
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
      <tr><th>Name</th><th>Type</th><th>Status</th><th>Avg RTT</th><th>Last</th><th>Queries</th><th>Fails</th><th></th></tr>
    </thead>
    <tbody>
      {#each stats as s}
        <tr>
          <td class="mono" title={s.spec}>{s.name}</td>
          <td><span class="tag">{s.kind.toUpperCase()}</span></td>
          <td><span class="badge {s.up ? 'up' : 'down'}">{s.up ? "up" : "down"}</span></td>
          <td>{ms(s.avg_rtt_ms)}</td>
          <td class="muted">{ms(s.last_rtt_ms)}</td>
          <td>{num(s.total_queries)}</td>
          <td class="muted">{num(s.total_failures)}</td>
          <td style="text-align:right"><button onclick={() => testSpec(s.spec)} disabled={testing}>Test</button></td>
        </tr>
      {/each}
      {#if stats.length === 0}
        <tr><td colspan="8" class="muted" style="text-align:center;padding:1.5rem">No upstreams configured.</td></tr>
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
      Each query goes to the single fastest healthy upstream, failing over
      sequentially — never fanned out in parallel. Supports plain DNS, <code>tls://</code>,
      <code>https://…/dns-query</code>, and <code>quic://</code>.
    </p>
    {#each cfg.servers as u, i}
      <div class="toolbar" style="margin-bottom:0.5rem">
        <input bind:value={u.spec} style="flex:1" class="mono" />
        <input bind:value={u.name} placeholder="name" style="max-width:160px" />
        <label class="switch"><input type="checkbox" bind:checked={u.enabled} /><span class="slider"></span></label>
        <button onclick={() => testSpec(u.spec)}>Test</button>
        <button class="danger" onclick={() => removeUpstream(i)}>✕</button>
      </div>
    {/each}

    <div class="toolbar">
      <input placeholder="1.1.1.1 or https://dns.google/dns-query" bind:value={newSpec} style="flex:1" class="mono" />
      <input placeholder="name (optional)" bind:value={newName} style="max-width:160px" />
      <button onclick={addUpstream}>Add</button>
    </div>

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
