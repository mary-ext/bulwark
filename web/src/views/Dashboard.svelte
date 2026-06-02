<script lang="ts">
  import { api, type StatsSummary, type TopEntry } from "../lib/api";
  import { toaster } from "../lib/toast.svelte";
  import { num, pct, ms } from "../lib/format";
  import Chart from "../lib/Chart.svelte";
  import type { ChartConfiguration } from "chart.js/auto";

  let stats = $state<StatsSummary | null>(null);

  async function load() {
    try {
      stats = await api.getStats(10);
    } catch (e: any) {
      if (e.status !== 401) toaster.show("Failed to load stats", true);
    }
  }

  $effect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  });

  const cacheRate = $derived(
    stats && stats.cache_hits + stats.cache_misses > 0
      ? stats.cache_hits / (stats.cache_hits + stats.cache_misses)
      : 0,
  );

  function barConfig(entries: TopEntry[], color: string): ChartConfiguration {
    return {
      type: "bar",
      data: {
        labels: entries.map((e) => e.name),
        datasets: [{ data: entries.map((e) => e.count), backgroundColor: color, borderRadius: 4 }],
      },
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: { x: { grid: { display: false } }, y: { grid: { display: false } } },
      },
    };
  }

  const seriesConfig = $derived<ChartConfiguration>({
    type: "line",
    data: {
      labels: (stats?.series ?? []).map((p) =>
        new Date(p.hour * 3600_000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" }),
      ),
      datasets: [
        {
          label: "Total",
          data: (stats?.series ?? []).map((p) => p.total),
          borderColor: "#4f8cff",
          backgroundColor: "rgba(79,140,255,0.15)",
          fill: true,
          tension: 0.3,
        },
        {
          label: "Blocked",
          data: (stats?.series ?? []).map((p) => p.blocked),
          borderColor: "#f85149",
          backgroundColor: "rgba(248,81,73,0.12)",
          fill: true,
          tension: 0.3,
        },
        {
          label: "Cached",
          data: (stats?.series ?? []).map((p) => p.cached),
          borderColor: "#3fb950",
          backgroundColor: "rgba(63,185,80,0.10)",
          fill: true,
          tension: 0.3,
        },
      ],
    },
    options: {
      interaction: { mode: "index", intersect: false },
      scales: { x: { grid: { display: false } } },
    },
  });

  const qtypeConfig = $derived<ChartConfiguration>({
    type: "doughnut",
    data: {
      labels: (stats?.qtypes ?? []).map((e) => e.name),
      datasets: [
        {
          data: (stats?.qtypes ?? []).map((e) => e.count),
          backgroundColor: ["#4f8cff", "#3fb950", "#d29922", "#f85149", "#a371f7", "#56d4dd"],
        },
      ],
    },
    options: { plugins: { legend: { position: "right" } }, cutout: "60%" },
  });

  const latencyConfig = $derived<ChartConfiguration>({
    type: "bar",
    data: {
      labels: stats?.latency_buckets ?? [],
      datasets: [{ data: stats?.latency_hist ?? [], backgroundColor: "#56d4dd", borderRadius: 4 }],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: { x: { grid: { display: false } } },
    },
  });
</script>

<h1 class="page-title">Dashboard</h1>

{#if stats}
  <div class="grid cols-4">
    <div class="card stat">
      <div class="label">Total queries</div>
      <div class="value">{num(stats.total)}</div>
      <div class="sub">{num(stats.errors)} errors</div>
    </div>
    <div class="card stat">
      <div class="label">Blocked</div>
      <div class="value" style="color:var(--red)">{num(stats.blocked)}</div>
      <div class="sub">{pct(stats.block_rate)} of queries</div>
    </div>
    <div class="card stat">
      <div class="label">Cache hit rate</div>
      <div class="value" style="color:var(--green)">{pct(cacheRate)}</div>
      <div class="sub">{num(stats.cache_size)} entries cached</div>
    </div>
    <div class="card stat">
      <div class="label">Avg processing</div>
      <div class="value">{ms(stats.avg_processing_ms)}</div>
      <div class="sub">{num(stats.rewritten)} rewritten</div>
    </div>
  </div>

  <div class="grid cols-1" style="margin-top:1rem">
    <div class="card">
      <h3 style="margin-top:0">Queries over time</h3>
      <div class="chart-box">
        <Chart config={seriesConfig} />
      </div>
    </div>
  </div>

  <div class="grid cols-2" style="margin-top:1rem">
    <div class="card">
      <h3 style="margin-top:0">Top blocked domains</h3>
      <div class="chart-box">
        {#if stats.top_blocked_domains.length}
          <Chart config={barConfig(stats.top_blocked_domains, "#f85149")} />
        {:else}
          <p class="muted">Nothing blocked yet.</p>
        {/if}
      </div>
    </div>
    <div class="card">
      <h3 style="margin-top:0">Top queried domains</h3>
      <div class="chart-box">
        <Chart config={barConfig(stats.top_domains, "#4f8cff")} />
      </div>
    </div>
  </div>

  <div class="grid cols-3" style="margin-top:1rem">
    <div class="card">
      <h3 style="margin-top:0">Top clients</h3>
      <div class="chart-box">
        <Chart config={barConfig(stats.top_clients, "#3fb950")} />
      </div>
    </div>
    <div class="card">
      <h3 style="margin-top:0">Query types</h3>
      <div class="chart-box">
        <Chart config={qtypeConfig} />
      </div>
    </div>
    <div class="card">
      <h3 style="margin-top:0">Processing latency</h3>
      <div class="chart-box">
        <Chart config={latencyConfig} />
      </div>
    </div>
  </div>
{:else}
  <p class="muted">Loading…</p>
{/if}
