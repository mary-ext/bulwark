<script lang="ts">
  import * as api from "../api/generated";
  import { ok } from "@oazapfts/runtime";
  import type { StatsResponse } from "../api/generated";
  import { isStatus } from "../lib/errors";
  import { toaster } from "../lib/toast.svelte";
  import { num, pct, duration } from "../lib/format";
  import Icon from "../components/Icon.svelte";
  import StatCard from "../components/StatCard.svelte";
  import Sparkline from "../components/Sparkline.svelte";
  import RankedList from "../components/RankedList.svelte";
  import UpstreamRanked from "../components/UpstreamRanked.svelte";

  let stats = $state<StatsResponse | null>(null);
  let loading = $state(false);

  async function load() {
    loading = true;
    try {
      stats = await ok(api.getStats({ top: 10 }));
    } catch (e) {
      if (!isStatus(e, 401)) toaster.show("Failed to load stats", true);
    } finally {
      loading = false;
    }
  }

  // Load once on mount — no background polling.
  $effect(() => {
    load();
  });

  // Optimistic-caching view, derived from the cache's lifetime counters (seeded
  // from stats.json on start, so they persist across restarts). The client-facing
  // hit rate alone is misleading: a stale serve
  // is a hit *and* a background upstream refresh, so the rate at which we
  // actually skip upstream is lower. These counters let us show both, plus the
  // true upstream-call volume the hit rate hides.
  const cache = $derived.by(() => {
    if (!stats) return null;
    const hits = stats.cache_hits;
    const misses = stats.cache_misses;
    const lookups = hits + misses;
    const stale = stats.cache_stale_hits;
    const fresh = Math.max(0, hits - stale);
    const refreshes = stats.cache_refreshes;
    return {
      lookups,
      hits,
      misses,
      stale,
      fresh,
      refreshes,
      // What the client experiences vs. what actually avoided upstream.
      hitRate: lookups > 0 ? hits / lookups : 0,
      upstreamAvoided: lookups > 0 ? fresh / lookups : 0,
      // Composition of the hit count, for the fresh/stale bar.
      freshPct: hits > 0 ? (fresh / hits) * 100 : 0,
      stalePct: hits > 0 ? (stale / hits) * 100 : 0,
      // True upstream traffic: foreground misses + background refreshes.
      upstreamCalls: misses + refreshes,
      refreshFailRate: refreshes > 0 ? stats.cache_refresh_failures / refreshes : 0,
    };
  });

  // Hourly trend, oldest → newest, for the stat-card sparklines.
  const series = $derived([...(stats?.series ?? [])].sort((a, b) => a.hour - b.hour));
  const sparkLabels = $derived(
    series.map((p) =>
      new Date(p.hour * 3_600_000).toLocaleString(undefined, {
        weekday: "short",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      }),
    ),
  );
  const totalTrend = $derived(series.map((p) => p.total));
  const blockedTrend = $derived(series.map((p) => p.blocked));
</script>

<div class="page-head">
  <h1 class="page-title">Dashboard</h1>
  <span class="spacer"></span>
  <button class="btn btn-sm" onclick={load} disabled={loading}>
    <Icon name="refresh" size={15} />
    Refresh
  </button>
</div>

{#if stats}
  {#snippet totalSpark()}
    <Sparkline
      values={totalTrend}
      labels={sparkLabels}
      color="var(--accent)"
      ariaLabel="Hourly query volume"
    />
  {/snippet}
  {#snippet blockedSpark()}
    <Sparkline
      values={blockedTrend}
      labels={sparkLabels}
      color="var(--bad)"
      ariaLabel="Hourly blocked volume"
    />
  {/snippet}
  <div class="grid cols-4">
    <StatCard
      label="Total queries"
      value={num(stats.total)}
      sub="{num(stats.errors)} errors"
      spark={totalSpark}
    />
    <StatCard
      label="Blocked"
      value={num(stats.blocked)}
      sub="{pct(stats.block_rate)} of queries"
      tone="bad"
      spark={blockedSpark}
    />
    <StatCard
      label="Cache hit rate"
      value={pct(cache?.hitRate ?? 0)}
      sub="{pct(cache?.upstreamAvoided ?? 0)} skipped upstream"
      tone="good"
    />
    <StatCard
      label="Processing time (p95)"
      value={duration(stats.p95_processing_ms)}
      sub="{num(stats.rewritten)} rewritten"
    />
  </div>

  {#if cache}
    <div class="card oc" style="margin-top:var(--sp-4)">
      <div class="card-title">Optimistic cache</div>
      <p class="oc-note muted">How much the hit rate actually saves upstream</p>
      <div class="oc-grid">
        <div class="oc-rates">
          <div class="oc-rate">
            <div class="oc-val good">{pct(cache.hitRate)}</div>
            <div class="oc-lab">Served from cache</div>
          </div>
          <div class="oc-rate">
            <div class="oc-val accent">{pct(cache.upstreamAvoided)}</div>
            <div class="oc-lab">Skipped upstream</div>
          </div>
        </div>

        <div class="oc-split">
          <div
            class="oc-bar"
            role="img"
            aria-label="{num(cache.fresh)} fresh hits, {num(cache.stale)} served stale"
          >
            <span class="oc-seg fresh" style="width:{cache.freshPct}%"></span>
            <span class="oc-seg stale" style="width:{cache.stalePct}%"></span>
          </div>
          <div class="oc-legend">
            <span><i class="oc-dot fresh"></i>{num(cache.fresh)} fresh</span>
            <span><i class="oc-dot stale"></i>{num(cache.stale)} stale → refreshed</span>
          </div>
        </div>

        <dl class="oc-rows">
          <div class="oc-row">
            <dt>Upstream calls</dt>
            <dd>{num(cache.upstreamCalls)}</dd>
          </div>
          <div class="oc-row sub">
            <dt>Cache misses</dt>
            <dd>{num(cache.misses)}</dd>
          </div>
          <div class="oc-row sub">
            <dt>Background refreshes</dt>
            <dd>{num(cache.refreshes)}</dd>
          </div>
          <div class="oc-row" class:warn={cache.refreshFailRate > 0.05}>
            <dt>Refresh failures</dt>
            <dd>{pct(cache.refreshFailRate)}</dd>
          </div>
          <div class="oc-row">
            <dt>Cached entries</dt>
            <dd>{num(stats.cache_size)}</dd>
          </div>
        </dl>
      </div>
    </div>
  {/if}

  <div class="grid cols-2" style="margin-top:var(--sp-4)">
    <div class="card">
      <div class="card-title">Top resolved domains</div>
      <RankedList items={stats.top_resolved_domains} total={stats.total} color="var(--chart-2)" />
    </div>
    <div class="card">
      <div class="card-title">Top blocked domains</div>
      <RankedList
        items={stats.top_blocked_domains}
        total={stats.blocked}
        color="var(--chart-5)"
        empty="Nothing blocked yet."
      />
    </div>
    <div class="card">
      <div class="card-title">Top clients</div>
      <RankedList items={stats.top_clients} total={stats.total} color="var(--chart-3)" />
    </div>
    <div class="card">
      <div class="card-title">Top upstreams</div>
      <p class="up-hint muted">Sorted by median latency · bar shows query share</p>
      <UpstreamRanked
        upstreams={stats.top_upstreams}
        pct={stats.upstream_latency_pct}
        color="var(--chart-4)"
      />
    </div>
  </div>
{:else}
  <p class="muted">Loading…</p>
{/if}

<style>
  .up-hint {
    margin: -2px 0 var(--sp-3);
    font-size: 0.74rem;
  }

  .oc-note {
    margin: -2px 0 var(--sp-4);
    font-size: 0.74rem;
  }
  .oc-grid {
    display: grid;
    grid-template-columns: auto 1fr auto;
    gap: var(--sp-6);
    align-items: center;
  }
  @media (max-width: 760px) {
    .oc-grid {
      grid-template-columns: 1fr;
      gap: var(--sp-4);
    }
  }
  .oc-rates {
    display: flex;
    gap: var(--sp-5);
  }
  .oc-val {
    font-size: 1.6rem;
    font-weight: 650;
    line-height: 1.1;
    font-variant-numeric: tabular-nums;
  }
  .oc-val.good {
    color: var(--good);
  }
  .oc-val.accent {
    color: var(--accent);
  }
  .oc-lab {
    margin-top: 3px;
    font-size: 0.72rem;
    color: var(--text-dim);
  }
  .oc-split {
    min-width: 0;
  }
  .oc-bar {
    display: flex;
    height: 10px;
    border-radius: var(--radius-full);
    overflow: hidden;
    background: var(--chart-track);
  }
  .oc-seg.fresh {
    background: var(--good);
  }
  .oc-seg.stale {
    background: var(--warn);
  }
  .oc-legend {
    display: flex;
    flex-wrap: wrap;
    gap: var(--sp-2) var(--sp-4);
    margin-top: var(--sp-2);
    font-size: 0.74rem;
    color: var(--text-dim);
  }
  .oc-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 2px;
    margin-right: 5px;
    vertical-align: middle;
  }
  .oc-dot.fresh {
    background: var(--good);
  }
  .oc-dot.stale {
    background: var(--warn);
  }
  .oc-rows {
    display: grid;
    gap: 4px;
    min-width: 190px;
    margin: 0;
  }
  .oc-row {
    display: flex;
    justify-content: space-between;
    gap: var(--sp-4);
    font-size: 0.82rem;
  }
  .oc-row dt,
  .oc-row dd {
    margin: 0;
  }
  .oc-row dd {
    font-variant-numeric: tabular-nums;
  }
  .oc-row.sub {
    padding-left: var(--sp-3);
    font-size: 0.78rem;
    color: var(--text-dim);
  }
  .oc-row.warn dd {
    color: var(--bad);
    font-weight: 600;
  }
</style>
