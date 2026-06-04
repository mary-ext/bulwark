<script lang="ts">
  import * as api from "../api/generated";
  import { ok } from "@oazapfts/runtime";
  import type { StatsResponse } from "../api/generated";
  import { isStatus } from "../lib/errors";
  import { toaster } from "../lib/toast.svelte";
  import { num, pct, duration } from "../lib/format";
  import Icon from "../components/Icon.svelte";
  import StatCard from "../components/StatCard.svelte";
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

  // Derived from the persisted stats counters, not the cache's in-memory
  // hit/miss atomics (which reset on restart). Filtering runs before the cache
  // lookup, so blocked/rewritten queries never reach it — the lookup count is
  // total minus those, and `cached` is the hit count.
  const cacheRate = $derived.by(() => {
    if (!stats) return 0;
    const lookups = stats.total - stats.blocked - stats.rewritten;
    return lookups > 0 ? stats.cached / lookups : 0;
  });
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
  <div class="grid cols-4">
    <StatCard label="Total queries" value={num(stats.total)} sub="{num(stats.errors)} errors" />
    <StatCard
      label="Blocked"
      value={num(stats.blocked)}
      sub="{pct(stats.block_rate)} of queries"
      tone="bad"
    />
    <StatCard
      label="Cache hit rate"
      value={pct(cacheRate)}
      sub="{num(stats.cache_size)} entries cached"
      tone="good"
    />
    <StatCard
      label="Avg processing"
      value={duration(stats.avg_processing_ms)}
      sub="{num(stats.rewritten)} rewritten"
    />
  </div>

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
</style>
