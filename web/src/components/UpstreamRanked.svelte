<script lang="ts">
  import { num, duration, sharePcts } from "../lib/format";
  import type { TopEntryDto, LatencyPercentilesDto } from "../api/generated";

  let {
    upstreams,
    pct = {},
    color = "var(--chart-4)",
    empty = "No upstream traffic yet.",
    maxHeight = 264,
  }: {
    upstreams: TopEntryDto[];
    /** Per-upstream approximate latency percentiles, keyed by upstream name. */
    pct?: Record<string, LatencyPercentilesDto>;
    color?: string;
    empty?: string;
    /** Body scrolls past this height so long lists don't grow the card. */
    maxHeight?: number;
  } = $props();

  type Row = {
    name: string;
    count: number;
    p50: number | null;
    p90: number | null;
    p99: number | null;
  };

  // Join the query-count ranking with each upstream's median latency, then order
  // by lowest p50 first. Median (not mean) is the headline: it's robust to the
  // long latency tail, so a few slow responses don't make an otherwise-fast
  // upstream look bad. Upstreams that have served no queries have no meaningful
  // median, so they sort last regardless of count. The bar still encodes query
  // share, so volume and typical speed are both legible at a glance.
  const rows = $derived<Row[]>(
    upstreams
      .map((u) => {
        const p = pct[u.name];
        return {
          name: u.name,
          count: u.count,
          p50: p?.p50 ?? null,
          p90: p?.p90 ?? null,
          p99: p?.p99 ?? null,
        };
      })
      .sort((a, b) => (a.p50 ?? Infinity) - (b.p50 ?? Infinity)),
  );

  const max = $derived(Math.max(1, ...rows.map((r) => r.count)));
  // Whole-percent query shares that always sum to 100, avoiding the per-row
  // rounding drift that let the column read over 100%.
  const shares = $derived(sharePcts(rows.map((r) => r.count), rows.reduce((s, r) => s + r.count, 0)));

  const latTitle = (r: Row) => `p50 ${duration(r.p50)} · p90 ${duration(r.p90)} · p99 ${duration(r.p99)}`;
</script>

{#if rows.length}
  <ul class="ranked" style="max-height:{maxHeight}px">
    {#each rows as r, i (r.name)}
      <li class="rk-row">
        <span class="rk-name mono" title={r.name}>{r.name}</span>
        <div class="rk-value">
          <div class="rk-meta">
            <span class="rk-lat" title={latTitle(r)}>{duration(r.p50)}</span>
            <span class="rk-count">{num(r.count)} · {shares[i]}%</span>
          </div>
          <div class="rk-track">
            <div class="rk-bar" style="width:{(r.count / max) * 100}%;background:{color}"></div>
          </div>
        </div>
      </li>
    {/each}
  </ul>
{:else}
  <p class="muted">{empty}</p>
{/if}

<style>
  .ranked {
    list-style: none;
    margin: 0;
    padding: 0;
    overflow-y: auto;
  }
  .rk-row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(120px, 38%);
    align-items: center;
    gap: var(--sp-4);
    padding: 0.32rem 0;
  }
  .rk-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 0.83rem;
  }
  .rk-value {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .rk-meta {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: var(--sp-2);
  }
  .rk-lat {
    font-family: var(--font-mono);
    font-size: 0.8rem;
    font-weight: 500;
    font-variant-numeric: tabular-nums;
  }
  .rk-count {
    color: var(--text-faint);
    font-size: 0.72rem;
    font-variant-numeric: tabular-nums;
  }
  .rk-track {
    height: 4px;
    border-radius: var(--radius-full);
    background: var(--chart-track);
    overflow: hidden;
  }
  .rk-bar {
    height: 100%;
    border-radius: var(--radius-full);
    min-width: 2px;
    transition: width 0.3s ease;
  }
</style>
