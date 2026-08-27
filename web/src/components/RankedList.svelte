<script lang="ts">
  import { num, sharePcts } from "../lib/format";

  type Entry = { name: string; count: number };

  let {
    items,
    color = "var(--accent)",
    total,
    empty = "No data yet.",
    maxHeight = 264,
  }: {
    items: Entry[];
    color?: string;
    /** Optional percentage denominator. */
    total?: number;
    empty?: string;
    /** Optional scrolling threshold. */
    maxHeight?: number;
  } = $props();

  const max = $derived(Math.max(1, ...items.map((i) => i.count)));
  const shares = $derived(sharePcts(items.map((i) => i.count), total ?? items.reduce((s, i) => s + i.count, 0)));
</script>

{#if items.length}
  <ul class="ranked" style="max-height:{maxHeight}px">
    {#each items as it, i (it.name)}
      <li class="rk-row">
        <span class="rk-name mono" title={it.name}>{it.name}</span>
        <div class="rk-value">
          <div class="rk-meta">
            <span class="rk-count">{num(it.count)}</span>
            <span class="rk-pct">{shares[i]}%</span>
          </div>
          <div class="rk-track">
            <div class="rk-bar" style="width:{(it.count / max) * 100}%;background:{color}"></div>
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
  .rk-count {
    font-family: var(--font-mono);
    font-size: 0.8rem;
    font-weight: 500;
  }
  .rk-pct {
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
