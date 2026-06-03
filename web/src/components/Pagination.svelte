<script lang="ts">
  import Icon from "./Icon.svelte";

  let {
    offset,
    limit,
    total,
    onChange,
  }: {
    offset: number;
    limit: number;
    total: number;
    onChange: (offset: number) => void;
  } = $props();
</script>

<div class="pagination">
  <button
    class="btn btn-sm"
    disabled={offset === 0}
    onclick={() => onChange(Math.max(0, offset - limit))}
  >
    <Icon name="chevronRight" size={14} class="flip" /> Newer
  </button>
  <span class="range">
    {total === 0 ? 0 : offset + 1}–{Math.min(offset + limit, total)} of {total.toLocaleString()}
  </span>
  <button
    class="btn btn-sm"
    disabled={offset + limit >= total}
    onclick={() => onChange(offset + limit)}
  >
    Older <Icon name="chevronRight" size={14} />
  </button>
</div>

<style>
  .pagination {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: var(--sp-3);
    margin-top: var(--sp-4);
  }
  .range {
    color: var(--text-dim);
    font-size: 0.8rem;
    font-family: var(--font-mono);
  }
  .pagination :global(.flip) {
    transform: rotate(180deg);
  }
</style>
