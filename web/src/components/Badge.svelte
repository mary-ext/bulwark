<script lang="ts">
  import type { Snippet } from "svelte";

  let {
    tone = "neutral",
    children,
  }: {
    tone?: "good" | "bad" | "warn" | "info" | "neutral";
    children: Snippet;
  } = $props();
</script>

<span class="badge {tone}">{@render children()}</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.72rem;
    font-weight: 600;
    line-height: 1.4;
    padding: 0.1rem 0.5rem;
    border-radius: var(--radius-full);
    border: 1px solid transparent;
    white-space: nowrap;
  }
  .good {
    color: var(--good-fg);
    background: var(--good-bg);
    border-color: var(--good-border);
  }
  .bad {
    color: var(--bad-fg);
    background: var(--bad-bg);
    border-color: var(--bad-border);
  }
  .warn {
    color: var(--warn-fg);
    background: var(--warn-bg);
    border-color: var(--warn-border);
  }
  .info {
    color: var(--info-fg);
    background: var(--info-bg);
    border-color: var(--info-border);
  }
  .neutral {
    color: var(--text-dim);
    background: var(--bg-elev2);
    border-color: var(--border);
  }
</style>
