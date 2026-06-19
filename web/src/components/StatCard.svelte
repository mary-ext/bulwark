<script lang="ts">
  import type { Snippet } from "svelte";

  let {
    label,
    value,
    sub,
    sub2,
    tone = "default",
    spark,
  }: {
    label: string;
    value: string | number;
    sub?: string;
    /** Optional second sub line rendered below {sub}. */
    sub2?: string;
    tone?: "default" | "good" | "bad" | "accent";
    /** Optional trend visual rendered flush to the bottom of the card. */
    spark?: Snippet;
  } = $props();
</script>

<div class="stat card" class:has-spark={spark}>
  <div class="stat-label">{label}</div>
  <div class="stat-value {tone}">{value}</div>
  {#if sub}<div class="stat-sub">{sub}</div>{/if}
  {#if sub2}<div class="stat-sub">{sub2}</div>{/if}
  {#if spark}<div class="stat-spark">{@render spark()}</div>{/if}
</div>

<style>
  .stat {
    padding: var(--sp-4) var(--sp-5);
  }
  /* Reserve room so the bottom-bled sparkline never overlaps the text. */
  .stat.has-spark {
    display: flex;
    flex-direction: column;
    padding-bottom: 0;
  }
  .stat-spark {
    /* Bleed to the card's left/right edges and sit flush on the bottom. */
    margin: var(--sp-3) calc(var(--sp-5) * -1) 0;
  }
  .stat-label {
    color: var(--text-dim);
    font-size: 0.8rem;
    font-weight: 500;
  }
  .stat-value {
    font-size: 1.9rem;
    font-weight: 680;
    letter-spacing: -0.025em;
    line-height: 1.15;
    margin-top: var(--sp-1);
  }
  .stat-value.good {
    color: var(--good);
  }
  .stat-value.bad {
    color: var(--bad);
  }
  .stat-value.accent {
    color: var(--accent);
  }
  .stat-sub {
    color: var(--text-dim);
    font-size: 0.78rem;
    margin-top: 2px;
  }
</style>
