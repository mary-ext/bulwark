<script lang="ts">
  let {
    label,
    value,
    sub,
    tone = "default",
  }: {
    label: string;
    value: string | number;
    sub?: string;
    tone?: "default" | "good" | "bad" | "accent";
  } = $props();
</script>

<div class="stat card">
  <div class="stat-label">{label}</div>
  <div class="stat-value {tone}">{value}</div>
  {#if sub}<div class="stat-sub">{sub}</div>{/if}
</div>

<style>
  .stat {
    padding: var(--sp-4) var(--sp-5);
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
