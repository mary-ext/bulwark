<script lang="ts">
  import type { Snippet } from "svelte";

  let {
    label,
    hint,
    htmlFor,
    children,
  }: { label?: string; hint?: string; htmlFor?: string; children: Snippet } = $props();
</script>

<div class="field">
  {#if label}<label class="field-label" for={htmlFor}>{label}</label>{/if}
  {@render children()}
  {#if hint}<span class="field-hint">{hint}</span>{/if}
</div>
