<script lang="ts">
  import Switch from "./Switch.svelte";

  let {
    checked = $bindable(false),
    label,
    hint,
    disabled = false,
    onCheckedChange,
  }: {
    checked?: boolean;
    label: string;
    hint?: string;
    disabled?: boolean;
    onCheckedChange?: (v: boolean) => void;
  } = $props();

  const uid = $props.id();
</script>

<div class="switch-row">
  <div class="text">
    <label for={uid}>{label}</label>
    {#if hint}<p class="hint">{hint}</p>{/if}
  </div>
  <Switch bind:checked {disabled} id={uid} {onCheckedChange} />
</div>

<style>
  .switch-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-4);
    padding: var(--sp-1) 0;
  }
  .text label {
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
  }
  .hint {
    font-size: 0.78rem;
    color: var(--text-faint);
    margin-top: 2px;
    max-width: 46ch;
  }
</style>
