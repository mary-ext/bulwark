<script lang="ts">
  import { Select } from "bits-ui";
  import Icon from "./Icon.svelte";

  type Item = { value: string; label: string };

  let {
    value = $bindable(""),
    items,
    id,
    placeholder = "Select…",
  }: { value?: string; items: Item[]; id?: string; placeholder?: string } = $props();

  const selectedLabel = $derived(items.find((i) => i.value === value)?.label ?? placeholder);
</script>

<Select.Root type="single" bind:value {items}>
  <Select.Trigger class="bw-select-trigger" {id}>
    <span class="truncate">{selectedLabel}</span>
    <Icon name="chevronDown" size={16} />
  </Select.Trigger>
  <Select.Portal>
    <Select.Content class="bw-select-content" sideOffset={6}>
      {#each items as item (item.value)}
        <Select.Item class="bw-select-item" value={item.value} label={item.label}>
          {item.label}
        </Select.Item>
      {/each}
    </Select.Content>
  </Select.Portal>
</Select.Root>
