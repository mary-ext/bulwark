<script lang="ts">
  import { Switch } from "bits-ui";

  let {
    checked = $bindable(false),
    disabled = false,
    id,
    onCheckedChange,
  }: {
    checked?: boolean;
    disabled?: boolean;
    id?: string;
    onCheckedChange?: (v: boolean) => void;
  } = $props();
</script>

<Switch.Root bind:checked {disabled} {id} {onCheckedChange} class="bw-switch">
  <Switch.Thumb class="bw-switch-thumb" />
</Switch.Root>
