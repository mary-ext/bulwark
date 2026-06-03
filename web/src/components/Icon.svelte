<script lang="ts">
  import { icons, type IconName } from "../lib/icons";

  let {
    name,
    size = 18,
    strokeWidth = 2,
    class: cls = "",
  }: { name: IconName; size?: number; strokeWidth?: number; class?: string } = $props();
</script>

<svg
  class={cls}
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width={strokeWidth}
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
  style="display:block;flex-shrink:0">{@html icons[name]}</svg
>
