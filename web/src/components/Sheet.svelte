<script lang="ts">
  import type { Snippet } from "svelte";
  import { Dialog } from "bits-ui";

  let {
    open = $bindable(false),
    title,
    description,
    variant = "sheet",
    children,
  }: {
    open?: boolean;
    title?: string;
    description?: string;
    variant?: "sheet" | "dialog";
    children: Snippet;
  } = $props();
</script>

<Dialog.Root bind:open>
  <Dialog.Portal>
    <Dialog.Overlay class="bw-overlay" />
    <Dialog.Content class={variant === "sheet" ? "bw-sheet" : "bw-dialog"}>
      {#if title}<Dialog.Title class="bw-dialog-title">{title}</Dialog.Title>{/if}
      {#if description}<Dialog.Description class="bw-dialog-desc">{description}</Dialog.Description>{/if}
      {@render children()}
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
