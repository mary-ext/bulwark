<script lang="ts">
  import { Dialog } from "bits-ui";

  let {
    open = $bindable(false),
    title = "Are you sure?",
    message = "",
    confirmLabel = "Confirm",
    danger = false,
    onConfirm,
  }: {
    open?: boolean;
    title?: string;
    message?: string;
    confirmLabel?: string;
    danger?: boolean;
    onConfirm: () => void;
  } = $props();

  function doConfirm() {
    open = false;
    onConfirm();
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Portal>
    <Dialog.Overlay class="bw-overlay" />
    <Dialog.Content class="bw-dialog">
      <Dialog.Title class="bw-dialog-title">{title}</Dialog.Title>
      {#if message}<Dialog.Description class="bw-dialog-desc">{message}</Dialog.Description>{/if}
      <div class="confirm-actions">
        <Dialog.Close class="btn">Cancel</Dialog.Close>
        <button class="btn {danger ? 'btn-danger' : 'btn-primary'}" onclick={doConfirm}>
          {confirmLabel}
        </button>
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>

<style>
  .confirm-actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--sp-2);
    margin-top: var(--sp-5);
  }
</style>
