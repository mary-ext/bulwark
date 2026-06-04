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
    // `unknown` so callers can return anything (incl. a Promise or a
    // short-circuit like `cond && doThing()`); `await` handles both.
    onConfirm: () => unknown;
  } = $props();

  let busy = $state(false);

  async function doConfirm() {
    busy = true;
    try {
      // Await so an async action completes (and can fail) before we close. If it
      // throws, leave the dialog open — the handler surfaces the error itself.
      await onConfirm();
      open = false;
    } catch {
      /* keep open so the user can retry or cancel */
    } finally {
      busy = false;
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Portal>
    <Dialog.Overlay class="bw-overlay" />
    <Dialog.Content class="bw-dialog">
      <Dialog.Title class="bw-dialog-title">{title}</Dialog.Title>
      {#if message}<Dialog.Description class="bw-dialog-desc">{message}</Dialog.Description>{/if}
      <div class="confirm-actions">
        <Dialog.Close class="btn" disabled={busy}>Cancel</Dialog.Close>
        <button
          class="btn {danger ? 'btn-danger' : 'btn-primary'}"
          onclick={doConfirm}
          disabled={busy}
        >
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
