<script lang="ts">
  import { Dialog } from "bits-ui";
  import type { StatusResponse } from "../api/generated";
  import NavContent from "./NavContent.svelte";

  let {
    open = $bindable(false),
    status,
    onLogout,
  }: {
    open?: boolean;
    status: StatusResponse | null;
    onLogout: () => void;
  } = $props();
</script>

<Dialog.Root bind:open>
  <Dialog.Portal>
    <Dialog.Overlay class="bw-overlay" />
    <Dialog.Content class="bw-drawer">
      <Dialog.Title class="visually-hidden">Navigation</Dialog.Title>
      <NavContent {status} {onLogout} onNavigate={() => (open = false)} />
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
