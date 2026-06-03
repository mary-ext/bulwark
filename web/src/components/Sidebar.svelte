<script lang="ts">
  import type { StatusResponse } from "../api/generated";
  import NavContent from "./NavContent.svelte";

  let { status, onLogout }: { status: StatusResponse | null; onLogout: () => void } =
    $props();
</script>

<aside class="sidebar">
  <NavContent {status} {onLogout} />
</aside>

<style>
  .sidebar {
    flex-shrink: 0;
    width: var(--sidebar-w);
    height: 100dvh;
    position: sticky;
    top: 0;
    border-right: 1px solid var(--border);
    background: var(--bg-elev);
  }
</style>
