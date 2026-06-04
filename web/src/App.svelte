<script lang="ts">
  import * as api from "./api/generated";
  import { ok } from "@oazapfts/runtime";
  import type { StatusResponse } from "./api/generated";
  import { toaster } from "./lib/toast.svelte";
  import { session } from "./lib/session.svelte";
  import { router } from "./lib/router.svelte";
  import AppShell from "./components/AppShell.svelte";
  import Toast from "./components/Toast.svelte";
  import Login from "./views/Login.svelte";
  import Dashboard from "./views/Dashboard.svelte";
  import QueryLog from "./views/QueryLog.svelte";
  import Filters from "./views/Filters.svelte";
  import Upstreams from "./views/Upstreams.svelte";
  import Clients from "./views/Clients.svelte";
  import Settings from "./views/Settings.svelte";

  let status = $state<StatusResponse | null>(null);
  let loading = $state(true);

  async function refreshStatus() {
    try {
      status = await ok(api.status());
      // A successful status fetch means we're talking to the server again; if a
      // prior 401 had flagged the session expired, this re-auth clears it.
      session.clear();
    } catch {
      toaster.show("Failed to reach server", true);
    } finally {
      loading = false;
    }
  }

  async function logout() {
    // Pessimistically drop to the login screen even if the logout call fails, so
    // we never leave a half-logged-out UI showing privileged data.
    try {
      await ok(api.logout());
    } catch {
      /* ignore — we clear local auth state regardless */
    }
    if (status) status = { ...status, authed: false };
    await refreshStatus();
  }

  refreshStatus();

  // Any 401 from an API call flips `session.expired`; treat that as logged-out.
  const authed = $derived(
    status?.authed === true && !status?.setup_needed && !session.expired,
  );

  // Surface the expiry once, so the user knows why they're back at the login.
  $effect(() => {
    if (session.expired) toaster.show("Session expired — please sign in again", true);
  });
</script>

{#if loading}
  <div class="boot muted">Loading…</div>
{:else if !authed}
  <Login {status} onAuthed={refreshStatus} />
{:else}
  <AppShell {status} onLogout={logout}>
    {#if router.route === "dashboard"}
      <Dashboard />
    {:else if router.route === "querylog"}
      <QueryLog />
    {:else if router.route === "filters"}
      <Filters />
    {:else if router.route === "upstreams"}
      <Upstreams />
    {:else if router.route === "clients"}
      <Clients />
    {:else if router.route === "settings"}
      <Settings />
    {/if}
  </AppShell>
{/if}

<Toast />

<style>
  .boot {
    display: grid;
    place-items: center;
    min-height: 100dvh;
  }
</style>
