<script lang="ts">
  import { api, type Status } from "./lib/api";
  import { toaster } from "./lib/toast.svelte";
  import Login from "./views/Login.svelte";
  import Dashboard from "./views/Dashboard.svelte";
  import QueryLog from "./views/QueryLog.svelte";
  import Filters from "./views/Filters.svelte";
  import Upstreams from "./views/Upstreams.svelte";
  import Clients from "./views/Clients.svelte";
  import Settings from "./views/Settings.svelte";

  let status = $state<Status | null>(null);
  let route = $state(currentRoute());
  let loading = $state(true);

  const nav = [
    { id: "dashboard", label: "Dashboard", icon: "📊" },
    { id: "querylog", label: "Query Log", icon: "📜" },
    { id: "filters", label: "Filters", icon: "🛡️" },
    { id: "upstreams", label: "Upstreams", icon: "🌐" },
    { id: "clients", label: "Clients", icon: "💻" },
    { id: "settings", label: "Settings", icon: "⚙️" },
  ];

  function currentRoute(): string {
    return location.hash.replace(/^#\/?/, "") || "dashboard";
  }

  function go(id: string) {
    location.hash = "/" + id;
  }

  $effect(() => {
    const onHash = () => (route = currentRoute());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  });

  async function refreshStatus() {
    try {
      status = await api.status();
    } catch (e) {
      toaster.show("Failed to reach server", true);
    } finally {
      loading = false;
    }
  }

  async function logout() {
    await api.logout().catch(() => {});
    await refreshStatus();
  }

  refreshStatus();

  const authed = $derived(status?.authed === true && !status?.setup_needed);
</script>

{#if loading}
  <div class="login-wrap"><div class="muted">Loading…</div></div>
{:else if !authed}
  <Login {status} onAuthed={refreshStatus} />
{:else}
  <div class="app">
    <aside class="sidebar">
      <div class="brand">Bul<span>wark</span></div>
      {#each nav as item}
        <div
          class="nav-item {route === item.id ? 'active' : ''}"
          onclick={() => go(item.id)}
          role="button"
          tabindex="0"
          onkeydown={(e) => e.key === "Enter" && go(item.id)}
        >
          <span>{item.icon}</span>
          <span>{item.label}</span>
        </div>
      {/each}
      <div class="nav-spacer"></div>
      <div class="muted" style="padding:0 0.7rem;font-size:0.75rem">
        v{status?.version}
      </div>
      <div class="nav-item" onclick={logout} role="button" tabindex="0" onkeydown={() => {}}>
        <span>🚪</span><span>Log out</span>
      </div>
    </aside>

    <main class="main">
      {#if route === "dashboard"}
        <Dashboard />
      {:else if route === "querylog"}
        <QueryLog />
      {:else if route === "filters"}
        <Filters />
      {:else if route === "upstreams"}
        <Upstreams />
      {:else if route === "clients"}
        <Clients />
      {:else if route === "settings"}
        <Settings />
      {:else}
        <Dashboard />
      {/if}
    </main>
  </div>
{/if}

{#if toaster.msg}
  <div class="toast {toaster.error ? 'error' : ''}">{toaster.msg}</div>
{/if}
