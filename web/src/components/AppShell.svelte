<script lang="ts">
  import type { Snippet } from "svelte";
  import { Tooltip } from "bits-ui";
  import type { StatusResponse } from "../api/generated";
  import { isMobile } from "../lib/media.svelte";
  import Sidebar from "./Sidebar.svelte";
  import NavDrawer from "./NavDrawer.svelte";
  import ThemeToggle from "./ThemeToggle.svelte";
  import Icon from "./Icon.svelte";

  let {
    status,
    onLogout,
    children,
  }: {
    status: StatusResponse | null;
    onLogout: () => void;
    children: Snippet;
  } = $props();

  let drawerOpen = $state(false);
</script>

<Tooltip.Provider delayDuration={300} disableHoverableContent>
  <div class="shell">
    {#if !isMobile.matches}
      <Sidebar {status} {onLogout} />
    {/if}

    <div class="main-col">
      {#if isMobile.matches}
        <header class="topbar">
          <button class="btn btn-icon" onclick={() => (drawerOpen = true)} aria-label="Open menu">
            <Icon name="menu" size={22} />
          </button>
          <span class="logo">B</span>
          <span class="brand-text">Bul<span class="accent">wark</span></span>
          <span class="spacer"></span>
          <ThemeToggle />
        </header>
      {/if}

      <main class="main">
        {@render children()}
      </main>
    </div>
  </div>

  {#if isMobile.matches}
    <NavDrawer bind:open={drawerOpen} {status} {onLogout} />
  {/if}
</Tooltip.Provider>

<style>
  .shell {
    display: flex;
    min-height: 100dvh;
  }
  .main-col {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
  .topbar {
    position: sticky;
    top: 0;
    z-index: var(--z-sticky);
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    height: var(--topbar-h);
    padding: 0 var(--sp-2);
    border-bottom: 1px solid var(--border);
    background: var(--bg);
  }
  .logo {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 26px;
    height: 26px;
    border-radius: 7px;
    background: var(--accent);
    color: var(--accent-contrast);
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 0.9rem;
  }
  .brand-text {
    font-weight: 700;
    font-size: 1.05rem;
    letter-spacing: -0.02em;
  }
  .accent {
    color: var(--accent);
  }
  .main {
    flex: 1;
    width: 100%;
    max-width: var(--content-max);
    margin: 0 auto;
    padding: var(--sp-5) var(--sp-6);
  }
  @media (max-width: 768px) {
    .main {
      padding: var(--sp-4);
    }
  }
</style>
