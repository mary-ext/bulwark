<script lang="ts">
  import { router, NAV, type RouteId } from "../lib/router.svelte";
  import type { StatusResponse } from "../api/generated";
  import Icon from "./Icon.svelte";
  import ThemeToggle from "./ThemeToggle.svelte";

  let {
    status,
    onLogout,
    onNavigate,
  }: {
    status: StatusResponse | null;
    onLogout: () => void;
    onNavigate?: () => void;
  } = $props();

  function nav(id: RouteId) {
    router.go(id);
    onNavigate?.();
  }
</script>

<div class="nav-body">
  <div class="brand">
    <span class="logo">B</span>
    <span class="brand-text">Bul<span class="accent">wark</span></span>
    <span class="spacer"></span>
    <ThemeToggle />
  </div>

  <nav class="nav">
    {#each NAV as item (item.id)}
      <button
        class="nav-item"
        class:active={router.route === item.id}
        onclick={() => nav(item.id)}
      >
        <Icon name={item.icon} size={18} />
        <span>{item.label}</span>
      </button>
    {/each}
  </nav>

  <div class="spacer"></div>

  <div class="nav-footer">
    <span class="muted version">v{status?.version ?? "—"}</span>
    <button class="nav-item logout" onclick={onLogout}>
      <Icon name="logout" size={18} />
      <span>Log out</span>
    </button>
  </div>
</div>

<style>
  .nav-body {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--sp-4) var(--sp-3);
    gap: 2px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    font-weight: 700;
    font-size: 1.1rem;
    letter-spacing: -0.02em;
    padding: var(--sp-1) var(--sp-2) var(--sp-4);
  }
  .logo {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 8px;
    background: var(--accent);
    color: var(--accent-contrast);
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 0.95rem;
  }
  .accent {
    color: var(--accent);
  }
  .nav {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .nav-item {
    display: flex;
    align-items: center;
    gap: var(--sp-3);
    width: 100%;
    text-align: left;
    padding: 0.55rem 0.6rem;
    border: none;
    background: transparent;
    color: var(--text-dim);
    border-radius: var(--radius-sm);
    font-size: 0.9rem;
    font-weight: 500;
    cursor: pointer;
  }
  .nav-item:hover {
    background: var(--bg-hover);
    color: var(--text);
  }
  .nav-item.active {
    background: var(--accent-bg);
    color: var(--accent);
  }
  .nav-footer {
    border-top: 1px solid var(--border);
    padding-top: var(--sp-2);
    margin-top: var(--sp-2);
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .version {
    padding: 0 0.6rem 0.2rem;
    font-size: 0.75rem;
    font-family: var(--font-mono);
  }
</style>
