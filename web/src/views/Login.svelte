<script lang="ts">
  import * as api from "../api/generated";
  import { ok } from "@oazapfts/runtime";
  import type { StatusResponse } from "../api/generated";
  import { errMsg } from "../lib/errors";
  import { toaster } from "../lib/toast.svelte";

  let { status, onAuthed }: { status: StatusResponse | null; onAuthed: () => void } = $props();

  let username = $state("");
  let password = $state("");
  let confirm = $state("");
  let busy = $state(false);

  const setup = $derived(status?.setup_needed === true);

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    try {
      if (setup) {
        if (password !== confirm) {
          toaster.show("Passwords do not match", true);
          return;
        }
        await ok(api.setup({ username, password }));
        toaster.show("Welcome to Bulwark!");
      } else {
        await ok(api.login({ username, password }));
      }
      onAuthed();
    } catch (err) {
      toaster.show(errMsg(err, "Authentication failed"), true);
    } finally {
      busy = false;
    }
  }
</script>

<div class="login-wrap">
  <form class="login-card" onsubmit={submit}>
    <div class="brand">
      <span class="logo">B</span>
      <span class="brand-text">Bul<span class="accent">wark</span></span>
    </div>
    <p class="muted sub">
      {setup ? "Create your admin account to get started." : "Sign in to continue."}
    </p>

    <div class="field">
      <label for="u">Username</label>
      <input id="u" bind:value={username} autocomplete="username" required />
    </div>
    <div class="field">
      <label for="p">Password</label>
      <input
        id="p"
        type="password"
        bind:value={password}
        autocomplete={setup ? "new-password" : "current-password"}
        required
      />
    </div>
    {#if setup}
      <div class="field">
        <label for="c">Confirm password</label>
        <input id="c" type="password" bind:value={confirm} required />
      </div>
    {/if}

    <button class="btn btn-primary submit" type="submit" disabled={busy}>
      {busy ? "…" : setup ? "Create account" : "Sign in"}
    </button>
  </form>
</div>

<style>
  .login-wrap {
    display: grid;
    place-items: center;
    min-height: 100dvh;
    padding: var(--sp-4);
  }
  .login-card {
    width: 380px;
    max-width: 100%;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow);
    padding: var(--sp-6);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    font-weight: 700;
    font-size: 1.4rem;
    letter-spacing: -0.02em;
  }
  .logo {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: 8px;
    background: var(--accent);
    color: var(--accent-contrast);
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 1.05rem;
  }
  .accent {
    color: var(--accent);
  }
  .sub {
    margin: var(--sp-2) 0 var(--sp-5);
    font-size: 0.875rem;
  }
  .field {
    margin-bottom: var(--sp-4);
  }
  .field label {
    display: block;
    font-size: 0.8rem;
    color: var(--text-dim);
    margin-bottom: var(--sp-1);
    font-weight: 500;
  }
  .submit {
    width: 100%;
    margin-top: var(--sp-2);
  }
</style>
