<script lang="ts">
  import { api, type Status } from "../lib/api";
  import { toaster } from "../lib/toast.svelte";

  let { status, onAuthed }: { status: Status | null; onAuthed: () => void } = $props();

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
        await api.setup(username, password);
        toaster.show("Welcome to Bulwark!");
      } else {
        await api.login(username, password);
      }
      onAuthed();
    } catch (err: any) {
      toaster.show(err.message ?? "Authentication failed", true);
    } finally {
      busy = false;
    }
  }
</script>

<div class="login-wrap">
  <form class="card login-card" onsubmit={submit}>
    <div class="brand" style="padding-left:0">Bul<span>wark</span></div>
    <p class="muted" style="margin-top:-0.6rem">
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

    <button class="primary" type="submit" disabled={busy} style="width:100%">
      {busy ? "…" : setup ? "Create account" : "Sign in"}
    </button>
  </form>
</div>
