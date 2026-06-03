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
