<script lang="ts">
  import { api, type ClientCfg } from "../lib/api";
  import { toaster } from "../lib/toast.svelte";

  let clients = $state<ClientCfg[]>([]);
  let saving = $state(false);

  async function load() {
    try {
      clients = await api.getClients();
    } catch (e: any) {
      if (e.status !== 401) toaster.show("Failed to load clients", true);
    }
  }

  $effect(() => {
    load();
  });

  function addClient() {
    clients.push({ name: "", ids: [], tags: [], filtering_enabled: true });
  }

  function removeClient(i: number) {
    clients.splice(i, 1);
  }

  async function save() {
    saving = true;
    try {
      // Drop empty/incomplete rows.
      const cleaned = clients
        .filter((c) => c.name.trim() && c.ids.length)
        .map((c) => ({ ...c, name: c.name.trim() }));
      await api.putClients(cleaned);
      clients = cleaned;
      toaster.show("Clients saved");
    } catch (e: any) {
      toaster.show(e.message ?? "Save failed", true);
    } finally {
      saving = false;
    }
  }
</script>

<h1 class="page-title">Clients</h1>

<div class="card">
  <p class="muted" style="margin-top:0">
    Give friendly names to devices by IP or CIDR. Tags can be referenced in rules
    via <code>$ctag=</code>, and you can disable filtering per client.
  </p>

  <table>
    <thead>
      <tr><th>Name</th><th>IPs / CIDRs</th><th>Tags</th><th>Filtering</th><th></th></tr>
    </thead>
    <tbody>
      {#each clients as c, i}
        <tr>
          <td><input bind:value={c.name} placeholder="Living room TV" /></td>
          <td>
            <input
              class="mono"
              value={c.ids.join(", ")}
              placeholder="192.168.1.10, 10.0.0.0/24"
              onchange={(e) => (c.ids = (e.target as HTMLInputElement).value.split(",").map((s) => s.trim()).filter(Boolean))}
            />
          </td>
          <td>
            <input
              value={c.tags.join(", ")}
              placeholder="device_kids"
              onchange={(e) => (c.tags = (e.target as HTMLInputElement).value.split(",").map((s) => s.trim()).filter(Boolean))}
            />
          </td>
          <td style="text-align:center">
            <label class="switch"><input type="checkbox" bind:checked={c.filtering_enabled} /><span class="slider"></span></label>
          </td>
          <td style="text-align:right"><button class="danger" onclick={() => removeClient(i)}>✕</button></td>
        </tr>
      {/each}
      {#if clients.length === 0}
        <tr><td colspan="5" class="muted" style="text-align:center;padding:1.5rem">No named clients yet.</td></tr>
      {/if}
    </tbody>
  </table>

  <div class="toolbar" style="margin-top:1rem">
    <button onclick={addClient}>+ Add client</button>
    <div class="spacer"></div>
    <button class="primary" onclick={save} disabled={saving}>{saving ? "Saving…" : "Save clients"}</button>
  </div>
</div>
