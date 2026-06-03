<script lang="ts">
  import * as api from "../api/generated";
  import { ok } from "@oazapfts/runtime";
  import type { ClientConfig } from "../api/generated";
  import { isStatus, errMsg } from "../lib/errors";
  import { parseList } from "../lib/format";
  import { toaster } from "../lib/toast.svelte";
  import { isMobile } from "../lib/media.svelte";
  import Icon from "../components/Icon.svelte";
  import Badge from "../components/Badge.svelte";
  import Field from "../components/Field.svelte";
  import SwitchRow from "../components/SwitchRow.svelte";
  import Sheet from "../components/Sheet.svelte";
  import ConfirmDialog from "../components/ConfirmDialog.svelte";
  import ResponsiveTable from "../components/ResponsiveTable.svelte";

  type Client = Required<ClientConfig>;

  let clients = $state<Client[]>([]);

  // Edit dialog state.
  let dialogOpen = $state(false);
  let editIndex = $state(-1); // -1 = adding a new client
  let draftName = $state("");
  let draftIds = $state("");
  let draftTags = $state("");
  let draftFiltering = $state(true);
  let saving = $state(false);

  let pendingDelete = $state<Client | null>(null);
  let confirmOpen = $state(false);

  async function load() {
    try {
      clients = (await ok(api.getClients())) as Client[];
    } catch (e) {
      if (!isStatus(e, 401)) toaster.show("Failed to load clients", true);
    }
  }

  $effect(() => {
    load();
  });

  function openAdd() {
    editIndex = -1;
    draftName = "";
    draftIds = "";
    draftTags = "";
    draftFiltering = true;
    dialogOpen = true;
  }

  function openEdit(c: Client) {
    editIndex = clients.indexOf(c);
    draftName = c.name;
    draftIds = c.ids.join(", ");
    draftTags = c.tags.join(", ");
    draftFiltering = c.filtering_enabled;
    dialogOpen = true;
  }

  async function persist(next: Client[]): Promise<boolean> {
    try {
      await ok(api.putClients(next));
      clients = next;
      return true;
    } catch (e) {
      toaster.show(errMsg(e, "Save failed"), true);
      return false;
    }
  }

  async function saveDraft() {
    const ids = parseList(draftIds);
    if (!draftName.trim()) {
      toaster.show("Name is required", true);
      return;
    }
    if (!ids.length) {
      toaster.show("Add at least one IP or CIDR", true);
      return;
    }
    saving = true;
    const entry: Client = {
      name: draftName.trim(),
      ids,
      tags: parseList(draftTags),
      filtering_enabled: draftFiltering,
    };
    const next = [...clients];
    if (editIndex >= 0) next[editIndex] = entry;
    else next.push(entry);
    if (await persist(next)) {
      toaster.show(editIndex >= 0 ? "Client updated" : "Client added");
      dialogOpen = false;
    }
    saving = false;
  }

  function askDelete(c: Client) {
    pendingDelete = c;
    confirmOpen = true;
  }

  async function doDelete(c: Client) {
    const next = clients.filter((x) => x !== c);
    if (await persist(next)) toaster.show("Client removed");
  }
</script>

<div class="page-head">
  <h1 class="page-title">Clients</h1>
  <span class="spacer"></span>
  <button class="btn btn-primary btn-sm" onclick={openAdd}>
    <Icon name="plus" size={15} /> Add client
  </button>
</div>

<p class="muted intro">
  Give friendly names to devices by IP or CIDR. Tags can be referenced in rules via
  <code>$ctag=</code>, and you can disable filtering per client.
</p>

<section class="card" style="padding:0;overflow:hidden">
  <ResponsiveTable items={clients} key={(c) => c}>
    {#snippet head()}
      <tr><th>Name</th><th>IPs / CIDRs</th><th>Tags</th><th>Filtering</th><th></th></tr>
    {/snippet}
    {#snippet row(c)}
      <tr class="hoverable clickable" onclick={() => openEdit(c)}>
        <td class="name">{c.name}</td>
        <td class="mono muted">{c.ids.join(", ")}</td>
        <td>
          {#if c.tags.length}
            <span class="tags">{#each c.tags as t}<span class="tag">{t}</span>{/each}</span>
          {:else}<span class="muted">—</span>{/if}
        </td>
        <td>
          <Badge tone={c.filtering_enabled ? "good" : "neutral"}>
            {c.filtering_enabled ? "on" : "off"}
          </Badge>
        </td>
        <td class="row-actions" onclick={(e) => e.stopPropagation()}>
          <button class="btn btn-icon" title="Edit" onclick={() => openEdit(c)}>
            <Icon name="settings" size={15} />
          </button>
          <button class="btn btn-icon danger" title="Remove" onclick={() => askDelete(c)}>
            <Icon name="trash" size={16} />
          </button>
        </td>
      </tr>
    {/snippet}
    {#snippet card(c)}
      <div class="client-card">
        <div class="client-card-top">
          <button class="name-btn" onclick={() => openEdit(c)}>{c.name}</button>
          <Badge tone={c.filtering_enabled ? "good" : "neutral"}>
            {c.filtering_enabled ? "on" : "off"}
          </Badge>
        </div>
        <div class="mono muted ids">{c.ids.join(", ")}</div>
        {#if c.tags.length}
          <div class="tags">{#each c.tags as t}<span class="tag">{t}</span>{/each}</div>
        {/if}
        <div class="client-card-foot">
          <button class="btn btn-sm" onclick={() => openEdit(c)}>
            <Icon name="settings" size={14} /> Edit
          </button>
          <span class="spacer"></span>
          <button class="btn btn-icon danger" title="Remove" onclick={() => askDelete(c)}>
            <Icon name="trash" size={16} />
          </button>
        </div>
      </div>
    {/snippet}
    {#snippet empty()}No named clients yet — add one to get started.{/snippet}
  </ResponsiveTable>
</section>

<!-- Add / edit dialog -->
<Sheet
  bind:open={dialogOpen}
  title={editIndex >= 0 ? "Edit client" : "Add client"}
  variant={isMobile.matches ? "sheet" : "dialog"}
>
  <div class="stack" style="gap:var(--sp-4)">
    <Field label="Name" htmlFor="cl-name">
      <input id="cl-name" bind:value={draftName} placeholder="Living room TV" />
    </Field>
    <Field
      label="IPs / CIDRs"
      htmlFor="cl-ids"
      hint="Comma-separated. e.g. 192.168.1.10, 10.0.0.0/24"
    >
      <input id="cl-ids" class="mono" bind:value={draftIds} placeholder="192.168.1.10, 10.0.0.0/24" />
    </Field>
    <Field label="Tags" htmlFor="cl-tags" hint="Comma-separated. Reference in rules via $ctag=">
      <input id="cl-tags" bind:value={draftTags} placeholder="device_kids" />
    </Field>
    <SwitchRow bind:checked={draftFiltering} label="Filtering enabled" />
    <div class="dialog-actions">
      <button class="btn" onclick={() => (dialogOpen = false)}>Cancel</button>
      <button class="btn btn-primary" onclick={saveDraft} disabled={saving}>
        {saving ? "Saving…" : editIndex >= 0 ? "Save changes" : "Add client"}
      </button>
    </div>
  </div>
</Sheet>

<ConfirmDialog
  bind:open={confirmOpen}
  title="Remove client?"
  message={pendingDelete ? `Remove "${pendingDelete.name}"?` : ""}
  confirmLabel="Remove"
  danger
  onConfirm={() => pendingDelete && doDelete(pendingDelete)}
/>

<style>
  .intro {
    margin: 0 0 var(--sp-4);
    font-size: 0.85rem;
    max-width: 70ch;
  }
  .name {
    font-weight: 500;
  }
  .clickable {
    cursor: pointer;
  }
  .tags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .client-card {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    padding: 0.8rem 0.85rem;
    border-bottom: 1px solid var(--border);
  }
  .client-card-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-2);
  }
  .name-btn {
    background: none;
    border: none;
    padding: 0;
    font-weight: 600;
    font-size: 0.95rem;
    color: var(--text);
    cursor: pointer;
  }
  .client-card-foot {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    margin-top: 2px;
  }

  .dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--sp-2);
    margin-top: var(--sp-2);
  }
</style>
