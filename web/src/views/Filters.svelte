<script lang="ts">
  import * as api from "../api/generated";
  import { ok } from "@oazapfts/runtime";
  import type { FilterListConfig, CheckResponse } from "../api/generated";
  import { isStatus, errMsg } from "../lib/errors";
  import { toaster } from "../lib/toast.svelte";
  import { num, relTime } from "../lib/format";
  import Icon from "../components/Icon.svelte";
  import Badge from "../components/Badge.svelte";
  import Switch from "../components/Switch.svelte";
  import Field from "../components/Field.svelte";
  import Select from "../components/Select.svelte";
  import ConfirmDialog from "../components/ConfirmDialog.svelte";
  import ResponsiveTable from "../components/ResponsiveTable.svelte";

  let lists = $state<Required<FilterListConfig>[]>([]);
  let customRules = $state("");
  let savingRules = $state(false);

  let newName = $state("");
  let newUrl = $state("");
  let adding = $state(false);

  let checkDomain = $state("");
  let checkType = $state("A");
  let checkResult = $state<CheckResponse | null>(null);

  let pendingDelete = $state<Required<FilterListConfig> | null>(null);
  let confirmOpen = $state(false);

  function askDelete(l: Required<FilterListConfig>) {
    pendingDelete = l;
    confirmOpen = true;
  }

  const qtypes = ["A", "AAAA", "HTTPS", "TXT", "MX"].map((v) => ({ value: v, label: v }));

  async function load() {
    try {
      const f = await ok(api.getFilters());
      lists = f.lists as Required<FilterListConfig>[];
      customRules = f.custom_rules;
    } catch (e) {
      if (!isStatus(e, 401)) toaster.show("Failed to load filters", true);
    }
  }

  $effect(() => {
    load();
  });

  async function addList(e: Event) {
    e.preventDefault();
    if (!newName.trim()) return;
    adding = true;
    try {
      await ok(api.addList({ name: newName, url: newUrl || undefined, enabled: true }));
      toaster.show("List added");
      newName = "";
      newUrl = "";
      await load();
    } catch (err) {
      toaster.show(errMsg(err, "Failed to add list"), true);
    } finally {
      adding = false;
    }
  }

  async function toggleList(l: FilterListConfig) {
    await ok(api.updateList(l.id, { enabled: !l.enabled }));
    await load();
  }

  async function refresh(l: FilterListConfig) {
    toaster.show(`Refreshing ${l.name}…`);
    try {
      await ok(api.refreshList(l.id));
      toaster.show("Refreshed");
      await load();
    } catch (err) {
      toaster.show(errMsg(err, "Refresh failed"), true);
    }
  }

  async function remove(l: FilterListConfig) {
    await ok(api.deleteList(l.id));
    await load();
  }

  async function saveRules() {
    savingRules = true;
    try {
      await ok(api.putCustomRules({ rules: customRules }));
      toaster.show("Custom rules saved");
      await load();
    } catch (err) {
      toaster.show(errMsg(err, "Failed to save"), true);
    } finally {
      savingRules = false;
    }
  }

  async function runCheck() {
    try {
      checkResult = await ok(api.checkDomain({ domain: checkDomain.trim(), qtype: checkType }));
    } catch (err) {
      toaster.show(errMsg(err, "Check failed"), true);
    }
  }

  function checkTone(action: string): "good" | "bad" | "warn" | "neutral" {
    if (action === "block") return "bad";
    if (action === "allow") return "good";
    if (action === "rewrite") return "warn";
    return "neutral";
  }
</script>

<div class="page-head">
  <h1 class="page-title">Filters</h1>
</div>

<section class="card" style="padding:0;overflow:hidden">
  <div class="card-pad"><div class="card-title" style="margin:0">Blocklists</div></div>
  <ResponsiveTable items={lists} key={(l) => l.id}>
    {#snippet head()}
      <tr><th>Name</th><th>Source</th><th>Rules</th><th>Updated</th><th>Enabled</th><th></th></tr>
    {/snippet}
    {#snippet row(l)}
      <tr class="hoverable">
        <td>{l.name}</td>
        <td class="mono muted src" title={l.url ?? "inline"}>{l.url ?? "inline"}</td>
        <td>{num(l.rule_count)}</td>
        <td class="muted nowrap">{l.last_updated ? relTime(l.last_updated) : "—"}</td>
        <td><Switch checked={l.enabled} onCheckedChange={() => toggleList(l)} /></td>
        <td class="row-actions">
          {#if l.url}
            <button class="btn btn-icon" title="Refresh" onclick={() => refresh(l)}>
              <Icon name="refresh" size={16} />
            </button>
          {/if}
          <button class="btn btn-icon danger" title="Delete" onclick={() => askDelete(l)}>
            <Icon name="trash" size={16} />
          </button>
        </td>
      </tr>
    {/snippet}
    {#snippet card(l)}
      <div class="list-card">
        <div class="list-card-top">
          <span class="name">{l.name}</span>
          <Switch checked={l.enabled} onCheckedChange={() => toggleList(l)} />
        </div>
        <div class="mono muted src" title={l.url ?? "inline"}>{l.url ?? "inline"}</div>
        <div class="list-card-foot">
          <span class="muted">{num(l.rule_count)} rules · {l.last_updated ? relTime(l.last_updated) : "never"}</span>
          <span class="spacer"></span>
          {#if l.url}
            <button class="btn btn-icon" title="Refresh" onclick={() => refresh(l)}>
              <Icon name="refresh" size={16} />
            </button>
          {/if}
          <button class="btn btn-icon danger" title="Delete" onclick={() => askDelete(l)}>
            <Icon name="trash" size={16} />
          </button>
        </div>
      </div>
    {/snippet}
    {#snippet empty()}No lists yet.{/snippet}
  </ResponsiveTable>

  <form class="card-pad add-form" onsubmit={addList}>
    <input placeholder="List name" bind:value={newName} required />
    <input placeholder="https://… (URL, optional)" bind:value={newUrl} class="url-input" />
    <button class="btn btn-primary" type="submit" disabled={adding}>
      <Icon name="plus" size={15} />
      {adding ? "Adding…" : "Add list"}
    </button>
  </form>
</section>

<div class="grid cols-2" style="margin-top:var(--sp-4)">
  <section class="card">
    <div class="card-title">Custom rules</div>
    <p class="muted hint">
      AdGuard-style DNS rules or hosts entries, one per line. e.g.
      <code>||ads.example.com^</code>, <code>@@||good.example.com^</code>,
      <code>||router.lan^$dnsrewrite=10.0.0.1</code>.
    </p>
    <textarea bind:value={customRules} rows="12" spellcheck="false"></textarea>
    <div style="margin-top:var(--sp-3)">
      <button class="btn btn-primary" onclick={saveRules} disabled={savingRules}>
        {savingRules ? "Saving…" : "Save rules"}
      </button>
    </div>
  </section>

  <section class="card">
    <div class="card-title">Check a domain</div>
    <p class="muted hint">See how the current rules would treat a domain.</p>
    <div class="check-row">
      <Field label="Domain" htmlFor="cd">
        <input id="cd" placeholder="ads.example.com" bind:value={checkDomain} />
      </Field>
      <Field label="Type" htmlFor="ct">
        <Select id="ct" bind:value={checkType} items={qtypes} />
      </Field>
      <button class="btn btn-primary check-btn" onclick={runCheck}>Check</button>
    </div>
    {#if checkResult}
      <div class="check-result">
        <Badge tone={checkTone(checkResult.action)}>{checkResult.action}</Badge>
        {#if checkResult.rule}
          <div class="mono" style="margin-top:var(--sp-2)">{checkResult.rule}</div>
        {:else}
          <div class="muted" style="margin-top:var(--sp-2)">
            No matching rule — would be resolved normally.
          </div>
        {/if}
      </div>
    {/if}
  </section>
</div>

<ConfirmDialog
  bind:open={confirmOpen}
  title="Delete list?"
  message={pendingDelete ? `Delete "${pendingDelete.name}"? This removes its rules.` : ""}
  confirmLabel="Delete"
  danger
  onConfirm={() => pendingDelete && remove(pendingDelete)}
/>

<style>
  .card-pad {
    padding: var(--sp-5) var(--sp-5) var(--sp-4);
  }
  .hint {
    margin: 0 0 var(--sp-3);
    font-size: 0.82rem;
  }
  .src {
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .add-form {
    display: flex;
    gap: var(--sp-2);
    flex-wrap: wrap;
    border-top: 1px solid var(--border);
  }
  .add-form input {
    flex: 0 1 200px;
  }
  .add-form .url-input {
    flex: 1 1 240px;
  }
  .list-card {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 0.7rem 0.85rem;
    border-bottom: 1px solid var(--border);
  }
  .list-card-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-2);
  }
  .list-card-top .name {
    font-weight: 500;
  }
  .list-card-foot {
    display: flex;
    align-items: center;
    gap: var(--sp-1);
    font-size: 0.8rem;
  }
  .check-row {
    display: grid;
    grid-template-columns: 1fr 120px auto;
    gap: var(--sp-3);
    align-items: end;
  }
  .check-btn {
    height: fit-content;
  }
  .check-result {
    margin-top: var(--sp-4);
    padding: var(--sp-3);
    background: var(--bg-inset);
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }
  @media (max-width: 540px) {
    .check-row {
      grid-template-columns: 1fr;
    }
  }
</style>
