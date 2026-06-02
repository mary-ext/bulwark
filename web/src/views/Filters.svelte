<script lang="ts">
  import { api, type FilterList } from "../lib/api";
  import { toaster } from "../lib/toast.svelte";
  import { num, relTime } from "../lib/format";

  let lists = $state<FilterList[]>([]);
  let customRules = $state("");
  let savingRules = $state(false);

  // Add-list form
  let newName = $state("");
  let newUrl = $state("");
  let adding = $state(false);

  // Check tool
  let checkDomain = $state("");
  let checkType = $state("A");
  let checkResult = $state<{ action: string; rule?: string } | null>(null);

  async function load() {
    try {
      const f = await api.getFilters();
      lists = f.lists;
      customRules = f.custom_rules;
    } catch (e: any) {
      if (e.status !== 401) toaster.show("Failed to load filters", true);
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
      await api.addList({ name: newName, url: newUrl || undefined, enabled: true });
      toaster.show("List added");
      newName = "";
      newUrl = "";
      await load();
    } catch (err: any) {
      toaster.show(err.message ?? "Failed to add list", true);
    } finally {
      adding = false;
    }
  }

  async function toggleList(l: FilterList) {
    await api.updateList(l.id, { enabled: !l.enabled });
    await load();
  }

  async function refresh(l: FilterList) {
    toaster.show(`Refreshing ${l.name}…`);
    try {
      await api.refreshList(l.id);
      toaster.show("Refreshed");
      await load();
    } catch (err: any) {
      toaster.show(err.message ?? "Refresh failed", true);
    }
  }

  async function remove(l: FilterList) {
    if (!confirm(`Delete list "${l.name}"?`)) return;
    await api.deleteList(l.id);
    await load();
  }

  async function saveRules() {
    savingRules = true;
    try {
      await api.putCustomRules(customRules);
      toaster.show("Custom rules saved");
      await load();
    } catch (err: any) {
      toaster.show(err.message ?? "Failed to save", true);
    } finally {
      savingRules = false;
    }
  }

  async function runCheck() {
    try {
      checkResult = await api.checkDomain(checkDomain.trim(), checkType);
    } catch (err: any) {
      toaster.show(err.message ?? "Check failed", true);
    }
  }
</script>

<h1 class="page-title">Filters</h1>

<div class="card">
  <h3 style="margin-top:0">Blocklists</h3>
  <table>
    <thead>
      <tr><th>Name</th><th>Source</th><th>Rules</th><th>Updated</th><th>Enabled</th><th></th></tr>
    </thead>
    <tbody>
      {#each lists as l (l.id)}
        <tr>
          <td>{l.name}</td>
          <td class="mono muted" title={l.url ?? "inline"}>{l.url ?? "inline"}</td>
          <td>{num(l.rule_count)}</td>
          <td class="muted">{l.last_updated ? relTime(l.last_updated) : "—"}</td>
          <td>
            <label class="switch">
              <input type="checkbox" checked={l.enabled} onchange={() => toggleList(l)} />
              <span class="slider"></span>
            </label>
          </td>
          <td class="row" style="justify-content:flex-end">
            {#if l.url}<button onclick={() => refresh(l)}>↻</button>{/if}
            <button class="danger" onclick={() => remove(l)}>✕</button>
          </td>
        </tr>
      {/each}
      {#if lists.length === 0}
        <tr><td colspan="6" class="muted" style="text-align:center;padding:1.5rem">No lists yet.</td></tr>
      {/if}
    </tbody>
  </table>

  <form class="toolbar" style="margin-top:1rem" onsubmit={addList}>
    <input placeholder="List name" bind:value={newName} style="max-width:200px" required />
    <input placeholder="https://… (URL, optional)" bind:value={newUrl} style="flex:1" />
    <button class="primary" type="submit" disabled={adding}>{adding ? "Adding…" : "Add list"}</button>
  </form>
</div>

<div class="grid cols-2" style="margin-top:1rem">
  <div class="card">
    <h3 style="margin-top:0">Custom rules</h3>
    <p class="muted" style="margin-top:0">
      AdGuard-style DNS rules or hosts entries, one per line. e.g.
      <code>||ads.example.com^</code>, <code>@@||good.example.com^</code>,
      <code>||router.lan^$dnsrewrite=10.0.0.1</code>.
    </p>
    <textarea bind:value={customRules} rows="12"></textarea>
    <div class="row" style="margin-top:0.7rem">
      <button class="primary" onclick={saveRules} disabled={savingRules}>
        {savingRules ? "Saving…" : "Save rules"}
      </button>
    </div>
  </div>

  <div class="card">
    <h3 style="margin-top:0">Check a domain</h3>
    <p class="muted" style="margin-top:0">See how the current rules would treat a domain.</p>
    <div class="row" style="align-items:flex-end">
      <div style="flex:1">
        <label for="cd">Domain</label>
        <input id="cd" placeholder="ads.example.com" bind:value={checkDomain} />
      </div>
      <div style="width:110px">
        <label for="ct">Type</label>
        <select id="ct" bind:value={checkType}>
          <option>A</option>
          <option>AAAA</option>
          <option>HTTPS</option>
          <option>TXT</option>
          <option>MX</option>
        </select>
      </div>
      <button class="primary" onclick={runCheck}>Check</button>
    </div>
    {#if checkResult}
      <div class="card" style="margin-top:1rem;background:var(--bg-elev2)">
        <div class="row">
          <span class="badge {checkResult.action === 'block' ? 'block' : checkResult.action}">
            {checkResult.action}
          </span>
        </div>
        {#if checkResult.rule}
          <div class="mono" style="margin-top:0.6rem">{checkResult.rule}</div>
        {:else}
          <div class="muted" style="margin-top:0.6rem">No matching rule — would be resolved normally.</div>
        {/if}
      </div>
    {/if}
  </div>
</div>
