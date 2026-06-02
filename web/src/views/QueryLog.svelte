<script lang="ts">
  import { api, type LogEntry } from "../lib/api";
  import { toaster } from "../lib/toast.svelte";
  import { relTime, ms } from "../lib/format";

  let entries = $state<LogEntry[]>([]);
  let total = $state(0);
  let search = $state("");
  let client = $state("");
  let blockedOnly = $state(false);
  let offset = $state(0);
  let live = $state(true);
  const limit = 100;

  async function load() {
    try {
      const r = await api.getQuerylog({
        search: search || undefined,
        client: client || undefined,
        blocked_only: blockedOnly,
        offset,
        limit,
      });
      entries = r.entries;
      total = r.total;
    } catch (e: any) {
      if (e.status !== 401) toaster.show("Failed to load query log", true);
    }
  }

  $effect(() => {
    // Re-run when any filter changes.
    search;
    client;
    blockedOnly;
    offset;
    load();
  });

  $effect(() => {
    if (!live) return;
    const t = setInterval(() => {
      if (offset === 0) load();
    }, 4000);
    return () => clearInterval(t);
  });

  async function clearLog() {
    if (!confirm("Clear the in-memory query log?")) return;
    await api.clearQuerylog();
    offset = 0;
    load();
  }

  function badgeClass(e: LogEntry): string {
    if (e.action === "blocked") return "block";
    return e.action;
  }
</script>

<h1 class="page-title">
  Query Log
  <span class="muted" style="font-size:0.9rem;font-weight:400">{total.toLocaleString()} matching</span>
</h1>

<div class="toolbar">
  <input placeholder="Search domain…" bind:value={search} style="max-width:240px" oninput={() => (offset = 0)} />
  <input placeholder="Client IP / name…" bind:value={client} style="max-width:200px" oninput={() => (offset = 0)} />
  <label class="row" style="margin:0;gap:0.4rem;align-items:center">
    <input type="checkbox" bind:checked={blockedOnly} style="width:auto" onchange={() => (offset = 0)} />
    <span>Blocked only</span>
  </label>
  <label class="row" style="margin:0;gap:0.4rem;align-items:center">
    <input type="checkbox" bind:checked={live} style="width:auto" />
    <span>Live</span>
  </label>
  <div class="spacer"></div>
  <button class="danger" onclick={clearLog}>Clear log</button>
</div>

<div class="card" style="padding:0;overflow-x:auto">
  <table>
    <thead>
      <tr>
        <th>Time</th>
        <th>Domain</th>
        <th>Type</th>
        <th>Client</th>
        <th>Status</th>
        <th>Result</th>
        <th>Upstream</th>
        <th>Time</th>
      </tr>
    </thead>
    <tbody>
      {#each entries as e (e.id)}
        <tr>
          <td class="muted" title={new Date(e.time_ms).toLocaleString()}>{relTime(e.time_ms)}</td>
          <td class="mono" title={e.question}>{e.question}</td>
          <td>{e.qtype}</td>
          <td>{e.client_name ?? e.client_ip}</td>
          <td>
            <span class="badge {badgeClass(e)}">{e.allowlisted ? "allowed" : e.action}</span>
          </td>
          <td class="mono muted" title={e.rule ?? e.answers.join(", ")}>
            {#if e.rule}{e.rule}{:else}{e.answers[0] ?? e.rcode}{/if}
          </td>
          <td class="muted">{e.upstream ?? (e.cached ? "cache" : "—")}</td>
          <td class="muted">{ms(e.elapsed_ms)}</td>
        </tr>
      {/each}
      {#if entries.length === 0}
        <tr><td colspan="8" class="muted" style="text-align:center;padding:2rem">No matching queries.</td></tr>
      {/if}
    </tbody>
  </table>
</div>

<div class="toolbar" style="margin-top:1rem;justify-content:center">
  <button disabled={offset === 0} onclick={() => (offset = Math.max(0, offset - limit))}>← Newer</button>
  <span class="muted">{offset + 1}–{Math.min(offset + limit, total)} of {total.toLocaleString()}</span>
  <button disabled={offset + limit >= total} onclick={() => (offset += limit)}>Older →</button>
</div>
