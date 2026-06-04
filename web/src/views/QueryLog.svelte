<script lang="ts">
  import * as api from "../api/generated";
  import { ok } from "@oazapfts/runtime";
  import { DropdownMenu } from "bits-ui";
  import type { LogEntryView } from "../api/generated";
  import { isStatus, errMsg } from "../lib/errors";
  import { toaster } from "../lib/toast.svelte";
  import { relTime, ms, dateTime } from "../lib/format";
  import { isMobile } from "../lib/media.svelte";
  import Icon from "../components/Icon.svelte";
  import Badge from "../components/Badge.svelte";
  import Switch from "../components/Switch.svelte";
  import Sheet from "../components/Sheet.svelte";
  import Pagination from "../components/Pagination.svelte";
  import ResponsiveTable from "../components/ResponsiveTable.svelte";

  let entries = $state<LogEntryView[]>([]);
  let total = $state(0);
  let search = $state("");
  let client = $state("");
  let blockedOnly = $state(false);
  let offset = $state(0);
  let live = $state(false); // auto-refresh is opt-in and starts OFF.
  const limit = 100;

  let loading = $state(false);
  let detail = $state<LogEntryView | null>(null);
  let sheetOpen = $state(false);

  async function load() {
    loading = true;
    try {
      const r = await ok(
        api.getQuerylog({
          search: search || undefined,
          client: client || undefined,
          blockedOnly,
          offset,
          limit,
        }),
      );
      entries = r.entries;
      total = r.total;
    } catch (e) {
      if (!isStatus(e, 401)) toaster.show("Failed to load query log", true);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    search;
    client;
    blockedOnly;
    offset;
    // Debounce so typing in the search/client fields doesn't fire a request per keystroke.
    const t = setTimeout(load, 250);
    return () => clearTimeout(t);
  });

  $effect(() => {
    if (!live) return;
    const t = setInterval(() => {
      if (offset === 0) load();
    }, 4000);
    return () => clearInterval(t);
  });

  function bareDomain(question: string): string {
    return question.replace(/\.$/, "");
  }

  function tone(e: LogEntryView): "good" | "bad" | "info" | "warn" | "neutral" {
    if (e.allowlisted) return "good";
    switch (e.action) {
      case "blocked":
      case "error":
        return "bad";
      case "allowed":
      case "forwarded":
        return "good";
      case "cached":
        return "info";
      case "rewritten":
        return "warn";
      default:
        return "neutral";
    }
  }

  function statusLabel(e: LogEntryView): string {
    return e.allowlisted ? "allowed" : e.action;
  }

  // Match AdGuard Home: allow => @@||host^$important, block => ||host^$important.
  async function addRule(e: LogEntryView, allow: boolean) {
    const domain = bareDomain(e.question);
    const rule = `${allow ? "@@" : ""}||${domain}^$important`;
    try {
      const r = await ok(api.addCustomRule({ rule }));
      toaster.show(r.added ? `Added: ${rule}` : `Already present: ${rule}`);
      load();
    } catch (err) {
      toaster.show(errMsg(err, "Failed to add rule"), true);
    }
  }

  function openDetail(e: LogEntryView) {
    detail = e;
    sheetOpen = true;
  }

  async function actFromSheet(allow: boolean) {
    if (detail) await addRule(detail, allow);
    sheetOpen = false;
  }

  function resetOffset() {
    offset = 0;
  }
</script>

<div class="page-head">
  <h1 class="page-title">Query Log</h1>
  <span class="page-sub">{total.toLocaleString()} matching</span>
</div>

<div class="toolbar">
  <div class="search-field">
    <Icon name="search" size={15} class="search-icon" />
    <input placeholder="Search domain…" bind:value={search} oninput={resetOffset} />
  </div>
  <input
    class="client-field"
    placeholder="Client IP / name…"
    bind:value={client}
    oninput={resetOffset}
  />
  <label class="inline-switch">
    <Switch bind:checked={blockedOnly} onCheckedChange={resetOffset} />
    <span>Blocked only</span>
  </label>
  <label class="inline-switch">
    <Switch bind:checked={live} />
    <span>Live</span>
  </label>
  <span class="spacer"></span>
  <button class="btn btn-sm" onclick={load} disabled={loading || live} title={live ? "Auto-refreshing while Live is on" : "Refresh"}>
    <Icon name="refresh" size={15} /> Refresh
  </button>
</div>

<div class="card" style="padding:0;overflow:hidden">
  <ResponsiveTable items={entries} key={(e) => e.id}>
    {#snippet head()}
      <tr>
        <th>Time</th>
        <th class="domain-col">Domain</th>
        <th>Client</th>
        <th class="resp-col">Response</th>
        <th></th>
      </tr>
    {/snippet}

    {#snippet row(e)}
      <tr class="hoverable clickable" onclick={() => openDetail(e)}>
        <td class="muted nowrap" title={dateTime(e.time_ms)}>{relTime(e.time_ms)}</td>
        <td class="domain-col">
          <div class="domain-cell">
            <span class="mono domain" title={e.question}>{e.question}</span>
            <span class="qtype">{e.qtype}</span>
          </div>
        </td>
        <td class="nowrap">{e.client_name ?? e.client_ip}</td>
        <td class="resp-col">
          <div class="response-cell">
            <span class="status status-{tone(e)}">{statusLabel(e)}</span>
            {#if e.rule}
              <span class="resp-detail mono muted" title={e.rule}>{e.rule}</span>
            {/if}
            <span class="resp-latency muted" title="Response time">{ms(e.elapsed_ms)}</span>
          </div>
        </td>
        <td class="actions-cell" onclick={(ev) => ev.stopPropagation()}>
          <DropdownMenu.Root>
            <DropdownMenu.Trigger class="btn btn-icon" aria-label="Row actions">
              <Icon name="more" size={16} />
            </DropdownMenu.Trigger>
            <DropdownMenu.Portal>
              <DropdownMenu.Content class="bw-menu" align="end" sideOffset={4}>
                <span class="bw-menu-label">{bareDomain(e.question)}</span>
                <DropdownMenu.Item class="bw-menu-item" onSelect={() => addRule(e, true)}>
                  <Icon name="allow" size={15} /> Allow this domain
                </DropdownMenu.Item>
                <DropdownMenu.Item class="bw-menu-item danger" onSelect={() => addRule(e, false)}>
                  <Icon name="block" size={15} /> Block this domain
                </DropdownMenu.Item>
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu.Root>
        </td>
      </tr>
    {/snippet}

    {#snippet card(e)}
      <button class="log-card" onclick={() => openDetail(e)}>
        <div class="log-card-top">
          <span class="mono domain">{e.question}</span>
          <Badge tone={tone(e)}>{statusLabel(e)}</Badge>
        </div>
        <div class="log-card-meta muted">
          {relTime(e.time_ms)} · {e.qtype} · {e.client_name ?? e.client_ip} · {ms(e.elapsed_ms)}
        </div>
      </button>
    {/snippet}

    {#snippet empty()}
      No matching queries.
    {/snippet}
  </ResponsiveTable>
</div>

<Pagination {offset} {limit} {total} onChange={(o) => (offset = o)} />

<!-- Detail view: bottom sheet on mobile, centered dialog on desktop. -->
<Sheet bind:open={sheetOpen} title="Query detail" variant={isMobile.matches ? "sheet" : "dialog"}>
  {#if detail}
    <div class="detail">
      <section class="detail-group">
        <h4 class="detail-heading">Request</h4>
        <dl>
          <dt>Domain</dt>
          <dd class="mono wrap">{bareDomain(detail.question)}</dd>
          <dt>Type</dt>
          <dd class="mono">{detail.qtype}</dd>
          <dt>Client</dt>
          <dd>
            {#if detail.client_name}
              {detail.client_name} <span class="muted mono">{detail.client_ip}</span>
            {:else}
              <span class="mono">{detail.client_ip}</span>
            {/if}
          </dd>
          <dt>Time</dt>
          <dd>{dateTime(detail.time_ms)}</dd>
        </dl>
      </section>

      <section class="detail-group">
        <h4 class="detail-heading">Response</h4>
        <dl>
          <dt>Status</dt>
          <dd>
            <Badge tone={tone(detail)}>{statusLabel(detail)}</Badge>
            {#if detail.allowlisted}<span class="muted small">via @@ exception</span>{/if}
          </dd>
          <dt>Response code</dt>
          <dd class="mono">{detail.rcode}</dd>
          {#if detail.rule}
            <dt>Rule</dt>
            <dd class="mono wrap">{detail.rule}</dd>
            <dt>Filter list</dt>
            <dd>{detail.list_name ?? (detail.list_id === 0 ? "Custom rules" : "—")}</dd>
          {/if}
          <dt>Upstream</dt>
          <dd class="mono">{detail.upstream ?? (detail.action === "cached" ? "cache" : "—")}</dd>
          <dt>Elapsed</dt>
          <dd>{ms(detail.elapsed_ms)}</dd>
          <dt>Answers</dt>
          <dd class="answers">
            {#if detail.answers.length}
              {#each detail.answers as a}<div class="mono wrap">{a}</div>{/each}
            {:else}
              <span class="muted">—</span>
            {/if}
          </dd>
        </dl>
      </section>
    </div>

    <div class="detail-actions">
      <button class="btn" onclick={() => actFromSheet(true)}>
        <Icon name="allow" size={16} /> Allow
      </button>
      <button class="btn btn-danger" onclick={() => actFromSheet(false)}>
        <Icon name="block" size={16} /> Block
      </button>
    </div>
  {/if}
</Sheet>

<style>
  .search-field {
    position: relative;
    flex: 1 1 220px;
    max-width: 280px;
    min-width: 150px;
  }
  .search-field :global(.search-icon) {
    position: absolute;
    left: 10px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-faint);
    pointer-events: none;
  }
  .search-field input {
    padding-left: 32px;
  }
  .client-field {
    flex: 0 1 200px;
    min-width: 140px;
  }
  .inline-switch {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    font-size: 0.85rem;
    color: var(--text-dim);
    cursor: pointer;
    white-space: nowrap;
  }

  /* Desktop table cells (~5 columns — no horizontal scroll) */
  .clickable {
    cursor: pointer;
  }
  /* Let Domain absorb all leftover width; the other columns size to content.
     width:100% + max-width:0 makes the cell take the slack while the inner
     text truncates instead of stretching the row. */
  .domain-col {
    width: 100%;
    max-width: 0;
  }
  .domain-cell {
    display: flex;
    align-items: baseline;
    gap: var(--sp-2);
  }
  .domain {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .qtype {
    flex-shrink: 0;
    font-size: 0.7rem;
    font-family: var(--font-mono);
    color: var(--text-faint);
  }
  /* Size the Response column to its content (don't let the greedy Domain
     column squeeze it narrower than its widest row, which clipped latency). */
  .resp-col {
    width: 1%;
    white-space: nowrap;
  }
  .response-cell {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
  }
  /* Plain-text status (no badge pill); a subtle color keeps the verdict scannable. */
  .status {
    flex-shrink: 0;
    font-size: 0.82rem;
  }
  .status-good {
    color: var(--good-fg);
  }
  .status-bad {
    color: var(--bad-fg);
  }
  .status-warn {
    color: var(--warn-fg);
  }
  .status-info {
    color: var(--info-fg);
  }
  .status-neutral {
    color: var(--text-dim);
  }
  .resp-detail {
    min-width: 0;
    max-width: 240px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 0.8rem;
  }
  /* Response time, right-aligned within the cell so the values form a tidy
     column; td padding keeps it clear of the actions column. */
  .resp-latency {
    flex-shrink: 0;
    margin-left: auto;
    padding-left: var(--sp-3);
    font-size: 0.78rem;
    font-variant-numeric: tabular-nums;
  }
  .actions-cell {
    text-align: right;
    width: 1%;
  }

  /* Mobile cards */
  .log-card {
    display: flex;
    flex-direction: column;
    gap: 4px;
    width: 100%;
    text-align: left;
    background: var(--bg-elev);
    border: none;
    border-bottom: 1px solid var(--border);
    padding: 0.7rem 0.85rem;
    cursor: pointer;
  }
  .log-card:active {
    background: var(--bg-hover);
  }
  .log-card-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-2);
  }
  .log-card-top .domain {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 0.85rem;
  }
  .log-card-meta {
    font-size: 0.78rem;
  }

  /* Detail dialog / sheet */
  .detail {
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
    margin: 0 0 var(--sp-5);
  }
  .detail-group dl {
    display: grid;
    grid-template-columns: minmax(7rem, auto) 1fr;
    gap: 0.45rem var(--sp-4);
    margin: 0;
  }
  .detail-heading {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-faint);
    font-weight: 600;
    margin-bottom: var(--sp-2);
    padding-bottom: var(--sp-1);
    border-bottom: 1px solid var(--border);
  }
  .detail dt {
    color: var(--text-dim);
    font-size: 0.82rem;
  }
  .detail dd {
    margin: 0;
    text-align: right;
    font-size: 0.85rem;
    min-width: 0;
  }
  .detail dd.wrap,
  .detail dd .wrap {
    word-break: break-all;
  }
  .detail dd.answers {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .detail .small {
    font-size: 0.72rem;
    margin-left: 0.35rem;
  }
  .detail-actions {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--sp-3);
  }
  .detail-actions .btn {
    padding: 0.7rem;
    font-size: 0.95rem;
  }
</style>
