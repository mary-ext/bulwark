<script lang="ts" generics="T">
  import type { Snippet } from "svelte";
  import { isMobile } from "../lib/media.svelte";

  let {
    items,
    key,
    head,
    row,
    card,
    empty,
  }: {
    items: T[];
    key: (item: T) => unknown;
    head: Snippet;
    row: Snippet<[T]>;
    card: Snippet<[T]>;
    empty?: Snippet;
  } = $props();
</script>

{#if isMobile.matches}
  <div class="bw-cards">
    {#if items.length === 0}
      <div class="bw-empty">{#if empty}{@render empty()}{:else}Nothing here.{/if}</div>
    {:else}
      {#each items as item (key(item))}
        {@render card(item)}
      {/each}
    {/if}
  </div>
{:else}
  <div class="table-wrap">
    <table class="bw-table">
      <thead>{@render head()}</thead>
      <tbody>
        {#if items.length === 0}
          <tr>
            <td colspan="99">
              <div class="bw-empty">{#if empty}{@render empty()}{:else}Nothing here.{/if}</div>
            </td>
          </tr>
        {:else}
          {#each items as item (key(item))}
            {@render row(item)}
          {/each}
        {/if}
      </tbody>
    </table>
  </div>
{/if}
