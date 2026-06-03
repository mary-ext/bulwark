<script lang="ts">
  import { theme } from "../lib/theme.svelte";
  import Icon from "./Icon.svelte";
</script>

<button
  class="btn btn-icon"
  onclick={() => theme.toggle()}
  aria-label="Toggle light/dark theme"
  title="Toggle theme"
>
  <Icon name={theme.current === "dark" ? "sun" : "moon"} size={18} />
</button>
