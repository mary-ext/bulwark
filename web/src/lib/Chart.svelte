<script lang="ts">
  import { Chart, type ChartConfiguration } from "chart.js/auto";

  let { config }: { config: ChartConfiguration } = $props();

  let canvas: HTMLCanvasElement;

  $effect(() => {
    // Re-create whenever the config changes (Svelte tracks the `config` dep).
    const chart = new Chart(canvas, config);
    return () => chart.destroy();
  });
</script>

<canvas bind:this={canvas}></canvas>
