<script module lang="ts">
  // Per-instance gradient ids so multiple sparklines don't share a <defs>.
  let uid = 0;
</script>

<script lang="ts">
  let {
    values,
    labels = [],
    color = "var(--accent)",
    height = 44,
    area = true,
    ariaLabel,
  }: {
    values: number[];
    /** Tooltip text per point (e.g. "Mon 16:00"); index-aligned with values. */
    labels?: string[];
    color?: string;
    height?: number;
    area?: boolean;
    ariaLabel?: string;
  } = $props();

  const gid = `spark-${uid++}`;
  // The SVG is drawn in measured pixel space (no viewBox scaling) so the stroke
  // and hover dot stay round instead of stretching with the card width.
  let w = $state(0);
  let hover = $state<number | null>(null);

  const pad = 3;
  const n = $derived(values.length);
  const max = $derived(Math.max(1, ...values));
  const xAt = (i: number) => (n <= 1 ? w / 2 : (i / (n - 1)) * w);
  const yAt = (v: number) => height - pad - (v / max) * (height - 2 * pad);

  // A single bucket (e.g. a fresh instance with only the current hour) has no
  // span to plot across, so draw it as a flat line spanning the full width
  // instead of one degenerate vertex that renders as nothing.
  const pts = $derived(
    n === 1
      ? [
          [0, yAt(values[0])],
          [w, yAt(values[0])],
        ]
      : values.map((v, i) => [xAt(i), yAt(v)]),
  );

  const linePts = $derived(pts.map(([x, y]) => `${x},${y}`).join(" "));
  const areaPath = $derived(
    `M0,${height} ` + pts.map(([x, y]) => `L${x},${y}`).join(" ") + ` L${w},${height} Z`,
  );

  function onmove(e: PointerEvent) {
    if (n === 0 || w === 0) return;
    const rect = (e.currentTarget as SVGElement).getBoundingClientRect();
    const x = e.clientX - rect.left;
    hover = Math.max(0, Math.min(n - 1, Math.round((x / w) * (n - 1))));
  }
</script>

<div class="spark" style="height:{height}px" bind:clientWidth={w}>
  {#if w > 0 && n > 0}
    <svg
      width={w}
      {height}
      role="img"
      aria-label={ariaLabel ?? "trend"}
      onpointermove={onmove}
      onpointerleave={() => (hover = null)}
    >
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color={color} stop-opacity="0.28" />
          <stop offset="100%" stop-color={color} stop-opacity="0" />
        </linearGradient>
      </defs>
      {#if area}
        <path d={areaPath} fill="url(#{gid})" />
      {/if}
      <polyline
        points={linePts}
        fill="none"
        stroke={color}
        stroke-width="1.5"
        stroke-linejoin="round"
        stroke-linecap="round"
      />
      {#if hover !== null}
        <line
          x1={xAt(hover)}
          y1={pad}
          x2={xAt(hover)}
          y2={height}
          stroke={color}
          stroke-width="1"
          stroke-opacity="0.35"
        />
        <circle cx={xAt(hover)} cy={yAt(values[hover])} r="2.75" fill={color} />
      {/if}
    </svg>
    {#if hover !== null}
      <div
        class="spark-tip"
        style="left:{Math.max(0, Math.min(w - 1, xAt(hover)))}px"
        class:flip={xAt(hover) > w / 2}
      >
        <span class="v">{values[hover].toLocaleString()}</span>
        {#if labels[hover]}<span class="t">{labels[hover]}</span>{/if}
      </div>
    {/if}
  {/if}
</div>

<style>
  .spark {
    position: relative;
    width: 100%;
  }
  .spark svg {
    display: block;
  }
  .spark-tip {
    position: absolute;
    bottom: calc(100% + 4px);
    transform: translateX(-50%);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1px;
    padding: 4px 7px;
    border-radius: var(--radius-sm);
    background: var(--bg-elev2);
    border: 1px solid var(--border);
    box-shadow: 0 4px 14px rgb(0 0 0 / 0.3);
    pointer-events: none;
    white-space: nowrap;
    z-index: 2;
  }
  /* Keep the tip on-canvas near the right edge by anchoring it to its left. */
  .spark-tip.flip {
    transform: translateX(-100%);
  }
  .spark-tip .v {
    font-size: 0.8rem;
    font-weight: 650;
    line-height: 1.1;
  }
  .spark-tip .t {
    font-size: 0.68rem;
    color: var(--text-dim);
  }
</style>
