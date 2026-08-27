<script module lang="ts">
  // Keep gradient IDs instance-local.
  let uid = 0;
</script>

<script lang="ts">
  let {
    values,
    labels = [],
    color = "var(--accent)",
    height = 44,
    area = true,
    smooth = true,
    ariaLabel,
  }: {
    values: number[];
    /** Point-aligned tooltip labels. */
    labels?: string[];
    color?: string;
    height?: number;
    area?: boolean;
    /** Enable interpolation and density-aware smoothing. */
    smooth?: boolean;
    ariaLabel?: string;
  } = $props();

  const gid = `spark-${uid++}`;
  // Pixel coordinates keep strokes and dots undistorted.
  let w = $state(0);
  let hover = $state<number | null>(null);

  const pad = 3;
  const n = $derived(values.length);
  const max = $derived(Math.max(1, ...values));
  const xAt = (i: number) => (n <= 1 ? w / 2 : (i / (n - 1)) * w);
  const yAt = (v: number) => height - pad - (v / max) * (height - 2 * pad);
  const r = (x: number) => Math.round(x * 10) / 10;

  // Average samples denser than roughly one point per three pixels.
  const win = $derived(
    smooth && n >= 8 && w > 0 ? Math.max(1, Math.round((n / w) * 3)) : 1,
  );
  const plotted = $derived(win > 1 ? movingAvg(values, win) : values);

  function movingAvg(a: number[], window: number): number[] {
    const half = Math.floor(window / 2);
    return a.map((_, i) => {
      let sum = 0,
        cnt = 0;
      for (let j = i - half; j <= i + half; j++) {
        if (j >= 0 && j < a.length) {
          sum += a[j];
          cnt++;
        }
      }
      return sum / cnt;
    });
  }

  // Render a single sample as a full-width line.
  const pts = $derived(
    n === 1
      ? [
          [0, yAt(plotted[0])],
          [w, yAt(plotted[0])],
        ]
      : plotted.map((v, i) => [r(xAt(i)), r(yAt(v))]),
  );

  // Fritsch-Carlson interpolation avoids overshoot.
  function curve(p: number[][]): string {
    const N = p.length;
    if (N < 2) return "";
    if (!smooth) return p.map(([x, y]) => `L${x},${y}`).join(" ");
    const dx: number[] = [],
      m: number[] = [];
    for (let i = 0; i < N - 1; i++) {
      dx[i] = p[i + 1][0] - p[i][0];
      m[i] = dx[i] === 0 ? 0 : (p[i + 1][1] - p[i][1]) / dx[i];
    }
    const t = new Array(N);
    t[0] = m[0];
    t[N - 1] = m[N - 2];
    for (let i = 1; i < N - 1; i++) t[i] = m[i - 1] * m[i] <= 0 ? 0 : (m[i - 1] + m[i]) / 2;
    for (let i = 0; i < N - 1; i++) {
      if (m[i] === 0) {
        t[i] = 0;
        t[i + 1] = 0;
        continue;
      }
      const a = t[i] / m[i],
        b = t[i + 1] / m[i],
        s = a * a + b * b;
      if (s > 9) {
        const tau = 3 / Math.sqrt(s);
        t[i] = tau * a * m[i];
        t[i + 1] = tau * b * m[i];
      }
    }
    let d = "";
    for (let i = 0; i < N - 1; i++) {
      const c1x = r(p[i][0] + dx[i] / 3),
        c1y = r(p[i][1] + (t[i] * dx[i]) / 3),
        c2x = r(p[i + 1][0] - dx[i] / 3),
        c2y = r(p[i + 1][1] - (t[i + 1] * dx[i]) / 3);
      d += `C${c1x},${c1y} ${c2x},${c2y} ${p[i + 1][0]},${p[i + 1][1]} `;
    }
    return d.trim();
  }

  const mid = $derived(pts.length ? `M${pts[0][0]},${pts[0][1]} ${curve(pts)}` : "");
  const linePath = $derived(mid);
  const areaPath = $derived(
    pts.length ? `M0,${height} L${mid.slice(1)} L${w},${height} Z` : "",
  );

  const hoverX = $derived(hover === null ? 0 : xAt(hover));

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
      <path
        d={linePath}
        fill="none"
        stroke={color}
        stroke-width="1.5"
        stroke-linejoin="round"
        stroke-linecap="round"
      />
      {#if hover !== null}
        <line
          x1={hoverX}
          y1={pad}
          x2={hoverX}
          y2={height}
          stroke={color}
          stroke-width="1"
          stroke-opacity="0.35"
        />
        <circle cx={hoverX} cy={yAt(plotted[hover])} r="2.75" fill={color} />
      {/if}
    </svg>
    {#if hover !== null}
      <div
        class="spark-tip"
        style="left:{Math.max(0, Math.min(w - 1, hoverX))}px"
        class:flip={hoverX > w / 2}
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
  /* Keep edge tooltips on-canvas. */
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
