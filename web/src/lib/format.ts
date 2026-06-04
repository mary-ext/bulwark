export function num(n: number): string {
  return n.toLocaleString();
}

export function pct(frac: number): string {
  return (frac * 100).toFixed(1) + "%";
}

/**
 * Round a list of `counts` to whole-percent shares of `denom` using the
 * largest-remainder (Hamilton) method, so the displayed integers add up to the
 * same total the exact shares would (100 when `denom` is the sum of `counts`,
 * less when `denom` is a larger grand total). Rounding each share independently
 * with `toFixed(0)` lets the column drift past 100%; this distributes the
 * leftover points to the rows with the largest fractional remainders instead.
 */
export function sharePcts(counts: number[], denom: number): number[] {
  if (denom <= 0) return counts.map(() => 0);
  const exact = counts.map((c) => (c / denom) * 100);
  const floors = exact.map(Math.floor);
  const target = Math.round(exact.reduce((s, v) => s + v, 0));
  let leftover = target - floors.reduce((s, v) => s + v, 0);
  // Hand out the remaining whole points to the largest fractional parts first.
  const order = exact
    .map((v, i) => ({ i, frac: v - Math.floor(v) }))
    .sort((a, b) => b.frac - a.frac);
  for (const { i } of order) {
    if (leftover <= 0) break;
    floors[i] += 1;
    leftover -= 1;
  }
  return floors;
}

// Reused across every render; instantiating Intl.NumberFormat is comparatively
// expensive, so keep one per (unit, precision) we display. `style: "unit"` lets
// the formatter emit the locale-aware unit label ("ms", "μs", "s") for us.
const unitFmt = (unit: string, max: number) =>
  new Intl.NumberFormat(undefined, {
    style: "unit",
    unit,
    unitDisplay: "short",
    maximumFractionDigits: max,
  });
const usFmt1 = unitFmt("microsecond", 1);
const usFmt0 = unitFmt("microsecond", 0);
const msFmt = unitFmt("millisecond", 1);
const sFmt = unitFmt("second", 2);

/**
 * Format a duration given in **milliseconds**, auto-scaling the unit so
 * sub-millisecond values (e.g. cache hits at ~0.001 ms) stay legible as
 * microseconds instead of collapsing to "0.00 ms".
 */
export function duration(milliseconds: number | null | undefined): string {
  if (milliseconds == null) return "—";
  if (milliseconds <= 0) return msFmt.format(0);
  if (milliseconds < 1) {
    const us = milliseconds * 1000;
    return (us < 10 ? usFmt1 : usFmt0).format(us);
  }
  if (milliseconds < 1000) return msFmt.format(milliseconds);
  return sFmt.format(milliseconds / 1000);
}

export function relTime(epochMs: number): string {
  const diff = Date.now() - epochMs;
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return new Date(epochMs).toLocaleDateString();
}

export function dateTime(epochMs: number): string {
  return new Date(epochMs).toLocaleString();
}

/** Parse a comma-separated input into a trimmed, non-empty string list. */
export function parseList(v: string): string[] {
  return v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
