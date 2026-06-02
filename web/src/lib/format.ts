export function num(n: number): string {
  return n.toLocaleString();
}

export function pct(frac: number): string {
  return (frac * 100).toFixed(1) + "%";
}

export function ms(v: number | null | undefined): string {
  if (v == null) return "—";
  if (v < 1) return v.toFixed(2) + " ms";
  if (v < 1000) return v.toFixed(1) + " ms";
  return (v / 1000).toFixed(2) + " s";
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
