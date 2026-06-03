// Reactive matchMedia as a rune. Singletons are shared across all consumers so
// we register one listener per query, not one per component.

class MediaQuery {
  matches = $state(false);

  constructor(query: string) {
    const mql = window.matchMedia(query);
    this.matches = mql.matches;
    mql.addEventListener("change", (e) => (this.matches = e.matches));
  }
}

/** True below the shell/table breakpoint (sidebar → drawer, tables → cards). */
export const isMobile = new MediaQuery("(max-width: 768px)");
