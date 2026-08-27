// Shared reactive media queries.

class MediaQuery {
  matches = $state(false);

  constructor(query: string) {
    const mql = window.matchMedia(query);
    this.matches = mql.matches;
    mql.addEventListener("change", (e) => (this.matches = e.matches));
  }
}

/** Mobile layout breakpoint. */
export const isMobile = new MediaQuery("(max-width: 768px)");
