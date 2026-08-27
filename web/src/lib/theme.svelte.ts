// Persistent `data-theme` state; no attribute means light mode.

export type Theme = "light" | "dark";
const KEY = "bulwark-theme";

function initial(): Theme {
  const saved = localStorage.getItem(KEY);
  return saved === "dark" ? "dark" : "light";
}

class ThemeStore {
  current = $state<Theme>(initial());

  constructor() {
    this.#apply();
  }

  #apply() {
    document.documentElement.setAttribute("data-theme", this.current);
  }

  set(t: Theme) {
    this.current = t;
    localStorage.setItem(KEY, t);
    this.#apply();
  }

  toggle() {
    this.set(this.current === "light" ? "dark" : "light");
  }
}

export const theme = new ThemeStore();
