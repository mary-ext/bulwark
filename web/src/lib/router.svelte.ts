// Shared hash-based route state.

import type { IconName } from "./icons";

export type RouteId =
  | "dashboard"
  | "querylog"
  | "filters"
  | "upstreams"
  | "clients"
  | "settings";

export const NAV: { id: RouteId; label: string; icon: IconName }[] = [
  { id: "dashboard", label: "Dashboard", icon: "dashboard" },
  { id: "querylog", label: "Query Log", icon: "list" },
  { id: "filters", label: "Filters", icon: "shield" },
  { id: "upstreams", label: "Upstreams", icon: "globe" },
  { id: "clients", label: "Clients", icon: "monitor" },
  { id: "settings", label: "Settings", icon: "settings" },
];

function parse(): RouteId {
  const id = location.hash.replace(/^#\/?/, "") || "dashboard";
  return (NAV.some((n) => n.id === id) ? id : "dashboard") as RouteId;
}

class Router {
  route = $state<RouteId>(parse());

  constructor() {
    window.addEventListener("hashchange", () => (this.route = parse()));
  }

  go(id: RouteId) {
    location.hash = "/" + id;
  }
}

export const router = new Router();
