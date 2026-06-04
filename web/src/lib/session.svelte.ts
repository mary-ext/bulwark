// Global session state. Any API response that comes back 401 flips `expired`,
// so the app can drop straight back to the login screen instead of leaving
// stale privileged data (query logs, config) on screen after the session ends.

import { defaults } from "../api/generated";

let expired = $state(false);

export const session = {
  /** True once any API call returned 401, until the next successful auth. */
  get expired() {
    return expired;
  },
  /** Reset after a successful (re-)authentication. */
  clear() {
    expired = false;
  },
};

// Wrap the API client's fetch so every response is checked for 401. Mutating
// `defaults.fetch` (rather than editing the generated client) survives client
// regeneration. Installed once, at import time, before any request is made.
const base = defaults.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
defaults.fetch = async (input, init) => {
  const res = await base(input, init);
  if (res.status === 401) expired = true;
  return res;
};
