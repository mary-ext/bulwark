// Global API session-expiry state.

import { defaults } from "../api/generated";

let expired = $state(false);

export const session = {
  /** Set after an API request returns 401. */
  get expired() {
    return expired;
  },
  /** Clear after authentication. */
  clear() {
    expired = false;
  },
};

// Detect 401 responses without modifying generated code.
const base = defaults.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
defaults.fetch = async (input, init) => {
  const res = await base(input, init);
  if (res.status === 401) expired = true;
  return res;
};
