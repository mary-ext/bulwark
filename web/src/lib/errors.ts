// Helpers for working with the error oazapfts throws (`HttpError`) from `ok(...)`.

import { HttpError } from "@oazapfts/runtime";

/** True when `e` is an oazapfts HttpError carrying the given HTTP status. */
export function isStatus(e: unknown, status: number): boolean {
  return e instanceof HttpError && e.status === status;
}

/**
 * Best-effort human message from a thrown API error: the server's
 * `{ "error": ... }` body when present, otherwise the provided fallback.
 */
export function errMsg(e: unknown, fallback: string): string {
  if (e instanceof HttpError) {
    const data = e.data as { error?: string } | undefined;
    return data?.error ?? fallback;
  }
  return fallback;
}
