// oazapfts error helpers.

import { HttpError } from "@oazapfts/runtime";

/** Checks an oazapfts HTTP status. */
export function isStatus(e: unknown, status: number): boolean {
  return e instanceof HttpError && e.status === status;
}

/** Extracts an API error message or returns `fallback`. */
export function errMsg(e: unknown, fallback: string): string {
  if (e instanceof HttpError) {
    const data = e.data as { error?: string } | undefined;
    return data?.error ?? fallback;
  }
  return fallback;
}
