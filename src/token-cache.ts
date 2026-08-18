/** Long-lived OAuth tokens keep the conventional five-minute refresh margin. */
export const MAX_TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;

/** Short-lived tokens reserve ten percent of their observed lifetime. */
const SHORT_TOKEN_REFRESH_FRACTION = 0.1;

/**
 * Compute when a token should be refreshed from the lifetime observed when it
 * entered the cache. A fixed five-minute margin makes every token with a TTL of
 * five minutes or less stale immediately; the bounded fraction keeps those
 * supported short TTLs cacheable while preserving the conventional margin for
 * hour-long tokens.
 */
export function tokenRefreshAt(expiresAtMs: number, observedAtMs: number): number {
  const lifetimeMs = Math.max(0, expiresAtMs - observedAtMs);
  const marginMs = Math.min(MAX_TOKEN_REFRESH_MARGIN_MS, lifetimeMs * SHORT_TOKEN_REFRESH_FRACTION);
  return expiresAtMs - marginMs;
}
