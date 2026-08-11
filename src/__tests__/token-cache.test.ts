import { describe, expect, test } from "bun:test";
import { MAX_TOKEN_REFRESH_MARGIN_MS, tokenRefreshAt } from "../token-cache.ts";

describe("tokenRefreshAt", () => {
  test("keeps the five-minute margin for an hour-long token", () => {
    const observedAt = 1_000;
    const expiresAt = observedAt + 60 * 60 * 1000;
    expect(tokenRefreshAt(expiresAt, observedAt)).toBe(expiresAt - MAX_TOKEN_REFRESH_MARGIN_MS);
  });

  test("uses a bounded fractional margin for a short token", () => {
    const observedAt = 1_000;
    const expiresAt = observedAt + 60_000;
    expect(tokenRefreshAt(expiresAt, observedAt)).toBe(expiresAt - 6_000);
  });

  test("marks an already-expired token stale immediately", () => {
    expect(tokenRefreshAt(500, 1_000)).toBe(500);
  });
});
