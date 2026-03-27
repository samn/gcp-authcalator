import { describe, expect, test } from "bun:test";
import { createSessionTokenProvider } from "../../with-prod/session-token-provider.ts";
import type { GateConnection } from "../../gate/connection.ts";
import type { CachedToken } from "../../gate/types.ts";

const unixConn: GateConnection = { mode: "unix", socketPath: "/tmp/test.sock" };

function mockFetch(responses: Array<{ status: number; body: Record<string, unknown> }>): {
  fetchFn: typeof globalThis.fetch;
  callCount: () => number;
} {
  let idx = 0;
  const fn = (async () => {
    const resp = responses[idx++];
    if (!resp) throw new Error("No more mock responses");
    return new Response(JSON.stringify(resp.body), {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;

  return { fetchFn: fn, callCount: () => idx };
}

describe("createSessionTokenProvider", () => {
  const validInitialToken: CachedToken = {
    access_token: "initial-token",
    expires_at: new Date(Date.now() + 3600_000),
  };

  test("returns initial token from cache without fetching", async () => {
    const { fetchFn, callCount } = mockFetch([]);
    const provider = createSessionTokenProvider(unixConn, "session-id", validInitialToken, {
      fetchFn,
    });

    const token = await provider.getToken();
    expect(token.access_token).toBe("initial-token");
    expect(callCount()).toBe(0);
  });

  test("returns same cached token on repeated calls", async () => {
    const { fetchFn, callCount } = mockFetch([]);
    const provider = createSessionTokenProvider(unixConn, "session-id", validInitialToken, {
      fetchFn,
    });

    const first = await provider.getToken();
    const second = await provider.getToken();
    expect(first).toBe(second);
    expect(callCount()).toBe(0);
  });

  test("re-fetches when token is near expiry (within 5-min margin)", async () => {
    const nearExpiry: CachedToken = {
      access_token: "old-token",
      expires_at: new Date(Date.now() + 2 * 60 * 1000), // 2 minutes left
    };

    const { fetchFn } = mockFetch([
      { status: 200, body: { access_token: "new-token", expires_in: 3600 } },
    ]);
    const provider = createSessionTokenProvider(unixConn, "session-id", nearExpiry, { fetchFn });

    const token = await provider.getToken();
    expect(token.access_token).toBe("new-token");
  });

  test("calls onRefresh callback after successful refresh", async () => {
    const nearExpiry: CachedToken = {
      access_token: "old-token",
      expires_at: new Date(Date.now() + 60_000), // 1 minute left
    };

    let refreshedToken: CachedToken | undefined;
    const { fetchFn } = mockFetch([
      { status: 200, body: { access_token: "refreshed-token", expires_in: 3600 } },
    ]);
    const provider = createSessionTokenProvider(unixConn, "session-id", nearExpiry, {
      fetchFn,
      onRefresh: (t) => {
        refreshedToken = t;
      },
    });

    await provider.getToken();
    expect(refreshedToken).toBeDefined();
    expect(refreshedToken!.access_token).toBe("refreshed-token");
  });

  test("does not call onRefresh on cache hit", async () => {
    let refreshCalled = false;
    const { fetchFn } = mockFetch([]);
    const provider = createSessionTokenProvider(unixConn, "session-id", validInitialToken, {
      fetchFn,
      onRefresh: () => {
        refreshCalled = true;
      },
    });

    await provider.getToken();
    expect(refreshCalled).toBe(false);
  });

  test("throws descriptive error on 401 (session expired)", async () => {
    const expired: CachedToken = {
      access_token: "old",
      expires_at: new Date(Date.now() - 1000),
    };

    const { fetchFn } = mockFetch([{ status: 401, body: { error: "Session expired or invalid" } }]);
    const provider = createSessionTokenProvider(unixConn, "session-id", expired, { fetchFn });

    await expect(provider.getToken()).rejects.toThrow(
      /Prod session expired or revoked.*Re-run with-prod/,
    );
  });

  test("throws on non-OK response", async () => {
    const expired: CachedToken = {
      access_token: "old",
      expires_at: new Date(Date.now() - 1000),
    };

    const { fetchFn } = mockFetch([{ status: 500, body: { error: "Internal error" } }]);
    const provider = createSessionTokenProvider(unixConn, "session-id", expired, { fetchFn });

    await expect(provider.getToken()).rejects.toThrow("gcp-gate returned 500");
  });

  test("throws when response has no access_token", async () => {
    const expired: CachedToken = {
      access_token: "old",
      expires_at: new Date(Date.now() - 1000),
    };

    const { fetchFn } = mockFetch([{ status: 200, body: { expires_in: 3600 } }]);
    const provider = createSessionTokenProvider(unixConn, "session-id", expired, { fetchFn });

    await expect(provider.getToken()).rejects.toThrow("no access_token");
  });

  test("defaults expires_in to 3600 when missing", async () => {
    const expired: CachedToken = {
      access_token: "old",
      expires_at: new Date(Date.now() - 1000),
    };

    const { fetchFn } = mockFetch([{ status: 200, body: { access_token: "new-token" } }]);
    const provider = createSessionTokenProvider(unixConn, "session-id", expired, { fetchFn });

    const token = await provider.getToken();
    expect(token.access_token).toBe("new-token");
    // Expires roughly 1 hour from now
    const diffMs = token.expires_at.getTime() - Date.now();
    expect(diffMs).toBeGreaterThan(3500_000);
    expect(diffMs).toBeLessThanOrEqual(3600_000);
  });

  test("caches the refreshed token for subsequent calls", async () => {
    const nearExpiry: CachedToken = {
      access_token: "old-token",
      expires_at: new Date(Date.now() + 60_000),
    };

    const { fetchFn, callCount } = mockFetch([
      { status: 200, body: { access_token: "new-token", expires_in: 3600 } },
    ]);
    const provider = createSessionTokenProvider(unixConn, "session-id", nearExpiry, { fetchFn });

    const first = await provider.getToken();
    expect(first.access_token).toBe("new-token");
    expect(callCount()).toBe(1);

    // Second call should use cache
    const second = await provider.getToken();
    expect(second.access_token).toBe("new-token");
    expect(callCount()).toBe(1);
  });
});
