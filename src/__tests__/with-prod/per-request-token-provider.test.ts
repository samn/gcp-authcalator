import { describe, expect, test } from "bun:test";
import { createPerRequestTokenProvider } from "../../with-prod/per-request-token-provider.ts";
import type { GateConnection } from "../../gate/connection.ts";
import type { CachedToken } from "../../gate/types.ts";

const unixConn: GateConnection = { mode: "unix", socketPath: "/tmp/test.sock" };

function mockFetch(responses: Array<{ status: number; body?: Record<string, unknown> }>): {
  fetchFn: typeof globalThis.fetch;
  callCount: () => number;
  capturedUrls: string[];
} {
  let idx = 0;
  const capturedUrls: string[] = [];
  const fn = (async (url: string) => {
    capturedUrls.push(url);
    const resp = responses[idx++];
    if (!resp) throw new Error("No more mock responses");
    return new Response(JSON.stringify(resp.body ?? {}), {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;

  return { fetchFn: fn, callCount: () => idx, capturedUrls };
}

describe("createPerRequestTokenProvider", () => {
  const validInitialToken: CachedToken = {
    access_token: "initial-token",
    expires_at: new Date(Date.now() + 3600_000),
  };

  test("returns initial token from cache without fetching", async () => {
    const { fetchFn, callCount } = mockFetch([]);
    const provider = createPerRequestTokenProvider(unixConn, validInitialToken, {
      fetchFn,
    });

    const token = await provider.getToken();
    expect(token.access_token).toBe("initial-token");
    expect(callCount()).toBe(0);
  });

  test("re-fetches via fetchProdToken when cache expires", async () => {
    const expiringToken: CachedToken = {
      access_token: "old-token",
      expires_at: new Date(Date.now() + 60_000), // inside 5-min margin
    };
    const { fetchFn, capturedUrls } = mockFetch([
      { status: 200, body: { access_token: "fresh-token", expires_in: 3600 } },
      { status: 200, body: { email: "u@example.com" } },
    ]);
    const provider = createPerRequestTokenProvider(unixConn, expiringToken, {
      fetchFn,
    });

    const token = await provider.getToken();
    expect(token.access_token).toBe("fresh-token");
    // Per-request mode goes to /token?level=prod, never /token?session=...
    expect(capturedUrls[0]).toContain("/token?level=prod");
    expect(capturedUrls[0]).not.toContain("session=");
  });

  test("invokes onRefresh after a successful re-fetch", async () => {
    const expiringToken: CachedToken = {
      access_token: "old-token",
      expires_at: new Date(Date.now() + 60_000),
    };
    const { fetchFn } = mockFetch([
      { status: 200, body: { access_token: "fresh-token", expires_in: 3600 } },
      { status: 200, body: { email: "u@example.com" } },
    ]);
    let refreshed: CachedToken | undefined;
    const provider = createPerRequestTokenProvider(unixConn, expiringToken, {
      fetchFn,
      onRefresh: (t) => {
        refreshed = t;
      },
    });

    await provider.getToken();
    expect(refreshed?.access_token).toBe("fresh-token");
  });

  test("does NOT refresh when initial token is still valid", async () => {
    const { fetchFn, callCount } = mockFetch([]);
    const provider = createPerRequestTokenProvider(unixConn, validInitialToken, {
      fetchFn,
    });

    await provider.getToken();
    await provider.getToken();
    expect(callCount()).toBe(0);
  });

  test("forwards command, scopes, and pamPolicy on refresh", async () => {
    const expiringToken: CachedToken = {
      access_token: "old-token",
      expires_at: new Date(Date.now() + 60_000),
    };
    const { fetchFn, capturedUrls } = mockFetch([
      { status: 200, body: { access_token: "fresh", expires_in: 3600 } },
      { status: 200, body: { email: "u@example.com" } },
    ]);
    const provider = createPerRequestTokenProvider(unixConn, expiringToken, {
      fetchFn,
      command: ["gcloud", "projects", "list"],
      scopes: ["https://www.googleapis.com/auth/cloud-platform"],
      pamPolicy: "projects/p/locations/global/entitlements/e",
    });

    await provider.getToken();
    expect(capturedUrls[0]).toContain("scopes=");
    expect(capturedUrls[0]).toContain("pam_policy=");
  });
});
