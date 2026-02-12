import { describe, expect, test } from "bun:test";
import { createGateClient } from "../../metadata-proxy/gate-client.ts";

function mockFetch(
  token: string,
  expiresIn = 3600,
): { fetchFn: typeof globalThis.fetch; callCount: () => number } {
  let count = 0;
  const fetchFn = (async () => {
    count++;
    return new Response(
      JSON.stringify({ access_token: token, expires_in: expiresIn, token_type: "Bearer" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }) as unknown as typeof globalThis.fetch;

  return { fetchFn, callCount: () => count };
}

function mockFetchError(status: number, body: string): typeof globalThis.fetch {
  return (async () => new Response(body, { status })) as unknown as typeof globalThis.fetch;
}

describe("createGateClient", () => {
  test("fetches token from gate daemon", async () => {
    const { fetchFn } = mockFetch("test-token-abc");
    const client = createGateClient("/tmp/test.sock", { fetchFn });

    const result = await client.getToken();
    expect(result.access_token).toBe("test-token-abc");
    expect(result.expires_at).toBeInstanceOf(Date);
    expect(result.expires_at.getTime()).toBeGreaterThan(Date.now());
  });

  test("caches token on subsequent calls", async () => {
    const { fetchFn, callCount } = mockFetch("cached-token");
    const client = createGateClient("/tmp/test.sock", { fetchFn });

    const first = await client.getToken();
    const second = await client.getToken();

    expect(first.access_token).toBe("cached-token");
    expect(second.access_token).toBe("cached-token");
    expect(callCount()).toBe(1);
  });

  test("re-fetches when token is about to expire", async () => {
    let count = 0;
    const fetchFn = (async () => {
      count++;
      // First call: token that expires in 2 minutes (below 5-min margin)
      // Second call: fresh token
      const expiresIn = count === 1 ? 120 : 3600;
      return new Response(
        JSON.stringify({
          access_token: `token-${count}`,
          expires_in: expiresIn,
          token_type: "Bearer",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof globalThis.fetch;

    const client = createGateClient("/tmp/test.sock", { fetchFn });

    const first = await client.getToken();
    expect(first.access_token).toBe("token-1");

    // Should re-fetch because expires_in of 120s < 300s margin
    const second = await client.getToken();
    expect(second.access_token).toBe("token-2");
    expect(count).toBe(2);
  });

  test("throws on non-OK response", async () => {
    const fetchFn = mockFetchError(500, '{"error":"internal error"}');
    const client = createGateClient("/tmp/test.sock", { fetchFn });

    await expect(client.getToken()).rejects.toThrow("gcp-gate returned 500");
  });

  test("throws when response has no access_token", async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ expires_in: 3600 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as unknown as typeof globalThis.fetch;

    const client = createGateClient("/tmp/test.sock", { fetchFn });

    await expect(client.getToken()).rejects.toThrow("no access_token");
  });

  test("defaults expires_in to 3600 when not provided", async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ access_token: "tok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as unknown as typeof globalThis.fetch;

    const client = createGateClient("/tmp/test.sock", { fetchFn });

    const result = await client.getToken();
    // Should expire roughly 1 hour from now
    const expectedMin = Date.now() + 3500 * 1000;
    const expectedMax = Date.now() + 3700 * 1000;
    expect(result.expires_at.getTime()).toBeGreaterThan(expectedMin);
    expect(result.expires_at.getTime()).toBeLessThan(expectedMax);
  });
});
