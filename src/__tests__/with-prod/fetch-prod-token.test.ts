import { describe, expect, test } from "bun:test";
import { fetchProdToken } from "../../with-prod/fetch-prod-token.ts";

function mockFetch(body: Record<string, unknown>, status = 200): typeof globalThis.fetch {
  return (async (url: string, init: RequestInit & { unix?: string }) => {
    // Capture call info for assertions
    (mockFetch as unknown as Record<string, unknown>)._lastUrl = url;
    (mockFetch as unknown as Record<string, unknown>)._lastInit = init;
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;
}

function mockFetchText(text: string, status: number): typeof globalThis.fetch {
  return (async () => new Response(text, { status })) as unknown as typeof globalThis.fetch;
}

describe("fetchProdToken", () => {
  test("fetches with ?level=prod and unix socket option", async () => {
    let capturedUrl = "";
    let capturedInit: Record<string, unknown> = {};

    const fetchFn = (async (url: string, init: Record<string, unknown>) => {
      capturedUrl = url;
      capturedInit = init;
      return new Response(JSON.stringify({ access_token: "prod-tok-123", expires_in: 1800 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    const result = await fetchProdToken("/tmp/gate.sock", { fetchFn });

    expect(capturedUrl).toBe("http://localhost/token?level=prod");
    expect(capturedInit.unix).toBe("/tmp/gate.sock");
    expect(result.access_token).toBe("prod-tok-123");
    expect(result.expires_in).toBe(1800);
  });

  test("defaults expires_in to 3600 when not provided", async () => {
    const fetchFn = mockFetch({ access_token: "tok" });
    const result = await fetchProdToken("/tmp/gate.sock", { fetchFn });

    expect(result.access_token).toBe("tok");
    expect(result.expires_in).toBe(3600);
  });

  test("throws on non-OK response", async () => {
    const fetchFn = mockFetchText("forbidden", 403);

    await expect(fetchProdToken("/tmp/gate.sock", { fetchFn })).rejects.toThrow(
      "gcp-gate returned 403: forbidden",
    );
  });

  test("throws when access_token is missing", async () => {
    const fetchFn = mockFetch({ expires_in: 3600 });

    await expect(fetchProdToken("/tmp/gate.sock", { fetchFn })).rejects.toThrow(
      "gcp-gate returned no access_token",
    );
  });
});
