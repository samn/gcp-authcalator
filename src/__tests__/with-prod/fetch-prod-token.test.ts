import { describe, expect, test } from "bun:test";
import { fetchProdToken } from "../../with-prod/fetch-prod-token.ts";

/**
 * Creates a URL-aware mock fetch that returns different responses for
 * /token and /identity endpoints.
 */
function mockGateFetch(
  tokenBody: Record<string, unknown> = { access_token: "tok", expires_in: 1800 },
  identityBody: Record<string, unknown> = { email: "eng@example.com" },
  overrides?: { tokenStatus?: number; identityStatus?: number },
): typeof globalThis.fetch {
  return (async (url: string) => {
    const parsed = new URL(url);
    if (parsed.pathname === "/token") {
      return new Response(JSON.stringify(tokenBody), {
        status: overrides?.tokenStatus ?? 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (parsed.pathname === "/identity") {
      return new Response(JSON.stringify(identityBody), {
        status: overrides?.identityStatus ?? 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  }) as unknown as typeof globalThis.fetch;
}

describe("fetchProdToken", () => {
  test("fetches token and identity with correct URLs and unix socket option", async () => {
    const capturedUrls: string[] = [];
    let capturedUnix = "";

    const fetchFn = (async (url: string, init: Record<string, unknown>) => {
      capturedUrls.push(url);
      capturedUnix = init.unix as string;
      const parsed = new URL(url);
      if (parsed.pathname === "/token") {
        return new Response(JSON.stringify({ access_token: "prod-tok-123", expires_in: 1800 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ email: "alice@corp.com" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    const result = await fetchProdToken("/tmp/gate.sock", { fetchFn });

    expect(capturedUrls).toContain("http://localhost/token?level=prod");
    expect(capturedUrls).toContain("http://localhost/identity");
    expect(capturedUnix).toBe("/tmp/gate.sock");
    expect(result.access_token).toBe("prod-tok-123");
    expect(result.expires_in).toBe(1800);
    expect(result.email).toBe("alice@corp.com");
  });

  test("defaults expires_in to 3600 when not provided", async () => {
    const fetchFn = mockGateFetch({ access_token: "tok" });
    const result = await fetchProdToken("/tmp/gate.sock", { fetchFn });

    expect(result.access_token).toBe("tok");
    expect(result.expires_in).toBe(3600);
  });

  test("throws on non-OK token response", async () => {
    const fetchFn = (async (url: string) => {
      const parsed = new URL(url);
      if (parsed.pathname === "/token") {
        return new Response("forbidden", { status: 403 });
      }
      return new Response(JSON.stringify({ email: "a@b.com" }), { status: 200 });
    }) as unknown as typeof globalThis.fetch;

    await expect(fetchProdToken("/tmp/gate.sock", { fetchFn })).rejects.toThrow(
      "gcp-gate returned 403: forbidden",
    );
  });

  test("throws when access_token is missing", async () => {
    const fetchFn = mockGateFetch({ expires_in: 3600 });

    await expect(fetchProdToken("/tmp/gate.sock", { fetchFn })).rejects.toThrow(
      "gcp-gate returned no access_token",
    );
  });

  test("throws on non-OK identity response", async () => {
    const fetchFn = mockGateFetch(
      { access_token: "tok", expires_in: 1800 },
      {},
      { identityStatus: 500 },
    );

    await expect(fetchProdToken("/tmp/gate.sock", { fetchFn })).rejects.toThrow(
      "gcp-gate /identity returned 500",
    );
  });

  test("throws when identity email is missing", async () => {
    const fetchFn = mockGateFetch({ access_token: "tok", expires_in: 1800 }, {});

    await expect(fetchProdToken("/tmp/gate.sock", { fetchFn })).rejects.toThrow(
      "gcp-gate /identity returned no email",
    );
  });
});
