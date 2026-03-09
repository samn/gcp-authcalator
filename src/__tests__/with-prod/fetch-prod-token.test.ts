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
  test("fetches token and identity with correct URLs", async () => {
    const capturedUrls: string[] = [];

    const fetchFn = (async (url: string) => {
      capturedUrls.push(url);
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

    const result = await fetchProdToken(
      { mode: "unix" as const, socketPath: "/tmp/gate.sock" },
      { fetchFn },
    );

    expect(capturedUrls).toContain("http://localhost/token?level=prod");
    expect(capturedUrls).toContain("http://localhost/identity");
    expect(result.access_token).toBe("prod-tok-123");
    expect(result.expires_in).toBe(1800);
    expect(result.email).toBe("alice@corp.com");
  });

  test("defaults expires_in to 3600 when not provided", async () => {
    const fetchFn = mockGateFetch({ access_token: "tok" });
    const result = await fetchProdToken(
      { mode: "unix" as const, socketPath: "/tmp/gate.sock" },
      { fetchFn },
    );

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

    await expect(
      fetchProdToken({ mode: "unix" as const, socketPath: "/tmp/gate.sock" }, { fetchFn }),
    ).rejects.toThrow("gcp-gate returned 403: forbidden");
  });

  test("throws when access_token is missing", async () => {
    const fetchFn = mockGateFetch({ expires_in: 3600 });

    await expect(
      fetchProdToken({ mode: "unix" as const, socketPath: "/tmp/gate.sock" }, { fetchFn }),
    ).rejects.toThrow("gcp-gate returned no access_token");
  });

  test("throws on non-OK identity response", async () => {
    const fetchFn = mockGateFetch(
      { access_token: "tok", expires_in: 1800 },
      {},
      { identityStatus: 500 },
    );

    await expect(
      fetchProdToken({ mode: "unix" as const, socketPath: "/tmp/gate.sock" }, { fetchFn }),
    ).rejects.toThrow("gcp-gate /identity returned 500");
  });

  test("throws when identity email is missing", async () => {
    const fetchFn = mockGateFetch({ access_token: "tok", expires_in: 1800 }, {});

    await expect(
      fetchProdToken({ mode: "unix" as const, socketPath: "/tmp/gate.sock" }, { fetchFn }),
    ).rejects.toThrow("gcp-gate /identity returned no email");
  });

  test("sends X-Wrapped-Command header when command is provided", async () => {
    let capturedHeaders: Headers | undefined;

    const fetchFn = (async (url: string, init: RequestInit) => {
      const parsed = new URL(url);
      if (parsed.pathname === "/token") {
        capturedHeaders = new Headers(init.headers);
        return new Response(JSON.stringify({ access_token: "tok", expires_in: 1800 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ email: "eng@example.com" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    await fetchProdToken(
      { mode: "unix" as const, socketPath: "/tmp/gate.sock" },
      {
        fetchFn,
        command: ["gcloud", "compute", "instances", "list"],
      },
    );

    expect(capturedHeaders).toBeDefined();
    const headerValue = capturedHeaders!.get("X-Wrapped-Command");
    expect(headerValue).toBe(JSON.stringify(["gcloud", "compute", "instances", "list"]));
  });

  test("does not send X-Wrapped-Command header when command is not provided", async () => {
    let capturedHeaders: Headers | undefined;

    const fetchFn = (async (url: string, init: RequestInit) => {
      const parsed = new URL(url);
      if (parsed.pathname === "/token") {
        capturedHeaders = new Headers(init.headers);
        return new Response(JSON.stringify({ access_token: "tok", expires_in: 1800 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ email: "eng@example.com" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    await fetchProdToken({ mode: "unix" as const, socketPath: "/tmp/gate.sock" }, { fetchFn });

    expect(capturedHeaders).toBeDefined();
    const headerValue = capturedHeaders!.get("X-Wrapped-Command");
    expect(headerValue).toBeNull();
  });
});

describe("fetchProdToken — TCP mode", () => {
  const tcpConn = {
    mode: "tcp" as const,
    gateUrl: "https://localhost:8174",
    caCert: "ca-cert-pem",
    clientCert: "client-cert-pem",
    clientKey: "client-key-pem",
  };

  test("fetches token and identity using TCP connection with TLS options", async () => {
    const capturedUrls: string[] = [];
    let capturedTls: unknown;

    const fetchFn = (async (url: string, opts: RequestInit) => {
      capturedUrls.push(url);
      capturedTls = (opts as Record<string, unknown>).tls;
      const parsed = new URL(url);
      if (parsed.pathname === "/token") {
        return new Response(JSON.stringify({ access_token: "tcp-prod-tok", expires_in: 900 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ email: "tcp-eng@corp.com" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    const result = await fetchProdToken(tcpConn, { fetchFn });

    expect(capturedUrls).toContain("https://localhost:8174/token?level=prod");
    expect(capturedUrls).toContain("https://localhost:8174/identity");
    expect(result.access_token).toBe("tcp-prod-tok");
    expect(result.expires_in).toBe(900);
    expect(result.email).toBe("tcp-eng@corp.com");
    expect(capturedTls).toEqual({
      cert: "client-cert-pem",
      key: "client-key-pem",
      ca: "ca-cert-pem",
    });
  });

  test("throws on non-OK token response in TCP mode", async () => {
    const fetchFn = (async (url: string) => {
      const parsed = new URL(url);
      if (parsed.pathname === "/token") {
        return new Response("denied", { status: 403 });
      }
      return new Response(JSON.stringify({ email: "a@b.com" }), { status: 200 });
    }) as unknown as typeof globalThis.fetch;

    await expect(fetchProdToken(tcpConn, { fetchFn })).rejects.toThrow(
      "gcp-gate returned 403: denied",
    );
  });
});
