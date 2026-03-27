import { describe, expect, test } from "bun:test";
import {
  fetchProdToken,
  createProdSession,
  revokeProdSession,
} from "../../with-prod/fetch-prod-token.ts";

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

  test("includes scopes in token URL query parameter when scopes provided", async () => {
    let capturedTokenUrl = "";

    const fetchFn = (async (url: string) => {
      const parsed = new URL(url);
      if (parsed.pathname === "/token") {
        capturedTokenUrl = url;
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
      { mode: "unix", socketPath: "/tmp/gate.sock" },
      {
        fetchFn,
        scopes: ["https://www.googleapis.com/auth/sqlservice.login"],
      },
    );

    expect(capturedTokenUrl).toContain("level=prod");
    expect(capturedTokenUrl).toContain(
      `scopes=${encodeURIComponent("https://www.googleapis.com/auth/sqlservice.login")}`,
    );
  });

  test("includes token_ttl_seconds in token URL when provided", async () => {
    let capturedTokenUrl = "";

    const fetchFn = (async (url: string) => {
      const parsed = new URL(url);
      if (parsed.pathname === "/token") {
        capturedTokenUrl = url;
        return new Response(JSON.stringify({ access_token: "tok", expires_in: 900 }), {
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
      { mode: "unix", socketPath: "/tmp/gate.sock" },
      { fetchFn, tokenTtlSeconds: 900 },
    );

    expect(capturedTokenUrl).toContain("token_ttl_seconds=900");
  });

  test("omits token_ttl_seconds from token URL when not provided", async () => {
    let capturedTokenUrl = "";

    const fetchFn = (async (url: string) => {
      const parsed = new URL(url);
      if (parsed.pathname === "/token") {
        capturedTokenUrl = url;
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

    await fetchProdToken({ mode: "unix", socketPath: "/tmp/gate.sock" }, { fetchFn });

    expect(capturedTokenUrl).not.toContain("token_ttl_seconds");
  });

  test("omits scopes from token URL when scopes not provided", async () => {
    let capturedTokenUrl = "";

    const fetchFn = (async (url: string) => {
      const parsed = new URL(url);
      if (parsed.pathname === "/token") {
        capturedTokenUrl = url;
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

    await fetchProdToken({ mode: "unix", socketPath: "/tmp/gate.sock" }, { fetchFn });

    expect(capturedTokenUrl).toContain("/token?level=prod");
    expect(capturedTokenUrl).not.toContain("scopes");
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

// ---------------------------------------------------------------------------
// createProdSession
// ---------------------------------------------------------------------------

describe("createProdSession", () => {
  const unixConn = { mode: "unix" as const, socketPath: "/tmp/gate.sock" };

  function mockSessionFetch(
    body: Record<string, unknown> = {
      session_id: "abc123",
      access_token: "prod-tok",
      expires_in: 1800,
      email: "eng@example.com",
    },
    status = 200,
  ): { fetchFn: typeof globalThis.fetch; capturedUrls: string[]; capturedMethods: string[] } {
    const capturedUrls: string[] = [];
    const capturedMethods: string[] = [];
    const fn = (async (url: string, init?: RequestInit) => {
      capturedUrls.push(url);
      capturedMethods.push(init?.method ?? "GET");
      return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;
    return { fetchFn: fn, capturedUrls, capturedMethods };
  }

  test("sends POST to /session", async () => {
    const { fetchFn, capturedUrls, capturedMethods } = mockSessionFetch();
    await createProdSession(unixConn, { fetchFn });

    expect(capturedUrls[0]).toContain("/session");
    expect(capturedMethods[0]).toBe("POST");
  });

  test("returns session_id, access_token, expires_in, email", async () => {
    const { fetchFn } = mockSessionFetch();
    const result = await createProdSession(unixConn, { fetchFn });

    expect(result.session_id).toBe("abc123");
    expect(result.access_token).toBe("prod-tok");
    expect(result.expires_in).toBe(1800);
    expect(result.email).toBe("eng@example.com");
  });

  test("includes scopes, pam_policy, token_ttl_seconds, session_ttl_seconds in URL", async () => {
    const { fetchFn, capturedUrls } = mockSessionFetch();
    await createProdSession(unixConn, {
      fetchFn,
      scopes: ["scope1"],
      pamPolicy: "my-policy",
      tokenTtlSeconds: 900,
      sessionTtlSeconds: 7200,
    });

    expect(capturedUrls[0]).toContain("scopes=scope1");
    expect(capturedUrls[0]).toContain("pam_policy=my-policy");
    expect(capturedUrls[0]).toContain("token_ttl_seconds=900");
    expect(capturedUrls[0]).toContain("session_ttl_seconds=7200");
  });

  test("sends X-Wrapped-Command header", async () => {
    let capturedHeaders: Headers | undefined;
    const fetchFn = (async (_url: string, init?: RequestInit) => {
      capturedHeaders = new Headers(init?.headers);
      return new Response(
        JSON.stringify({
          session_id: "s",
          access_token: "t",
          expires_in: 3600,
          email: "e@e.com",
        }),
        { status: 200 },
      );
    }) as unknown as typeof globalThis.fetch;

    await createProdSession(unixConn, { fetchFn, command: ["gcloud", "sql", "connect"] });
    expect(capturedHeaders!.get("X-Wrapped-Command")).toBe(
      JSON.stringify(["gcloud", "sql", "connect"]),
    );
  });

  test("throws on non-OK response", async () => {
    const { fetchFn } = mockSessionFetch({ error: "denied" }, 403);
    await expect(createProdSession(unixConn, { fetchFn })).rejects.toThrow("gcp-gate returned 403");
  });

  test("throws when session_id is missing", async () => {
    const { fetchFn } = mockSessionFetch({ access_token: "t", email: "e@e.com" });
    await expect(createProdSession(unixConn, { fetchFn })).rejects.toThrow("no session_id");
  });

  test("throws when access_token is missing", async () => {
    const { fetchFn } = mockSessionFetch({ session_id: "s", email: "e@e.com" });
    await expect(createProdSession(unixConn, { fetchFn })).rejects.toThrow("no access_token");
  });

  test("throws when email is missing", async () => {
    const { fetchFn } = mockSessionFetch({ session_id: "s", access_token: "t" });
    await expect(createProdSession(unixConn, { fetchFn })).rejects.toThrow("no email");
  });
});

// ---------------------------------------------------------------------------
// revokeProdSession
// ---------------------------------------------------------------------------

describe("revokeProdSession", () => {
  const unixConn = { mode: "unix" as const, socketPath: "/tmp/gate.sock" };

  test("sends DELETE to /session?id=<sessionId>", async () => {
    let capturedUrl = "";
    let capturedMethod = "";
    const fetchFn = (async (url: string, init?: RequestInit) => {
      capturedUrl = url;
      capturedMethod = init?.method ?? "GET";
      return new Response("{}", { status: 200 });
    }) as unknown as typeof globalThis.fetch;

    await revokeProdSession(unixConn, "my-session-id", { fetchFn });

    expect(capturedUrl).toContain("/session?id=my-session-id");
    expect(capturedMethod).toBe("DELETE");
  });

  test("does not throw on network error (best-effort)", async () => {
    const fetchFn = (async () => {
      throw new Error("Connection refused");
    }) as unknown as typeof globalThis.fetch;

    // Should not throw
    await revokeProdSession(unixConn, "my-session-id", { fetchFn });
  });

  test("does not throw on non-OK response (best-effort)", async () => {
    const fetchFn = (async () => {
      return new Response("not found", { status: 404 });
    }) as unknown as typeof globalThis.fetch;

    await revokeProdSession(unixConn, "my-session-id", { fetchFn });
  });
});
