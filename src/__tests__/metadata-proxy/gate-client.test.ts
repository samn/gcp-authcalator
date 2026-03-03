import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createGateClient, checkGateSocket } from "../../metadata-proxy/gate-client.ts";

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

function mockProjectNumberFetch(projectNumber: string): {
  fetchFn: typeof globalThis.fetch;
  callCount: () => number;
} {
  let count = 0;
  const fetchFn = (async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    count++;
    if (url.includes("/project-number")) {
      return new Response(JSON.stringify({ project_number: projectNumber }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(
      JSON.stringify({ access_token: "tok", expires_in: 3600, token_type: "Bearer" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }) as unknown as typeof globalThis.fetch;

  return { fetchFn, callCount: () => count };
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

describe("createGateClient — scopes", () => {
  test("includes scopes query param in token URL when scopes configured", async () => {
    let capturedUrl = "";
    const fetchFn = (async (url: string) => {
      capturedUrl = url;
      return new Response(
        JSON.stringify({ access_token: "tok", expires_in: 3600, token_type: "Bearer" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof globalThis.fetch;

    const client = createGateClient("/tmp/test.sock", {
      fetchFn,
      scopes: [
        "https://www.googleapis.com/auth/sqlservice.login",
        "https://www.googleapis.com/auth/devstorage.read_only",
      ],
    });

    await client.getToken();
    expect(capturedUrl).toBe(
      "http://localhost/token?scopes=https://www.googleapis.com/auth/sqlservice.login,https://www.googleapis.com/auth/devstorage.read_only",
    );
  });

  test("uses bare /token URL when no scopes configured", async () => {
    let capturedUrl = "";
    const fetchFn = (async (url: string) => {
      capturedUrl = url;
      return new Response(
        JSON.stringify({ access_token: "tok", expires_in: 3600, token_type: "Bearer" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof globalThis.fetch;

    const client = createGateClient("/tmp/test.sock", { fetchFn });

    await client.getToken();
    expect(capturedUrl).toBe("http://localhost/token");
  });
});

describe("createGateClient — getNumericProjectId", () => {
  test("fetches numeric project ID from gate daemon", async () => {
    const { fetchFn } = mockProjectNumberFetch("987654321098");
    const client = createGateClient("/tmp/test.sock", { fetchFn });

    const result = await client.getNumericProjectId();
    expect(result).toBe("987654321098");
  });

  test("caches numeric project ID on subsequent calls", async () => {
    const { fetchFn, callCount } = mockProjectNumberFetch("111222333444");
    const client = createGateClient("/tmp/test.sock", { fetchFn });

    const first = await client.getNumericProjectId();
    const second = await client.getNumericProjectId();

    expect(first).toBe("111222333444");
    expect(second).toBe("111222333444");
    expect(callCount()).toBe(1);
  });

  test("throws on non-OK response", async () => {
    const fetchFn = mockFetchError(500, '{"error":"CRM API failed"}');
    const client = createGateClient("/tmp/test.sock", { fetchFn });

    await expect(client.getNumericProjectId()).rejects.toThrow("gcp-gate returned 500");
  });

  test("throws when response has no project_number", async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ something_else: "value" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as unknown as typeof globalThis.fetch;

    const client = createGateClient("/tmp/test.sock", { fetchFn });

    await expect(client.getNumericProjectId()).rejects.toThrow("no project_number");
  });
});

describe("checkGateSocket", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "gate-client-test-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  test("throws when socket path does not exist", async () => {
    await expect(checkGateSocket("/tmp/nonexistent-socket.sock")).rejects.toThrow(
      /socket not found/,
    );
  });

  test("throws when path exists but is not a socket", async () => {
    const filePath = join(tmpDir, "not-a-socket");
    writeFileSync(filePath, "");

    await expect(checkGateSocket(filePath)).rejects.toThrow(/not a Unix socket/);
  });

  test("throws when socket exists but daemon is not responding", async () => {
    // Create a real Unix socket that nothing is listening on
    const socketPath = join(tmpDir, "dead.sock");
    const tempServer = Bun.serve({
      unix: socketPath,
      fetch() {
        return new Response("ok");
      },
    });
    tempServer.stop(true);

    // The socket file still exists but nobody is listening
    await expect(checkGateSocket(socketPath)).rejects.toThrow(/not responding/);
  });

  test("throws when health check returns non-OK status", async () => {
    // Create a real socket with a server that returns 500
    const socketPath = join(tmpDir, "unhealthy.sock");
    const tempServer = Bun.serve({
      unix: socketPath,
      fetch() {
        return new Response("internal error", { status: 500 });
      },
    });

    try {
      await expect(checkGateSocket(socketPath)).rejects.toThrow(/health check failed/);
    } finally {
      tempServer.stop(true);
    }
  });

  test("succeeds when socket exists and health check passes", async () => {
    const socketPath = join(tmpDir, "healthy.sock");
    const tempServer = Bun.serve({
      unix: socketPath,
      fetch() {
        return new Response(JSON.stringify({ status: "ok" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      },
    });

    try {
      await expect(checkGateSocket(socketPath)).resolves.toBeUndefined();
    } finally {
      tempServer.stop(true);
    }
  });
});
