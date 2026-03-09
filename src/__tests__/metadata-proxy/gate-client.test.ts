import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createGateClient,
  checkGateSocket,
  checkGateConnection,
} from "../../metadata-proxy/gate-client.ts";
import type { GateConnection } from "../../gate/connection.ts";

function unixConn(socketPath: string): GateConnection {
  return { mode: "unix", socketPath };
}

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
    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    const result = await client.getToken();
    expect(result.access_token).toBe("test-token-abc");
    expect(result.expires_at).toBeInstanceOf(Date);
    expect(result.expires_at.getTime()).toBeGreaterThan(Date.now());
  });

  test("caches token on subsequent calls", async () => {
    const { fetchFn, callCount } = mockFetch("cached-token");
    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

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

    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    const first = await client.getToken();
    expect(first.access_token).toBe("token-1");

    // Should re-fetch because expires_in of 120s < 300s margin
    const second = await client.getToken();
    expect(second.access_token).toBe("token-2");
    expect(count).toBe(2);
  });

  test("throws on non-OK response", async () => {
    const fetchFn = mockFetchError(500, '{"error":"internal error"}');
    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    await expect(client.getToken()).rejects.toThrow("gcp-gate returned 500");
  });

  test("throws when response has no access_token", async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ expires_in: 3600 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as unknown as typeof globalThis.fetch;

    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    await expect(client.getToken()).rejects.toThrow("no access_token");
  });

  test("defaults expires_in to 3600 when not provided", async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ access_token: "tok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as unknown as typeof globalThis.fetch;

    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    const result = await client.getToken();
    // Should expire roughly 1 hour from now
    const expectedMin = Date.now() + 3500 * 1000;
    const expectedMax = Date.now() + 3700 * 1000;
    expect(result.expires_at.getTime()).toBeGreaterThan(expectedMin);
    expect(result.expires_at.getTime()).toBeLessThan(expectedMax);
  });
});

describe("createGateClient — getNumericProjectId", () => {
  test("fetches numeric project ID from gate daemon", async () => {
    const { fetchFn } = mockProjectNumberFetch("987654321098");
    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    const result = await client.getNumericProjectId();
    expect(result).toBe("987654321098");
  });

  test("caches numeric project ID on subsequent calls", async () => {
    const { fetchFn, callCount } = mockProjectNumberFetch("111222333444");
    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    const first = await client.getNumericProjectId();
    const second = await client.getNumericProjectId();

    expect(first).toBe("111222333444");
    expect(second).toBe("111222333444");
    expect(callCount()).toBe(1);
  });

  test("throws on non-OK response", async () => {
    const fetchFn = mockFetchError(500, '{"error":"CRM API failed"}');
    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    await expect(client.getNumericProjectId()).rejects.toThrow("gcp-gate returned 500");
  });

  test("throws when response has no project_number", async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ something_else: "value" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as unknown as typeof globalThis.fetch;

    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

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

describe("checkGateConnection", () => {
  test("delegates to checkGateSocket for unix mode", async () => {
    await expect(
      checkGateConnection({ mode: "unix", socketPath: "/tmp/nonexistent.sock" }),
    ).rejects.toThrow(/socket not found/);
  });

  test("throws on TCP connection failure", async () => {
    const conn: GateConnection = {
      mode: "tcp",
      gateUrl: "https://localhost:19999",
      caCert: "dummy",
      clientCert: "dummy",
      clientKey: "dummy",
    };
    await expect(checkGateConnection(conn)).rejects.toThrow(/Could not connect/);
  });

  test("throws on TCP health check non-OK response", async () => {
    const fetchFn = (async () =>
      new Response("bad state", { status: 503 })) as unknown as typeof globalThis.fetch;

    const conn: GateConnection = {
      mode: "tcp",
      gateUrl: "https://localhost:8174",
      caCert: "ca",
      clientCert: "cc",
      clientKey: "ck",
    };
    await expect(checkGateConnection(conn, fetchFn)).rejects.toThrow(
      /health check failed \(HTTP 503\)/,
    );
  });

  test("succeeds on TCP health check OK response", async () => {
    const fetchFn = (async () =>
      new Response('{"status":"ok"}', { status: 200 })) as unknown as typeof globalThis.fetch;

    const conn: GateConnection = {
      mode: "tcp",
      gateUrl: "https://localhost:8174",
      caCert: "ca",
      clientCert: "cc",
      clientKey: "ck",
    };
    await expect(checkGateConnection(conn, fetchFn)).resolves.toBeUndefined();
  });

  test("passes mTLS client certs in TCP health check", async () => {
    let capturedOpts: Record<string, unknown> | undefined;

    const fetchFn = (async (_url: string, opts: Record<string, unknown>) => {
      capturedOpts = opts;
      return new Response('{"status":"ok"}', { status: 200 });
    }) as unknown as typeof globalThis.fetch;

    const conn: GateConnection = {
      mode: "tcp",
      gateUrl: "https://localhost:8174",
      caCert: "ca-pem",
      clientCert: "client-cert-pem",
      clientKey: "client-key-pem",
    };
    await checkGateConnection(conn, fetchFn);

    expect(capturedOpts).toBeDefined();
    expect(capturedOpts!.tls).toEqual({
      cert: "client-cert-pem",
      key: "client-key-pem",
      ca: "ca-pem",
    });
  });
});

function tcpConn(): GateConnection {
  return {
    mode: "tcp",
    gateUrl: "https://localhost:8174",
    caCert: "ca-cert-pem",
    clientCert: "client-cert-pem",
    clientKey: "client-key-pem",
  };
}

describe("createGateClient — TCP mode", () => {
  test("fetches token using TCP connection with TLS options", async () => {
    let capturedUrl = "";
    let capturedOpts: RequestInit | undefined;

    const fetchFn = (async (url: string, opts: RequestInit) => {
      capturedUrl = url;
      capturedOpts = opts;
      return new Response(JSON.stringify({ access_token: "tcp-token", expires_in: 3600 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    const client = createGateClient(tcpConn(), { fetchFn });
    const result = await client.getToken();

    expect(result.access_token).toBe("tcp-token");
    expect(capturedUrl).toBe("https://localhost:8174/token");
    expect((capturedOpts as Record<string, unknown>).tls).toEqual({
      cert: "client-cert-pem",
      key: "client-key-pem",
      ca: "ca-cert-pem",
    });
  });

  test("fetches numeric project ID using TCP connection", async () => {
    const fetchFn = (async (url: string) => {
      if (url.includes("/project-number")) {
        return new Response(JSON.stringify({ project_number: "123456" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ access_token: "tok", expires_in: 3600 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    const client = createGateClient(tcpConn(), { fetchFn });
    const result = await client.getNumericProjectId();
    expect(result).toBe("123456");
  });
});

describe("createGateClient — getUniverseDomain", () => {
  function mockUniverseDomainFetch(domain: string): {
    fetchFn: typeof globalThis.fetch;
    callCount: () => number;
  } {
    let count = 0;
    const fetchFn = (async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      count++;
      if (url.includes("/universe-domain")) {
        return new Response(JSON.stringify({ universe_domain: domain }), {
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

  test("fetches universe domain from gate daemon", async () => {
    const { fetchFn } = mockUniverseDomainFetch("googleapis.com");
    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    const result = await client.getUniverseDomain();
    expect(result).toBe("googleapis.com");
  });

  test("caches universe domain on subsequent calls", async () => {
    const { fetchFn, callCount } = mockUniverseDomainFetch("googleapis.com");
    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    const first = await client.getUniverseDomain();
    const second = await client.getUniverseDomain();

    expect(first).toBe("googleapis.com");
    expect(second).toBe("googleapis.com");
    expect(callCount()).toBe(1);
  });

  test("throws on non-OK response", async () => {
    const fetchFn = mockFetchError(500, '{"error":"internal"}');
    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    await expect(client.getUniverseDomain()).rejects.toThrow("gcp-gate returned 500");
  });

  test("throws when response has no universe_domain", async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ something: "else" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as unknown as typeof globalThis.fetch;

    const client = createGateClient(unixConn("/tmp/test.sock"), { fetchFn });

    await expect(client.getUniverseDomain()).rejects.toThrow("no universe_domain");
  });

  test("fetches universe domain using TCP connection", async () => {
    const { fetchFn } = mockUniverseDomainFetch("googleapis.com");
    const client = createGateClient(tcpConn(), { fetchFn });

    const result = await client.getUniverseDomain();
    expect(result).toBe("googleapis.com");
  });
});
