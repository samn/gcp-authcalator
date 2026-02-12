import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startGateServer, type GateServerResult } from "../../gate/server.ts";
import type { GateConfig } from "../../config.ts";
import type { AuthClient } from "google-auth-library";

function mockClient(token: string): AuthClient {
  return {
    getAccessToken: async () => ({ token, res: null }),
  } as unknown as AuthClient;
}

function mockFetch(email: string): typeof globalThis.fetch {
  return (async () =>
    new Response(JSON.stringify({ email }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })) as unknown as typeof globalThis.fetch;
}

function makeConfig(socketPath: string): GateConfig {
  return {
    project_id: "test-project",
    service_account: "sa@test-project.iam.gserviceaccount.com",
    socket_path: socketPath,
    port: 8173,
  };
}

async function fetchUnix(socketPath: string, path: string): Promise<Response> {
  return fetch(`http://localhost${path}`, {
    unix: socketPath,
  } as RequestInit);
}

describe("startGateServer", () => {
  let result: GateServerResult | null = null;

  afterEach(() => {
    if (result) {
      result.stop();
      result = null;
    }
  });

  test("starts server and responds to /health", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const res = await fetchUnix(socketPath, "/health");
    expect(res.status).toBe(200);

    const body = (await res.json()) as { status: string; uptime_seconds: number };
    expect(body.status).toBe("ok");
    expect(body.uptime_seconds).toBeGreaterThanOrEqual(0);
  });

  test("serves dev token via /token", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("my-dev-token"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const res = await fetchUnix(socketPath, "/token");
    expect(res.status).toBe(200);

    const body = (await res.json()) as { access_token: string; token_type: string };
    expect(body.access_token).toBe("my-dev-token");
    expect(body.token_type).toBe("Bearer");
  });

  test("serves identity via /identity", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("identity@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const res = await fetchUnix(socketPath, "/identity");
    expect(res.status).toBe(200);

    const body = (await res.json()) as { email: string };
    expect(body.email).toBe("identity@example.com");
  });

  test("returns 404 for unknown paths", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const res = await fetchUnix(socketPath, "/nonexistent");
    expect(res.status).toBe(404);
  });

  test("removes stale socket file on startup", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    // Create a stale socket file
    writeFileSync(socketPath, "stale");
    expect(existsSync(socketPath)).toBe(true);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    // Server should have started successfully despite stale file
    const res = await fetchUnix(socketPath, "/health");
    expect(res.status).toBe(200);
  });

  test("stop() cleans up socket file", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    expect(existsSync(socketPath)).toBe(true);

    result.stop();
    result = null;

    expect(existsSync(socketPath)).toBe(false);
  });
});
