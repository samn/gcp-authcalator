import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, existsSync, writeFileSync, statSync, symlinkSync } from "node:fs";
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

  test("removes stale socket on startup", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    const serverOpts = {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    };

    // Start then stop a server to leave a real stale socket behind.
    const first = await startGateServer(config, serverOpts);
    first.stop();

    // The stop() above deletes the socket, so re-create a stale one
    // by starting and hard-killing (just stop the server, leave the file).
    const second = await startGateServer(config, serverOpts);
    second.server.stop(true); // stop server but don't clean up socket
    expect(existsSync(socketPath)).toBe(true);

    // Now starting a new server should succeed by removing the stale socket.
    result = await startGateServer(config, serverOpts);
    const res = await fetchUnix(socketPath, "/health");
    expect(res.status).toBe(200);
  });

  test("refuses to start when socket path is a regular file", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    writeFileSync(socketPath, "not-a-socket");

    await expect(
      startGateServer(config, {
        authOptions: {
          sourceClient: mockClient("source-tok"),
          impersonatedClient: mockClient("dev-tok"),
          fetchFn: mockFetch("test@example.com"),
        },
        auditLogDir: join(tempDir, "audit"),
      }),
    ).rejects.toThrow("not a socket");
  });

  test("refuses to start when socket path is a symlink", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const target = join(tempDir, "target");
    const config = makeConfig(socketPath);

    writeFileSync(target, "target-file");
    symlinkSync(target, socketPath);

    await expect(
      startGateServer(config, {
        authOptions: {
          sourceClient: mockClient("source-tok"),
          impersonatedClient: mockClient("dev-tok"),
          fetchFn: mockFetch("test@example.com"),
        },
        auditLogDir: join(tempDir, "audit"),
      }),
    ).rejects.toThrow("symlink");

    // Target file must not have been deleted
    expect(existsSync(target)).toBe(true);
  });

  test("refuses to start when another instance is running", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    const serverOpts = {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    };

    // Start a running instance
    result = await startGateServer(config, serverOpts);

    // Trying to start a second instance on the same socket should fail
    await expect(startGateServer(config, serverOpts)).rejects.toThrow(
      "another instance is already running",
    );
  });

  test("sets socket permissions to 0600 (owner-only)", async () => {
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

    const stats = statSync(socketPath);
    // mode includes file-type bits; mask with 0o777 to get permission bits only
    const permissions = stats.mode & 0o777;
    expect(permissions).toBe(0o600);
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
