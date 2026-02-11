import { describe, expect, test, afterEach } from "bun:test";
import { z } from "zod";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AuthClient } from "google-auth-library";
import { GateConfigSchema } from "../../config.ts";
import { startGateServer, type GateServerResult } from "../../gate/server.ts";

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

describe("runGate", () => {
  let result: GateServerResult | null = null;

  afterEach(() => {
    if (result) {
      result.stop();
      result = null;
    }
  });

  test("validates config and starts server", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gate-cmd-"));
    const socketPath = join(dir, "gate.sock");

    const config = GateConfigSchema.parse({
      project_id: "test-proj",
      service_account: "sa@test-proj.iam.gserviceaccount.com",
      socket_path: socketPath,
      port: 8173,
    });

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("src-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("user@test.com"),
      },
      auditLogDir: join(dir, "audit"),
    });

    // Verify server is running by hitting health endpoint
    const res = await fetch("http://localhost/health", {
      unix: socketPath,
    } as RequestInit);
    expect(res.status).toBe(200);
  });

  test("throws ZodError when project_id is missing", () => {
    expect(() =>
      GateConfigSchema.parse({
        socket_path: "/tmp/gate.sock",
        port: 8173,
      }),
    ).toThrow(z.ZodError);
  });

  test("throws ZodError when service_account is missing", () => {
    expect(() =>
      GateConfigSchema.parse({
        project_id: "test-proj",
        socket_path: "/tmp/gate.sock",
        port: 8173,
      }),
    ).toThrow(z.ZodError);
  });
});
