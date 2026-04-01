import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createPendingQueue } from "../../gate/pending.ts";
import { handleAdminRequest } from "../../gate/admin-handlers.ts";
import type { GateDeps, CachedToken } from "../../gate/types.ts";
import { createProdRateLimiter } from "../../gate/rate-limit.ts";
import { createSessionManager } from "../../gate/session.ts";

function makeDeps(overrides: Partial<GateDeps> = {}): GateDeps {
  const token: CachedToken = {
    access_token: "test-access-token",
    expires_at: new Date(Date.now() + 3600 * 1000),
  };

  return {
    mintDevToken: async () => token,
    mintProdToken: async () => token,
    getIdentityEmail: async () => "user@example.com",
    getProjectNumber: async () => "123456789012",
    getUniverseDomain: async () => "googleapis.com",
    confirmProdAccess: async () => true,
    writeAuditLog: () => {},
    prodRateLimiter: createProdRateLimiter(),
    startTime: new Date(Date.now() - 60_000),
    defaultTokenTtlSeconds: 3600,
    sessionManager: createSessionManager(),
    sessionTtlSeconds: 28800,
    ...overrides,
  };
}

describe("approve command (admin socket)", () => {
  let server: ReturnType<typeof Bun.serve> | null = null;

  afterEach(() => {
    if (server) {
      server.stop(true);
      server = null;
    }
  });

  function setup() {
    const dir = mkdtempSync(join(tmpdir(), "approve-test-"));
    const adminSocketPath = join(dir, "admin.sock");
    const queue = createPendingQueue({ timeoutMs: 30000, now: () => Date.now() });
    const deps = makeDeps({ pendingQueue: queue });

    server = Bun.serve({
      unix: adminSocketPath,
      fetch(req) {
        return handleAdminRequest(req, deps);
      },
    });

    return { adminSocketPath, queue };
  }

  test("approves a pending request via admin socket", async () => {
    const { adminSocketPath, queue } = setup();
    const promise = queue.enqueue("user@example.com");
    const [req] = queue.list();

    const res = await fetch(`http://localhost/pending/${req!.id}/approve`, {
      method: "POST",
      unix: adminSocketPath,
    } as RequestInit);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("approved");

    expect(await promise).toBe(true);
  });

  test("denies a pending request via admin socket", async () => {
    const { adminSocketPath, queue } = setup();
    const promise = queue.enqueue("user@example.com");
    const [req] = queue.list();

    const res = await fetch(`http://localhost/pending/${req!.id}/deny`, {
      method: "POST",
      unix: adminSocketPath,
    } as RequestInit);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("denied");

    expect(await promise).toBe(false);
  });

  test("returns 404 for unknown request ID", async () => {
    const { adminSocketPath } = setup();

    const res = await fetch(`http://localhost/pending/${"f".repeat(32)}/approve`, {
      method: "POST",
      unix: adminSocketPath,
    } as RequestInit);
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("Request not found or expired");
  });

  test("GET /pending returns 404 on admin socket (no listing)", async () => {
    const { adminSocketPath } = setup();

    const res = await fetch("http://localhost/pending", {
      unix: adminSocketPath,
    } as RequestInit);
    expect(res.status).toBe(404);
  });

  test("GET /health returns 200 on admin socket", async () => {
    const { adminSocketPath } = setup();

    const res = await fetch("http://localhost/health", {
      unix: adminSocketPath,
    } as RequestInit);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("ok");
  });
});
