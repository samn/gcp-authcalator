import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createPendingQueue } from "../../gate/pending.ts";
import { handleAdminRequest } from "../../gate/admin-handlers.ts";
import { makeGateDeps as makeDeps } from "../gate/test-helpers.ts";

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
