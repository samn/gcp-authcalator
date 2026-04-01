import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createPendingQueue } from "../../gate/pending.ts";

describe("approve command", () => {
  let server: ReturnType<typeof Bun.serve> | null = null;

  afterEach(() => {
    if (server) {
      server.stop(true);
      server = null;
    }
  });

  function setup() {
    const dir = mkdtempSync(join(tmpdir(), "approve-test-"));
    const socketPath = join(dir, "gate.sock");
    const queue = createPendingQueue({ timeoutMs: 30000, now: () => Date.now() });

    server = Bun.serve({
      unix: socketPath,
      fetch(req) {
        const url = new URL(req.url, "http://localhost");

        if (url.pathname === "/pending" && req.method === "GET") {
          return new Response(JSON.stringify({ pending: queue.list() }), {
            headers: { "Content-Type": "application/json" },
          });
        }

        const match = url.pathname.match(/^\/pending\/([a-f0-9]+)\/(approve|deny)$/);
        if (match && req.method === "POST") {
          const [, id, action] = match;
          const resolved = action === "approve" ? queue.approve(id!) : queue.deny(id!);
          if (!resolved) {
            return new Response(JSON.stringify({ error: "Request not found or expired" }), {
              status: 404,
              headers: { "Content-Type": "application/json" },
            });
          }
          return new Response(
            JSON.stringify({ status: action === "approve" ? "approved" : "denied" }),
            { headers: { "Content-Type": "application/json" } },
          );
        }

        return new Response(JSON.stringify({ error: "Not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      },
    });

    return { socketPath, queue };
  }

  test("lists pending requests via gate socket", async () => {
    const { socketPath, queue } = setup();
    queue.enqueue("user@example.com", "gcloud compute list");

    const res = await fetch("http://localhost/pending", {
      unix: socketPath,
    } as RequestInit);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { pending: Array<{ email: string }> };
    expect(body.pending).toHaveLength(1);
    expect(body.pending[0]!.email).toBe("user@example.com");

    queue.denyAll();
  });

  test("approves a pending request via gate socket", async () => {
    const { socketPath, queue } = setup();
    const promise = queue.enqueue("user@example.com");
    const [req] = queue.list();

    const res = await fetch(`http://localhost/pending/${req!.id}/approve`, {
      method: "POST",
      unix: socketPath,
    } as RequestInit);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("approved");

    expect(await promise).toBe(true);
  });

  test("denies a pending request via gate socket", async () => {
    const { socketPath, queue } = setup();
    const promise = queue.enqueue("user@example.com");
    const [req] = queue.list();

    const res = await fetch(`http://localhost/pending/${req!.id}/deny`, {
      method: "POST",
      unix: socketPath,
    } as RequestInit);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("denied");

    expect(await promise).toBe(false);
  });

  test("returns 404 for unknown request ID", async () => {
    const { socketPath } = setup();

    const res = await fetch("http://localhost/pending/deadbeef/approve", {
      method: "POST",
      unix: socketPath,
    } as RequestInit);
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("Request not found or expired");
  });

  test("returns empty list when no pending requests", async () => {
    const { socketPath } = setup();

    const res = await fetch("http://localhost/pending", {
      unix: socketPath,
    } as RequestInit);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { pending: unknown[] };
    expect(body.pending).toHaveLength(0);
  });
});
