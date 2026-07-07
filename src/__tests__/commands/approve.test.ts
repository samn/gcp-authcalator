import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createPendingQueue } from "../../gate/pending.ts";
import { handleAdminRequest } from "../../gate/admin-handlers.ts";
import { runApprove } from "../../commands/approve.ts";
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

describe("runApprove — fetch timeout", () => {
  /**
   * The approve/deny CLI talks to the admin socket with no fetch timeout.
   * A wedged admin socket hangs the approval CLI indefinitely — confusing in
   * an already-stressful approval flow. Verify the fetch carries an
   * AbortSignal and that an abort surfaces an actionable error.
   */
  function makeConfig(adminSocketPath: string) {
    return { admin_socket_path: adminSocketPath } as Parameters<typeof runApprove>[0];
  }

  test("attaches an AbortSignal to the approve fetch", async () => {
    let capturedInit: RequestInit | undefined;
    const fetchFn = (async (_url: string, init?: RequestInit) => {
      capturedInit = init;
      return new Response(JSON.stringify({ status: "approved" }), { status: 200 });
    }) as unknown as typeof globalThis.fetch;

    // Suppress console.log from runApprove's success path.
    const origLog = console.log;
    console.log = () => {};
    try {
      await runApprove(makeConfig("/tmp/test-admin.sock"), ["f".repeat(32)], {
        deny: false,
        fetchFn,
      });
    } finally {
      console.log = origLog;
    }

    expect(capturedInit).toBeDefined();
    expect(capturedInit!.signal).toBeInstanceOf(AbortSignal);
  });

  test("surfaces an admin-socket timeout as an actionable error and exits 1", async () => {
    const fetchFn = (async () => {
      throw new DOMException("The operation timed out", "TimeoutError");
    }) as unknown as typeof globalThis.fetch;

    const origExit = process.exit;
    const origErr = console.error;
    const exitCalls: number[] = [];
    let errorMsg = "";
    process.exit = ((code?: number) => {
      exitCalls.push(code ?? 0);
      throw new Error(`exit:${code ?? 0}`);
    }) as typeof process.exit;
    console.error = (msg: unknown) => {
      errorMsg = typeof msg === "string" ? msg : String(msg);
    };

    try {
      await expect(
        runApprove(makeConfig("/tmp/test-admin.sock"), ["f".repeat(32)], {
          deny: false,
          fetchFn,
        }),
      ).rejects.toThrow(/exit:1/);
    } finally {
      process.exit = origExit;
      console.error = origErr;
    }

    expect(exitCalls).toContain(1);
    // Must hit the dedicated timeout branch, not the generic connection-failure
    // fallback (whose message can also embed "timed out" via the cause's
    // message) — the fallback's "is gcp-authcalator running?" guidance is
    // wrong for a present-but-wedged socket.
    expect(errorMsg).toMatch(/admin socket not responding/);
    expect(errorMsg).not.toMatch(/could not connect to the admin socket/);
  });

  test("surfaces a socket-connection failure as an actionable error and exits 1", async () => {
    // The common failure is not a timeout but the gate being stopped / a wrong
    // admin_socket_path: Bun throws Error{name:"Error"} for that, so it must
    // still turn into clear guidance rather than a raw stack trace.
    const fetchFn = (async () => {
      const err = new Error("Was there a typo in the url or port?");
      (err as Error & { code?: string }).code = "FailedToOpenSocket";
      throw err;
    }) as unknown as typeof globalThis.fetch;

    const origExit = process.exit;
    const origErr = console.error;
    const exitCalls: number[] = [];
    let errorMsg = "";
    process.exit = ((code?: number) => {
      exitCalls.push(code ?? 0);
      throw new Error(`exit:${code ?? 0}`);
    }) as typeof process.exit;
    console.error = (msg: unknown) => {
      errorMsg = typeof msg === "string" ? msg : String(msg);
    };

    try {
      await expect(
        runApprove(makeConfig("/tmp/test-admin.sock"), ["f".repeat(32)], {
          deny: false,
          fetchFn,
        }),
      ).rejects.toThrow(/exit:1/);
    } finally {
      process.exit = origExit;
      console.error = origErr;
    }

    expect(exitCalls).toContain(1);
    expect(errorMsg).toMatch(/could not connect to the admin socket/);
    expect(errorMsg).toContain("/tmp/test-admin.sock");
  });

  test("prints usage and makes no fetch when no id is given", async () => {
    let fetchCalls = 0;
    const fetchFn = (async () => {
      fetchCalls++;
      return new Response("{}", { status: 200 });
    }) as unknown as typeof globalThis.fetch;

    const origLog = console.log;
    const logs: string[] = [];
    console.log = (msg: unknown) => {
      logs.push(typeof msg === "string" ? msg : String(msg));
    };
    try {
      await runApprove(makeConfig("/tmp/test-admin.sock"), [], { fetchFn });
    } finally {
      console.log = origLog;
    }

    expect(fetchCalls).toBe(0);
    expect(logs.join("\n")).toMatch(/Usage: gcp-authcalator approve <id>/);
  });

  test("reports a 404 as an expired/unknown request and exits 1", async () => {
    const fetchFn = (async () =>
      new Response("{}", { status: 404 })) as unknown as typeof globalThis.fetch;

    const origExit = process.exit;
    const origErr = console.error;
    const exitCalls: number[] = [];
    let errorMsg = "";
    process.exit = ((code?: number) => {
      exitCalls.push(code ?? 0);
      throw new Error(`exit:${code ?? 0}`);
    }) as typeof process.exit;
    console.error = (msg: unknown) => {
      errorMsg = typeof msg === "string" ? msg : String(msg);
    };

    try {
      await expect(
        runApprove(makeConfig("/tmp/test-admin.sock"), ["a".repeat(32)], { fetchFn }),
      ).rejects.toThrow(/exit:1/);
    } finally {
      process.exit = origExit;
      console.error = origErr;
    }

    expect(exitCalls).toContain(1);
    expect(errorMsg).toMatch(/not found \(may have expired\)/);
  });

  test("surfaces a non-ok error body and exits 1", async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ error: "already resolved" }), {
        status: 409,
      })) as unknown as typeof globalThis.fetch;

    const origExit = process.exit;
    const origErr = console.error;
    const exitCalls: number[] = [];
    let errorMsg = "";
    process.exit = ((code?: number) => {
      exitCalls.push(code ?? 0);
      throw new Error(`exit:${code ?? 0}`);
    }) as typeof process.exit;
    console.error = (msg: unknown) => {
      errorMsg = typeof msg === "string" ? msg : String(msg);
    };

    try {
      await expect(
        runApprove(makeConfig("/tmp/test-admin.sock"), ["a".repeat(32)], { fetchFn }),
      ).rejects.toThrow(/exit:1/);
    } finally {
      process.exit = origExit;
      console.error = origErr;
    }

    expect(exitCalls).toContain(1);
    expect(errorMsg).toMatch(/already resolved/);
  });

  test("reports a non-JSON error body as a clean error instead of crashing", async () => {
    // A handler crash can produce a plain-text 500 (or an empty body); the CLI
    // must fall back to the HTTP status, not reject with a raw SyntaxError.
    const fetchFn = (async () =>
      new Response("Internal Server Error", { status: 500 })) as unknown as typeof globalThis.fetch;

    const origExit = process.exit;
    const origErr = console.error;
    const exitCalls: number[] = [];
    let errorMsg = "";
    process.exit = ((code?: number) => {
      exitCalls.push(code ?? 0);
      throw new Error(`exit:${code ?? 0}`);
    }) as typeof process.exit;
    console.error = (msg: unknown) => {
      errorMsg = typeof msg === "string" ? msg : String(msg);
    };

    try {
      await expect(
        runApprove(makeConfig("/tmp/test-admin.sock"), ["a".repeat(32)], { fetchFn }),
      ).rejects.toThrow(/exit:1/);
    } finally {
      process.exit = origExit;
      console.error = origErr;
    }

    expect(exitCalls).toContain(1);
    expect(errorMsg).toMatch(/admin socket returned HTTP 500/);
  });
});
