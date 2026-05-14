import { describe, expect, test } from "bun:test";
import { handleAdminRequest } from "../../gate/admin-handlers.ts";
import type { AuditEntry } from "../../gate/types.ts";
import { createPendingQueue } from "../../gate/pending.ts";
import { makeGateDeps as makeDeps, makeRequest } from "./test-helpers.ts";

describe("admin socket: POST /pending/:id/approve", () => {
  test("approves a pending request", async () => {
    const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
    const promise = pendingQueue.enqueue("user@example.com", "test-project");
    const [req] = pendingQueue.list();

    const auditLog: AuditEntry[] = [];
    const deps = makeDeps({
      pendingQueue,
      writeAuditLog: (entry) => auditLog.push(entry),
    });

    const res = await handleAdminRequest(makeRequest(`/pending/${req!.id}/approve`, "POST"), deps);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("approved");

    expect(await promise).toBe(true);

    expect(auditLog).toHaveLength(1);
    expect(auditLog[0]!.result).toBe("granted");
    expect(auditLog[0]!.endpoint).toContain(req!.id);
  });

  test("returns 404 for unknown ID", async () => {
    const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
    const deps = makeDeps({ pendingQueue });

    const res = await handleAdminRequest(
      makeRequest(`/pending/${"d".repeat(32)}/approve`, "POST"),
      deps,
    );
    expect(res.status).toBe(404);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("Request not found or expired");
  });

  test("returns 501 when pendingQueue not in deps", async () => {
    const deps = makeDeps();
    const res = await handleAdminRequest(
      makeRequest(`/pending/${"e".repeat(32)}/approve`, "POST"),
      deps,
    );
    expect(res.status).toBe(501);
  });
});

describe("admin socket: POST /pending/:id/deny", () => {
  test("denies a pending request", async () => {
    const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
    const promise = pendingQueue.enqueue("user@example.com", "test-project");
    const [req] = pendingQueue.list();

    const auditLog: AuditEntry[] = [];
    const deps = makeDeps({
      pendingQueue,
      writeAuditLog: (entry) => auditLog.push(entry),
    });

    const res = await handleAdminRequest(makeRequest(`/pending/${req!.id}/deny`, "POST"), deps);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("denied");

    expect(await promise).toBe(false);

    expect(auditLog).toHaveLength(1);
    expect(auditLog[0]!.result).toBe("denied");
  });
});

describe("admin socket: GET /health", () => {
  test("returns status ok with uptime", async () => {
    const deps = makeDeps({ startTime: new Date(Date.now() - 120_000) });
    const res = await handleAdminRequest(makeRequest("/health"), deps);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("ok");
    expect(body.uptime_seconds).toBeGreaterThanOrEqual(119);
  });
});

describe("admin socket: non-admin routes return 404", () => {
  test("GET /token returns 404", async () => {
    const res = await handleAdminRequest(makeRequest("/token"), makeDeps());
    expect(res.status).toBe(404);
  });

  test("GET /identity returns 404", async () => {
    const res = await handleAdminRequest(makeRequest("/identity"), makeDeps());
    expect(res.status).toBe(404);
  });

  test("GET /pending returns 404 (no listing)", async () => {
    const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
    const deps = makeDeps({ pendingQueue });
    const res = await handleAdminRequest(makeRequest("/pending"), deps);
    expect(res.status).toBe(404);
  });

  test("POST /session returns 404", async () => {
    const res = await handleAdminRequest(makeRequest("/session", "POST"), makeDeps());
    expect(res.status).toBe(404);
  });
});
