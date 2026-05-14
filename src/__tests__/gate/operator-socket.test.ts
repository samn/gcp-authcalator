import { describe, expect, test } from "bun:test";
import { handleRequest } from "../../gate/handlers.ts";
import type { AuditEntry, RequestContext } from "../../gate/types.ts";
import { makeGateDeps as makeDeps, makeRequest } from "./test-helpers.ts";

const TRUSTED: RequestContext = { trusted: true, socket: "operator" };
const UNTRUSTED: RequestContext = { trusted: false, socket: "main" };

const ALLOWLISTED = "projects/p/locations/global/entitlements/break-glass";
const NOT_ALLOWLISTED = "projects/p/locations/global/entitlements/something-else";

function makeOpDeps(overrides: Parameters<typeof makeDeps>[0] = {}) {
  return makeDeps({
    pamAllowedPolicies: new Set([ALLOWLISTED]),
    autoApprovePamPolicies: new Set([ALLOWLISTED]),
    pamDefaultPolicy: ALLOWLISTED,
    ensurePamGrant: async () => ({
      name: "grant-1",
      state: "ACTIVATED",
      expiresAt: new Date(Date.now() + 3600 * 1000),
      cached: false,
    }),
    resolvePamPolicy: (p) => p,
    ...overrides,
  });
}

describe("operator socket — auto-approve", () => {
  test("auto-approves allowlisted PAM policy without calling confirmProdAccess", async () => {
    let confirmCalled = false;
    const logs: AuditEntry[] = [];
    const deps = makeOpDeps({
      confirmProdAccess: async () => {
        confirmCalled = true;
        return false;
      },
      writeAuditLog: (e) => logs.push(e),
    });

    const res = await handleRequest(makeRequest("/token?level=prod"), deps, TRUSTED);

    expect(res.status).toBe(200);
    expect(confirmCalled).toBe(false);
    const granted = logs.find((l) => l.result === "granted");
    expect(granted).toBeDefined();
    expect(granted?.auto_approved).toBe(true);
    expect(granted?.socket).toBe("operator");
  });

  test("does NOT auto-approve when policy is in pam_allowed but not in auto_approve set", async () => {
    let confirmCalled = false;
    const deps = makeOpDeps({
      pamAllowedPolicies: new Set([ALLOWLISTED, NOT_ALLOWLISTED]),
      autoApprovePamPolicies: new Set([ALLOWLISTED]),
      confirmProdAccess: async () => {
        confirmCalled = true;
        return true;
      },
    });

    const res = await handleRequest(
      makeRequest(`/token?level=prod&pam_policy=${encodeURIComponent(NOT_ALLOWLISTED)}`),
      deps,
      TRUSTED,
    );

    expect(res.status).toBe(200);
    expect(confirmCalled).toBe(true);
  });

  test("returns 403 when PAM policy is not in pam_allowed_policies", async () => {
    const deps = makeOpDeps({
      pamAllowedPolicies: new Set([ALLOWLISTED]),
    });

    const res = await handleRequest(
      makeRequest(`/token?level=prod&pam_policy=${encodeURIComponent(NOT_ALLOWLISTED)}`),
      deps,
      TRUSTED,
    );

    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("PAM policy not in allowlist");
  });

  test("rejects X-Pending-Id on auto-approve path with 400", async () => {
    const deps = makeOpDeps();
    const req = makeRequest("/token?level=prod", "GET", {
      "X-Pending-Id": "a".repeat(32),
    });

    const res = await handleRequest(req, deps, TRUSTED);

    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("X-Pending-Id");
  });

  test("audit entry on auto-approved request includes socket and auto_approved fields", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeOpDeps({ writeAuditLog: (e) => logs.push(e) });

    await handleRequest(makeRequest("/token?level=prod"), deps, TRUSTED);

    const granted = logs.find((l) => l.result === "granted");
    expect(granted?.auto_approved).toBe(true);
    expect(granted?.socket).toBe("operator");
    expect(granted?.endpoint).toBe("/token?level=prod");
    expect(granted?.level).toBe("prod");
  });
});

describe("operator socket — sessions disabled", () => {
  test("POST /session returns 403", async () => {
    const deps = makeOpDeps();
    const res = await handleRequest(makeRequest("/session", "POST"), deps, TRUSTED);

    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("operator socket");
  });

  test("GET /token?session=... returns 403", async () => {
    const deps = makeOpDeps();
    const res = await handleRequest(makeRequest("/token?session=abc123"), deps, TRUSTED);

    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("Session refresh");
  });

  test("does not call sessionManager when session refresh is rejected", async () => {
    let validateCalled = false;
    const deps = makeOpDeps({
      sessionManager: {
        create: () => {
          throw new Error("should not be called");
        },
        validate: () => {
          validateCalled = true;
          return null;
        },
        revoke: () => false,
        revokeAll: () => {},
      },
    });

    await handleRequest(makeRequest("/token?session=abc"), deps, TRUSTED);

    expect(validateCalled).toBe(false);
  });
});

describe("main socket — unaffected by auto_approve_pam_policies", () => {
  test("still calls confirmProdAccess for an auto-approve-listed policy", async () => {
    let confirmCalls = 0;
    const deps = makeOpDeps({
      confirmProdAccess: async () => {
        confirmCalls++;
        return true;
      },
    });

    const res = await handleRequest(makeRequest("/token?level=prod"), deps, UNTRUSTED);

    expect(res.status).toBe(200);
    expect(confirmCalls).toBe(1);
  });

  test('audit entries from main socket carry socket="main"', async () => {
    const logs: AuditEntry[] = [];
    const deps = makeOpDeps({ writeAuditLog: (e) => logs.push(e) });

    await handleRequest(makeRequest("/token?level=prod"), deps, UNTRUSTED);

    const granted = logs.find((l) => l.result === "granted");
    expect(granted?.socket).toBe("main");
    expect(granted?.auto_approved).toBeUndefined();
  });

  test("X-Pending-Id is allowed on main socket", async () => {
    const deps = makeOpDeps({
      confirmProdAccess: async (_email, _project, _cmd, _policy, pendingId) => {
        // The pending id should be passed through to confirm
        expect(pendingId).toBe("b".repeat(32));
        return true;
      },
    });
    const req = makeRequest("/token?level=prod", "GET", {
      "X-Pending-Id": "b".repeat(32),
    });

    const res = await handleRequest(req, deps, UNTRUSTED);
    expect(res.status).toBe(200);
  });
});

describe("rate limiter is shared across sockets", () => {
  test("auto-approved request consumes a rate-limiter slot", async () => {
    let acquireCalls = 0;
    let releaseCalls = 0;
    const deps = makeOpDeps({
      prodRateLimiter: {
        acquire: () => {
          acquireCalls++;
          return { allowed: true };
        },
        release: () => {
          releaseCalls++;
        },
      },
    });

    await handleRequest(makeRequest("/token?level=prod"), deps, TRUSTED);

    expect(acquireCalls).toBe(1);
    expect(releaseCalls).toBe(1);
  });

  test("rate limiter denial on operator socket returns 429", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeOpDeps({
      prodRateLimiter: {
        acquire: () => ({ allowed: false, reason: "too many" }),
        release: () => {},
      },
      writeAuditLog: (e) => logs.push(e),
    });

    const res = await handleRequest(makeRequest("/token?level=prod"), deps, TRUSTED);

    expect(res.status).toBe(429);
    const limited = logs.find((l) => l.result === "rate_limited");
    expect(limited?.socket).toBe("operator");
  });
});
