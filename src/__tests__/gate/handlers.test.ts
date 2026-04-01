import { describe, expect, test } from "bun:test";
import { handleRequest } from "../../gate/handlers.ts";
import type { AuditEntry, CachedToken } from "../../gate/types.ts";
import type { ProdRateLimiter } from "../../gate/rate-limit.ts";
import { createSessionManager } from "../../gate/session.ts";
import { createPendingQueue } from "../../gate/pending.ts";
import { makeGateDeps as makeDeps, makeRequest } from "./test-helpers.ts";

/** A rate limiter that always blocks. */
function blockedRateLimiter(reason = "rate limited"): ProdRateLimiter {
  return {
    acquire: () => ({ allowed: false, reason }),
    release: () => {},
  };
}

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

describe("GET /health", () => {
  test("returns status ok with uptime", async () => {
    const deps = makeDeps({ startTime: new Date(Date.now() - 120_000) });
    const res = await handleRequest(makeRequest("/health"), deps);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("ok");
    expect(body.uptime_seconds).toBeGreaterThanOrEqual(119);
    expect(body.uptime_seconds).toBeLessThanOrEqual(121);
  });

  test("returns JSON content type", async () => {
    const res = await handleRequest(makeRequest("/health"), makeDeps());
    expect(res.headers.get("Content-Type")).toBe("application/json");
  });
});

// ---------------------------------------------------------------------------
// GET /identity
// ---------------------------------------------------------------------------

describe("GET /identity", () => {
  test("returns email from identity provider", async () => {
    const deps = makeDeps({ getIdentityEmail: async () => "dev@company.com" });
    const res = await handleRequest(makeRequest("/identity"), deps);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.email).toBe("dev@company.com");
  });

  test("returns 500 when identity lookup fails", async () => {
    const deps = makeDeps({
      getIdentityEmail: async () => {
        throw new Error("ADC not configured");
      },
    });
    const res = await handleRequest(makeRequest("/identity"), deps);

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("ADC not configured");
  });
});

// ---------------------------------------------------------------------------
// GET /project-number
// ---------------------------------------------------------------------------

describe("GET /project-number", () => {
  test("returns project number from provider", async () => {
    const deps = makeDeps({ getProjectNumber: async () => "987654321098" });
    const res = await handleRequest(makeRequest("/project-number"), deps);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.project_number).toBe("987654321098");
  });

  test("returns JSON content type", async () => {
    const res = await handleRequest(makeRequest("/project-number"), makeDeps());
    expect(res.headers.get("Content-Type")).toBe("application/json");
  });

  test("returns 500 when project number lookup fails", async () => {
    const deps = makeDeps({
      getProjectNumber: async () => {
        throw new Error("CRM API unreachable");
      },
    });
    const res = await handleRequest(makeRequest("/project-number"), deps);

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("CRM API unreachable");
  });
});

// ---------------------------------------------------------------------------
// GET /universe-domain
// ---------------------------------------------------------------------------

describe("GET /universe-domain", () => {
  test("returns universe domain from provider", async () => {
    const deps = makeDeps({ getUniverseDomain: async () => "googleapis.com" });
    const res = await handleRequest(makeRequest("/universe-domain"), deps);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.universe_domain).toBe("googleapis.com");
  });

  test("returns JSON content type", async () => {
    const res = await handleRequest(makeRequest("/universe-domain"), makeDeps());
    expect(res.headers.get("Content-Type")).toBe("application/json");
  });

  test("returns 500 when universe domain lookup fails", async () => {
    const deps = makeDeps({
      getUniverseDomain: async () => {
        throw new Error("auth not configured");
      },
    });
    const res = await handleRequest(makeRequest("/universe-domain"), deps);

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("auth not configured");
  });
});

// ---------------------------------------------------------------------------
// GET /token (dev)
// ---------------------------------------------------------------------------

describe("GET /token (dev)", () => {
  test("returns access token with Bearer type", async () => {
    const res = await handleRequest(makeRequest("/token"), makeDeps());

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBe("test-access-token");
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
  });

  test("writes granted audit entry", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({ writeAuditLog: (e) => logs.push(e) });

    await handleRequest(makeRequest("/token"), deps);

    expect(logs).toHaveLength(1);
    expect(logs[0]!.level).toBe("dev");
    expect(logs[0]!.result).toBe("granted");
    expect(logs[0]!.endpoint).toBe("/token");
  });

  test("returns 500 and writes error audit on mint failure", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({
      mintDevToken: async () => {
        throw new Error("GCP unreachable");
      },
      writeAuditLog: (e) => logs.push(e),
    });

    const res = await handleRequest(makeRequest("/token"), deps);

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("GCP unreachable");

    expect(logs).toHaveLength(1);
    expect(logs[0]!.result).toBe("error");
    expect(logs[0]!.error).toBe("GCP unreachable");
  });
});

// ---------------------------------------------------------------------------
// GET /token with scopes
// ---------------------------------------------------------------------------

describe("GET /token with scopes", () => {
  test("passes scopes to mintDevToken when scopes query param present", async () => {
    let capturedScopes: string[] | undefined;
    const deps = makeDeps({
      mintDevToken: async (scopes) => {
        capturedScopes = scopes;
        return {
          access_token: "scoped-dev-token",
          expires_at: new Date(Date.now() + 3600 * 1000),
        };
      },
    });

    const res = await handleRequest(makeRequest("/token?scopes=scope1,scope2"), deps);
    expect(res.status).toBe(200);
    expect(capturedScopes).toEqual(["scope1", "scope2"]);
  });

  test("passes scopes to mintProdToken when scopes query param present", async () => {
    let capturedScopes: string[] | undefined;
    const deps = makeDeps({
      mintProdToken: async (scopes) => {
        capturedScopes = scopes;
        return {
          access_token: "scoped-prod-token",
          expires_at: new Date(Date.now() + 3600 * 1000),
        };
      },
    });

    const res = await handleRequest(makeRequest("/token?level=prod&scopes=scope1"), deps);
    expect(res.status).toBe(200);
    expect(capturedScopes).toEqual(["scope1"]);
  });

  test("passes undefined scopes when no scopes query param", async () => {
    let capturedScopes: string[] | undefined = ["should-be-replaced"];
    const deps = makeDeps({
      mintDevToken: async (scopes) => {
        capturedScopes = scopes;
        return {
          access_token: "test-token",
          expires_at: new Date(Date.now() + 3600 * 1000),
        };
      },
    });

    await handleRequest(makeRequest("/token"), deps);
    expect(capturedScopes).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// GET /token?level=prod
// ---------------------------------------------------------------------------

describe("GET /token?level=prod", () => {
  test("returns prod token when confirmed", async () => {
    const deps = makeDeps({ confirmProdAccess: async () => true });
    const res = await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBe("prod-access-token");
    expect(body.token_type).toBe("Bearer");
  });

  test("returns 403 when denied", async () => {
    const deps = makeDeps({ confirmProdAccess: async () => false });
    const res = await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(res.status).toBe(403);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("denied");
  });

  test("writes granted audit with email for approved prod", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({
      confirmProdAccess: async () => true,
      writeAuditLog: (e) => logs.push(e),
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(logs).toHaveLength(1);
    expect(logs[0]!.level).toBe("prod");
    expect(logs[0]!.result).toBe("granted");
    expect(logs[0]!.email).toBe("user@example.com");
  });

  test("writes denied audit with email for rejected prod", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({
      confirmProdAccess: async () => false,
      writeAuditLog: (e) => logs.push(e),
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(logs).toHaveLength(1);
    expect(logs[0]!.level).toBe("prod");
    expect(logs[0]!.result).toBe("denied");
    expect(logs[0]!.email).toBe("user@example.com");
  });

  test("returns 500 when identity lookup fails during prod flow", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({
      getIdentityEmail: async () => {
        throw new Error("no identity");
      },
      writeAuditLog: (e) => logs.push(e),
    });

    const res = await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(res.status).toBe(500);
    expect(logs).toHaveLength(1);
    expect(logs[0]!.result).toBe("error");
  });

  test("returns 429 when rate limited", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({
      prodRateLimiter: blockedRateLimiter("too many attempts"),
      writeAuditLog: (e) => logs.push(e),
    });

    const res = await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(res.status).toBe(429);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("too many attempts");
  });

  test("writes rate_limited audit entry when blocked", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({
      prodRateLimiter: blockedRateLimiter("dialog pending"),
      writeAuditLog: (e) => logs.push(e),
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(logs).toHaveLength(1);
    expect(logs[0]!.level).toBe("prod");
    expect(logs[0]!.result).toBe("rate_limited");
    expect(logs[0]!.error).toContain("dialog pending");
  });

  test("does not call confirmProdAccess when rate limited", async () => {
    let confirmCalled = false;
    const deps = makeDeps({
      prodRateLimiter: blockedRateLimiter(),
      confirmProdAccess: async () => {
        confirmCalled = true;
        return true;
      },
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(confirmCalled).toBe(false);
  });

  test("releases rate limiter on granted", async () => {
    const releases: string[] = [];
    const deps = makeDeps({
      confirmProdAccess: async () => true,
      prodRateLimiter: {
        acquire: () => ({ allowed: true }),
        release: (r) => {
          releases.push(r);
        },
      },
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);
    expect(releases).toEqual(["granted"]);
  });

  test("releases rate limiter on denied", async () => {
    const releases: string[] = [];
    const deps = makeDeps({
      confirmProdAccess: async () => false,
      prodRateLimiter: {
        acquire: () => ({ allowed: true }),
        release: (r) => {
          releases.push(r);
        },
      },
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);
    expect(releases).toEqual(["denied"]);
  });

  test("releases rate limiter on error", async () => {
    const releases: string[] = [];
    const deps = makeDeps({
      getIdentityEmail: async () => {
        throw new Error("boom");
      },
      prodRateLimiter: {
        acquire: () => ({ allowed: true }),
        release: (r) => {
          releases.push(r);
        },
      },
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);
    expect(releases).toEqual(["error"]);
  });

  test("passes command summary to confirmProdAccess when header is present", async () => {
    let capturedCommand: string | undefined;
    const deps = makeDeps({
      confirmProdAccess: async (_email, command) => {
        capturedCommand = command;
        return true;
      },
    });

    const headers = {
      "X-Wrapped-Command": JSON.stringify(["gcloud", "compute", "instances", "list"]),
    };
    await handleRequest(makeRequest("/token?level=prod", "GET", headers), deps);

    expect(capturedCommand).toBe("gcloud compute instances list");
  });

  test("passes undefined command when header is missing", async () => {
    let capturedCommand: string | undefined = "should-be-replaced";
    const deps = makeDeps({
      confirmProdAccess: async (_email, command) => {
        capturedCommand = command;
        return true;
      },
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(capturedCommand).toBeUndefined();
  });

  test("passes undefined command when header contains invalid JSON", async () => {
    let capturedCommand: string | undefined = "should-be-replaced";
    const deps = makeDeps({
      confirmProdAccess: async (_email, command) => {
        capturedCommand = command;
        return true;
      },
    });

    const headers = { "X-Wrapped-Command": "not-json" };
    await handleRequest(makeRequest("/token?level=prod", "GET", headers), deps);

    expect(capturedCommand).toBeUndefined();
  });

  test("summarizes long commands with truncation", async () => {
    let capturedCommand: string | undefined;
    const deps = makeDeps({
      confirmProdAccess: async (_email, command) => {
        capturedCommand = command;
        return true;
      },
    });

    const longArgs = Array.from({ length: 20 }, (_, i) => `arg-with-content-${i}`);
    const headers = {
      "X-Wrapped-Command": JSON.stringify(["mybinary", ...longArgs]),
    };
    await handleRequest(makeRequest("/token?level=prod", "GET", headers), deps);

    expect(capturedCommand).toBeDefined();
    expect(capturedCommand!.length).toBeLessThanOrEqual(80);
    expect(capturedCommand!.startsWith("mybinary")).toBe(true);
  });

  test("redacts sensitive-looking values in command", async () => {
    let capturedCommand: string | undefined;
    const deps = makeDeps({
      confirmProdAccess: async (_email, command) => {
        capturedCommand = command;
        return true;
      },
    });

    const token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";
    const headers = {
      "X-Wrapped-Command": JSON.stringify(["curl", "-H", token]),
    };
    await handleRequest(makeRequest("/token?level=prod", "GET", headers), deps);

    expect(capturedCommand).toBeDefined();
    expect(capturedCommand).toContain("***");
    expect(capturedCommand).not.toContain(token);
  });
});

// ---------------------------------------------------------------------------
// GET /token?level=prod with PAM
// ---------------------------------------------------------------------------

describe("GET /token?level=prod with PAM", () => {
  test("calls ensurePamGrant when pam_policy query param is in allowlist", async () => {
    let capturedPath: string | undefined;
    const deps = makeDeps({
      pamDefaultPolicy: undefined,
      pamAllowedPolicies: new Set(["my-policy"]),
      ensurePamGrant: async (path) => {
        capturedPath = path;
        return { name: "grants/g1", state: "ACTIVATED", cached: false };
      },
    });

    await handleRequest(makeRequest("/token?level=prod&pam_policy=my-policy"), deps);
    expect(capturedPath).toBe("my-policy");
  });

  test("uses pamDefaultPolicy when no query param", async () => {
    let capturedPath: string | undefined;
    const deps = makeDeps({
      pamDefaultPolicy: "default-entitlement",
      pamAllowedPolicies: new Set(["default-entitlement"]),
      ensurePamGrant: async (path) => {
        capturedPath = path;
        return { name: "grants/g1", state: "ACTIVATED", cached: false };
      },
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);
    expect(capturedPath).toBe("default-entitlement");
  });

  test("query param overrides pamDefaultPolicy", async () => {
    let capturedPath: string | undefined;
    const deps = makeDeps({
      pamDefaultPolicy: "default-entitlement",
      pamAllowedPolicies: new Set(["default-entitlement", "override-entitlement"]),
      ensurePamGrant: async (path) => {
        capturedPath = path;
        return { name: "grants/g1", state: "ACTIVATED", cached: false };
      },
    });

    await handleRequest(makeRequest("/token?level=prod&pam_policy=override-entitlement"), deps);
    expect(capturedPath).toBe("override-entitlement");
  });

  test("returns 403 when pam_policy not in allowlist", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({
      pamAllowedPolicies: new Set(["allowed-policy"]),
      ensurePamGrant: async () => ({ name: "g", state: "ACTIVATED", cached: false }),
      writeAuditLog: (e) => logs.push(e),
    });

    const res = await handleRequest(
      makeRequest("/token?level=prod&pam_policy=forbidden-policy"),
      deps,
    );

    expect(res.status).toBe(403);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("not in allowlist");

    expect(logs).toHaveLength(1);
    expect(logs[0]!.result).toBe("denied");
  });

  test("returns 500 when pam_policy is present but ensurePamGrant not wired", async () => {
    const deps = makeDeps({
      pamDefaultPolicy: undefined,
      pamAllowedPolicies: undefined,
      ensurePamGrant: undefined,
    });

    const res = await handleRequest(makeRequest("/token?level=prod&pam_policy=some-policy"), deps);

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("PAM module not configured");
  });

  test("skips PAM when no pam_policy and no default", async () => {
    let ensureCalled = false;
    const deps = makeDeps({
      pamDefaultPolicy: undefined,
      ensurePamGrant: async () => {
        ensureCalled = true;
        return { name: "g", state: "ACTIVATED", cached: false };
      },
    });

    const res = await handleRequest(makeRequest("/token?level=prod"), deps);
    expect(res.status).toBe(200);
    expect(ensureCalled).toBe(false);
  });

  test("includes PAM fields in audit log when grant succeeds", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({
      pamDefaultPolicy: "my-policy",
      pamAllowedPolicies: new Set(["my-policy"]),
      ensurePamGrant: async () => ({
        name: "grants/pam-grant-123",
        state: "ACTIVATED",
        cached: false,
      }),
      writeAuditLog: (e) => logs.push(e),
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(logs).toHaveLength(1);
    expect(logs[0]!.pam_policy).toBe("my-policy");
    expect(logs[0]!.pam_grant).toBe("grants/pam-grant-123");
    expect(logs[0]!.pam_cached).toBe(false);
  });

  test("passes PAM policy to confirmProdAccess", async () => {
    let capturedPam: string | undefined;
    const deps = makeDeps({
      pamDefaultPolicy: "my-entitlement",
      pamAllowedPolicies: new Set(["my-entitlement"]),
      ensurePamGrant: async () => ({
        name: "g",
        state: "ACTIVATED",
        cached: false,
      }),
      confirmProdAccess: async (_email, _command, pamPolicy) => {
        capturedPam = pamPolicy;
        return true;
      },
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);
    expect(capturedPam).toBe("my-entitlement");
  });

  test("resolves pam_policy query param via resolvePamPolicy before allowlist check", async () => {
    let capturedPath: string | undefined;
    const resolvedPath = "projects/p/locations/global/entitlements/short-id";
    const deps = makeDeps({
      pamAllowedPolicies: new Set([resolvedPath]),
      resolvePamPolicy: (_policy) => resolvedPath,
      ensurePamGrant: async (path) => {
        capturedPath = path;
        return { name: "grants/g1", state: "ACTIVATED", cached: false };
      },
    });

    const res = await handleRequest(makeRequest("/token?level=prod&pam_policy=short-id"), deps);

    expect(res.status).toBe(200);
    expect(capturedPath).toBe(resolvedPath);
  });

  test("returns 400 when resolvePamPolicy rejects invalid query param", async () => {
    const deps = makeDeps({
      pamAllowedPolicies: new Set(["valid"]),
      resolvePamPolicy: () => {
        throw new Error('Invalid PAM entitlement ID: "BAD!"');
      },
      ensurePamGrant: async () => ({ name: "g", state: "ACTIVATED", cached: false }),
    });

    const res = await handleRequest(makeRequest("/token?level=prod&pam_policy=BAD!"), deps);

    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("Invalid PAM entitlement ID");
  });

  test("returns 403 when resolved pam_policy not in allowlist", async () => {
    const deps = makeDeps({
      pamAllowedPolicies: new Set(["projects/p/locations/global/entitlements/allowed"]),
      resolvePamPolicy: (policy) => `projects/p/locations/global/entitlements/${policy}`,
      ensurePamGrant: async () => ({ name: "g", state: "ACTIVATED", cached: false }),
    });

    const res = await handleRequest(makeRequest("/token?level=prod&pam_policy=forbidden"), deps);

    expect(res.status).toBe(403);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("not in allowlist");
  });

  test("returns 500 when ensurePamGrant fails", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({
      pamDefaultPolicy: "my-policy",
      pamAllowedPolicies: new Set(["my-policy"]),
      ensurePamGrant: async () => {
        throw new Error("PAM API unreachable");
      },
      writeAuditLog: (e) => logs.push(e),
    });

    const res = await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("PAM API unreachable");

    expect(logs).toHaveLength(1);
    expect(logs[0]!.result).toBe("error");
  });
});

// ---------------------------------------------------------------------------
// Concurrent dialog prevention
// ---------------------------------------------------------------------------

describe("concurrent dialog prevention", () => {
  test("second prod request is rejected while first dialog is pending", async () => {
    let resolveDialog!: (value: boolean) => void;
    const dialogPromise = new Promise<boolean>((resolve) => {
      resolveDialog = resolve;
    });

    const deps = makeDeps({
      confirmProdAccess: async () => dialogPromise,
    });

    // Fire first request (will block on the confirmation dialog)
    const first = handleRequest(makeRequest("/token?level=prod"), deps);

    // Fire second request while first dialog is still pending
    const second = await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(second.status).toBe(429);
    const body = (await second.json()) as Record<string, unknown>;
    expect(body.error).toContain("already pending");

    // Resolve the first dialog so the test can complete cleanly
    resolveDialog(true);
    const firstRes = await first;
    expect(firstRes.status).toBe(200);
  });

  test("only one confirm call is made when concurrent requests arrive", async () => {
    let confirmCallCount = 0;
    let resolveDialog!: (value: boolean) => void;
    const dialogPromise = new Promise<boolean>((resolve) => {
      resolveDialog = resolve;
    });

    const deps = makeDeps({
      confirmProdAccess: async () => {
        confirmCallCount++;
        return dialogPromise;
      },
    });

    // Fire two requests concurrently
    const first = handleRequest(makeRequest("/token?level=prod"), deps);
    const secondRes = await handleRequest(makeRequest("/token?level=prod"), deps);

    // Second should be rate-limited without calling confirm
    expect(secondRes.status).toBe(429);
    expect(confirmCallCount).toBe(1);

    // Clean up
    resolveDialog(true);
    await first;
  });
});

// ---------------------------------------------------------------------------
// Method not allowed
// ---------------------------------------------------------------------------

describe("non-GET methods", () => {
  test("returns 405 for POST", async () => {
    const res = await handleRequest(makeRequest("/token", "POST"), makeDeps());
    expect(res.status).toBe(405);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("Method not allowed");
  });

  test("returns 405 for DELETE", async () => {
    const res = await handleRequest(makeRequest("/health", "DELETE"), makeDeps());
    expect(res.status).toBe(405);
  });
});

// ---------------------------------------------------------------------------
// Unknown path
// ---------------------------------------------------------------------------

describe("unknown path", () => {
  test("returns 404", async () => {
    const res = await handleRequest(makeRequest("/unknown"), makeDeps());
    expect(res.status).toBe(404);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("Not found");
  });
});

// ---------------------------------------------------------------------------
// expires_in edge cases
// ---------------------------------------------------------------------------

describe("expires_in edge cases", () => {
  test("dev token expires_in is never negative", async () => {
    const pastToken: CachedToken = {
      access_token: "expired-token",
      expires_at: new Date(Date.now() - 1000), // already expired
    };
    const deps = makeDeps({ mintDevToken: async () => pastToken });
    const res = await handleRequest(makeRequest("/token"), deps);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.expires_in).toBe(0);
  });

  test("prod token expires_in is never negative", async () => {
    const pastToken: CachedToken = {
      access_token: "expired-prod-token",
      expires_at: new Date(Date.now() - 5000),
    };
    const deps = makeDeps({
      mintProdToken: async () => pastToken,
      confirmProdAccess: async () => true,
    });
    const res = await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.expires_in).toBe(0);
  });

  test("dev token error audit handles non-Error thrown values", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({
      mintDevToken: async () => {
        throw "string-error"; // eslint-disable-line no-throw-literal
      },
      writeAuditLog: (e) => logs.push(e),
    });

    const res = await handleRequest(makeRequest("/token"), deps);

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("Unknown error");
    expect(logs[0]!.error).toBe("Unknown error");
  });
});

// ---------------------------------------------------------------------------
// token_ttl_seconds query param
// ---------------------------------------------------------------------------

describe("token_ttl_seconds query param", () => {
  test("passes ttlSeconds to mintDevToken when param is present", async () => {
    let capturedTtl: number | undefined;
    const deps = makeDeps({
      mintDevToken: async (_scopes, ttlSeconds) => {
        capturedTtl = ttlSeconds;
        return { access_token: "t", expires_at: new Date(Date.now() + 1800 * 1000) };
      },
    });

    const res = await handleRequest(makeRequest("/token?token_ttl_seconds=1800"), deps);
    expect(res.status).toBe(200);
    expect(capturedTtl).toBe(1800);
  });

  test("passes ttlSeconds to mintProdToken when param is present", async () => {
    let capturedTtl: number | undefined;
    const deps = makeDeps({
      mintProdToken: async (_scopes, ttlSeconds) => {
        capturedTtl = ttlSeconds;
        return { access_token: "t", expires_at: new Date(Date.now() + 900 * 1000) };
      },
    });

    const res = await handleRequest(makeRequest("/token?level=prod&token_ttl_seconds=900"), deps);
    expect(res.status).toBe(200);
    expect(capturedTtl).toBe(900);
  });

  test("does not pass ttlSeconds when param is absent", async () => {
    let capturedTtl: number | undefined = 9999;
    const deps = makeDeps({
      mintDevToken: async (_scopes, ttlSeconds) => {
        capturedTtl = ttlSeconds;
        return { access_token: "t", expires_at: new Date(Date.now() + 3600 * 1000) };
      },
    });

    await handleRequest(makeRequest("/token"), deps);
    expect(capturedTtl).toBeUndefined();
  });

  test("returns 400 when ttl exceeds configured default", async () => {
    const deps = makeDeps({ defaultTokenTtlSeconds: 1800 });

    const res = await handleRequest(makeRequest("/token?token_ttl_seconds=3600"), deps);
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("exceeds configured maximum");
    expect(body.error).toContain("3600");
    expect(body.error).toContain("1800");
  });

  test("accepts ttl equal to configured default", async () => {
    const deps = makeDeps({ defaultTokenTtlSeconds: 1800 });

    const res = await handleRequest(makeRequest("/token?token_ttl_seconds=1800"), deps);
    expect(res.status).toBe(200);
  });

  test("returns 400 when ttl is below 60", async () => {
    const res = await handleRequest(makeRequest("/token?token_ttl_seconds=30"), makeDeps());
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain(">= 60");
  });

  test("returns 400 for non-integer value", async () => {
    const res = await handleRequest(makeRequest("/token?token_ttl_seconds=3.5"), makeDeps());
    expect(res.status).toBe(400);
  });

  test("returns 400 for non-numeric value", async () => {
    const res = await handleRequest(makeRequest("/token?token_ttl_seconds=abc"), makeDeps());
    expect(res.status).toBe(400);
  });

  test("returns 400 for trailing-text value like '3600abc'", async () => {
    const res = await handleRequest(makeRequest("/token?token_ttl_seconds=3600abc"), makeDeps());
    expect(res.status).toBe(400);
  });

  test("returns 400 for empty string value", async () => {
    const res = await handleRequest(makeRequest("/token?token_ttl_seconds="), makeDeps());
    expect(res.status).toBe(400);
  });

  test("includes token_ttl_seconds in audit entry when non-default TTL is used", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({ writeAuditLog: (e) => logs.push(e) });

    await handleRequest(makeRequest("/token?token_ttl_seconds=1800"), deps);

    expect(logs).toHaveLength(1);
    expect(logs[0]!.token_ttl_seconds).toBe(1800);
  });

  test("audit entry omits token_ttl_seconds when param is absent", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({ writeAuditLog: (e) => logs.push(e) });

    await handleRequest(makeRequest("/token"), deps);

    expect(logs).toHaveLength(1);
    expect(logs[0]!.token_ttl_seconds).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// POST /session (create prod session)
// ---------------------------------------------------------------------------

describe("POST /session", () => {
  test("creates a session and returns session_id with initial token", async () => {
    const deps = makeDeps();
    const res = await handleRequest(makeRequest("/session", "POST"), deps);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.session_id).toBeString();
    expect((body.session_id as string).length).toBe(64);
    expect(body.access_token).toBe("prod-access-token");
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.token_type).toBe("Bearer");
    expect(body.email).toBe("user@example.com");
  });

  test("triggers confirmation dialog", async () => {
    let confirmed = false;
    const deps = makeDeps({
      confirmProdAccess: async () => {
        confirmed = true;
        return true;
      },
    });

    await handleRequest(makeRequest("/session", "POST"), deps);
    expect(confirmed).toBe(true);
  });

  test("returns 403 when user denies confirmation", async () => {
    const deps = makeDeps({ confirmProdAccess: async () => false });
    const res = await handleRequest(makeRequest("/session", "POST"), deps);

    expect(res.status).toBe(403);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("Prod access denied by user");
  });

  test("returns 429 when rate-limited", async () => {
    const deps = makeDeps({ prodRateLimiter: blockedRateLimiter() });
    const res = await handleRequest(makeRequest("/session", "POST"), deps);
    expect(res.status).toBe(429);
  });

  test("passes scopes to mintProdToken", async () => {
    let capturedScopes: string[] | undefined;
    const deps = makeDeps({
      mintProdToken: async (scopes) => {
        capturedScopes = scopes;
        return { access_token: "t", expires_at: new Date(Date.now() + 3600_000) };
      },
    });

    await handleRequest(makeRequest("/session?scopes=scope1,scope2", "POST"), deps);
    expect(capturedScopes).toEqual(["scope1", "scope2"]);
  });

  test("writes audit log with session_id on success", async () => {
    const logs: AuditEntry[] = [];
    const deps = makeDeps({ writeAuditLog: (e) => logs.push(e) });

    const res = await handleRequest(makeRequest("/session", "POST"), deps);
    const body = (await res.json()) as Record<string, unknown>;

    expect(logs).toHaveLength(1);
    expect(logs[0]!.endpoint).toBe("/session");
    expect(logs[0]!.level).toBe("prod");
    expect(logs[0]!.result).toBe("granted");
    expect(logs[0]!.session_id).toBe(body.session_id as string);
  });

  test("returns 405 for GET method", async () => {
    const res = await handleRequest(makeRequest("/session", "GET"), makeDeps());
    expect(res.status).toBe(405);
  });

  test("validates session_ttl_seconds param", async () => {
    const res = await handleRequest(
      makeRequest("/session?session_ttl_seconds=100", "POST"),
      makeDeps(),
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("session_ttl_seconds must be >= 300");
  });

  test("validates token_ttl_seconds param", async () => {
    const res = await handleRequest(
      makeRequest("/session?token_ttl_seconds=10", "POST"),
      makeDeps(),
    );
    expect(res.status).toBe(400);
  });

  test("stores session scopes and ttl for later refresh", async () => {
    const sessionManager = createSessionManager();
    const deps = makeDeps({ sessionManager });

    const res = await handleRequest(
      makeRequest("/session?scopes=scope1&token_ttl_seconds=900", "POST"),
      deps,
    );
    const body = (await res.json()) as Record<string, unknown>;
    const session = sessionManager.validate(body.session_id as string);

    expect(session).not.toBeNull();
    expect(session!.scopes).toEqual(["scope1"]);
    expect(session!.ttlSeconds).toBe(900);
  });
});

// ---------------------------------------------------------------------------
// DELETE /session (revoke prod session)
// ---------------------------------------------------------------------------

describe("DELETE /session", () => {
  test("revokes an existing session", async () => {
    const sessionManager = createSessionManager();
    const session = sessionManager.create({
      email: "eng@example.com",
      ttlSeconds: 3600,
      sessionLifetimeSeconds: 28800,
    });
    const deps = makeDeps({ sessionManager });

    const res = await handleRequest(makeRequest(`/session?id=${session.id}`, "DELETE"), deps);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("revoked");
    expect(sessionManager.validate(session.id)).toBeNull();
  });

  test("returns 404 for unknown session", async () => {
    const res = await handleRequest(
      makeRequest(`/session?id=${"0".repeat(64)}`, "DELETE"),
      makeDeps(),
    );
    expect(res.status).toBe(404);
  });

  test("returns 400 when id param is missing", async () => {
    const res = await handleRequest(makeRequest("/session", "DELETE"), makeDeps());
    expect(res.status).toBe(400);
  });

  test("writes audit log on revocation", async () => {
    const logs: AuditEntry[] = [];
    const sessionManager = createSessionManager();
    const session = sessionManager.create({
      email: "eng@example.com",
      ttlSeconds: 3600,
      sessionLifetimeSeconds: 28800,
    });
    const deps = makeDeps({ sessionManager, writeAuditLog: (e) => logs.push(e) });

    await handleRequest(makeRequest(`/session?id=${session.id}`, "DELETE"), deps);

    expect(logs).toHaveLength(1);
    expect(logs[0]!.result).toBe("revoked");
    expect(logs[0]!.session_id).toBe(session.id);
  });
});

// ---------------------------------------------------------------------------
// GET /token?session=<id> (session-based token refresh)
// ---------------------------------------------------------------------------

describe("GET /token?session=<id>", () => {
  test("mints a fresh prod token for a valid session", async () => {
    const sessionManager = createSessionManager();
    const session = sessionManager.create({
      email: "eng@example.com",
      ttlSeconds: 3600,
      sessionLifetimeSeconds: 28800,
    });
    const deps = makeDeps({ sessionManager });

    const res = await handleRequest(makeRequest(`/token?session=${session.id}`), deps);

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBe("prod-access-token");
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.token_type).toBe("Bearer");
  });

  test("returns 401 for expired session", async () => {
    let time = 1_000_000;
    const sessionManager = createSessionManager({ now: () => time });
    const session = sessionManager.create({
      email: "eng@example.com",
      ttlSeconds: 3600,
      sessionLifetimeSeconds: 60,
    });

    time = 1_000_000 + 61_000;
    const deps = makeDeps({ sessionManager });
    const res = await handleRequest(makeRequest(`/token?session=${session.id}`), deps);

    expect(res.status).toBe(401);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("expired or invalid");
  });

  test("returns 401 for unknown session ID", async () => {
    const res = await handleRequest(makeRequest(`/token?session=${"0".repeat(64)}`), makeDeps());
    expect(res.status).toBe(401);
  });

  test("uses session scopes and ttl for token minting", async () => {
    let capturedScopes: string[] | undefined;
    let capturedTtl: number | undefined;
    const sessionManager = createSessionManager();
    const session = sessionManager.create({
      email: "eng@example.com",
      scopes: ["scope1", "scope2"],
      ttlSeconds: 900,
      sessionLifetimeSeconds: 28800,
    });

    const deps = makeDeps({
      sessionManager,
      mintProdToken: async (scopes, ttl) => {
        capturedScopes = scopes;
        capturedTtl = ttl;
        return { access_token: "t", expires_at: new Date(Date.now() + 900_000) };
      },
    });

    await handleRequest(makeRequest(`/token?session=${session.id}`), deps);

    expect(capturedScopes).toEqual(["scope1", "scope2"]);
    expect(capturedTtl).toBe(900);
  });

  test("does not trigger confirmation or rate limiting", async () => {
    let confirmCalled = false;
    const sessionManager = createSessionManager();
    const session = sessionManager.create({
      email: "eng@example.com",
      ttlSeconds: 3600,
      sessionLifetimeSeconds: 28800,
    });

    const deps = makeDeps({
      sessionManager,
      confirmProdAccess: async () => {
        confirmCalled = true;
        return true;
      },
      prodRateLimiter: blockedRateLimiter(),
    });

    const res = await handleRequest(makeRequest(`/token?session=${session.id}`), deps);

    expect(res.status).toBe(200);
    expect(confirmCalled).toBe(false);
  });

  test("writes audit log with session_id", async () => {
    const logs: AuditEntry[] = [];
    const sessionManager = createSessionManager();
    const session = sessionManager.create({
      email: "eng@example.com",
      ttlSeconds: 3600,
      sessionLifetimeSeconds: 28800,
    });
    const deps = makeDeps({ sessionManager, writeAuditLog: (e) => logs.push(e) });

    await handleRequest(makeRequest(`/token?session=${session.id}`), deps);

    expect(logs).toHaveLength(1);
    expect(logs[0]!.session_id).toBe(session.id);
    expect(logs[0]!.email).toBe("eng@example.com");
    expect(logs[0]!.level).toBe("prod");
  });

  test("returns 500 when mintProdToken fails", async () => {
    const sessionManager = createSessionManager();
    const session = sessionManager.create({
      email: "eng@example.com",
      ttlSeconds: 3600,
      sessionLifetimeSeconds: 28800,
    });

    const deps = makeDeps({
      sessionManager,
      mintProdToken: async () => {
        throw new Error("ADC expired");
      },
    });

    const res = await handleRequest(makeRequest(`/token?session=${session.id}`), deps);
    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("ADC expired");
  });

  test("renews PAM grant for sessions with a PAM policy", async () => {
    let ensureGrantCalled = false;
    let capturedEntitlement = "";
    const sessionManager = createSessionManager();
    const session = sessionManager.create({
      email: "eng@example.com",
      ttlSeconds: 3600,
      sessionLifetimeSeconds: 28800,
      pamPolicy: "projects/p/locations/global/entitlements/e",
    });

    const deps = makeDeps({
      sessionManager,
      ensurePamGrant: async (entitlementPath) => {
        ensureGrantCalled = true;
        capturedEntitlement = entitlementPath;
        return { name: "grants/g1", state: "ACTIVATED", cached: false };
      },
    });

    const res = await handleRequest(makeRequest(`/token?session=${session.id}`), deps);

    expect(res.status).toBe(200);
    expect(ensureGrantCalled).toBe(true);
    expect(capturedEntitlement).toBe("projects/p/locations/global/entitlements/e");
  });

  test("does not call ensurePamGrant when session has no PAM policy", async () => {
    let ensureGrantCalled = false;
    const sessionManager = createSessionManager();
    const session = sessionManager.create({
      email: "eng@example.com",
      ttlSeconds: 3600,
      sessionLifetimeSeconds: 28800,
    });

    const deps = makeDeps({
      sessionManager,
      ensurePamGrant: async () => {
        ensureGrantCalled = true;
        return { name: "grants/g1", state: "ACTIVATED", cached: false };
      },
    });

    const res = await handleRequest(makeRequest(`/token?session=${session.id}`), deps);

    expect(res.status).toBe(200);
    expect(ensureGrantCalled).toBe(false);
  });

  test("includes pam_grant in audit log for session refresh with PAM", async () => {
    const logs: AuditEntry[] = [];
    const sessionManager = createSessionManager();
    const session = sessionManager.create({
      email: "eng@example.com",
      ttlSeconds: 3600,
      sessionLifetimeSeconds: 28800,
      pamPolicy: "projects/p/locations/global/entitlements/e",
    });

    const deps = makeDeps({
      sessionManager,
      writeAuditLog: (e) => logs.push(e),
      ensurePamGrant: async () => ({ name: "grants/g1", state: "ACTIVATED", cached: true }),
    });

    await handleRequest(makeRequest(`/token?session=${session.id}`), deps);

    expect(logs).toHaveLength(1);
    expect(logs[0]!.pam_grant).toBe("grants/g1");
    expect(logs[0]!.pam_cached).toBe(true);
    expect(logs[0]!.pam_policy).toBe("projects/p/locations/global/entitlements/e");
  });

  test("returns 500 when PAM grant renewal fails during session refresh", async () => {
    const sessionManager = createSessionManager();
    const session = sessionManager.create({
      email: "eng@example.com",
      ttlSeconds: 3600,
      sessionLifetimeSeconds: 28800,
      pamPolicy: "projects/p/locations/global/entitlements/e",
    });

    const deps = makeDeps({
      sessionManager,
      ensurePamGrant: async () => {
        throw new Error("PAM grant expired and renewal failed");
      },
    });

    const res = await handleRequest(makeRequest(`/token?session=${session.id}`), deps);
    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("PAM grant expired and renewal failed");
  });
});

// ---------------------------------------------------------------------------
// /pending routes removed from main socket (served on admin socket only)
// ---------------------------------------------------------------------------

describe("/pending routes on main socket", () => {
  test("GET /pending returns 404 on main socket", async () => {
    const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
    const deps = makeDeps({ pendingQueue });
    const res = await handleRequest(makeRequest("/pending"), deps);
    expect(res.status).toBe(404);
  });

  test("POST /pending/:id/approve returns 405 on main socket", async () => {
    const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
    const deps = makeDeps({ pendingQueue });
    const res = await handleRequest(makeRequest("/pending/deadbeef/approve", "POST"), deps);
    expect(res.status).toBe(405);
  });

  test("POST /pending/:id/deny returns 405 on main socket", async () => {
    const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
    const deps = makeDeps({ pendingQueue });
    const res = await handleRequest(makeRequest("/pending/deadbeef/deny", "POST"), deps);
    expect(res.status).toBe(405);
  });
});

// ---------------------------------------------------------------------------
// X-Pending-Id header passthrough
// ---------------------------------------------------------------------------

describe("X-Pending-Id header", () => {
  test("passes X-Pending-Id to confirmProdAccess", async () => {
    let capturedPendingId: string | undefined;
    const deps = makeDeps({
      confirmProdAccess: async (_email, _cmd, _pam, pendingId) => {
        capturedPendingId = pendingId;
        return true;
      },
    });

    const headers = { "X-Pending-Id": "a".repeat(32) };
    await handleRequest(makeRequest("/token?level=prod", "GET", headers), deps);

    expect(capturedPendingId).toBe("a".repeat(32));
  });

  test("passes undefined when X-Pending-Id header is missing", async () => {
    let capturedPendingId: string | undefined = "should-be-replaced";
    const deps = makeDeps({
      confirmProdAccess: async (_email, _cmd, _pam, pendingId) => {
        capturedPendingId = pendingId;
        return true;
      },
    });

    await handleRequest(makeRequest("/token?level=prod"), deps);

    expect(capturedPendingId).toBeUndefined();
  });

  test("passes X-Pending-Id to confirmProdAccess on POST /session", async () => {
    let capturedPendingId: string | undefined;
    const deps = makeDeps({
      confirmProdAccess: async (_email, _cmd, _pam, pendingId) => {
        capturedPendingId = pendingId;
        return true;
      },
    });

    const headers = { "X-Pending-Id": "b".repeat(32) };
    await handleRequest(makeRequest("/session", "POST", headers), deps);

    expect(capturedPendingId).toBe("b".repeat(32));
  });
});
