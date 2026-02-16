import { describe, expect, test } from "bun:test";
import { handleRequest } from "../../gate/handlers.ts";
import type { GateDeps, AuditEntry, CachedToken } from "../../gate/types.ts";
import { createProdRateLimiter } from "../../gate/rate-limit.ts";
import type { ProdRateLimiter } from "../../gate/rate-limit.ts";

function makeDeps(overrides: Partial<GateDeps> = {}): GateDeps {
  const token: CachedToken = {
    access_token: "test-access-token",
    expires_at: new Date(Date.now() + 3600 * 1000),
  };

  return {
    mintDevToken: async () => token,
    mintProdToken: async () => ({
      access_token: "prod-access-token",
      expires_at: new Date(Date.now() + 3600 * 1000),
    }),
    getIdentityEmail: async () => "user@example.com",
    getProjectNumber: async () => "123456789012",
    getUniverseDomain: async () => "googleapis.com",
    confirmProdAccess: async () => true,
    writeAuditLog: () => {},
    prodRateLimiter: createProdRateLimiter(),
    startTime: new Date(Date.now() - 60_000),
    ...overrides,
  };
}

/** A rate limiter that always blocks. */
function blockedRateLimiter(reason = "rate limited"): ProdRateLimiter {
  return {
    acquire: () => ({ allowed: false, reason }),
    release: () => {},
  };
}

function makeRequest(path: string, method = "GET"): Request {
  return new Request(`http://localhost${path}`, { method });
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
