import { describe, expect, spyOn, test } from "bun:test";
import {
  resolveEntitlementPath,
  createPamModule,
  PamRequesterLookupError,
  type PamModule,
} from "../../gate/pam.ts";
import { CredentialsExpiredError } from "../../gate/credentials-error.ts";

// ---------------------------------------------------------------------------
// resolveEntitlementPath
// ---------------------------------------------------------------------------

describe("resolveEntitlementPath", () => {
  test("expands short-form entitlement ID", () => {
    const result = resolveEntitlementPath("prod-db-admin", "my-project", "global");
    expect(result).toBe("projects/my-project/locations/global/entitlements/prod-db-admin");
  });

  test("expands short-form with non-global location", () => {
    const result = resolveEntitlementPath("my-policy", "my-project", "us-central1");
    expect(result).toBe("projects/my-project/locations/us-central1/entitlements/my-policy");
  });

  test("defaults location to global", () => {
    const result = resolveEntitlementPath("my-policy", "my-project");
    expect(result).toBe("projects/my-project/locations/global/entitlements/my-policy");
  });

  test("passes through full resource path unchanged", () => {
    const fullPath = "projects/my-project/locations/global/entitlements/prod-admin";
    const result = resolveEntitlementPath(fullPath, "my-project", "global");
    expect(result).toBe(fullPath);
  });

  test("rejects short-form ID with uppercase letters", () => {
    expect(() => resolveEntitlementPath("ProdAdmin", "p")).toThrow("Invalid PAM entitlement ID");
  });

  test("rejects short-form ID with underscores", () => {
    expect(() => resolveEntitlementPath("prod_admin", "p")).toThrow("Invalid PAM entitlement ID");
  });

  test("rejects short-form ID starting with digit", () => {
    expect(() => resolveEntitlementPath("1-policy", "p")).toThrow("Invalid PAM entitlement ID");
  });

  test("rejects short-form ID starting with hyphen", () => {
    expect(() => resolveEntitlementPath("-policy", "p")).toThrow("Invalid PAM entitlement ID");
  });

  test("rejects full path with wrong format", () => {
    expect(() => resolveEntitlementPath("projects/p/entitlements/e", "p")).toThrow(
      "Invalid PAM entitlement path",
    );
  });

  test("rejects full path referencing wrong project", () => {
    const path = "projects/other-project/locations/global/entitlements/admin";
    expect(() => resolveEntitlementPath(path, "my-project")).toThrow(
      'references project "other-project" but gate is configured for "my-project"',
    );
  });

  test("accepts full path with matching project", () => {
    const path = "projects/my-project/locations/us-east1/entitlements/reader";
    const result = resolveEntitlementPath(path, "my-project");
    expect(result).toBe(path);
  });

  test("accepts folder-scoped full path verbatim, ignoring projectId", () => {
    const path = "folders/123456789/locations/global/entitlements/prod-db-admin";
    expect(resolveEntitlementPath(path, "any-project")).toBe(path);
    // The whole point of folder paths is that they're project-agnostic;
    // resolution must not change when the gate's project_id changes.
    expect(resolveEntitlementPath(path, "different-project")).toBe(path);
  });

  test("accepts folder-scoped path with non-global location", () => {
    const path = "folders/42/locations/us-central1/entitlements/reader";
    expect(resolveEntitlementPath(path, "p")).toBe(path);
  });

  test("rejects folder-scoped path with non-numeric folder id", () => {
    expect(() =>
      resolveEntitlementPath("folders/abc/locations/global/entitlements/reader", "p"),
    ).toThrow("Invalid PAM folder entitlement path");
  });

  test("rejects folder-scoped path missing the location segment", () => {
    expect(() => resolveEntitlementPath("folders/123/entitlements/reader", "p")).toThrow(
      "Invalid PAM folder entitlement path",
    );
  });

  test("rejects folder-scoped path with empty entitlement id", () => {
    expect(() => resolveEntitlementPath("folders/123/locations/global/entitlements/", "p")).toThrow(
      "Invalid PAM folder entitlement path",
    );
  });

  test("rejects malformed project-scoped path with helpful message mentioning folder form", () => {
    expect(() => resolveEntitlementPath("projects/p/entitlements/e", "p")).toThrow(
      "folders/{folder}/locations/{location}/entitlements/{id}",
    );
  });

  test("rejects malformed project-scoped path with helpful message mentioning organization form", () => {
    expect(() => resolveEntitlementPath("projects/p/entitlements/e", "p")).toThrow(
      "organizations/{org}/locations/{location}/entitlements/{id}",
    );
  });

  test("accepts org-scoped full path verbatim, ignoring projectId", () => {
    const path = "organizations/987654321/locations/global/entitlements/prod-db-admin";
    expect(resolveEntitlementPath(path, "any-project")).toBe(path);
    expect(resolveEntitlementPath(path, "different-project")).toBe(path);
  });

  test("accepts org-scoped path with non-global location", () => {
    const path = "organizations/42/locations/us-central1/entitlements/reader";
    expect(resolveEntitlementPath(path, "p")).toBe(path);
  });

  test("rejects org-scoped path with non-numeric org id", () => {
    expect(() =>
      resolveEntitlementPath("organizations/acme/locations/global/entitlements/reader", "p"),
    ).toThrow("Invalid PAM organization entitlement path");
  });

  test("rejects org-scoped path missing the location segment", () => {
    expect(() => resolveEntitlementPath("organizations/123/entitlements/reader", "p")).toThrow(
      "Invalid PAM organization entitlement path",
    );
  });

  test("rejects org-scoped path with empty entitlement id", () => {
    expect(() =>
      resolveEntitlementPath("organizations/123/locations/global/entitlements/", "p"),
    ).toThrow("Invalid PAM organization entitlement path");
  });
});

// ---------------------------------------------------------------------------
// createPamModule
// ---------------------------------------------------------------------------

function makeActivatedGrant(name: string, createTime?: string) {
  return {
    name,
    state: "ACTIVATED",
    createTime: createTime ?? new Date().toISOString(),
    requestedDuration: "3600s",
  };
}

function mockFetch(responses: Array<{ status: number; body: unknown }>): typeof globalThis.fetch {
  let callIndex = 0;
  return (async () => {
    const resp = responses[callIndex++];
    if (!resp) throw new Error("No more mock responses");
    return new Response(JSON.stringify(resp.body), {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;
}

function isGrantCollectionUrl(url: string): boolean {
  return new URL(url).pathname.endsWith("/grants");
}

/**
 * Mock fetch that auto-responds to withdraw POSTs with `{}` 200 and dispenses
 * `creates` (lazy bodies — evaluated when the create call fires, so they can
 * close over a `currentTime` that has advanced between calls). Returns the
 * `events` log so tests can assert ordering of create vs withdraw.
 */
function mockGrantOps(creates: Array<() => Record<string, unknown>>): {
  fetchFn: typeof globalThis.fetch;
  events: Array<{ kind: "create" | "withdraw"; url: string }>;
} {
  const events: Array<{ kind: "create" | "withdraw"; url: string }> = [];
  let createIdx = 0;
  const fetchFn = (async (url: string, init?: RequestInit) => {
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "POST" && url.includes(":withdraw")) {
      events.push({ kind: "withdraw", url });
      return new Response("{}", { status: 200 });
    }
    if (method === "POST") {
      const factory = creates[createIdx++];
      if (!factory) throw new Error(`unexpected create call: ${url}`);
      events.push({ kind: "create", url });
      return new Response(JSON.stringify(factory()), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch: ${method} ${url}`);
  }) as unknown as typeof globalThis.fetch;
  return { fetchFn, events };
}

function makeModule(
  fetchResponses: Array<{ status: number; body: unknown }>,
  nowFn?: () => number,
): { pam: PamModule; getAccessTokenCalls: number } {
  let getAccessTokenCalls = 0;
  const pam = createPamModule(
    async () => {
      getAccessTokenCalls++;
      return "test-adc-token";
    },
    {
      fetchFn: mockFetch(fetchResponses),
      now: nowFn,
    },
  );
  return { pam, getAccessTokenCalls };
}

describe("ensureGrant", () => {
  const entitlementPath = "projects/p/locations/global/entitlements/e";
  const requestId1 = "11111111-1111-4111-8111-111111111111";
  const requestId2 = "22222222-2222-4222-8222-222222222222";

  test("creates and returns an immediately activated grant", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const { pam } = makeModule([{ status: 200, body: makeActivatedGrant(grantName) }]);

    const result = await pam.ensureGrant(entitlementPath);

    expect(result.name).toBe(grantName);
    expect(result.state).toBe("ACTIVATED");
    expect(result.cached).toBe(false);
  });

  test("sends a nonzero UUID requestId on grants.create", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    let createUrl: string | undefined;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string) => {
        createUrl = url;
        return Response.json(makeActivatedGrant(grantName));
      }) as unknown as typeof globalThis.fetch,
      requestIdFactory: () => requestId1,
    });

    await pam.ensureGrant(entitlementPath);

    expect(new URL(createUrl!).searchParams.get("requestId")).toBe(requestId1);
  });

  test("retries a network-ambiguous create exactly once with the same requestId", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const createUrls: string[] = [];
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string) => {
        createUrls.push(url);
        if (createUrls.length === 1) throw new TypeError("socket reset");
        return Response.json(makeActivatedGrant(grantName));
      }) as unknown as typeof globalThis.fetch,
      requestIdFactory: () => requestId1,
    });

    const result = await pam.ensureGrant(entitlementPath);

    expect(result.name).toBe(grantName);
    expect(createUrls).toHaveLength(2);
    expect(createUrls[1]).toBe(createUrls[0]);
  });

  test("retries a timed-out create exactly once with the same requestId", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const createUrls: string[] = [];
    const pam = createPamModule(async () => "token", {
      fetchFn: ((url: string, init?: RequestInit) => {
        createUrls.push(url);
        if (createUrls.length === 1) {
          return new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), {
              once: true,
            });
          });
        }
        return Promise.resolve(Response.json(makeActivatedGrant(grantName)));
      }) as unknown as typeof globalThis.fetch,
      fetchTimeoutMs: 20,
      requestIdFactory: () => requestId1,
    });

    const result = await pam.ensureGrant(entitlementPath);

    expect(result.name).toBe(grantName);
    expect(createUrls).toHaveLength(2);
    expect(createUrls[1]).toBe(createUrls[0]);
  });

  test.each([429, 500, 503])(
    "retries transient HTTP %d exactly once with the same requestId",
    async (status) => {
      const grantName = `${entitlementPath}/grants/grant-1`;
      const createUrls: string[] = [];
      const pam = createPamModule(async () => "token", {
        fetchFn: (async (url: string) => {
          createUrls.push(url);
          if (createUrls.length === 1) {
            return Response.json({ error: { message: "transient" } }, { status });
          }
          return Response.json(makeActivatedGrant(grantName));
        }) as unknown as typeof globalThis.fetch,
        requestIdFactory: () => requestId1,
      });

      const result = await pam.ensureGrant(entitlementPath);

      expect(result.name).toBe(grantName);
      expect(createUrls).toHaveLength(2);
      expect(createUrls[1]).toBe(createUrls[0]);
    },
  );

  test("does not retry a deterministic 4xx create failure", async () => {
    let createCalls = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async () => {
        createCalls++;
        return Response.json({ error: { message: "denied" } }, { status: 403 });
      }) as unknown as typeof globalThis.fetch,
      requestIdFactory: () => requestId1,
    });

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("access denied (403)");
    expect(createCalls).toBe(1);
  });

  test("uses a new requestId for create after open-grant recovery", async () => {
    const currentTime = 10_000_000;
    const staleName = `${entitlementPath}/grants/stale`;
    const freshName = `${entitlementPath}/grants/fresh`;
    const ids = [requestId1, requestId2];
    const createUrls: string[] = [];
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) return Response.json({});
        if (method === "GET") {
          return Response.json({
            grants: [
              {
                name: staleName,
                state: "ACTIVE",
                createTime: new Date(currentTime - 2 * 60 * 60 * 1000).toISOString(),
                requestedDuration: "3600s",
              },
            ],
          });
        }
        createUrls.push(url);
        if (createUrls.length === 1) {
          return Response.json({ error: { message: "Already exists" } }, { status: 409 });
        }
        return Response.json(makeActivatedGrant(freshName, new Date(currentTime).toISOString()));
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
      requestIdFactory: () => ids.shift()!,
    });

    const result = await pam.ensureGrant(entitlementPath);

    expect(result.name).toBe(freshName);
    expect(createUrls).toHaveLength(2);
    expect(new URL(createUrls[0]!).searchParams.get("requestId")).toBe(requestId1);
    expect(new URL(createUrls[1]!).searchParams.get("requestId")).toBe(requestId2);
  });

  test("rejects an invalid requestId before issuing create", async () => {
    let fetchCalls = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async () => {
        fetchCalls++;
        return Response.json({});
      }) as unknown as typeof globalThis.fetch,
      requestIdFactory: () => "00000000-0000-0000-0000-000000000000",
    });

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("invalid UUID");
    expect(fetchCalls).toBe(0);
  });

  test("uses configured grant duration in request body", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    let capturedBody: string | undefined;

    const fetchFn = (async (_url: string, init?: RequestInit) => {
      if (init?.body) {
        capturedBody = init.body as string;
      }
      return new Response(JSON.stringify(makeActivatedGrant(grantName)), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    const pam = createPamModule(async () => "test-token", {
      fetchFn,
      grantDurationSeconds: 1800,
    });

    await pam.ensureGrant(entitlementPath);
    expect(capturedBody).toBeDefined();
    const parsed = JSON.parse(capturedBody!) as Record<string, unknown>;
    expect(parsed.requestedDuration).toBe("1800s");
  });

  test("defaults grant duration to 3600s when not configured", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    let capturedBody: string | undefined;

    const fetchFn = (async (_url: string, init?: RequestInit) => {
      if (init?.body) {
        capturedBody = init.body as string;
      }
      return new Response(JSON.stringify(makeActivatedGrant(grantName)), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    const pam = createPamModule(async () => "test-token", { fetchFn });

    await pam.ensureGrant(entitlementPath);
    expect(capturedBody).toBeDefined();
    const parsed = JSON.parse(capturedBody!) as Record<string, unknown>;
    expect(parsed.requestedDuration).toBe("3600s");
  });

  test("returns cached grant on second call", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const { pam } = makeModule([{ status: 200, body: makeActivatedGrant(grantName) }]);

    const first = await pam.ensureGrant(entitlementPath);
    expect(first.cached).toBe(false);

    const second = await pam.ensureGrant(entitlementPath);
    expect(second.cached).toBe(true);
    expect(second.name).toBe(grantName);
  });

  test("re-requests grant when cache expires", async () => {
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    const grantName2 = `${entitlementPath}/grants/grant-2`;
    let currentTime = 1000000;
    const createTime = new Date(currentTime).toISOString();

    const { pam } = makeModule(
      [
        { status: 200, body: makeActivatedGrant(grantName1, createTime) },
        // ensureGrant pre-withdraws the cached entry before re-creating
        // (PAM's state can lag; the withdraw clears any stale "open" state).
        { status: 200, body: {} },
        { status: 200, body: makeActivatedGrant(grantName2, createTime) },
      ],
      () => currentTime,
    );

    const first = await pam.ensureGrant(entitlementPath);
    expect(first.name).toBe(grantName1);
    expect(first.cached).toBe(false);

    // Advance time past grant expiry (1 hour + margin)
    currentTime += 3600 * 1000;

    const second = await pam.ensureGrant(entitlementPath);
    expect(second.name).toBe(grantName2);
    expect(second.cached).toBe(false);
  });

  test("polls pending grant until activated", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const { pam } = makeModule([
      { status: 200, body: { name: grantName, state: "APPROVAL_AWAITED" } },
      { status: 200, body: { name: grantName, state: "APPROVED" } },
      { status: 200, body: makeActivatedGrant(grantName) },
    ]);

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grantName);
    expect(result.state).toBe("ACTIVATED");
  });

  test("throws on 403 Forbidden", async () => {
    const { pam } = makeModule([
      { status: 403, body: { error: { message: "Permission denied" } } },
    ]);

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("PAM API access denied (403)");
  });

  test("throws on 404 Not Found", async () => {
    const { pam } = makeModule([{ status: 404, body: { error: { message: "Not found" } } }]);

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(
      "PAM entitlement not found (404)",
    );
  });

  test("handles 409 Conflict by finding active grant", async () => {
    const grantName = `${entitlementPath}/grants/existing-grant`;
    const { pam } = makeModule([
      { status: 409, body: { error: { message: "Already exists" } } },
      { status: 200, body: { grants: [makeActivatedGrant(grantName)] } },
    ]);

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grantName);
  });

  test("throws on 409 when no active grant found", async () => {
    const { pam } = makeModule([
      { status: 409, body: { error: { message: "Already exists" } } },
      { status: 200, body: { grants: [] } },
    ]);

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(
      /no open grant of ours found.*across 1 page\(s\)/,
    );
  });

  test("throws when grant is denied during polling", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const { pam } = makeModule([
      { status: 200, body: { name: grantName, state: "APPROVAL_AWAITED" } },
      { status: 200, body: { name: grantName, state: "DENIED" } },
    ]);

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(
      "PAM grant entered terminal state DENIED",
    );
  });

  test.each([
    "EXPIRED",
    "ACTIVATION_FAILED",
    "EXTERNALLY_MODIFIED",
    "WITHDRAWN",
    "ENDED",
    "REVOKED",
  ])("throws on terminal state %s during polling", async (state) => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const { pam } = makeModule([
      { status: 200, body: { name: grantName, state: "APPROVAL_AWAITED" } },
      { status: 200, body: { name: grantName, state } },
    ]);

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(
      `PAM grant entered terminal state ${state}`,
    );
  });

  test("throws when grant response has no name", async () => {
    const { pam } = makeModule([{ status: 200, body: { state: "ACTIVATED" } }]);

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("no resource name");
  });

  test("throws on 409 when listing grants fails", async () => {
    const { pam } = makeModule([
      { status: 409, body: { error: { message: "Already exists" } } },
      { status: 500, body: { error: { message: "Internal error" } } },
    ]);

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(
      "PAM API error listing grants (500)",
    );
  });

  test("handles 400 FAILED_PRECONDITION 'open Grant' by finding active grant", async () => {
    const grantName = `${entitlementPath}/grants/existing-grant`;
    const { pam } = makeModule([
      {
        status: 400,
        body: {
          error: {
            code: 400,
            status: "FAILED_PRECONDITION",
            message: `You have an open Grant "${grantName}" that gives the same privileged access.`,
          },
        },
      },
      { status: 200, body: { grants: [makeActivatedGrant(grantName)] } },
    ]);

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grantName);
  });

  test("throws on 400 FAILED_PRECONDITION 'open Grant' when no active grant found", async () => {
    const grantName = `${entitlementPath}/grants/existing-grant`;
    const { pam } = makeModule([
      {
        status: 400,
        body: {
          error: {
            code: 400,
            status: "FAILED_PRECONDITION",
            message: `You have an open Grant "${grantName}" that gives the same privileged access.`,
          },
        },
      },
      { status: 200, body: { grants: [] } },
    ]);

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("no open grant of ours found");
  });

  test("throws on 400 FAILED_PRECONDITION without 'open Grant' phrase", async () => {
    let listCalls = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        if (init?.method === undefined && /\/grants\?pageSize=\d+/.test(url)) {
          listCalls++;
          return new Response(JSON.stringify({ grants: [] }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(
          JSON.stringify({
            error: {
              code: 400,
              status: "FAILED_PRECONDITION",
              message: "Entitlement is disabled.",
            },
          }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        );
      }) as unknown as typeof globalThis.fetch,
    });

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(
      /PAM API error \(400\).*Entitlement is disabled/s,
    );
    expect(listCalls).toBe(0);
  });

  test("throws on 400 with non-FAILED_PRECONDITION status", async () => {
    let listCalls = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        if (init?.method === undefined && /\/grants\?pageSize=\d+/.test(url)) {
          listCalls++;
          return new Response(JSON.stringify({ grants: [] }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(
          JSON.stringify({
            error: {
              code: 400,
              status: "INVALID_ARGUMENT",
              message: "Invalid requestedDuration.",
            },
          }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        );
      }) as unknown as typeof globalThis.fetch,
    });

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(
      /PAM API error \(400\).*INVALID_ARGUMENT/s,
    );
    expect(listCalls).toBe(0);
  });

  test("findActiveGrant lists without a server-side filter", async () => {
    const grantName = `${entitlementPath}/grants/existing-grant`;
    let listUrl: string | undefined;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        if (init?.method === undefined && url.includes("/grants?")) {
          listUrl = url;
          return new Response(JSON.stringify({ grants: [makeActivatedGrant(grantName)] }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ error: { message: "already exists" } }), {
          status: 409,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch,
    });

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grantName);
    expect(listUrl).toBeDefined();
    expect(listUrl).not.toContain("filter=");
  });

  test("findActiveGrant accepts state='ACTIVE'", async () => {
    const grantName = `${entitlementPath}/grants/existing-grant`;
    const { pam } = makeModule([
      { status: 409, body: { error: { message: "Already exists" } } },
      {
        status: 200,
        body: {
          grants: [
            {
              name: grantName,
              state: "ACTIVE",
              createTime: new Date().toISOString(),
              requestedDuration: "3600s",
            },
          ],
        },
      },
    ]);

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grantName);
    expect(result.state).toBe("ACTIVE");
  });

  test("findActiveGrant skips ENDED grants and picks the active one", async () => {
    const endedName = `${entitlementPath}/grants/old-ended`;
    const activeName = `${entitlementPath}/grants/current-active`;
    const { pam } = makeModule([
      { status: 409, body: { error: { message: "Already exists" } } },
      {
        status: 200,
        body: {
          grants: [
            { name: endedName, state: "ENDED", requestedDuration: "3600s" },
            {
              name: activeName,
              state: "ACTIVE",
              createTime: new Date().toISOString(),
              requestedDuration: "3600s",
            },
          ],
        },
      },
    ]);

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(activeName);
  });

  test("findActiveGrant follows nextPageToken when active grant is on a later page", async () => {
    const activeName = `${entitlementPath}/grants/current-active`;
    const observedTokens: Array<string | null> = [];
    let pageIndex = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        if (init?.method === undefined && url.includes("/grants?")) {
          const tokenMatch = /pageToken=([^&]+)/.exec(url);
          observedTokens.push(tokenMatch ? decodeURIComponent(tokenMatch[1]!) : null);
          const body =
            pageIndex++ === 0
              ? {
                  grants: [{ name: `${entitlementPath}/grants/old`, state: "ENDED" }],
                  nextPageToken: "tok-page-2",
                }
              : {
                  grants: [
                    {
                      name: activeName,
                      state: "ACTIVE",
                      createTime: new Date().toISOString(),
                      requestedDuration: "3600s",
                    },
                  ],
                };
          return new Response(JSON.stringify(body), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ error: { message: "already exists" } }), {
          status: 409,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch,
    });

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(activeName);
    expect(observedTokens).toEqual([null, "tok-page-2"]);
  });

  test("findActiveGrant gives up after the page-scan bound", async () => {
    let pages = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        if (init?.method === undefined && url.includes("/grants?")) {
          pages++;
          return new Response(
            JSON.stringify({
              grants: [{ name: `${entitlementPath}/grants/g${pages}`, state: "ENDED" }],
              nextPageToken: `tok-${pages}`,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        return new Response(JSON.stringify({ error: { message: "already exists" } }), {
          status: 409,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch,
    });

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(
      /no open grant of ours found.*scanned \d+ grant\(s\) across 10 page\(s\)/,
    );
    expect(pages).toBe(10);
  });

  test("pollGrant accepts state='ACTIVE' as activated", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const { pam } = makeModule([
      { status: 200, body: { name: grantName, state: "APPROVAL_AWAITED" } },
      {
        status: 200,
        body: {
          name: grantName,
          state: "ACTIVE",
          createTime: new Date().toISOString(),
          requestedDuration: "3600s",
        },
      },
    ]);

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grantName);
    expect(result.state).toBe("ACTIVE");
  });

  test("throws when polling API returns error", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const { pam } = makeModule([
      { status: 200, body: { name: grantName, state: "APPROVAL_AWAITED" } },
      { status: 500, body: { error: { message: "Internal error" } } },
    ]);

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(
      "PAM API error polling grant (500)",
    );
  });

  test("throws on polling timeout", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    // Use a now() function that jumps past the deadline after first poll
    let currentTime = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async () => {
        // After the create call, advance time past deadline on every poll
        currentTime += 200_000;
        return new Response(JSON.stringify({ name: grantName, state: "APPROVAL_AWAITED" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
    });

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("was not activated within");
  });

  test("throws on generic PAM API error", async () => {
    const { pam } = makeModule([
      { status: 500, body: { error: { message: "Internal error" } } },
      { status: 500, body: { error: { message: "Internal error" } } },
    ]);

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("PAM API error (500)");
  });

  test("passes justification to grant request", async () => {
    let capturedBody: string | undefined;
    const grantName = `${entitlementPath}/grants/grant-1`;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (_url: string, init?: RequestInit) => {
        capturedBody = init?.body as string;
        return new Response(JSON.stringify(makeActivatedGrant(grantName)), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch,
    });

    await pam.ensureGrant(entitlementPath, "running migration");

    expect(capturedBody).toBeDefined();
    const parsed = JSON.parse(capturedBody!) as {
      justification?: { unstructuredJustification?: string };
    };
    expect(parsed.justification?.unstructuredJustification).toBe("running migration");
  });

  test("reuses an active grant until the token drain boundary", async () => {
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    const currentTime = 1_000_000;

    // Nine minutes remain. Tokens minted under this grant can still be valid
    // for four more minutes because their expiry is clamped five minutes short
    // of the grant. Withdrawing now would invalidate authorization before the
    // advertised token lifetime, so the conflict recovery path must reuse it.
    const createdAt = currentTime - 51 * 60 * 1000;
    const oldGrant = {
      name: grantName1,
      state: "ACTIVATED",
      createTime: new Date(createdAt).toISOString(),
      requestedDuration: "3600s",
    };

    const { pam } = makeModule(
      [
        // 409 on create, then find the old grant
        { status: 409, body: { error: { message: "Already exists" } } },
        { status: 200, body: { grants: [oldGrant] } },
      ],
      () => currentTime,
    );

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grantName1);
    expect(result.cached).toBe(false);
  });

  test("falls back to conservative TTL when grant lacks createTime", async () => {
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    let currentTime = 1_000_000;

    // Grant without createTime
    const grantNoTime = {
      name: grantName1,
      state: "ACTIVATED",
      // no createTime, no requestedDuration
    };

    const { pam } = makeModule([{ status: 200, body: grantNoTime }], () => currentTime);

    const first = await pam.ensureGrant(entitlementPath);
    expect(first.name).toBe(grantName1);
    expect(first.expiresAt.getTime()).toBe(currentTime + 3600 * 1000);

    // Request start is earlier than activation, so using the full requested
    // duration from that anchor remains conservative and avoids early churn.
    currentTime += 11 * 60 * 1000;
    const second = await pam.ensureGrant(entitlementPath);
    expect(second.name).toBe(grantName1);
    expect(second.cached).toBe(true);
  });

  test("uses the full configured multi-hour fallback for an incomplete create response", async () => {
    const grantName = `${entitlementPath}/grants/grant-long`;
    const requestedAt = 5_000_000;
    let currentTime = requestedAt;
    let fetchCalls = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async () => {
        fetchCalls++;
        return Response.json({ name: grantName, state: "ACTIVATED" });
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
      grantDurationSeconds: 4 * 60 * 60,
    });

    const first = await pam.ensureGrant(entitlementPath);
    expect(first.expiresAt.getTime()).toBe(requestedAt + 4 * 60 * 60 * 1000);

    currentTime += 30 * 60 * 1000;
    const second = await pam.ensureGrant(entitlementPath);
    expect(second.cached).toBe(true);
    expect(fetchCalls).toBe(1);
  });

  test("409 with a stale-but-still-open grant: withdraws the stale grant and retries create", async () => {
    // PAM's `state` field can lag actual expiry: a grant whose
    // createTime + requestedDuration is already in the past may briefly
    // continue to be reported as ACTIVE/ACTIVATED, blocking a new
    // createGrant with 409 / 400 FAILED_PRECONDITION. Reusing the stale
    // grant directly would hand the caller a dead entitlement, so the
    // recovery harness withdraws the stale grant and retries createGrant
    // once — the returned grant always has usable remaining lifetime.
    const currentTime = 10_000_000;
    const staleName = `${entitlementPath}/grants/stale-active`;
    const freshName = `${entitlementPath}/grants/fresh-active`;
    const staleGrant = {
      name: staleName,
      state: "ACTIVE",
      // Created 2 hours ago with a 1-hour duration — clearly expired.
      createTime: new Date(currentTime - 2 * 60 * 60 * 1000).toISOString(),
      requestedDuration: "3600s",
    };
    const freshGrant = {
      name: freshName,
      state: "ACTIVATED",
      createTime: new Date(currentTime).toISOString(),
      requestedDuration: "3600s",
    };

    const withdrawnNames: string[] = [];
    let listCalls = 0;
    let createCalls = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          withdrawnNames.push(url);
          return new Response("{}", { status: 200 });
        }
        if (method === "GET" && /\/grants\?pageSize=\d+/.test(url)) {
          listCalls++;
          return new Response(JSON.stringify({ grants: [staleGrant] }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (method === "POST" && isGrantCollectionUrl(url)) {
          createCalls++;
          if (createCalls === 1) {
            // First create: PAM rejects because the stale grant is still open.
            return new Response(JSON.stringify({ error: { message: "Already exists" } }), {
              status: 409,
              headers: { "Content-Type": "application/json" },
            });
          }
          // Second create (after the stale grant was withdrawn) succeeds.
          return new Response(JSON.stringify(freshGrant), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
    });

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(freshName);
    expect(createCalls).toBe(2);
    expect(listCalls).toBeGreaterThanOrEqual(1);
    expect(withdrawnNames).toHaveLength(1);
    expect(withdrawnNames[0]).toContain(staleName);
    // The post-#98 invariant — never return a grant with no usable lifetime —
    // must still hold after the recovery path.
    expect(result.expiresAt.getTime() - currentTime).toBeGreaterThan(5 * 60 * 1000);
  });

  test("409 with only stale grants but persistent conflict surfaces a distinct error", async () => {
    // After withdrawing every stale grant the scan returned, a second
    // createGrant that still 409s is a real conflict (likely PAM lag
    // longer than our bounded retry can absorb, or another process
    // racing us). The error message must distinguish this from the
    // "no active grant found" path so operators can tell them apart.
    const currentTime = 10_000_000;
    const staleName = `${entitlementPath}/grants/stale-active`;
    const staleGrant = {
      name: staleName,
      state: "ACTIVE",
      createTime: new Date(currentTime - 2 * 60 * 60 * 1000).toISOString(),
      requestedDuration: "3600s",
    };

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          return new Response("{}", { status: 200 });
        }
        if (method === "GET" && /\/grants\?pageSize=\d+/.test(url)) {
          return new Response(JSON.stringify({ grants: [staleGrant] }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        // Both creates 409.
        return new Response(JSON.stringify({ error: { message: "Already exists" } }), {
          status: 409,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
    });

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(/grant conflict persists/);
  });

  test("recovery path tolerates withdraw failure on the stale grant", async () => {
    // withdrawGrantAndWait swallows errors so a 5xx on the withdraw
    // doesn't abort the retry — the next createGrant may still succeed
    // if PAM has caught up on its own by the time we try.
    const currentTime = 10_000_000;
    const staleName = `${entitlementPath}/grants/stale-active`;
    const freshName = `${entitlementPath}/grants/fresh-active`;
    const staleGrant = {
      name: staleName,
      state: "ACTIVE",
      createTime: new Date(currentTime - 2 * 60 * 60 * 1000).toISOString(),
      requestedDuration: "3600s",
    };
    const freshGrant = {
      name: freshName,
      state: "ACTIVATED",
      createTime: new Date(currentTime).toISOString(),
      requestedDuration: "3600s",
    };

    let createCalls = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          return new Response(JSON.stringify({ error: { message: "boom" } }), {
            status: 500,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (method === "GET" && /\/grants\?pageSize=\d+/.test(url)) {
          return new Response(JSON.stringify({ grants: [staleGrant] }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (method === "POST" && isGrantCollectionUrl(url)) {
          createCalls++;
          if (createCalls === 1) {
            return new Response(JSON.stringify({ error: { message: "Already exists" } }), {
              status: 409,
              headers: { "Content-Type": "application/json" },
            });
          }
          return new Response(JSON.stringify(freshGrant), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
    });

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(freshName);
  });

  test("findActiveGrant returns a still-fresh active grant on a later page", async () => {
    // Sanity check that the expiry filter does not drop grants with
    // genuine remaining lifetime.
    const currentTime = 10_000_000;
    const freshName = `${entitlementPath}/grants/fresh-active`;
    const expiredName = `${entitlementPath}/grants/stale-active`;

    const { pam } = makeModule(
      [
        { status: 409, body: { error: { message: "Already exists" } } },
        {
          status: 200,
          body: {
            grants: [
              {
                name: expiredName,
                state: "ACTIVE",
                createTime: new Date(currentTime - 2 * 60 * 60 * 1000).toISOString(),
                requestedDuration: "3600s",
              },
              {
                name: freshName,
                state: "ACTIVE",
                createTime: new Date(currentTime - 5 * 60 * 1000).toISOString(),
                requestedDuration: "3600s",
              },
            ],
          },
        },
      ],
      () => currentTime,
    );

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(freshName);
  });

  test("returns expiresAt computed from createTime + requestedDuration", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const createdAtMs = 5_000_000;
    const { pam } = makeModule(
      [
        {
          status: 200,
          body: {
            name: grantName,
            state: "ACTIVATED",
            createTime: new Date(createdAtMs).toISOString(),
            requestedDuration: "3600s",
          },
        },
      ],
      () => createdAtMs,
    );

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.expiresAt.getTime()).toBe(createdAtMs + 3600 * 1000);
  });

  test("anchors expiry to auditTrail.accessGrantTime after delayed approval", async () => {
    const grantName = `${entitlementPath}/grants/grant-delayed`;
    const currentTime = 20_000_000;
    const createdAt = currentTime - 20 * 60 * 1000;
    const accessGrantedAt = currentTime - 2 * 60 * 1000;
    const { pam } = makeModule(
      [
        {
          status: 200,
          body: {
            name: grantName,
            state: "ACTIVE",
            createTime: new Date(createdAt).toISOString(),
            requestedDuration: "3600s",
            auditTrail: { accessGrantTime: new Date(accessGrantedAt).toISOString() },
          },
        },
      ],
      () => currentTime,
    );

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.expiresAt.getTime()).toBe(accessGrantedAt + 3600 * 1000);
  });

  test("uses an activated timeline event when the audit trail is absent", async () => {
    const grantName = `${entitlementPath}/grants/grant-timeline`;
    const currentTime = 20_000_000;
    const activatedAt = currentTime - 60_000;
    const { pam } = makeModule(
      [
        {
          status: 200,
          body: {
            name: grantName,
            state: "ACTIVE",
            createTime: new Date(currentTime - 10 * 60 * 1000).toISOString(),
            requestedDuration: "3600.5s",
            timeline: {
              events: [{ eventTime: new Date(activatedAt).toISOString(), activated: {} }],
            },
          },
        },
      ],
      () => currentTime,
    );

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.expiresAt.getTime()).toBe(activatedAt + 3_600_500);
  });

  test("near-expiry renewal recovers when PAM still 409s after our pre-withdraw", async () => {
    // The proactive pre-withdraw in ensureGrant clears most of the
    // cache-margin races, but PAM may still echo the just-withdrawn grant
    // as "open" if the create lands before PAM has propagated the
    // withdraw. The recovery harness must scan, re-withdraw the stale
    // grant, and retry create — without rolling back the
    // "never return a grant with no usable lifetime" invariant.
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    const grantName2 = `${entitlementPath}/grants/grant-2`;
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();

    const withdrawnNames: string[] = [];
    let createCalls = 0;
    let staleStillAppearsOpen = true;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          withdrawnNames.push(url);
          // After a second withdraw against the stale grant, PAM finally
          // catches up — the next create can succeed.
          if (withdrawnNames.filter((u) => u.includes(grantName1)).length >= 2) {
            staleStillAppearsOpen = false;
          }
          return new Response("{}", { status: 200 });
        }
        if (method === "GET" && /\/grants\?pageSize=\d+/.test(url)) {
          // PAM still reports grant-1 as ACTIVE even though we withdrawn it,
          // but its computed expiry has passed (we advanced into the
          // margin), so the scan classifies it as stale.
          return new Response(
            JSON.stringify({
              grants: [
                {
                  name: grantName1,
                  state: "ACTIVE",
                  createTime: createTime1,
                  requestedDuration: "3600s",
                },
              ],
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (method === "POST" && isGrantCollectionUrl(url)) {
          createCalls++;
          if (createCalls === 1) {
            // Initial create the test driver runs against an empty cache.
            return new Response(
              JSON.stringify({
                name: grantName1,
                state: "ACTIVATED",
                createTime: createTime1,
                requestedDuration: "3600s",
              }),
              { status: 200, headers: { "Content-Type": "application/json" } },
            );
          }
          if (staleStillAppearsOpen) {
            return new Response(JSON.stringify({ error: { message: "Already exists" } }), {
              status: 409,
              headers: { "Content-Type": "application/json" },
            });
          }
          return new Response(
            JSON.stringify({
              name: grantName2,
              state: "ACTIVATED",
              createTime: new Date(currentTime).toISOString(),
              requestedDuration: "3600s",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
    });

    await pam.ensureGrant(entitlementPath);

    // Step into the 5-minute cache margin (grant has ~3 min left).
    currentTime += 57 * 60 * 1000;

    const second = await pam.ensureGrant(entitlementPath);
    expect(second.name).toBe(grantName2);
    expect(second.cached).toBe(false);
    // Two withdraw calls against grant-1: the pre-withdraw that ensureGrant
    // issues and the recovery-path withdraw against the stale scan result.
    expect(withdrawnNames.filter((u) => u.includes(grantName1))).toHaveLength(2);
    // Two create attempts after the initial: one 409, one success.
    expect(createCalls).toBe(3);
    // Invariant: the returned grant has usable remaining lifetime.
    expect(second.expiresAt.getTime() - currentTime).toBeGreaterThan(5 * 60 * 1000);
  });

  test("near-expiry renewal withdraws old grant before creating a new one", async () => {
    // The post-#98 lifetime filter in findActiveGrant turns the cache-margin
    // window into a dead-end: createGrant 409s on the still-open grant and
    // findActiveGrant rejects it for being too close to expiry. Pre-emptively
    // withdrawing the old grant unblocks the create, so renewal succeeds even
    // when triggered from inside the margin.
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    const grantName2 = `${entitlementPath}/grants/grant-2`;
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();

    const { fetchFn, events } = mockGrantOps([
      () => ({
        name: grantName1,
        state: "ACTIVATED",
        createTime: createTime1,
        requestedDuration: "3600s",
      }),
      () => ({
        name: grantName2,
        state: "ACTIVATED",
        createTime: new Date(currentTime).toISOString(),
        requestedDuration: "3600s",
      }),
    ]);

    const pam = createPamModule(async () => "token", {
      fetchFn,
      now: () => currentTime,
    });

    const first = await pam.ensureGrant(entitlementPath);
    expect(first.name).toBe(grantName1);

    // Advance to within the 5-minute cache margin (grant has ~3 min left).
    currentTime += 57 * 60 * 1000;

    const second = await pam.ensureGrant(entitlementPath);
    expect(second.name).toBe(grantName2);
    expect(second.cached).toBe(false);

    expect(events.map((e) => e.kind)).toEqual(["create", "withdraw", "create"]);
    expect(events[1]!.url).toContain(grantName1);
  });

  test("expired-grant renewal best-effort withdraws stale cache entry", async () => {
    // A grant whose computed expiry has already passed must still be
    // withdrawn before we re-create: PAM's state can lag actual expiry,
    // leaving the old grant in an "open" state that 409s the immediate
    // create. withdrawGrantAndWait is a no-op against truly-ended
    // grants, so this is safe in both cases — and it saves a recovery
    // round trip whenever PAM hasn't caught up yet.
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    const grantName2 = `${entitlementPath}/grants/grant-2`;
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();

    const { fetchFn, events } = mockGrantOps([
      () => ({
        name: grantName1,
        state: "ACTIVATED",
        createTime: createTime1,
        requestedDuration: "3600s",
      }),
      () => ({
        name: grantName2,
        state: "ACTIVATED",
        createTime: new Date(currentTime).toISOString(),
        requestedDuration: "3600s",
      }),
    ]);

    const pam = createPamModule(async () => "token", {
      fetchFn,
      now: () => currentTime,
    });

    await pam.ensureGrant(entitlementPath);

    // Advance well past expiry.
    currentTime += 3600 * 1000 + 60 * 1000;

    await pam.ensureGrant(entitlementPath);
    expect(events.map((e) => e.kind)).toEqual(["create", "withdraw", "create"]);
    expect(events[1]!.url).toContain(grantName1);
  });

  test("withdrawn grant is removed from cache so withdrawAll skips it", async () => {
    // After a near-expiry renewal withdraws the old grant, the cache should
    // hold the new grant only. Subsequent shutdown withdrawAll must not
    // re-withdraw the old (already-withdrawn) grant.
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    const grantName2 = `${entitlementPath}/grants/grant-2`;
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();

    const { fetchFn, events } = mockGrantOps([
      () => ({
        name: grantName1,
        state: "ACTIVATED",
        createTime: createTime1,
        requestedDuration: "3600s",
      }),
      () => ({
        name: grantName2,
        state: "ACTIVATED",
        createTime: new Date(currentTime).toISOString(),
        requestedDuration: "3600s",
      }),
    ]);

    const pam = createPamModule(async () => "token", {
      fetchFn,
      now: () => currentTime,
    });

    await pam.ensureGrant(entitlementPath);
    currentTime += 57 * 60 * 1000;
    await pam.ensureGrant(entitlementPath);

    const withdraws = events.filter((e) => e.kind === "withdraw");
    expect(withdraws).toHaveLength(1);
    expect(withdraws[0]!.url).toContain(grantName1);

    await pam.withdrawAll();
    const allWithdraws = events.filter((e) => e.kind === "withdraw");
    expect(allWithdraws).toHaveLength(2);
    expect(allWithdraws[1]!.url).toContain(grantName2);
  });

  test("expired cache entry is not retained after invalidation", async () => {
    // After a cached grant's expiry passes, ensureGrant pre-withdraws it
    // (best-effort, to clear PAM's lagged state) and purges the cache
    // entry before attempting to re-create. If the re-create then fails,
    // withdrawAll must not double-withdraw grant-1 — the cache should
    // already be empty.
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();

    const withdrawnNames: string[] = [];
    let createCalls = 0;
    const fetchFn = (async (url: string, init?: RequestInit) => {
      // Withdraw calls
      if (init?.method === "POST" && (url as string).includes(":withdraw")) {
        withdrawnNames.push(url as string);
        return new Response("{}", { status: 200 });
      }
      // First create — returns grant-1
      if (createCalls === 0 && init?.method === "POST") {
        createCalls++;
        return new Response(
          JSON.stringify({
            name: grantName1,
            state: "ACTIVATED",
            createTime: createTime1,
            requestedDuration: "3600s",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      throw new Error(`unexpected fetch: ${url}`);
    }) as unknown as typeof globalThis.fetch;

    const pam = createPamModule(async () => "token", {
      fetchFn,
      now: () => currentTime,
    });

    await pam.ensureGrant(entitlementPath);

    // Advance past expiry
    currentTime += 3600 * 1000 + 1000;

    // Calling ensureGrant again pre-withdraws grant-1 and then attempts to
    // re-create (which fails — no further create mock). After the
    // failure the cache should be empty so withdrawAll doesn't try to
    // withdraw grant-1 a second time.
    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow();
    expect(withdrawnNames).toHaveLength(1);
    expect(withdrawnNames[0]).toContain(grantName1);

    await pam.withdrawAll();
    expect(withdrawnNames).toHaveLength(1);
  });

  test("rotation failure is logged to the console, not just thrown", async () => {
    // The thrown error reaches the client and the audit file, but the gate's
    // console log must show it too — otherwise a failed rotation looks
    // silent in the daemon log (the original bug report symptom).
    const errorSpy = spyOn(console, "error").mockImplementation(() => {});
    try {
      const { pam } = makeModule([
        { status: 500, body: { error: { message: "boom" } } },
        { status: 500, body: { error: { message: "boom" } } },
      ]);
      await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("PAM API error (500)");
      const logged = errorSpy.mock.calls.map((c) => String(c[0]));
      expect(logged.some((m) => m.includes(`grant rotation failed for ${entitlementPath}`))).toBe(
        true,
      );
    } finally {
      errorSpy.mockRestore();
    }
  });

  test("withdraws the just-created grant when activation polling times out", async () => {
    // A grant that never activates (e.g. approval never arrives) still
    // holds the open-grant slot; leaving it behind would 409-block every
    // follow-up create. The failure path must withdraw it best-effort.
    const grantName = `${entitlementPath}/grants/grant-1`;
    let currentTime = 0;
    const withdrawn: string[] = [];

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          withdrawn.push(url);
          return new Response(JSON.stringify({ name: "op-1", done: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        // Create and every activation poll: the grant stays pending while
        // each poll advances time past the 120s deadline.
        if (method === "GET") currentTime += 200_000;
        return new Response(JSON.stringify({ name: grantName, state: "APPROVAL_AWAITED" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
      sleepFn: () => Promise.resolve(),
    });

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("was not activated within");
    expect(withdrawn).toHaveLength(1);
    expect(withdrawn[0]).toContain(grantName);
  });

  test("does not withdraw a grant that entered a terminal state during polling", async () => {
    // Terminal grants no longer hold the open-grant slot — cleanup would be
    // a wasted (and confusingly logged) API call.
    const grantName = `${entitlementPath}/grants/grant-1`;
    let withdrawCalls = 0;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          withdrawCalls++;
          return new Response("{}", { status: 200 });
        }
        if (method === "POST") {
          return new Response(JSON.stringify({ name: grantName, state: "APPROVAL_AWAITED" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ name: grantName, state: "DENIED" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch,
      sleepFn: () => Promise.resolve(),
    });

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("terminal state DENIED");
    expect(withdrawCalls).toBe(0);
  });

  test("persistent conflict error reports withdraw failures instead of claiming success", async () => {
    // When the blocking grant can't be withdrawn (e.g. the v1beta surface
    // is blocked by policy), the conflict error must not assert that the
    // withdrawals happened — that misdirects debugging away from the
    // actual withdraw failure in the gate log.
    const currentTime = 10_000_000;
    const staleGrant = {
      ...makeActivatedGrant(
        `${entitlementPath}/grants/stale-active`,
        new Date(currentTime - 2 * 60 * 60 * 1000).toISOString(),
      ),
      state: "ACTIVE",
    };

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          return new Response(JSON.stringify({ error: { message: "blocked" } }), { status: 403 });
        }
        if (method === "GET" && /\/grants\?pageSize=\d+/.test(url)) {
          return new Response(JSON.stringify({ grants: [staleGrant] }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        // Both creates 409.
        return new Response(JSON.stringify({ error: { message: "Already exists" } }), {
          status: 409,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
    });

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(
      /grant conflict persists and only 0 of 1 blocking grant\(s\) could be withdrawn/,
    );
  });
});

// ---------------------------------------------------------------------------
// withdrawAll
// ---------------------------------------------------------------------------

describe("withdrawAll", () => {
  const entitlementPath = "projects/p/locations/global/entitlements/e";

  test("withdraws cached active grants", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const withdrawnGrants: string[] = [];

    let callCount = 0;
    const fetchFn = (async (url: string, init?: RequestInit) => {
      callCount++;
      if (callCount === 1) {
        // createGrant
        return new Response(JSON.stringify(makeActivatedGrant(grantName)), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      // withdrawGrant
      if (init?.method === "POST" && (url as string).includes(":withdraw")) {
        withdrawnGrants.push(url as string);
      }
      return new Response("{}", { status: 200 });
    }) as unknown as typeof globalThis.fetch;

    const pam = createPamModule(async () => "token", { fetchFn });

    await pam.ensureGrant(entitlementPath);
    await pam.withdrawAll();

    expect(withdrawnGrants).toHaveLength(1);
    expect(withdrawnGrants[0]).toContain(grantName);
  });

  test("tolerates withdraw HTTP failures", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    let callCount = 0;

    const fetchFn = (async () => {
      callCount++;
      if (callCount === 1) {
        return new Response(JSON.stringify(makeActivatedGrant(grantName)), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      // Withdraw fails with HTTP error
      return new Response("Internal error", { status: 500 });
    }) as unknown as typeof globalThis.fetch;

    const pam = createPamModule(async () => "token", { fetchFn });

    await pam.ensureGrant(entitlementPath);
    // Should not throw
    await pam.withdrawAll();
  });

  test("tolerates withdraw network failures", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    let callCount = 0;

    const fetchFn = (async () => {
      callCount++;
      if (callCount === 1) {
        return new Response(JSON.stringify(makeActivatedGrant(grantName)), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      // Withdraw fails with network error
      throw new Error("Network unreachable");
    }) as unknown as typeof globalThis.fetch;

    const pam = createPamModule(async () => "token", { fetchFn });

    await pam.ensureGrant(entitlementPath);
    // Should not throw
    await pam.withdrawAll();
  });

  test("does nothing when no grants are cached", async () => {
    const { pam } = makeModule([]);
    // Should not throw
    await pam.withdrawAll();
  });

  test("aborts an activating rotation and withdraws its created grant", async () => {
    const grantName = `${entitlementPath}/grants/pending-at-shutdown`;
    const withdrawn: string[] = [];
    let pollStarted = false;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          withdrawn.push(url);
          return Response.json({ done: true });
        }
        if (method === "POST" && isGrantCollectionUrl(url)) {
          return Response.json({
            name: grantName,
            state: "ACTIVATING",
            requestedDuration: "3600s",
          });
        }
        if (method === "GET" && url.endsWith(grantName)) {
          pollStarted = true;
          return new Promise<Response>((_resolve, reject) => {
            const signal = init?.signal;
            if (signal?.aborted) {
              reject(signal.reason);
            } else {
              signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
            }
          });
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      sleepFn: async () => {},
      shutdownTimeoutMs: 500,
    });

    const rotationOutcome = pam.ensureGrant(entitlementPath).catch((error: unknown) => error);
    expect(await until(() => pollStarted, 1000)).toBe(true);

    await pam.withdrawAll();

    const rotationError = await rotationOutcome;
    expect(rotationError).toBeInstanceOf(Error);
    expect((rotationError as Error).message).toContain("shutting down");
    expect(withdrawn).toHaveLength(1);
    expect(withdrawn[0]).toContain(grantName);
  });

  test("withdraws a grant whose create response arrives after shutdown starts", async () => {
    const grantName = `${entitlementPath}/grants/late-create-response`;
    const withdrawn: string[] = [];
    let createStarted = false;
    let resolveCreate: ((response: Response) => void) | undefined;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          withdrawn.push(url);
          return Response.json({ done: true });
        }
        if (method === "POST" && isGrantCollectionUrl(url)) {
          createStarted = true;
          // Model a response already on the wire when shutdown aborts fetch.
          // The module must handle the conservative case where it still wins
          // the race and reveals the created grant's resource name.
          return new Promise<Response>((resolve) => {
            resolveCreate = resolve;
          });
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      shutdownTimeoutMs: 500,
    });

    const rotationOutcome = pam.ensureGrant(entitlementPath).catch((error: unknown) => error);
    expect(await until(() => createStarted, 1000)).toBe(true);

    const shutdown = pam.withdrawAll();
    resolveCreate!(
      Response.json({
        name: grantName,
        state: "ACTIVATING",
        requestedDuration: "3600s",
      }),
    );
    await shutdown;

    expect(await rotationOutcome).toBeInstanceOf(Error);
    expect(withdrawn).toHaveLength(1);
    expect(withdrawn[0]).toContain(grantName);
  });

  test("rejects new grant requests after shutdown", async () => {
    let fetchCalls = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async () => {
        fetchCalls++;
        return Response.json({});
      }) as unknown as typeof globalThis.fetch,
    });

    await pam.withdrawAll();

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("shutting down");
    expect(fetchCalls).toBe(0);
  });

  test("bounds shutdown when withdrawal access-token acquisition never settles", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    let tokenCalls = 0;
    const pam = createPamModule(
      () => {
        tokenCalls++;
        if (tokenCalls === 1) return Promise.resolve("token");
        return new Promise<string>(() => {});
      },
      {
        fetchFn: (async () =>
          Response.json(makeActivatedGrant(grantName))) as unknown as typeof globalThis.fetch,
        shutdownTimeoutMs: 30,
      },
    );
    await pam.ensureGrant(entitlementPath);

    const outcome = await settleWithin(pam.withdrawAll(), 500);

    expect(outcome.status).toBe("resolved");
    expect(tokenCalls).toBe(2);
  });

  test("does not withdraw a cached grant whose requester ownership was never confirmed", async () => {
    const otherGrant = `${entitlementPath}/grants/other-requester`;
    let withdrawCalls = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          withdrawCalls++;
          return Response.json({ done: true });
        }
        if (method === "POST") {
          return Response.json({ error: { message: "Already exists" } }, { status: 409 });
        }
        return Response.json({
          grants: [
            {
              ...makeActivatedGrant(otherGrant),
              requester: "other@example.com",
            },
          ],
        });
      }) as unknown as typeof globalThis.fetch,
    });

    const adopted = await pam.ensureGrant(entitlementPath);
    expect(adopted.name).toBe(otherGrant);

    await pam.withdrawAll();
    expect(withdrawCalls).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Single-flight rotation
// ---------------------------------------------------------------------------

describe("ensureGrant single-flight", () => {
  const entitlementPath = "projects/p/locations/global/entitlements/e";

  test("concurrent calls coalesce onto one create when cache is cold", async () => {
    const grantName = `${entitlementPath}/grants/g1`;
    let createCalls = 0;
    let releaseCreate: (() => void) | undefined;
    const createGate = new Promise<void>((r) => {
      releaseCreate = r;
    });

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (_url: string, init?: RequestInit) => {
        if (init?.method === "POST") {
          createCalls++;
          await createGate; // Block until released so we can fan-out callers.
          return new Response(
            JSON.stringify({
              name: grantName,
              state: "ACTIVATED",
              createTime: new Date().toISOString(),
              requestedDuration: "3600s",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`unexpected fetch: ${init?.method}`);
      }) as unknown as typeof globalThis.fetch,
    });

    const fanOut = Array.from({ length: 5 }, () => pam.ensureGrant(entitlementPath));
    // Yield so all five callers enter ensureGrant before we release the create.
    await new Promise((r) => setTimeout(r, 0));
    releaseCreate!();

    const results = await Promise.all(fanOut);
    expect(createCalls).toBe(1);
    for (const r of results) {
      expect(r.name).toBe(grantName);
    }
  });

  test("concurrent rotations during cache renewal coalesce onto one rotation", async () => {
    const grantName1 = `${entitlementPath}/grants/g1`;
    const grantName2 = `${entitlementPath}/grants/g2`;
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();

    let createCalls = 0;
    let withdrawCalls = 0;
    let releaseSecondCreate: (() => void) | undefined;
    const secondCreateGate = new Promise<void>((r) => {
      releaseSecondCreate = r;
    });

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          withdrawCalls++;
          return new Response("{}", { status: 200 });
        }
        if (method === "POST" && isGrantCollectionUrl(url)) {
          createCalls++;
          if (createCalls === 1) {
            // First ensureGrant — return grant-1 synchronously.
            return new Response(
              JSON.stringify({
                name: grantName1,
                state: "ACTIVATED",
                createTime: createTime1,
                requestedDuration: "3600s",
              }),
              { status: 200, headers: { "Content-Type": "application/json" } },
            );
          }
          // Second create — block to let three concurrent callers pile up.
          await secondCreateGate;
          return new Response(
            JSON.stringify({
              name: grantName2,
              state: "ACTIVATED",
              createTime: new Date(currentTime).toISOString(),
              requestedDuration: "3600s",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
    });

    await pam.ensureGrant(entitlementPath);
    // Advance past the drain margin so the cached grant triggers rotation.
    currentTime += 57 * 60 * 1000;

    const fanOut = Array.from({ length: 3 }, () => pam.ensureGrant(entitlementPath));
    await new Promise((r) => setTimeout(r, 0));
    releaseSecondCreate!();

    const results = await Promise.all(fanOut);
    expect(createCalls).toBe(2); // initial + one rotation create (not three)
    expect(withdrawCalls).toBe(1); // single pre-withdraw for the rotation
    for (const r of results) {
      expect(r.name).toBe(grantName2);
    }
  });

  test("does not coalesce when the cache fast-path serves both callers", async () => {
    const grantName = `${entitlementPath}/grants/g1`;
    let createCalls = 0;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (_url: string, init?: RequestInit) => {
        if (init?.method === "POST") {
          createCalls++;
          return new Response(
            JSON.stringify({
              name: grantName,
              state: "ACTIVATED",
              createTime: new Date().toISOString(),
              requestedDuration: "3600s",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`unexpected ${init?.method}`);
      }) as unknown as typeof globalThis.fetch,
    });

    // Warm the cache.
    await pam.ensureGrant(entitlementPath);
    // Two concurrent reads hit the cache fast-path; no rotation triggered.
    const [a, b] = await Promise.all([
      pam.ensureGrant(entitlementPath),
      pam.ensureGrant(entitlementPath),
    ]);
    expect(createCalls).toBe(1);
    expect(a.cached).toBe(true);
    expect(b.cached).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Withdraw LRO polling
// ---------------------------------------------------------------------------

describe("withdraw Operation (LRO) polling", () => {
  const entitlementPath = "projects/p/locations/global/entitlements/e";
  const grantName1 = `${entitlementPath}/grants/g1`;
  const grantName2 = `${entitlementPath}/grants/g2`;

  test("waits for the withdraw Operation to report done:true before retrying create", async () => {
    // When the withdraw endpoint returns an Operation with done:false, the
    // recovery path must poll the operation to done:true before posting
    // the follow-up createGrant — otherwise PAM still sees the old grant
    // as open and 409s the create.
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();
    const operationName = `${entitlementPath}/operations/op-1`;

    let createCalls = 0;
    let withdrawPosts = 0;
    let opPolls = 0;
    let opDone = false;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();

        if (method === "POST" && url.includes(":withdraw")) {
          withdrawPosts++;
          return new Response(JSON.stringify({ name: operationName, done: false }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }

        if (method === "GET" && url.includes(operationName)) {
          opPolls++;
          // After 2 polls, the operation flips to done:true.
          if (opPolls >= 2) opDone = true;
          return new Response(JSON.stringify({ name: operationName, done: opDone }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }

        if (method === "POST" && isGrantCollectionUrl(url)) {
          createCalls++;
          if (createCalls === 1) {
            // Initial create returns grant-1.
            return new Response(
              JSON.stringify({
                name: grantName1,
                state: "ACTIVATED",
                createTime: createTime1,
                requestedDuration: "3600s",
              }),
              { status: 200, headers: { "Content-Type": "application/json" } },
            );
          }
          // Retry create after withdraw LRO done — succeeds.
          return new Response(
            JSON.stringify({
              name: grantName2,
              state: "ACTIVATED",
              createTime: new Date(currentTime).toISOString(),
              requestedDuration: "3600s",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }

        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
      sleepFn: () => Promise.resolve(),
    });

    await pam.ensureGrant(entitlementPath);
    currentTime += 57 * 60 * 1000;

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grantName2);
    expect(withdrawPosts).toBe(1);
    expect(opPolls).toBeGreaterThanOrEqual(2);
  });

  test("synchronous withdraw response (done:true initial) skips polling", async () => {
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();
    let opPolls = 0;
    let createCalls = 0;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          return new Response(
            JSON.stringify({ name: `${entitlementPath}/operations/op-sync`, done: true }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (method === "GET" && url.includes("operations/")) {
          opPolls++;
          return new Response("{}", { status: 200 });
        }
        if (method === "POST" && isGrantCollectionUrl(url)) {
          createCalls++;
          const grant = createCalls === 1 ? grantName1 : grantName2;
          return new Response(
            JSON.stringify({
              name: grant,
              state: "ACTIVATED",
              createTime: createCalls === 1 ? createTime1 : new Date(currentTime).toISOString(),
              requestedDuration: "3600s",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
      sleepFn: () => Promise.resolve(),
    });

    await pam.ensureGrant(entitlementPath);
    currentTime += 57 * 60 * 1000;
    await pam.ensureGrant(entitlementPath);
    expect(opPolls).toBe(0);
  });

  test("withdraw Operation reporting an error returns without throwing", async () => {
    // Operation with done:true and a non-empty error field is treated as
    // an already-terminal grant — withdraw is best-effort so we don't throw.
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();
    let createCalls = 0;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          return new Response(
            JSON.stringify({
              name: `${entitlementPath}/operations/op-err`,
              done: true,
              error: { code: 9, message: "Grant is already in REVOKED state" },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (method === "POST" && isGrantCollectionUrl(url)) {
          createCalls++;
          const grant = createCalls === 1 ? grantName1 : grantName2;
          return new Response(
            JSON.stringify({
              name: grant,
              state: "ACTIVATED",
              createTime: createCalls === 1 ? createTime1 : new Date(currentTime).toISOString(),
              requestedDuration: "3600s",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
      sleepFn: () => Promise.resolve(),
    });

    await pam.ensureGrant(entitlementPath);
    currentTime += 57 * 60 * 1000;
    // Should not throw — withdraw is best-effort.
    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grantName2);
  });

  test("withdraw Operation that never finishes returns within its deadline (best-effort)", async () => {
    // If PAM never reports done:true, withdrawGrantAndWait must give up at
    // the deadline rather than blocking forever. Best-effort: it logs and
    // returns, the caller still attempts the follow-up create.
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();
    let createCalls = 0;
    let opPolls = 0;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          return new Response(
            JSON.stringify({ name: `${entitlementPath}/operations/op-stuck`, done: false }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (method === "GET" && url.includes("operations/")) {
          opPolls++;
          // Advance time toward the deadline so the loop exits.
          currentTime += 5_000;
          return new Response(
            JSON.stringify({ name: `${entitlementPath}/operations/op-stuck`, done: false }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (method === "POST" && isGrantCollectionUrl(url)) {
          createCalls++;
          const grant = createCalls === 1 ? grantName1 : grantName2;
          return new Response(
            JSON.stringify({
              name: grant,
              state: "ACTIVATED",
              createTime: createCalls === 1 ? createTime1 : new Date(currentTime).toISOString(),
              requestedDuration: "3600s",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
      sleepFn: () => Promise.resolve(),
    });

    await pam.ensureGrant(entitlementPath);
    const t0 = currentTime;
    currentTime += 57 * 60 * 1000;
    const t1 = currentTime;

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grantName2);
    expect(opPolls).toBeGreaterThan(0);
    // Cumulative time advance from operation polls stays inside the 30s
    // deadline; once exhausted the helper returns and create proceeds.
    expect(currentTime - t1).toBeLessThan(60 * 1000);
    // Sanity: we did advance past the cache margin between the two calls.
    expect(t1 - t0).toBeGreaterThan(50 * 60 * 1000);
  });
});

// ---------------------------------------------------------------------------
// Withdraw API surface
// ---------------------------------------------------------------------------

describe("withdraw API surface", () => {
  const entitlementPath = "projects/p/locations/global/entitlements/e";

  test("withdraw POSTs to the v1beta surface with an empty body and polls the LRO on v1beta", async () => {
    // grants:withdraw exists only on v1beta (v1 ships revoke but not
    // withdraw), and WithdrawGrantRequest has no fields — the request body
    // must be empty. The Operation it returns is polled on v1beta too.
    const grantName1 = `${entitlementPath}/grants/g1`;
    const grantName2 = `${entitlementPath}/grants/g2`;
    const operationName = `${entitlementPath}/operations/op-1`;
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();

    let withdrawUrl: string | undefined;
    let withdrawBody: unknown = "unset";
    let opPollUrl: string | undefined;
    let createCalls = 0;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          withdrawUrl = url;
          withdrawBody = init?.body;
          return new Response(JSON.stringify({ name: operationName, done: false }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (method === "GET" && url.includes("operations/")) {
          opPollUrl = url;
          return new Response(JSON.stringify({ name: operationName, done: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (method === "POST" && isGrantCollectionUrl(url)) {
          createCalls++;
          const grant = createCalls === 1 ? grantName1 : grantName2;
          return new Response(
            JSON.stringify({
              name: grant,
              state: "ACTIVATED",
              createTime: createCalls === 1 ? createTime1 : new Date(currentTime).toISOString(),
              requestedDuration: "3600s",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      now: () => currentTime,
      sleepFn: () => Promise.resolve(),
    });

    await pam.ensureGrant(entitlementPath);
    currentTime += 57 * 60 * 1000;
    await pam.ensureGrant(entitlementPath);

    expect(withdrawUrl).toBe(
      `https://privilegedaccessmanager.googleapis.com/v1beta/${grantName1}:withdraw`,
    );
    expect(withdrawBody).toBeUndefined();
    expect(opPollUrl).toBe(
      `https://privilegedaccessmanager.googleapis.com/v1beta/${operationName}`,
    );
  });
});

// ---------------------------------------------------------------------------
// Requester filtering on shared entitlements
// ---------------------------------------------------------------------------

describe("scanForOpenGrants requester filtering", () => {
  const entitlementPath = "projects/p/locations/global/entitlements/e";
  const ownEmail = "Me@Example.com"; // mixed case to exercise case-insensitivity

  function makeFilteringModule(
    grants: Array<Record<string, unknown>>,
    opts: { currentTime: number; onWithdraw: (url: string) => void; createAfterRetry?: object },
  ): PamModule {
    let createCalls = 0;
    return createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":withdraw")) {
          opts.onWithdraw(url);
          return new Response("{}", { status: 200 });
        }
        if (method === "GET" && /\/grants\?pageSize=\d+/.test(url)) {
          return new Response(JSON.stringify({ grants }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (method === "POST" && isGrantCollectionUrl(url)) {
          createCalls++;
          if (createCalls === 1 || !opts.createAfterRetry) {
            return new Response(JSON.stringify({ error: { message: "Already exists" } }), {
              status: 409,
              headers: { "Content-Type": "application/json" },
            });
          }
          return new Response(JSON.stringify(opts.createAfterRetry), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      now: () => opts.currentTime,
      getRequesterEmail: async () => ownEmail,
    });
  }

  test("does not reuse another requester's usable grant; withdraws only its own stale grant", async () => {
    const currentTime = 10_000_000;
    const teammateUsable = {
      ...makeActivatedGrant(
        `${entitlementPath}/grants/teammate-usable`,
        new Date(currentTime).toISOString(),
      ),
      requester: "teammate@example.com",
    };
    const ownStale = {
      ...makeActivatedGrant(
        `${entitlementPath}/grants/own-stale`,
        new Date(currentTime - 2 * 60 * 60 * 1000).toISOString(),
      ),
      requester: "me@example.com", // lowercase — must still match ownEmail
    };
    const freshName = `${entitlementPath}/grants/fresh`;
    const withdrawn: string[] = [];

    const pam = makeFilteringModule([teammateUsable, ownStale], {
      currentTime,
      onWithdraw: (url) => withdrawn.push(url),
      createAfterRetry: makeActivatedGrant(freshName, new Date(currentTime).toISOString()),
    });

    const result = await pam.ensureGrant(entitlementPath);
    // The teammate's usable grant must not be reused — a fresh grant of our
    // own is created after clearing only our own stale grant.
    expect(result.name).toBe(freshName);
    expect(withdrawn).toHaveLength(1);
    expect(withdrawn[0]).toContain("own-stale");
  });

  test("throws without withdrawing anything when only other requesters' grants exist", async () => {
    const currentTime = 10_000_000;
    const teammateStale = {
      ...makeActivatedGrant(
        `${entitlementPath}/grants/teammate-stale`,
        new Date(currentTime - 2 * 60 * 60 * 1000).toISOString(),
      ),
      requester: "teammate@example.com",
    };
    // A grant with no requester field can't be attributed to us — never
    // reuse or withdraw it.
    const unattributedUsable = makeActivatedGrant(
      `${entitlementPath}/grants/unattributed`,
      new Date(currentTime).toISOString(),
    );
    const withdrawn: string[] = [];

    const pam = makeFilteringModule([teammateStale, unattributedUsable], {
      currentTime,
      onWithdraw: (url) => withdrawn.push(url),
    });

    // The error must say that open grants were excluded by the requester
    // filter — without that diagnostic, a requester-format mismatch would
    // be indistinguishable from "no grants at all".
    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow(
      /no open grant of ours found.*2 open grant\(s\) belong to other requesters/s,
    );
    expect(withdrawn).toHaveLength(0);
  });

  test("reuses its own usable grant matched case-insensitively", async () => {
    const currentTime = 10_000_000;
    const ownUsable = {
      ...makeActivatedGrant(
        `${entitlementPath}/grants/own-usable`,
        new Date(currentTime).toISOString(),
      ),
      requester: "ME@example.COM",
    };
    const withdrawn: string[] = [];

    const pam = makeFilteringModule([ownUsable], {
      currentTime,
      onWithdraw: (url) => withdrawn.push(url),
    });

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toContain("own-usable");
    expect(withdrawn).toHaveLength(0);
  });

  test("withdraws its own pending grant that is blocking creation", async () => {
    // A grant stuck in a pending state (e.g. APPROVAL_AWAITED after a poll
    // timeout in a previous run) holds the open-grant slot just like an
    // active one, and withdraw can clear it — the scan must treat it as a
    // withdrawable blocker, not skip it for being non-active.
    const currentTime = 10_000_000;
    const ownPending = {
      name: `${entitlementPath}/grants/own-pending`,
      state: "APPROVAL_AWAITED",
      requester: "me@example.com",
    };
    const freshName = `${entitlementPath}/grants/fresh`;
    const withdrawn: string[] = [];

    const pam = makeFilteringModule([ownPending], {
      currentTime,
      onWithdraw: (url) => withdrawn.push(url),
      createAfterRetry: makeActivatedGrant(freshName, new Date(currentTime).toISOString()),
    });

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(freshName);
    expect(withdrawn).toHaveLength(1);
    expect(withdrawn[0]).toContain("own-pending");
  });

  test("does not reuse an own grant whose create time is missing", async () => {
    const currentTime = 10_000_000;
    const unbounded = {
      name: `${entitlementPath}/grants/own-unbounded`,
      state: "ACTIVATED",
      requester: "me@example.com",
      requestedDuration: "3600s",
    };
    const freshName = `${entitlementPath}/grants/fresh`;
    const withdrawn: string[] = [];
    const pam = makeFilteringModule([unbounded], {
      currentTime,
      onWithdraw: (url) => withdrawn.push(url),
      createAfterRetry: makeActivatedGrant(freshName, new Date(currentTime).toISOString()),
    });

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(freshName);
    expect(withdrawn[0]).toContain("own-unbounded");
  });

  test("does not reuse an own grant whose requested duration is missing", async () => {
    const currentTime = 10_000_000;
    const unbounded = {
      name: `${entitlementPath}/grants/own-no-duration`,
      state: "ACTIVATED",
      requester: "me@example.com",
      createTime: new Date(currentTime).toISOString(),
    };
    const freshName = `${entitlementPath}/grants/fresh`;
    const withdrawn: string[] = [];
    const pam = makeFilteringModule([unbounded], {
      currentTime,
      onWithdraw: (url) => withdrawn.push(url),
      createAfterRetry: makeActivatedGrant(freshName, new Date(currentTime).toISOString()),
    });

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(freshName);
    expect(withdrawn[0]).toContain("own-no-duration");
  });

  test("reuses an own grant with a fractional protobuf duration", async () => {
    const currentTime = 10_000_000;
    const grant = {
      name: `${entitlementPath}/grants/own-fractional`,
      state: "ACTIVATED",
      requester: "me@example.com",
      createTime: new Date(currentTime).toISOString(),
      requestedDuration: "3600.000000001s",
    };
    const withdrawn: string[] = [];
    const pam = makeFilteringModule([grant], {
      currentTime,
      onWithdraw: (url) => withdrawn.push(url),
    });

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grant.name);
    expect(withdrawn).toHaveLength(0);
  });

  test("does not trust a PAM grant marked externally modified", async () => {
    const currentTime = 10_000_000;
    const modified = {
      ...makeActivatedGrant(
        `${entitlementPath}/grants/own-modified`,
        new Date(currentTime).toISOString(),
      ),
      requester: "me@example.com",
      externallyModified: true,
    };
    const freshName = `${entitlementPath}/grants/fresh`;
    const withdrawn: string[] = [];
    const pam = makeFilteringModule([modified], {
      currentTime,
      onWithdraw: (url) => withdrawn.push(url),
      createAfterRetry: makeActivatedGrant(freshName, new Date(currentTime).toISOString()),
    });

    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(freshName);
    expect(withdrawn[0]).toContain("own-modified");
  });
});

// ---------------------------------------------------------------------------
// Per-request fetch timeout and overall rotation budget
//
// These bound the two ways a grant rotation could otherwise hang forever:
//   - a single PAM HTTP call that never completes (half-open connection)
//   - the cumulative time of a rotation, including the ADC token acquisition
//     that runs before every PAM call and is NOT covered by the per-fetch
//     signal.
// Without these bounds a wedged call also poisons the single-flight slot, so
// every concurrent and subsequent caller for the entitlement blocks too.
// ---------------------------------------------------------------------------

type Settled<T> =
  | { status: "resolved"; value: T }
  | { status: "rejected"; error: Error }
  | { status: "pending" };

/**
 * Await `p`, but resolve to `{status:"pending"}` if it hasn't settled within
 * `ms`. bun's per-test timeout does NOT abort a never-settling promise
 * (verified against bun 1.3.x), so a test that asserts "this call is bounded"
 * must bound the wait itself — otherwise a regression would hang the suite
 * instead of failing it. The guard timer is unref'd and cleared so it never
 * keeps the loop alive.
 */
async function settleWithin<T>(p: Promise<T>, ms: number): Promise<Settled<T>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const guard = new Promise<Settled<T>>((resolve) => {
    timer = setTimeout(() => resolve({ status: "pending" }), ms);
    timer.unref?.();
  });
  const settled = await Promise.race([
    p.then(
      (value): Settled<T> => ({ status: "resolved", value }),
      (error): Settled<T> => ({ status: "rejected", error }),
    ),
    guard,
  ]);
  clearTimeout(timer);
  return settled;
}

/** Poll `pred` every 10 ms until it is true or `ms` elapses. */
async function until(pred: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  return pred();
}

describe("ensureGrant fetch timeout and rotation budget", () => {
  const entitlementPath = "projects/p/locations/global/entitlements/e";

  test("aborts a hung PAM request via the per-request fetch timeout", async () => {
    // A fetch that settles only when its AbortSignal fires — so it resolves
    // iff pamFetch attaches a per-request timeout signal.
    const hangingFetch = ((_url: string, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject((init.signal as AbortSignal).reason);
        });
      })) as unknown as typeof globalThis.fetch;

    const pam = createPamModule(async () => "token", {
      fetchFn: hangingFetch,
      fetchTimeoutMs: 50,
    });

    const outcome = await settleWithin(pam.ensureGrant(entitlementPath), 1000);
    expect(outcome.status).toBe("rejected");
    if (outcome.status === "rejected") {
      expect(outcome.error.message).toMatch(/timed out/i);
    }
  });

  test("keeps a stalled PAM response body inside the per-request timeout", async () => {
    let requestSignal: AbortSignal | null | undefined;
    const stalledBodyFetch = (async (_url: string, init?: RequestInit) => {
      requestSignal = init?.signal;
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"name":'));
          init?.signal?.addEventListener("abort", () => {
            controller.error((init.signal as AbortSignal).reason);
          });
        },
      });
      return new Response(body, { status: 200 });
    }) as unknown as typeof globalThis.fetch;
    const pam = createPamModule(async () => "token", {
      fetchFn: stalledBodyFetch,
      fetchTimeoutMs: 50,
    });

    const outcome = await settleWithin(pam.ensureGrant(entitlementPath), 1000);
    expect(outcome.status).toBe("rejected");
    if (outcome.status === "rejected") {
      expect(outcome.error.message).toContain("PAM API request timed out after 50ms");
    }
    expect(requestSignal?.aborted).toBe(true);
  });

  test("bounds the whole rotation by the budget even when ADC token acquisition hangs", async () => {
    // getAccessToken runs inside pamFetch *before* the HTTP call and is not
    // covered by the per-fetch signal, so only the overall budget can bound it.
    const pam = createPamModule(() => new Promise<string>(() => {}), {
      fetchFn: mockFetch([]),
      rotationBudgetMs: 100,
    });

    const outcome = await settleWithin(pam.ensureGrant(entitlementPath), 1000);
    expect(outcome.status).toBe("rejected");
    if (outcome.status === "rejected") {
      expect(outcome.error.message).toMatch(/budget/i);
    }
  });

  test("a hung rotation clears the in-flight slot so a later call recovers", async () => {
    const grantName = `${entitlementPath}/grants/g1`;
    let tokenCalls = 0;
    const getToken = (): Promise<string> => {
      tokenCalls++;
      // First rotation hangs forever; the budget must abort it and clear the
      // single-flight slot so a fresh call can proceed.
      if (tokenCalls === 1) return new Promise<string>(() => {});
      return Promise.resolve("token");
    };

    const pam = createPamModule(getToken, {
      fetchFn: mockFetch([{ status: 200, body: makeActivatedGrant(grantName) }]),
      rotationBudgetMs: 100,
    });

    const first = await settleWithin(pam.ensureGrant(entitlementPath), 1000);
    expect(first.status).toBe("rejected");

    // Slot cleared → a fresh rotation starts and succeeds instead of returning
    // the previous (still-hung) promise.
    const second = await settleWithin(pam.ensureGrant(entitlementPath), 1000);
    expect(second.status).toBe("resolved");
    if (second.status === "resolved") {
      expect(second.value.name).toBe(grantName);
    }
  });

  test("a superseded renewal cannot delete the replacement rotation's cache entry", async () => {
    const oldGrant = `${entitlementPath}/grants/old`;
    const newGrant = `${entitlementPath}/grants/new`;
    let currentTime = Date.parse("2026-01-01T00:00:00Z");
    let tokenCalls = 0;
    let createCalls = 0;
    let withdrawCalls = 0;
    let releaseOldToken: (() => void) | undefined;
    const oldToken = new Promise<void>((resolve) => {
      releaseOldToken = resolve;
    });

    const pam = createPamModule(
      async () => {
        tokenCalls++;
        // The first renewal wedges while acquiring the token for its cached
        // grant withdrawal. Its public promise times out, but its async work
        // remains alive until this gate is released.
        if (tokenCalls === 2) {
          await oldToken;
        }
        return "token";
      },
      {
        fetchFn: (async (url: string, init?: RequestInit) => {
          const method = (init?.method ?? "GET").toUpperCase();
          if (method === "POST" && url.includes(":withdraw")) {
            withdrawCalls++;
            return Response.json({ done: true });
          }
          if (method === "POST" && isGrantCollectionUrl(url)) {
            createCalls++;
            return Response.json(
              makeActivatedGrant(
                createCalls === 1 ? oldGrant : newGrant,
                new Date(currentTime).toISOString(),
              ),
            );
          }
          throw new Error(`unexpected fetch: ${method} ${url}`);
        }) as unknown as typeof globalThis.fetch,
        now: () => currentTime,
        rotationBudgetMs: 100,
      },
    );

    await pam.ensureGrant(entitlementPath);
    // Leave less than the token drain margin so renewal is required next.
    currentTime += 3_301_000;

    const abandoned = pam.ensureGrant(entitlementPath);
    expect(await until(() => tokenCalls === 2, 1000)).toBe(true);
    const abandonedOutcome = await settleWithin(abandoned, 1000);
    expect(abandonedOutcome.status).toBe("rejected");

    const replacement = await pam.ensureGrant(entitlementPath);
    expect(replacement.name).toBe(newGrant);
    expect(replacement.cached).toBe(false);

    // Let the abandoned getAccessToken() return. Before the ownership fence,
    // its best-effort withdraw swallowed the abort and then unconditionally
    // deleted the replacement cache entry.
    releaseOldToken!();
    await oldToken;
    await new Promise((resolve) => setTimeout(resolve, 0));

    const cached = await pam.ensureGrant(entitlementPath);
    expect(cached.name).toBe(newGrant);
    expect(cached.cached).toBe(true);
    expect(createCalls).toBe(2);
    expect(withdrawCalls).toBe(1);
  });

  test("a superseded poller cannot withdraw the active grant adopted by its replacement", async () => {
    const grantName = `${entitlementPath}/grants/adopted`;
    let tokenCalls = 0;
    let createCalls = 0;
    const withdrawn: string[] = [];
    let releaseOldPollToken: (() => void) | undefined;
    const oldPollToken = new Promise<void>((resolve) => {
      releaseOldPollToken = resolve;
    });

    const pam = createPamModule(
      async () => {
        tokenCalls++;
        // The original rotation wedges before its first poll request. Once its
        // budget expires, the replacement sees and adopts the now-active grant.
        if (tokenCalls === 2) {
          await oldPollToken;
        }
        return "token";
      },
      {
        fetchFn: (async (url: string, init?: RequestInit) => {
          const method = (init?.method ?? "GET").toUpperCase();
          if (method === "POST" && url.includes(":withdraw")) {
            withdrawn.push(url);
            return Response.json({ done: true });
          }
          if (method === "POST" && isGrantCollectionUrl(url)) {
            createCalls++;
            if (createCalls === 1) {
              return Response.json({
                name: grantName,
                state: "APPROVAL_AWAITED",
                requestedDuration: "3600s",
              });
            }
            return Response.json({ error: { message: "Already exists" } }, { status: 409 });
          }
          if (method === "GET" && url.includes("?pageSize=")) {
            return Response.json({ grants: [makeActivatedGrant(grantName)] });
          }
          throw new Error(`unexpected fetch: ${method} ${url}`);
        }) as unknown as typeof globalThis.fetch,
        rotationBudgetMs: 100,
        sleepFn: async () => {},
      },
    );

    const abandoned = pam.ensureGrant(entitlementPath);
    expect(await until(() => tokenCalls === 2, 1000)).toBe(true);
    const abandonedOutcome = await settleWithin(abandoned, 1000);
    expect(abandonedOutcome.status).toBe("rejected");

    const replacement = await pam.ensureGrant(entitlementPath);
    expect(replacement.name).toBe(grantName);
    expect(replacement.cached).toBe(false);

    releaseOldPollToken!();
    await oldPollToken;
    await new Promise((resolve) => setTimeout(resolve, 0));

    const cached = await pam.ensureGrant(entitlementPath);
    expect(cached.name).toBe(grantName);
    expect(cached.cached).toBe(true);
    expect(withdrawn).toEqual([]);
  });

  test("supersession during cleanup token lookup does not retire or withdraw an adoptable grant", async () => {
    const grantName = `${entitlementPath}/grants/adoptable`;
    let tokenCalls = 0;
    let createCalls = 0;
    let pollStarted = false;
    let withdrawCalls = 0;
    let resolveOldPoll: ((response: Response) => void) | undefined;
    let releaseCleanupToken: (() => void) | undefined;
    const cleanupToken = new Promise<void>((resolve) => {
      releaseCleanupToken = resolve;
    });

    const pam = createPamModule(
      async () => {
        tokenCalls++;
        // After the old rotation's budget has expired, let its poll report the
        // grant ACTIVE. The abandoned work then enters its cleanup withdrawal
        // and wedges acquiring this third token before any POST is dispatched.
        if (tokenCalls === 3) await cleanupToken;
        return "token";
      },
      {
        fetchFn: (async (url: string, init?: RequestInit) => {
          const method = (init?.method ?? "GET").toUpperCase();
          if (method === "POST" && url.includes(":withdraw")) {
            withdrawCalls++;
            return Response.json({ done: true });
          }
          if (method === "POST" && isGrantCollectionUrl(url)) {
            createCalls++;
            if (createCalls === 1) {
              return Response.json({
                name: grantName,
                state: "APPROVAL_AWAITED",
                requestedDuration: "3600s",
              });
            }
            return Response.json({ error: { message: "Already exists" } }, { status: 409 });
          }
          if (method === "GET" && url.includes("?pageSize=")) {
            return Response.json({ grants: [makeActivatedGrant(grantName)] });
          }
          if (method === "GET" && url.endsWith(grantName)) {
            pollStarted = true;
            return new Promise<Response>((resolve) => {
              resolveOldPoll = resolve;
            });
          }
          throw new Error(`unexpected fetch: ${method} ${url}`);
        }) as unknown as typeof globalThis.fetch,
        rotationBudgetMs: 100,
        sleepFn: async () => {},
      },
    );

    const abandoned = pam.ensureGrant(entitlementPath);
    expect(await until(() => pollStarted, 1000)).toBe(true);
    expect((await settleWithin(abandoned, 1000)).status).toBe("rejected");

    // Complete the old poll only after its public budget has expired. It starts
    // cleanup while it is still the owner, but blocks before the HTTP request.
    resolveOldPoll!(Response.json(makeActivatedGrant(grantName)));
    expect(await until(() => tokenCalls === 3, 1000)).toBe(true);

    // The replacement supersedes that cleanup and can adopt the still-active
    // grant. A pre-token retiring mark would instead classify it as blocking,
    // withdraw it, and expose IAM propagation delay on a needless replacement.
    const replacement = await pam.ensureGrant(entitlementPath);
    expect(replacement.name).toBe(grantName);
    expect(withdrawCalls).toBe(0);

    releaseCleanupToken!();
    await cleanupToken;
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(withdrawCalls).toBe(0);
    const cached = await pam.ensureGrant(entitlementPath);
    expect(cached.name).toBe(grantName);
    expect(cached.cached).toBe(true);
  });

  test("a replacement never adopts a grant whose withdraw POST already landed", async () => {
    const retiringGrant = `${entitlementPath}/grants/retiring`;
    const freshGrant = `${entitlementPath}/grants/fresh`;
    let tokenCalls = 0;
    let createCalls = 0;
    let withdrawCalls = 0;
    let releaseOldPollToken: (() => void) | undefined;
    const oldPollToken = new Promise<void>((resolve) => {
      releaseOldPollToken = resolve;
    });
    let resolveOldWithdraw: ((response: Response) => void) | undefined;

    const pam = createPamModule(
      async () => {
        tokenCalls++;
        // Let the original rotation's public budget expire while its first
        // activation poll is waiting for an access token. Releasing this token
        // sends it into best-effort cleanup while it still owns the rotation.
        if (tokenCalls === 2) await oldPollToken;
        return "token";
      },
      {
        fetchFn: (async (url: string, init?: RequestInit) => {
          const method = (init?.method ?? "GET").toUpperCase();
          if (method === "POST" && url.includes(":withdraw")) {
            withdrawCalls++;
            if (withdrawCalls === 1) {
              // The old cleanup request reached PAM, but its response/LRO has
              // not settled when the replacement rotation starts.
              return new Promise<Response>((resolve) => {
                resolveOldWithdraw = resolve;
              });
            }
            return Response.json({ done: true });
          }
          if (method === "POST" && isGrantCollectionUrl(url)) {
            createCalls++;
            if (createCalls === 1) {
              return Response.json({
                name: retiringGrant,
                state: "APPROVAL_AWAITED",
                requestedDuration: "3600s",
              });
            }
            if (createCalls === 2) {
              return Response.json({ error: { message: "Already exists" } }, { status: 409 });
            }
            return Response.json(makeActivatedGrant(freshGrant));
          }
          if (method === "GET" && url.includes("?pageSize=")) {
            // grants.list can lag the withdrawal and still advertise ACTIVE.
            return Response.json({ grants: [makeActivatedGrant(retiringGrant)] });
          }
          throw new Error(`unexpected fetch: ${method} ${url}`);
        }) as unknown as typeof globalThis.fetch,
        rotationBudgetMs: 100,
        sleepFn: async () => {},
      },
    );

    const abandoned = pam.ensureGrant(entitlementPath);
    expect(await until(() => tokenCalls === 2, 1000)).toBe(true);
    expect((await settleWithin(abandoned, 1000)).status).toBe("rejected");

    releaseOldPollToken!();
    expect(await until(() => withdrawCalls === 1, 1000)).toBe(true);

    const replacement = await pam.ensureGrant(entitlementPath);
    expect(replacement.name).toBe(freshGrant);
    expect(createCalls).toBe(3);
    expect(withdrawCalls).toBe(2);

    // Let the abandoned cleanup settle so it cannot leave work behind after
    // the test. Its owner signal is now superseded, so it stops before polling.
    resolveOldWithdraw!(Response.json({ name: "operations/old-withdraw", done: false }));
    await new Promise((resolve) => setTimeout(resolve, 0));
  });

  test("a budget abort during polling rejects promptly and withdraws the un-activated grant", async () => {
    // The created grant never activates; the budget must fire mid-poll, reject
    // the rotation, and best-effort withdraw the grant so it is not orphaned
    // (rather than letting the abandoned rotation cache or leak it).
    const grantName = `${entitlementPath}/grants/pending-1`;
    const withdrawn: string[] = [];
    const pendingBody = JSON.stringify({
      name: grantName,
      state: "APPROVAL_AWAITED",
      requestedDuration: "3600s",
    });

    const fetchFn = (async (url: string, init?: RequestInit) => {
      const method = (init?.method ?? "GET").toUpperCase();
      if (method === "POST" && url.includes(":withdraw")) {
        withdrawn.push(url);
        return new Response("{}", { status: 200 });
      }
      // create POST and poll GET both return a never-activating grant.
      return new Response(pendingBody, {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    const pam = createPamModule(async () => "token", {
      fetchFn,
      rotationBudgetMs: 100,
      // Cap the real poll back-off so the budget fires within a few iterations.
      sleepFn: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 10))),
    });

    const outcome = await settleWithin(pam.ensureGrant(entitlementPath), 2000);
    expect(outcome.status).toBe("rejected");
    if (outcome.status === "rejected") {
      expect(outcome.error.message).toMatch(/budget/i);
    }

    // The grant we created must be withdrawn (background cleanup), not orphaned.
    expect(await until(() => withdrawn.length > 0, 2000)).toBe(true);
    expect(withdrawn[0]).toContain("pending-1");
  });
});

describe("scanForOpenGrants requester lookup failures", () => {
  const entitlementPath = "projects/p/locations/global/entitlements/e";

  function moduleWithLookup(getRequesterEmail: () => Promise<string>): PamModule {
    return createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && isGrantCollectionUrl(url)) {
          return Response.json({ error: { message: "Already exists" } }, { status: 409 });
        }
        throw new Error(`unexpected fetch: ${method} ${url}`);
      }) as unknown as typeof globalThis.fetch,
      getRequesterEmail,
    });
  }

  test("wraps an unrelated identity lookup failure with its cause", async () => {
    const pam = moduleWithLookup(async () => {
      throw new Error("tokeninfo returned 503");
    });

    const error = await pam.ensureGrant(entitlementPath).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(PamRequesterLookupError);
    expect((error as Error & { cause?: Error }).cause?.message).toContain("tokeninfo returned 503");
  });

  test("preserves CredentialsExpiredError for the typed re-auth path", async () => {
    const expired = new CredentialsExpiredError("credentials expired");
    const pam = moduleWithLookup(async () => {
      throw expired;
    });

    const error = await pam.ensureGrant(entitlementPath).catch((err: unknown) => err);
    expect(error).toBe(expired);
    expect(error).not.toBeInstanceOf(PamRequesterLookupError);
  });
});
