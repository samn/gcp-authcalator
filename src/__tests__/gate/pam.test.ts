import { describe, expect, test } from "bun:test";
import { resolveEntitlementPath, createPamModule, type PamModule } from "../../gate/pam.ts";

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

/**
 * Mock fetch that auto-responds to revoke POSTs with `{}` 200 and dispenses
 * `creates` (lazy bodies — evaluated when the create call fires, so they can
 * close over a `currentTime` that has advanced between calls). Returns the
 * `events` log so tests can assert ordering of create vs revoke.
 */
function mockGrantOps(creates: Array<() => Record<string, unknown>>): {
  fetchFn: typeof globalThis.fetch;
  events: Array<{ kind: "create" | "revoke"; url: string }>;
} {
  const events: Array<{ kind: "create" | "revoke"; url: string }> = [];
  let createIdx = 0;
  const fetchFn = (async (url: string, init?: RequestInit) => {
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "POST" && url.includes(":revoke")) {
      events.push({ kind: "revoke", url });
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

  test("creates and returns an immediately activated grant", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const { pam } = makeModule([{ status: 200, body: makeActivatedGrant(grantName) }]);

    const result = await pam.ensureGrant(entitlementPath);

    expect(result.name).toBe(grantName);
    expect(result.state).toBe("ACTIVATED");
    expect(result.cached).toBe(false);
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
        // ensureGrant pre-revokes the cached entry before re-creating
        // (PAM's state can lag; the revoke clears any stale "open" state).
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

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("no active grant found");
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

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("no active grant found");
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
      /no active grant found.*scanned \d+ grant\(s\) across 10 page\(s\)/,
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
    const { pam } = makeModule([{ status: 500, body: { error: { message: "Internal error" } } }]);

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

  test("cache expiry is derived from grant createTime, not current time", async () => {
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    const grantName2 = `${entitlementPath}/grants/grant-2`;
    let currentTime = 1_000_000;

    // Grant was created 50 minutes ago (only 10 minutes of lifetime remain)
    const createdAt = currentTime - 50 * 60 * 1000;
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
        // Second ensureGrant: cached grant is within the cache margin but not
        // yet expired, so the new behaviour revokes it before re-creating.
        { status: 200, body: {} },
        // Then it requests a fresh grant
        {
          status: 200,
          body: makeActivatedGrant(grantName2, new Date(currentTime + 7 * 60 * 1000).toISOString()),
        },
      ],
      () => currentTime,
    );

    const first = await pam.ensureGrant(entitlementPath);
    expect(first.name).toBe(grantName1);
    expect(first.cached).toBe(false);

    // Advance 7 minutes — past the old grant's real expiry (10 min remaining
    // minus 5 min cache margin = should be expired after ~5 min)
    currentTime += 7 * 60 * 1000;

    const second = await pam.ensureGrant(entitlementPath);
    // Should NOT be cached because the grant's real expiry was derived from createTime
    expect(second.name).toBe(grantName2);
    expect(second.cached).toBe(false);
  });

  test("falls back to conservative TTL when grant lacks createTime", async () => {
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    const grantName2 = `${entitlementPath}/grants/grant-2`;
    let currentTime = 1_000_000;

    // Grant without createTime
    const grantNoTime = {
      name: grantName1,
      state: "ACTIVATED",
      // no createTime, no requestedDuration
    };

    const { pam } = makeModule(
      [
        { status: 200, body: grantNoTime },
        // Second ensureGrant fires within the cache margin of the conservative
        // 15-minute fallback expiry, so the still-active grant is revoked
        // before a new one is created.
        { status: 200, body: {} },
        {
          status: 200,
          body: makeActivatedGrant(
            grantName2,
            new Date(currentTime + 16 * 60 * 1000).toISOString(),
          ),
        },
      ],
      () => currentTime,
    );

    const first = await pam.ensureGrant(entitlementPath);
    expect(first.name).toBe(grantName1);

    // Advance past the conservative 15-minute fallback TTL (minus 5 min margin = 10 min)
    currentTime += 11 * 60 * 1000;

    const second = await pam.ensureGrant(entitlementPath);
    expect(second.name).toBe(grantName2);
    expect(second.cached).toBe(false);
  });

  test("409 with a stale-but-still-open grant: revokes the stale grant and retries create", async () => {
    // PAM's `state` field can lag actual expiry: a grant whose
    // createTime + requestedDuration is already in the past may briefly
    // continue to be reported as ACTIVE/ACTIVATED, blocking a new
    // createGrant with 409 / 400 FAILED_PRECONDITION. Reusing the stale
    // grant directly would hand the caller a dead entitlement, so the
    // recovery harness revokes the stale grant and retries createGrant
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

    const revokedNames: string[] = [];
    let listCalls = 0;
    let createCalls = 0;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":revoke")) {
          revokedNames.push(url);
          return new Response("{}", { status: 200 });
        }
        if (method === "GET" && /\/grants\?pageSize=\d+/.test(url)) {
          listCalls++;
          return new Response(JSON.stringify({ grants: [staleGrant] }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (method === "POST" && url.endsWith("/grants")) {
          createCalls++;
          if (createCalls === 1) {
            // First create: PAM rejects because the stale grant is still open.
            return new Response(JSON.stringify({ error: { message: "Already exists" } }), {
              status: 409,
              headers: { "Content-Type": "application/json" },
            });
          }
          // Second create (after the stale grant was revoked) succeeds.
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
    expect(revokedNames).toHaveLength(1);
    expect(revokedNames[0]).toContain(staleName);
    // The post-#98 invariant — never return a grant with no usable lifetime —
    // must still hold after the recovery path.
    expect(result.expiresAt.getTime() - currentTime).toBeGreaterThan(5 * 60 * 1000);
  });

  test("409 with only stale grants but persistent conflict surfaces a distinct error", async () => {
    // After revoking every stale grant the scan returned, a second
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
        if (method === "POST" && url.includes(":revoke")) {
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

  test("recovery path tolerates revoke failure on the stale grant", async () => {
    // revokeGrantBestEffort swallows errors so a 5xx on the revoke
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
        if (method === "POST" && url.includes(":revoke")) {
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
        if (method === "POST" && url.endsWith("/grants")) {
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

  test("near-expiry renewal recovers when PAM still 409s after our pre-revoke", async () => {
    // The proactive pre-revoke in ensureGrant clears most of the
    // cache-margin races, but PAM may still echo the just-revoked grant
    // as "open" if the create lands before PAM has propagated the
    // revoke. The recovery harness must scan, re-revoke the stale
    // grant, and retry create — without rolling back the
    // "never return a grant with no usable lifetime" invariant.
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    const grantName2 = `${entitlementPath}/grants/grant-2`;
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();

    const revokedNames: string[] = [];
    let createCalls = 0;
    let staleStillAppearsOpen = true;
    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":revoke")) {
          revokedNames.push(url);
          // After a second revoke against the stale grant, PAM finally
          // catches up — the next create can succeed.
          if (revokedNames.filter((u) => u.includes(grantName1)).length >= 2) {
            staleStillAppearsOpen = false;
          }
          return new Response("{}", { status: 200 });
        }
        if (method === "GET" && /\/grants\?pageSize=\d+/.test(url)) {
          // PAM still reports grant-1 as ACTIVE even though we revoked it,
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
        if (method === "POST" && url.endsWith("/grants")) {
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
    // Two revoke calls against grant-1: the pre-revoke that ensureGrant
    // issues and the recovery-path revoke against the stale scan result.
    expect(revokedNames.filter((u) => u.includes(grantName1))).toHaveLength(2);
    // Two create attempts after the initial: one 409, one success.
    expect(createCalls).toBe(3);
    // Invariant: the returned grant has usable remaining lifetime.
    expect(second.expiresAt.getTime() - currentTime).toBeGreaterThan(5 * 60 * 1000);
  });

  test("near-expiry renewal revokes old grant before creating a new one", async () => {
    // The post-#98 lifetime filter in findActiveGrant turns the cache-margin
    // window into a dead-end: createGrant 409s on the still-open grant and
    // findActiveGrant rejects it for being too close to expiry. Pre-emptively
    // revoking the old grant unblocks the create, so renewal succeeds even
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

    expect(events.map((e) => e.kind)).toEqual(["create", "revoke", "create"]);
    expect(events[1]!.url).toContain(grantName1);
  });

  test("expired-grant renewal best-effort revokes stale cache entry", async () => {
    // A grant whose computed expiry has already passed must still be
    // revoked before we re-create: PAM's state can lag actual expiry,
    // leaving the old grant in an "open" state that 409s the immediate
    // create. revokeGrantBestEffort is a no-op against truly-ended
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
    expect(events.map((e) => e.kind)).toEqual(["create", "revoke", "create"]);
    expect(events[1]!.url).toContain(grantName1);
  });

  test("revoked grant is removed from cache so revokeAll skips it", async () => {
    // After a near-expiry renewal revokes the old grant, the cache should
    // hold the new grant only. Subsequent shutdown revokeAll must not
    // re-revoke the old (already-revoked) grant.
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

    const revokes = events.filter((e) => e.kind === "revoke");
    expect(revokes).toHaveLength(1);
    expect(revokes[0]!.url).toContain(grantName1);

    await pam.revokeAll();
    const allRevokes = events.filter((e) => e.kind === "revoke");
    expect(allRevokes).toHaveLength(2);
    expect(allRevokes[1]!.url).toContain(grantName2);
  });

  test("expired cache entry is not retained after invalidation", async () => {
    // After a cached grant's expiry passes, ensureGrant pre-revokes it
    // (best-effort, to clear PAM's lagged state) and purges the cache
    // entry before attempting to re-create. If the re-create then fails,
    // revokeAll must not double-revoke grant-1 — the cache should
    // already be empty.
    const grantName1 = `${entitlementPath}/grants/grant-1`;
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();

    const revokedNames: string[] = [];
    let createCalls = 0;
    const fetchFn = (async (url: string, init?: RequestInit) => {
      // Revoke calls
      if (init?.method === "POST" && (url as string).includes(":revoke")) {
        revokedNames.push(url as string);
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

    // Calling ensureGrant again pre-revokes grant-1 and then attempts to
    // re-create (which fails — no further create mock). After the
    // failure the cache should be empty so revokeAll doesn't try to
    // revoke grant-1 a second time.
    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow();
    expect(revokedNames).toHaveLength(1);
    expect(revokedNames[0]).toContain(grantName1);

    await pam.revokeAll();
    expect(revokedNames).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// revokeAll
// ---------------------------------------------------------------------------

describe("revokeAll", () => {
  const entitlementPath = "projects/p/locations/global/entitlements/e";

  test("revokes cached active grants", async () => {
    const grantName = `${entitlementPath}/grants/grant-1`;
    const revokedGrants: string[] = [];

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
      // revokeGrant
      if (init?.method === "POST" && (url as string).includes(":revoke")) {
        revokedGrants.push(url as string);
      }
      return new Response("{}", { status: 200 });
    }) as unknown as typeof globalThis.fetch;

    const pam = createPamModule(async () => "token", { fetchFn });

    await pam.ensureGrant(entitlementPath);
    await pam.revokeAll();

    expect(revokedGrants).toHaveLength(1);
    expect(revokedGrants[0]).toContain(grantName);
  });

  test("tolerates revoke HTTP failures", async () => {
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
      // Revoke fails with HTTP error
      return new Response("Internal error", { status: 500 });
    }) as unknown as typeof globalThis.fetch;

    const pam = createPamModule(async () => "token", { fetchFn });

    await pam.ensureGrant(entitlementPath);
    // Should not throw
    await pam.revokeAll();
  });

  test("tolerates revoke network failures", async () => {
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
      // Revoke fails with network error
      throw new Error("Network unreachable");
    }) as unknown as typeof globalThis.fetch;

    const pam = createPamModule(async () => "token", { fetchFn });

    await pam.ensureGrant(entitlementPath);
    // Should not throw
    await pam.revokeAll();
  });

  test("does nothing when no grants are cached", async () => {
    const { pam } = makeModule([]);
    // Should not throw
    await pam.revokeAll();
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
    let revokeCalls = 0;
    let releaseSecondCreate: (() => void) | undefined;
    const secondCreateGate = new Promise<void>((r) => {
      releaseSecondCreate = r;
    });

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":revoke")) {
          revokeCalls++;
          return new Response("{}", { status: 200 });
        }
        if (method === "POST" && url.endsWith("/grants")) {
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
    expect(revokeCalls).toBe(1); // single pre-revoke for the rotation
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
// Revoke LRO polling
// ---------------------------------------------------------------------------

describe("revoke Operation (LRO) polling", () => {
  const entitlementPath = "projects/p/locations/global/entitlements/e";
  const grantName1 = `${entitlementPath}/grants/g1`;
  const grantName2 = `${entitlementPath}/grants/g2`;

  test("waits for the revoke Operation to report done:true before retrying create", async () => {
    // When the revoke endpoint returns an Operation with done:false, the
    // recovery path must poll the operation to done:true before posting
    // the follow-up createGrant — otherwise PAM still sees the old grant
    // as open and 409s the create.
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();
    const operationName = `${entitlementPath}/operations/op-1`;

    let createCalls = 0;
    let revokePosts = 0;
    let opPolls = 0;
    let opDone = false;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();

        if (method === "POST" && url.includes(":revoke")) {
          revokePosts++;
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

        if (method === "POST" && url.endsWith("/grants")) {
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
          // Retry create after revoke LRO done — succeeds.
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
    expect(revokePosts).toBe(1);
    expect(opPolls).toBeGreaterThanOrEqual(2);
  });

  test("synchronous revoke response (done:true initial) skips polling", async () => {
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();
    let opPolls = 0;
    let createCalls = 0;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":revoke")) {
          return new Response(
            JSON.stringify({ name: `${entitlementPath}/operations/op-sync`, done: true }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (method === "GET" && url.includes("operations/")) {
          opPolls++;
          return new Response("{}", { status: 200 });
        }
        if (method === "POST" && url.endsWith("/grants")) {
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

  test("revoke Operation reporting an error returns without throwing", async () => {
    // Operation with done:true and a non-empty error field is treated as
    // an already-terminal grant — revoke is best-effort so we don't throw.
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();
    let createCalls = 0;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":revoke")) {
          return new Response(
            JSON.stringify({
              name: `${entitlementPath}/operations/op-err`,
              done: true,
              error: { code: 9, message: "Grant is already in REVOKED state" },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (method === "POST" && url.endsWith("/grants")) {
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
    // Should not throw — revoke is best-effort.
    const result = await pam.ensureGrant(entitlementPath);
    expect(result.name).toBe(grantName2);
  });

  test("revoke Operation that never finishes returns within its deadline (best-effort)", async () => {
    // If PAM never reports done:true, revokeGrantAndWait must give up at
    // the deadline rather than blocking forever. Best-effort: it logs and
    // returns, the caller still attempts the follow-up create.
    let currentTime = 1_000_000;
    const createTime1 = new Date(currentTime).toISOString();
    let createCalls = 0;
    let opPolls = 0;

    const pam = createPamModule(async () => "token", {
      fetchFn: (async (url: string, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "POST" && url.includes(":revoke")) {
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
        if (method === "POST" && url.endsWith("/grants")) {
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
