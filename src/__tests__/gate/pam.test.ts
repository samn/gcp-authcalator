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

    await expect(pam.ensureGrant(entitlementPath)).rejects.toThrow("PAM grant was DENIED");
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
      fetchFn: (async (url: string) => {
        if (url.includes("filter=")) {
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
      fetchFn: (async (url: string) => {
        if (url.includes("filter=")) {
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
        // Second call gets a fresh grant
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
