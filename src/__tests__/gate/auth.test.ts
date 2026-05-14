import { describe, expect, test } from "bun:test";
import { createAuthModule } from "../../gate/auth.ts";
import { CredentialsExpiredError } from "../../gate/credentials-error.ts";
import type { GateConfig } from "../../config.ts";
import type { AuthClient } from "google-auth-library";

const TEST_CONFIG: GateConfig = {
  project_id: "test-project",
  service_account: "sa@test-project.iam.gserviceaccount.com",
  socket_path: "/tmp/test.sock",
  admin_socket_path: "/tmp/test-admin.sock",
  port: 8173,
};

/** Create a mock AuthClient that returns the given token. */
function mockClient(
  token: string | null,
  expiryDate?: number,
  universeDomain = "googleapis.com",
): AuthClient {
  return {
    credentials: { expiry_date: expiryDate ?? Date.now() + 3600_000 },
    getAccessToken: async () => ({ token, res: null }),
    universeDomain,
  } as unknown as AuthClient;
}

/** Create a mock fetch that returns a tokeninfo response. */
function mockFetch(email: string): typeof globalThis.fetch {
  return (async () =>
    new Response(JSON.stringify({ email }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })) as unknown as typeof globalThis.fetch;
}

/** Create a URL-aware mock fetch that handles both tokeninfo and CRM API calls. */
function mockCrmFetch(projectNumber: string): typeof globalThis.fetch {
  return (async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.includes("cloudresourcemanager.googleapis.com")) {
      return new Response(JSON.stringify({ name: `projects/${projectNumber}` }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  }) as unknown as typeof globalThis.fetch;
}

describe("createAuthModule", () => {
  describe("mintDevToken", () => {
    test("returns a token from the impersonated client", async () => {
      const { mintDevToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source-token"),
        impersonatedClient: mockClient("dev-token-123"),
      });

      const result = await mintDevToken();
      expect(result.access_token).toBe("dev-token-123");
      expect(result.expires_at).toBeInstanceOf(Date);
      expect(result.expires_at.getTime()).toBeGreaterThan(Date.now());
    });

    test("caches the token on subsequent calls", async () => {
      let callCount = 0;
      const client = {
        credentials: { expiry_date: Date.now() + 3600_000 },
        getAccessToken: async () => {
          callCount++;
          return { token: `token-${callCount}`, res: null };
        },
      } as unknown as AuthClient;

      const { mintDevToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: client,
      });

      const first = await mintDevToken();
      const second = await mintDevToken();

      expect(first.access_token).toBe("token-1");
      expect(second.access_token).toBe("token-1");
      expect(callCount).toBe(1);
    });

    test("uses expiry_date from client credentials", async () => {
      const expectedExpiry = Date.now() + 1800_000; // 30 minutes from now
      const { mintDevToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source-token"),
        impersonatedClient: mockClient("dev-token", expectedExpiry),
      });

      const result = await mintDevToken();
      expect(result.expires_at.getTime()).toBe(expectedExpiry);
    });

    test("falls back to default lifetime when credentials lack expiry_date", async () => {
      const before = Date.now();
      const client = {
        credentials: {},
        getAccessToken: async () => ({ token: "dev-token", res: null }),
      } as unknown as AuthClient;

      const { mintDevToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: client,
      });

      const result = await mintDevToken();
      const after = Date.now();
      // Should fall back to ~1 hour from now
      expect(result.expires_at.getTime()).toBeGreaterThanOrEqual(before + 3600_000);
      expect(result.expires_at.getTime()).toBeLessThanOrEqual(after + 3600_000);
    });

    test("falls back to configured TTL when credentials lack expiry_date", async () => {
      const before = Date.now();
      const client = {
        credentials: {},
        getAccessToken: async () => ({ token: "dev-token", res: null }),
      } as unknown as AuthClient;

      const configWithTtl: GateConfig = { ...TEST_CONFIG, token_ttl_seconds: 1800 };
      const { mintDevToken } = createAuthModule(configWithTtl, {
        sourceClient: mockClient("source"),
        impersonatedClient: client,
      });

      const result = await mintDevToken();
      const after = Date.now();
      // Should fall back to ~30 min from now (configured TTL)
      expect(result.expires_at.getTime()).toBeGreaterThanOrEqual(before + 1800_000);
      expect(result.expires_at.getTime()).toBeLessThanOrEqual(after + 1800_000);
    });

    test("throws when no token is returned", async () => {
      const { mintDevToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: mockClient(null),
      });

      await expect(mintDevToken()).rejects.toThrow("Failed to mint dev token");
    });

    test("re-mints token when cache expires within 5-minute margin", async () => {
      let callCount = 0;
      // Token that expires in 4 minutes (within the 5-minute CACHE_MARGIN_MS)
      const nearExpiryMs = Date.now() + 4 * 60 * 1000;
      const client = {
        credentials: { expiry_date: nearExpiryMs },
        getAccessToken: async () => {
          callCount++;
          return { token: `token-${callCount}`, res: null };
        },
      } as unknown as AuthClient;

      const { mintDevToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: client,
      });

      const first = await mintDevToken();
      expect(first.access_token).toBe("token-1");

      // Second call should re-mint because remaining lifetime < 5 minutes
      const second = await mintDevToken();
      expect(second.access_token).toBe("token-2");
      expect(callCount).toBe(2);
    });
  });

  describe("mintProdToken", () => {
    test("returns a token from the source client", async () => {
      const { mintProdToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("prod-token-456"),
        impersonatedClient: mockClient("dev-token"),
      });

      const result = await mintProdToken();
      expect(result.access_token).toBe("prod-token-456");
      expect(result.expires_at).toBeInstanceOf(Date);
    });

    test("uses expiry_date from client credentials", async () => {
      const expectedExpiry = Date.now() + 1800_000;
      const { mintProdToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("prod-token", expectedExpiry),
        impersonatedClient: mockClient("dev-token"),
      });

      const result = await mintProdToken();
      expect(result.expires_at.getTime()).toBe(expectedExpiry);
    });

    test("does not cache — returns fresh token each time", async () => {
      let callCount = 0;
      const client = {
        credentials: { expiry_date: Date.now() + 3600_000 },
        getAccessToken: async () => {
          callCount++;
          return { token: `prod-${callCount}`, res: null };
        },
      } as unknown as AuthClient;

      const { mintProdToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: client,
        impersonatedClient: mockClient("dev-token"),
      });

      const first = await mintProdToken();
      const second = await mintProdToken();

      expect(first.access_token).toBe("prod-1");
      expect(second.access_token).toBe("prod-2");
      expect(callCount).toBe(2);
    });

    test("throws when no token is returned", async () => {
      const { mintProdToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient(null),
        impersonatedClient: mockClient("dev"),
      });

      await expect(mintProdToken()).rejects.toThrow("Failed to mint prod token");
    });

    test("caps expires_at to configured TTL", async () => {
      const before = Date.now();
      // Source client returns a token expiring far in the future
      const farFuture = Date.now() + 7200_000; // 2 hours
      const configWithTtl: GateConfig = { ...TEST_CONFIG, token_ttl_seconds: 900 };
      const { mintProdToken } = createAuthModule(configWithTtl, {
        sourceClient: mockClient("prod-token", farFuture),
        impersonatedClient: mockClient("dev-token"),
      });

      const result = await mintProdToken();
      const after = Date.now();
      // Should be capped to ~900s from now, not 7200s
      expect(result.expires_at.getTime()).toBeGreaterThanOrEqual(before + 900_000);
      expect(result.expires_at.getTime()).toBeLessThanOrEqual(after + 900_000);
    });

    test("caps expires_at to per-request TTL override", async () => {
      const before = Date.now();
      const farFuture = Date.now() + 7200_000;
      const { mintProdToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("prod-token", farFuture),
        impersonatedClient: mockClient("dev-token"),
      });

      const result = await mintProdToken(undefined, 600);
      const after = Date.now();
      // Should be capped to ~600s from now
      expect(result.expires_at.getTime()).toBeGreaterThanOrEqual(before + 600_000);
      expect(result.expires_at.getTime()).toBeLessThanOrEqual(after + 600_000);
    });

    test("uses credential expiry when it is shorter than TTL cap", async () => {
      const shortExpiry = Date.now() + 300_000; // 5 min
      const { mintProdToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("prod-token", shortExpiry),
        impersonatedClient: mockClient("dev-token"),
      });

      const result = await mintProdToken();
      // Credential expiry (5 min) is shorter than default TTL (1 hr), so use credential expiry
      expect(result.expires_at.getTime()).toBe(shortExpiry);
    });
  });

  describe("getIdentityEmail", () => {
    test("returns email from tokeninfo endpoint", async () => {
      const { getIdentityEmail } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source-token"),
        impersonatedClient: mockClient("dev-token"),
        fetchFn: mockFetch("user@example.com"),
      });

      const email = await getIdentityEmail();
      expect(email).toBe("user@example.com");
    });

    test("caches email on subsequent calls", async () => {
      let fetchCount = 0;
      const fetchFn = (async () => {
        fetchCount++;
        return new Response(JSON.stringify({ email: "user@example.com" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch;

      const { getIdentityEmail } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: mockClient("dev"),
        fetchFn,
      });

      await getIdentityEmail();
      await getIdentityEmail();

      expect(fetchCount).toBe(1);
    });

    test("throws when tokeninfo returns error", async () => {
      const fetchFn = (async () =>
        new Response("Unauthorized", { status: 401 })) as unknown as typeof globalThis.fetch;

      const { getIdentityEmail } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: mockClient("dev"),
        fetchFn,
      });

      await expect(getIdentityEmail()).rejects.toThrow("tokeninfo returned 401");
    });

    test("throws when source client returns null token", async () => {
      const { getIdentityEmail } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient(null),
        impersonatedClient: mockClient("dev"),
        fetchFn: mockFetch("user@example.com"),
      });

      await expect(getIdentityEmail()).rejects.toThrow("no access token available");
    });

    test("throws when tokeninfo has no email", async () => {
      const fetchFn = (async () =>
        new Response(JSON.stringify({ aud: "something" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })) as unknown as typeof globalThis.fetch;

      const { getIdentityEmail } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: mockClient("dev"),
        fetchFn,
      });

      await expect(getIdentityEmail()).rejects.toThrow("no email in tokeninfo");
    });
  });

  describe("getUniverseDomain", () => {
    test("returns universe domain from source client", async () => {
      const { getUniverseDomain } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source-token"),
        impersonatedClient: mockClient("dev-token"),
      });

      const domain = await getUniverseDomain();
      expect(domain).toBe("googleapis.com");
    });

    test("returns custom universe domain from source client", async () => {
      const { getUniverseDomain } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source-token", undefined, "custom.example.com"),
        impersonatedClient: mockClient("dev-token"),
      });

      const domain = await getUniverseDomain();
      expect(domain).toBe("custom.example.com");
    });

    test("caches universe domain on subsequent calls", async () => {
      const { getUniverseDomain } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source-token"),
        impersonatedClient: mockClient("dev-token"),
      });

      const first = await getUniverseDomain();
      const second = await getUniverseDomain();

      expect(first).toBe("googleapis.com");
      expect(second).toBe("googleapis.com");
    });
  });

  describe("getProjectNumber", () => {
    test("returns numeric project ID from CRM API", async () => {
      const { getProjectNumber } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source-token"),
        impersonatedClient: mockClient("dev-token"),
        fetchFn: mockCrmFetch("123456789012"),
      });

      const number = await getProjectNumber("test-project");
      expect(number).toBe("123456789012");
    });

    test("caches project number on subsequent calls", async () => {
      let fetchCount = 0;
      const fetchFn = (async () => {
        fetchCount++;
        return new Response(JSON.stringify({ name: "projects/111222333" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch;

      const { getProjectNumber } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: mockClient("dev"),
        fetchFn,
      });

      await getProjectNumber("test-project");
      await getProjectNumber("test-project");

      expect(fetchCount).toBe(1);
    });

    test("cache is keyed by project (different projects each hit CRM)", async () => {
      let fetchCount = 0;
      const seenUrls: string[] = [];
      const fetchFn = (async (url: string | URL) => {
        fetchCount++;
        seenUrls.push(typeof url === "string" ? url : url.toString());
        return new Response(JSON.stringify({ name: `projects/${fetchCount}00000` }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as unknown as typeof globalThis.fetch;

      const { getProjectNumber } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: mockClient("dev"),
        fetchFn,
      });

      expect(await getProjectNumber("tenant-a")).toBe("100000");
      expect(await getProjectNumber("tenant-b")).toBe("200000");
      // Re-request tenant-a — cache hit, no additional CRM call.
      expect(await getProjectNumber("tenant-a")).toBe("100000");

      expect(fetchCount).toBe(2);
      expect(seenUrls[0]).toContain("/projects/tenant-a");
      expect(seenUrls[1]).toContain("/projects/tenant-b");
    });

    test("throws when CRM API returns error", async () => {
      const fetchFn = (async () =>
        new Response("Forbidden", { status: 403 })) as unknown as typeof globalThis.fetch;

      const { getProjectNumber } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: mockClient("dev"),
        fetchFn,
      });

      await expect(getProjectNumber("test-project")).rejects.toThrow("CRM API returned 403");
    });

    test("throws when CRM API response has no name", async () => {
      const fetchFn = (async () =>
        new Response(JSON.stringify({ projectId: "test-project" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })) as unknown as typeof globalThis.fetch;

      const { getProjectNumber } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: mockClient("dev"),
        fetchFn,
      });

      await expect(getProjectNumber("test-project")).rejects.toThrow("no name in CRM API response");
    });

    test("throws when CRM API response has unexpected name format", async () => {
      const fetchFn = (async () =>
        new Response(JSON.stringify({ name: "unexpected-format" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })) as unknown as typeof globalThis.fetch;

      const { getProjectNumber } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: mockClient("dev"),
        fetchFn,
      });

      await expect(getProjectNumber("test-project")).rejects.toThrow("unexpected name format");
    });

    test("throws when source client has no token", async () => {
      const { getProjectNumber } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient(null),
        impersonatedClient: mockClient("dev"),
        fetchFn: mockCrmFetch("123"),
      });

      await expect(getProjectNumber("test-project")).rejects.toThrow("no access token available");
    });
  });

  describe("credentials_expired error mapping", () => {
    test("mintProdToken converts invalid_grant into CredentialsExpiredError", async () => {
      const failingClient = {
        credentials: {},
        getAccessToken: async () => {
          throw new Error("invalid_grant: reauth related error (rapt_required)");
        },
      } as unknown as AuthClient;

      const { mintProdToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: failingClient,
        impersonatedClient: mockClient("dev"),
      });

      const err = await mintProdToken().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(CredentialsExpiredError);
      expect((err as CredentialsExpiredError).code).toBe("credentials_expired");
      expect((err as Error).message).toContain("rapt_required");
      expect((err as Error).message).toContain("gcloud auth application-default login");
    });

    test("mintDevToken converts invalid_grant into CredentialsExpiredError", async () => {
      const failingImpersonated = {
        credentials: {},
        getAccessToken: async () => {
          throw new Error("invalid_grant: Token has been expired or revoked.");
        },
      } as unknown as AuthClient;

      const { mintDevToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: failingImpersonated,
      });

      await expect(mintDevToken()).rejects.toBeInstanceOf(CredentialsExpiredError);
    });

    test("getIdentityEmail converts invalid_grant into CredentialsExpiredError", async () => {
      const failingClient = {
        credentials: {},
        getAccessToken: async () => {
          throw new Error("invalid_grant: invalid_rapt");
        },
      } as unknown as AuthClient;

      const { getIdentityEmail } = createAuthModule(TEST_CONFIG, {
        sourceClient: failingClient,
        impersonatedClient: mockClient("dev"),
        fetchFn: mockFetch("user@example.com"),
      });

      await expect(getIdentityEmail()).rejects.toBeInstanceOf(CredentialsExpiredError);
    });

    test("getIdentityEmail converts tokeninfo invalid_token into CredentialsExpiredError", async () => {
      // The scenario the user actually hits: `gcloud auth application-default
      // revoke` cascade-revokes the access token at Google. The gate's cached
      // ADC client still hands out the locally-cached access token (it has
      // no way to know it was revoked server-side), so the failure surfaces
      // when tokeninfo rejects it with `400 invalid_token`.
      const fetchFn = (async () =>
        new Response(
          JSON.stringify({ error: "invalid_token", error_description: "Invalid Value" }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        )) as unknown as typeof globalThis.fetch;

      const { getIdentityEmail } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("revoked-but-locally-cached"),
        impersonatedClient: mockClient("dev"),
        fetchFn,
      });

      const err = await getIdentityEmail().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(CredentialsExpiredError);
      expect((err as Error).message).toContain("gcloud auth application-default login");
    });

    test("non-reauth errors are passed through unchanged", async () => {
      const failingClient = {
        credentials: {},
        getAccessToken: async () => {
          throw new Error("network unreachable");
        },
      } as unknown as AuthClient;

      const { mintProdToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: failingClient,
        impersonatedClient: mockClient("dev"),
      });

      const err = await mintProdToken().catch((e: unknown) => e);
      expect(err).not.toBeInstanceOf(CredentialsExpiredError);
      expect((err as Error).message).toBe("network unreachable");
    });

    test("getSourceAccessToken normalises reauth errors and returns the token on success", async () => {
      // First call fails with reauth, second succeeds — the resilient
      // self-heal path the PAM module relies on after the engineer
      // re-runs `gcloud auth application-default login`.
      let calls = 0;
      const client = {
        credentials: {},
        getAccessToken: async () => {
          calls++;
          if (calls === 1) {
            throw new Error("invalid_grant: rapt_required");
          }
          return { token: "fresh-adc", res: null };
        },
      } as unknown as AuthClient;

      const { getSourceAccessToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: client,
        impersonatedClient: mockClient("dev"),
      });

      await expect(getSourceAccessToken()).rejects.toBeInstanceOf(CredentialsExpiredError);
      const token = await getSourceAccessToken();
      expect(token).toBe("fresh-adc");
    });

    test("mintDevToken cache is invalidated after a credentials_expired error", async () => {
      // After a reauth failure, the dev-token cache holds a token minted with
      // a now-dead refresh token. The next call (after the engineer
      // re-authenticates) must get a freshly minted token, not the stale one.
      let succeed = false;
      const sourceClient = {
        credentials: { expiry_date: Date.now() + 3600_000 },
        getAccessToken: async () => ({ token: "source", res: null }),
      } as unknown as AuthClient;

      const impersonatedClient = {
        credentials: { expiry_date: Date.now() + 3600_000 },
        getAccessToken: async () => {
          if (!succeed) {
            throw new Error("invalid_grant: rapt_required");
          }
          return { token: "fresh-dev-token", res: null };
        },
      } as unknown as AuthClient;

      const { mintDevToken } = createAuthModule(TEST_CONFIG, {
        sourceClient,
        impersonatedClient,
      });

      await expect(mintDevToken()).rejects.toBeInstanceOf(CredentialsExpiredError);

      // Simulate the user re-authenticating; subsequent calls succeed.
      succeed = true;
      const result = await mintDevToken();
      expect(result.access_token).toBe("fresh-dev-token");
    });
  });
});
