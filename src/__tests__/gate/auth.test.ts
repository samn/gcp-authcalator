import { describe, expect, test } from "bun:test";
import { createAuthModule } from "../../gate/auth.ts";
import type { GateConfig } from "../../config.ts";
import type { AuthClient } from "google-auth-library";

const TEST_CONFIG: GateConfig = {
  project_id: "test-project",
  service_account: "sa@test-project.iam.gserviceaccount.com",
  socket_path: "/tmp/test.sock",
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

    test("throws when no token is returned", async () => {
      const { mintDevToken } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: mockClient(null),
      });

      await expect(mintDevToken()).rejects.toThrow("Failed to mint dev token");
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

      const number = await getProjectNumber();
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

      await getProjectNumber();
      await getProjectNumber();

      expect(fetchCount).toBe(1);
    });

    test("throws when CRM API returns error", async () => {
      const fetchFn = (async () =>
        new Response("Forbidden", { status: 403 })) as unknown as typeof globalThis.fetch;

      const { getProjectNumber } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient("source"),
        impersonatedClient: mockClient("dev"),
        fetchFn,
      });

      await expect(getProjectNumber()).rejects.toThrow("CRM API returned 403");
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

      await expect(getProjectNumber()).rejects.toThrow("no name in CRM API response");
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

      await expect(getProjectNumber()).rejects.toThrow("unexpected name format");
    });

    test("throws when source client has no token", async () => {
      const { getProjectNumber } = createAuthModule(TEST_CONFIG, {
        sourceClient: mockClient(null),
        impersonatedClient: mockClient("dev"),
        fetchFn: mockCrmFetch("123"),
      });

      await expect(getProjectNumber()).rejects.toThrow("no access token available");
    });
  });
});
