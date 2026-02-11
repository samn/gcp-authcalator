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
function mockClient(token: string | null): AuthClient {
  return {
    getAccessToken: async () => ({ token, res: null }),
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

    test("does not cache — returns fresh token each time", async () => {
      let callCount = 0;
      const client = {
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
});
