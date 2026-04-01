import type { GateDeps, CachedToken } from "../../gate/types.ts";
import { createProdRateLimiter } from "../../gate/rate-limit.ts";
import { createSessionManager } from "../../gate/session.ts";

export function makeRequest(
  path: string,
  method = "GET",
  headers?: Record<string, string>,
): Request {
  return new Request(`http://localhost${path}`, { method, headers });
}

export function makeGateDeps(overrides: Partial<GateDeps> = {}): GateDeps {
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
    defaultTokenTtlSeconds: 3600,
    sessionManager: createSessionManager(),
    sessionTtlSeconds: 28800,
    ...overrides,
  };
}
