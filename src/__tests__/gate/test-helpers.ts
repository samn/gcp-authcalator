import { ProjectNotInScopeError, type GateDeps, type CachedToken } from "../../gate/types.ts";
import { createProdRateLimiter } from "../../gate/rate-limit.ts";
import { createSessionManager } from "../../gate/session.ts";

export function makeRequest(
  path: string,
  method = "GET",
  headers?: Record<string, string>,
): Request {
  return new Request(`http://localhost${path}`, { method, headers });
}

/**
 * Pin Date.now to `fixedNow` for the duration of `fn`, restoring the
 * real Date.now afterwards (including on throw). The handlers use
 * Date.now directly (not an injected clock) when computing
 * expires_in, so tests that need to simulate the passage of time
 * between two handler invocations have to stub it out.
 */
export async function withFakeNow<T>(fixedNow: number, fn: () => Promise<T>): Promise<T> {
  const realDateNow = Date.now;
  Date.now = () => fixedNow;
  try {
    return await fn();
  } finally {
    Date.now = realDateNow;
  }
}

export function makeGateDeps(overrides: Partial<GateDeps> = {}): GateDeps {
  const token: CachedToken = {
    access_token: "test-access-token",
    expires_at: new Date(Date.now() + 3600 * 1000),
  };

  return {
    scope: { kind: "project", projectId: "test-project" },
    mintDevToken: async () => token,
    mintProdToken: async () => ({
      access_token: "prod-access-token",
      expires_at: new Date(Date.now() + 3600 * 1000),
    }),
    getIdentityEmail: async () => "user@example.com",
    getProjectNumber: async (_projectId: string) => "123456789012",
    getUniverseDomain: async () => "googleapis.com",
    resolveProject: async (requested: string | undefined) => {
      if (requested && requested !== "test-project") {
        throw new ProjectNotInScopeError(`Project "${requested}" not permitted`);
      }
      return "test-project";
    },
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
