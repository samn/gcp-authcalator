import { existsSync, lstatSync } from "node:fs";
import type { CachedToken, GateClient } from "./types.ts";

/** Minimum remaining lifetime before we re-fetch a cached token (5 minutes). */
const CACHE_MARGIN_MS = 5 * 60 * 1000;

export interface GateClientOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
}

/**
 * Verify that the gcp-gate daemon is reachable on the given Unix socket.
 *
 * 1. Checks that the socket file exists on disk (and is actually a socket)
 * 2. Sends a GET /health request to the daemon
 *
 * Throws a descriptive Error if the socket is missing or the healthcheck fails.
 */
export async function checkGateSocket(
  socketPath: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch,
): Promise<void> {
  if (!existsSync(socketPath)) {
    throw new Error(
      `gcp-gate socket not found at ${socketPath}\n` +
        `  Make sure gcp-gate is running (gcp-authcalator gate) and the --socket-path is correct.`,
    );
  }

  const stat = lstatSync(socketPath);
  if (!stat.isSocket()) {
    throw new Error(
      `${socketPath} exists but is not a Unix socket.\n` +
        `  Remove the file and start gcp-gate (gcp-authcalator gate).`,
    );
  }

  let res: Response;
  try {
    res = await fetchFn("http://localhost/health", {
      unix: socketPath,
      signal: AbortSignal.timeout(3_000),
    } as RequestInit);
  } catch {
    throw new Error(
      `Could not connect to gcp-gate at ${socketPath}\n` +
        `  The socket exists but the daemon is not responding.\n` +
        `  Try restarting gcp-gate (gcp-authcalator gate).`,
    );
  }

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `gcp-gate health check failed (HTTP ${res.status})${text ? `: ${text}` : ""}\n` +
        `  The daemon may be in a bad state. Try restarting gcp-gate.`,
    );
  }
}

/**
 * Create a gate client that fetches tokens and project metadata from the
 * gcp-gate daemon over a Unix socket.
 *
 * - Caches tokens in memory; re-fetches when remaining lifetime < 5 minutes
 * - Caches the numeric project ID permanently (immutable value)
 * - Caches the universe domain permanently (immutable value)
 * - Accepts an optional fetchFn for test injection
 */
export function createGateClient(socketPath: string, options: GateClientOptions = {}): GateClient {
  const fetchFn = options.fetchFn ?? globalThis.fetch;

  let tokenCache: CachedToken | null = null;
  let numericProjectIdCache: string | null = null;
  let universeDomainCache: string | null = null;

  function isCacheValid(cached: CachedToken | null): cached is CachedToken {
    if (!cached) return false;
    return cached.expires_at.getTime() - Date.now() > CACHE_MARGIN_MS;
  }

  async function getToken(): Promise<CachedToken> {
    if (isCacheValid(tokenCache)) {
      return tokenCache;
    }

    const res = await fetchFn("http://localhost/token", {
      unix: socketPath,
    } as RequestInit);

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`gcp-gate returned ${res.status}: ${text}`);
    }

    const body = (await res.json()) as { access_token?: string; expires_in?: number };

    if (!body.access_token) {
      throw new Error("gcp-gate returned no access_token");
    }

    const expiresIn = body.expires_in ?? 3600;

    tokenCache = {
      access_token: body.access_token,
      expires_at: new Date(Date.now() + expiresIn * 1000),
    };

    return tokenCache;
  }

  async function getNumericProjectId(): Promise<string> {
    if (numericProjectIdCache) {
      return numericProjectIdCache;
    }

    const res = await fetchFn("http://localhost/project-number", {
      unix: socketPath,
    } as RequestInit);

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`gcp-gate returned ${res.status}: ${text}`);
    }

    const body = (await res.json()) as { project_number?: string };

    if (!body.project_number) {
      throw new Error("gcp-gate returned no project_number");
    }

    numericProjectIdCache = body.project_number;
    return numericProjectIdCache;
  }

  async function getUniverseDomain(): Promise<string> {
    if (universeDomainCache) {
      return universeDomainCache;
    }

    const res = await fetchFn("http://localhost/universe-domain", {
      unix: socketPath,
    } as RequestInit);

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`gcp-gate returned ${res.status}: ${text}`);
    }

    const body = (await res.json()) as { universe_domain?: string };

    if (!body.universe_domain) {
      throw new Error("gcp-gate returned no universe_domain");
    }

    universeDomainCache = body.universe_domain;
    return universeDomainCache;
  }

  return { getToken, getNumericProjectId, getUniverseDomain };
}
