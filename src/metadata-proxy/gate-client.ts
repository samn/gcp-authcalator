import { existsSync, lstatSync } from "node:fs";
import {
  type GateConnection,
  type BunRequestInit,
  connectionFetchOpts,
  fetchWithGateTimeout,
} from "../gate/connection.ts";
import type { CachedToken, GateClient } from "./types.ts";
import { tokenRefreshAt } from "../token-cache.ts";

// Client backstops must sit outside the gate's sequential 30-second auth-stage
// deadlines. A cold token mint can perform ADC discovery plus minting; identity
// and project lookup can additionally perform one Google HTTP exchange.
const TOKEN_GATE_TIMEOUT_MS = 75_000;
const IDENTITY_GATE_TIMEOUT_MS = 105_000;
const PROJECT_GATE_TIMEOUT_MS = 105_000;
const UNIVERSE_GATE_TIMEOUT_MS = 45_000;

export interface GateClientOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
  /** OAuth scopes to request from the gate daemon. */
  scopes?: string[];
  /** Override the clock for testing cache expiry. */
  now?: () => number;
}

/**
 * Verify that the gcp-gate daemon is reachable.
 *
 * For Unix mode: checks socket file exists on disk and sends GET /health.
 * For TCP mode: sends GET /health with mTLS client certificate.
 */
export async function checkGateConnection(
  conn: GateConnection,
  fetchFn: typeof globalThis.fetch = globalThis.fetch,
): Promise<void> {
  if (conn.mode === "unix") {
    return checkGateSocket(conn.socketPath, fetchFn);
  }

  // TCP mode — health check with mTLS
  let res: Response;
  try {
    res = await fetchWithGateTimeout(
      fetchFn,
      `${conn.gateUrl}/health`,
      {
        tls: {
          cert: conn.clientCert,
          key: conn.clientKey,
          ca: conn.caCert,
        },
      } as BunRequestInit,
      3_000,
    );
  } catch {
    throw new Error(
      `Could not connect to gcp-gate at ${conn.gateUrl}\n` +
        `  Ensure gcp-gate is running with --gate-tls-port and port forwarding is active.`,
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
    res = await fetchWithGateTimeout(
      fetchFn,
      "http://localhost/health",
      { unix: socketPath } as BunRequestInit,
      3_000,
    );
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
 * gcp-gate daemon over a Unix socket or TCP+mTLS connection.
 *
 * - Caches tokens in memory; re-fetches when remaining lifetime < 5 minutes
 * - Caches the numeric project ID permanently (immutable value)
 * - Caches the universe domain permanently (immutable value)
 * - Re-reads authenticated identity so a gate-side credential-cache reset is observable
 * - Accepts an optional fetchFn for test injection
 */
export function createGateClient(
  conn: GateConnection,
  options: GateClientOptions = {},
): GateClient {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const now = options.now ?? Date.now;
  const { baseUrl, extraOpts } = connectionFetchOpts(conn);

  let tokenCache: CachedToken | null = null;
  let tokenRefreshAtMs = 0;
  let tokenRefresh: Promise<CachedToken> | null = null;
  let numericProjectIdCache: string | null = null;
  let universeDomainCache: string | null = null;

  function gateFetch(path: string, timeoutMs: number): Promise<Response> {
    const url = `${baseUrl}${path}`;
    return fetchWithGateTimeout(fetchFn, url, extraOpts, timeoutMs);
  }

  function isCacheValid(cached: CachedToken | null): cached is CachedToken {
    if (!cached) return false;
    return now() < tokenRefreshAtMs;
  }

  async function refreshToken(): Promise<CachedToken> {
    const tokenUrl = options.scopes
      ? `${baseUrl}/token?scopes=${options.scopes.map(encodeURIComponent).join(",")}`
      : `${baseUrl}/token`;
    const res = await fetchWithGateTimeout(fetchFn, tokenUrl, extraOpts, TOKEN_GATE_TIMEOUT_MS);

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
      expires_at: new Date(now() + expiresIn * 1000),
    };
    tokenRefreshAtMs = tokenRefreshAt(tokenCache.expires_at.getTime(), now());

    return tokenCache;
  }

  async function getToken(): Promise<CachedToken> {
    if (isCacheValid(tokenCache)) {
      return tokenCache;
    }

    if (tokenRefresh) return tokenRefresh;

    const pending = refreshToken();
    tokenRefresh = pending;
    try {
      return await pending;
    } finally {
      // Identity check avoids an older finally clearing a replacement request
      // if this function gains cancellation/retry behavior later.
      if (tokenRefresh === pending) tokenRefresh = null;
    }
  }

  async function getNumericProjectId(): Promise<string> {
    if (numericProjectIdCache) {
      return numericProjectIdCache;
    }

    const res = await gateFetch("/project-number", PROJECT_GATE_TIMEOUT_MS);

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

    const res = await gateFetch("/universe-domain", UNIVERSE_GATE_TIMEOUT_MS);

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

  async function getIdentity(): Promise<string> {
    const res = await gateFetch("/identity", IDENTITY_GATE_TIMEOUT_MS);

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`gcp-gate returned ${res.status}: ${text}`);
    }

    const body = (await res.json()) as { email?: string };

    if (!body.email) {
      throw new Error("gcp-gate returned no email");
    }

    return body.email;
  }

  return { getToken, getNumericProjectId, getUniverseDomain, getIdentity };
}
