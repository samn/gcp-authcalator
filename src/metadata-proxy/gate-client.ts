import { existsSync, lstatSync } from "node:fs";
import {
  type GateConnection,
  type BunRequestInit,
  connectionFetchOpts,
  fetchWithGateTimeout,
} from "../gate/connection.ts";
import type { CachedToken, GateClient } from "./types.ts";

/** Minimum remaining lifetime before we re-fetch a cached token (5 minutes). */
const CACHE_MARGIN_MS = 5 * 60 * 1000;

/**
 * Backstop timeout for gate fetches originating from the metadata proxy.
 *
 * Dev tokens, project-number, and universe-domain requests involve no human
 * confirmation — only ADC + impersonation / lookup — so legitimate latency is
 * small. Without this cap a wedged gate socket (half-open TCP, dead gate
 * process with socket file present, NAT/LB idle-drop on the TCP+mTLS path)
 * hangs every container command on the OS TCP retransmission timeout (~15 min
 * on Linux with default `tcp_retries2`). The rest of the codebase bounds
 * gate fetches (3 s healthcheck, 5 s kube-token, 10 s PAM, 30 s identity,
 * 480 s session refresh); the dev-token path was the lone gap.
 *
 * 30 s matches `IDENTITY_FETCH_TIMEOUT_MS` and comfortably covers slow
 * ADC/impersonation while still converting a stall into a clear error.
 */
const GATE_FETCH_TIMEOUT_MS = 30_000;

export interface GateClientOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
  /** OAuth scopes to request from the gate daemon. */
  scopes?: string[];
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
    res = await fetchFn(`${conn.gateUrl}/health`, {
      tls: {
        cert: conn.clientCert,
        key: conn.clientKey,
        ca: conn.caCert,
      },
      signal: AbortSignal.timeout(3_000),
    } as BunRequestInit);
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
    res = await fetchFn("http://localhost/health", {
      unix: socketPath,
      signal: AbortSignal.timeout(3_000),
    } as BunRequestInit);
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
 * - Accepts an optional fetchFn for test injection
 */
export function createGateClient(
  conn: GateConnection,
  options: GateClientOptions = {},
): GateClient {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const { baseUrl, extraOpts } = connectionFetchOpts(conn);

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

    const tokenUrl = options.scopes
      ? `${baseUrl}/token?scopes=${options.scopes.map(encodeURIComponent).join(",")}`
      : `${baseUrl}/token`;
    const res = await fetchWithGateTimeout(fetchFn, tokenUrl, extraOpts, GATE_FETCH_TIMEOUT_MS);

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

    const res = await fetchWithGateTimeout(
      fetchFn,
      `${baseUrl}/project-number`,
      extraOpts,
      GATE_FETCH_TIMEOUT_MS,
    );

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

    const res = await fetchWithGateTimeout(
      fetchFn,
      `${baseUrl}/universe-domain`,
      extraOpts,
      GATE_FETCH_TIMEOUT_MS,
    );

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
