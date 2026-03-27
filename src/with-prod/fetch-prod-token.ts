import { type GateConnection, connectionFetchOpts } from "../gate/connection.ts";

export interface FetchProdTokenOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
  /** The command being wrapped, sent to gcp-gate for display in the confirmation dialog. */
  command?: string[];
  /** OAuth scopes for the prod token. */
  scopes?: string[];
  /** PAM entitlement to escalate to (passed to gate as query param). */
  pamPolicy?: string;
  /** Token TTL override in seconds (must be LTE gate's configured default). */
  tokenTtlSeconds?: number;
  /** Session TTL override in seconds (for createProdSession). */
  sessionTtlSeconds?: number;
}

export interface ProdTokenResult {
  access_token: string;
  expires_in: number;
  /** Engineer's email address (from gcp-gate /identity endpoint). */
  email: string;
}

/**
 * One-shot fetch of a prod-level token and engineer identity from gcp-gate.
 *
 * 1. Hits `/token?level=prod` (triggers host-side confirmation).
 * 2. Hits `/identity` to retrieve the engineer's email address.
 *
 * The email is needed so the temporary metadata proxy can advertise a real
 * service-account email — gcloud ignores the "default" alias and only
 * recognises email-keyed accounts.
 */
export async function fetchProdToken(
  conn: GateConnection,
  options: FetchProdTokenOptions = {},
): Promise<ProdTokenResult> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const { baseUrl, extraOpts } = connectionFetchOpts(conn);

  const headers: Record<string, string> = {};
  if (options.command && options.command.length > 0) {
    headers["X-Wrapped-Command"] = JSON.stringify(options.command);
  }

  const fetchOpts = { ...extraOpts, headers };

  // Fetch prod token (may trigger host-side confirmation dialog)
  let tokenUrl = `${baseUrl}/token?level=prod`;
  if (options.scopes && options.scopes.length > 0) {
    tokenUrl += `&scopes=${options.scopes.map(encodeURIComponent).join(",")}`;
  }
  if (options.pamPolicy) {
    tokenUrl += `&pam_policy=${encodeURIComponent(options.pamPolicy)}`;
  }
  if (options.tokenTtlSeconds !== undefined) {
    tokenUrl += `&token_ttl_seconds=${options.tokenTtlSeconds}`;
  }
  const tokenRes = await fetchFn(tokenUrl, fetchOpts);

  if (!tokenRes.ok) {
    const text = await tokenRes.text();
    throw new Error(`gcp-gate returned ${tokenRes.status}: ${text}`);
  }

  const tokenBody = (await tokenRes.json()) as { access_token?: string; expires_in?: number };

  if (!tokenBody.access_token) {
    throw new Error("gcp-gate returned no access_token");
  }

  // Fetch engineer identity
  const identityRes = await fetchFn(`${baseUrl}/identity`, extraOpts);

  if (!identityRes.ok) {
    const text = await identityRes.text();
    throw new Error(`gcp-gate /identity returned ${identityRes.status}: ${text}`);
  }

  const identityBody = (await identityRes.json()) as { email?: string };

  if (!identityBody.email) {
    throw new Error("gcp-gate /identity returned no email");
  }

  return {
    access_token: tokenBody.access_token,
    expires_in: tokenBody.expires_in ?? 3600,
    email: identityBody.email,
  };
}

// ---------------------------------------------------------------------------
// Session-based prod access (auto-refresh)
// ---------------------------------------------------------------------------

export interface ProdSessionResult {
  session_id: string;
  access_token: string;
  expires_in: number;
  email: string;
}

/**
 * Create a prod session at the gate.
 *
 * Triggers the same confirmation + PAM flow as fetchProdToken, but also
 * creates a session that allows subsequent token refreshes without
 * re-confirmation.
 */
export async function createProdSession(
  conn: GateConnection,
  options: FetchProdTokenOptions = {},
): Promise<ProdSessionResult> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const { baseUrl, extraOpts } = connectionFetchOpts(conn);

  const headers: Record<string, string> = {};
  if (options.command && options.command.length > 0) {
    headers["X-Wrapped-Command"] = JSON.stringify(options.command);
  }

  let sessionUrl = `${baseUrl}/session`;
  const params: string[] = [];
  if (options.scopes && options.scopes.length > 0) {
    params.push(`scopes=${options.scopes.map(encodeURIComponent).join(",")}`);
  }
  if (options.pamPolicy) {
    params.push(`pam_policy=${encodeURIComponent(options.pamPolicy)}`);
  }
  if (options.tokenTtlSeconds !== undefined) {
    params.push(`token_ttl_seconds=${options.tokenTtlSeconds}`);
  }
  if (options.sessionTtlSeconds !== undefined) {
    params.push(`session_ttl_seconds=${options.sessionTtlSeconds}`);
  }
  if (params.length > 0) {
    sessionUrl += `?${params.join("&")}`;
  }

  const res = await fetchFn(sessionUrl, { ...extraOpts, method: "POST", headers });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`gcp-gate returned ${res.status}: ${text}`);
  }

  const body = (await res.json()) as {
    session_id?: string;
    access_token?: string;
    expires_in?: number;
    email?: string;
  };

  if (!body.session_id) {
    throw new Error("gcp-gate returned no session_id");
  }
  if (!body.access_token) {
    throw new Error("gcp-gate returned no access_token");
  }
  if (!body.email) {
    throw new Error("gcp-gate returned no email");
  }

  return {
    session_id: body.session_id,
    access_token: body.access_token,
    expires_in: body.expires_in ?? 3600,
    email: body.email,
  };
}

/**
 * Revoke a prod session at the gate.
 * Best-effort — errors are logged but not thrown.
 */
export async function revokeProdSession(
  conn: GateConnection,
  sessionId: string,
  options: { fetchFn?: typeof globalThis.fetch } = {},
): Promise<void> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const { baseUrl, extraOpts } = connectionFetchOpts(conn);

  try {
    await fetchFn(`${baseUrl}/session?id=${encodeURIComponent(sessionId)}`, {
      ...extraOpts,
      method: "DELETE",
    });
  } catch {
    // Best-effort cleanup — swallow errors
  }
}
