import { type GateConnection, connectionFetchOpts } from "../gate/connection.ts";
import { CREDENTIALS_EXPIRED_CODE, CredentialsExpiredError } from "../gate/credentials-error.ts";

/** Raised when the gate signals that sessions are disabled on this socket. */
export class SessionNotPermittedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SessionNotPermittedError";
  }
}

/**
 * Inspect an error response body and, if the gate flagged it as
 * `credentials_expired`, throw the typed client-side error so callers
 * can give the engineer the gate's already-formatted recovery
 * instructions. Returns the parsed body otherwise.
 */
export function maybeThrowCredentialsExpired(text: string): { code?: string; error?: string } {
  let body: { code?: string; error?: string } | undefined;
  try {
    body = JSON.parse(text) as { code?: string; error?: string };
  } catch {
    return {};
  }
  if (body && body.code === CREDENTIALS_EXPIRED_CODE) {
    throw new CredentialsExpiredError(body.error ?? "gate reported expired gcloud credentials");
  }
  return body ?? {};
}

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
  /** Client-generated pending ID for CLI approval flow (32 hex chars). */
  pendingId?: string;
}

export interface ProdTokenResult {
  access_token: string;
  expires_in: number;
  /** Engineer's email address (from gcp-gate /identity endpoint). */
  email: string;
}

/**
 * Fetch only `/token?level=prod` from gcp-gate. May trigger host-side
 * confirmation. Used by token-refresh paths that already know the engineer's
 * email and don't need to round-trip `/identity` again.
 */
export async function fetchProdAccessToken(
  conn: GateConnection,
  options: FetchProdTokenOptions = {},
): Promise<{ access_token: string; expires_in: number }> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const { baseUrl, extraOpts } = connectionFetchOpts(conn);

  const headers: Record<string, string> = {};
  if (options.command && options.command.length > 0) {
    headers["X-Wrapped-Command"] = JSON.stringify(options.command);
  }
  if (options.pendingId) {
    headers["X-Pending-Id"] = options.pendingId;
  }

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
  const tokenRes = await fetchFn(tokenUrl, { ...extraOpts, headers });

  if (!tokenRes.ok) {
    const text = await tokenRes.text();
    // Throws if the gate signalled credentials_expired so the caller
    // surfaces the gcloud reauth instruction instead of a generic 5xx.
    maybeThrowCredentialsExpired(text);
    throw new Error(`gcp-gate returned ${tokenRes.status}: ${text}`);
  }

  const tokenBody = (await tokenRes.json()) as { access_token?: string; expires_in?: number };

  if (!tokenBody.access_token) {
    throw new Error("gcp-gate returned no access_token");
  }

  return {
    access_token: tokenBody.access_token,
    expires_in: tokenBody.expires_in ?? 3600,
  };
}

/**
 * One-shot fetch of a prod-level token and engineer identity from gcp-gate.
 * The email is needed so the temporary metadata proxy can advertise a real
 * service-account email (gcloud ignores the "default" alias).
 */
export async function fetchProdToken(
  conn: GateConnection,
  options: FetchProdTokenOptions = {},
): Promise<ProdTokenResult> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const { baseUrl, extraOpts } = connectionFetchOpts(conn);

  const token = await fetchProdAccessToken(conn, options);

  const identityRes = await fetchFn(`${baseUrl}/identity`, extraOpts);
  if (!identityRes.ok) {
    const text = await identityRes.text();
    maybeThrowCredentialsExpired(text);
    throw new Error(`gcp-gate /identity returned ${identityRes.status}: ${text}`);
  }
  const identityBody = (await identityRes.json()) as { email?: string };
  if (!identityBody.email) {
    throw new Error("gcp-gate /identity returned no email");
  }

  return {
    access_token: token.access_token,
    expires_in: token.expires_in,
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
  if (options.pendingId) {
    headers["X-Pending-Id"] = options.pendingId;
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
    if (res.status === 403) {
      try {
        const body = JSON.parse(text) as { code?: string; error?: string };
        if (body.code === "session_not_permitted_on_operator_socket") {
          throw new SessionNotPermittedError(body.error ?? "Session creation not permitted");
        }
      } catch (err) {
        if (err instanceof SessionNotPermittedError) throw err;
        // body wasn't JSON — fall through to generic error
      }
    }
    // Surface the gate's reauth instruction to the user verbatim when
    // the gate flagged the failure as credentials_expired.
    maybeThrowCredentialsExpired(text);
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
