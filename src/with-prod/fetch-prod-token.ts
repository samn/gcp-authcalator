import {
  type BunRequestInit,
  type GateConnection,
  connectionFetchOpts,
} from "../gate/connection.ts";
import { CREDENTIALS_EXPIRED_CODE, CredentialsExpiredError } from "../gate/credentials-error.ts";
import { SESSION_NOT_PERMITTED_CODE, TARGET_PROJECT_HEADER } from "../gate/types.ts";
import { encodeCommandHeader } from "../gate/summarize-command.ts";

// ---------------------------------------------------------------------------
// Backstop timeouts for talking to the gate
//
// These exist to convert a wedged gate socket from an infinite client hang
// into a clear, actionable error — NOT to bound normal latency (the gate's own
// per-request and rotation timeouts do that). They are therefore sized ABOVE
// the gate's legitimate worst-case wait so they never false-abort a real one;
// the hierarchy is: gate per-call (10 s) < gate rotation budget (~420 s) <
// these client caps. See `fetchWithGateTimeout`.
// ---------------------------------------------------------------------------

/**
 * Acquisition requests (`/token?level=prod`, `POST /session`) block on
 * host-side confirmation (≤120 s pending-queue) AND a PAM grant rotation
 * (≤ the gate's rotation budget), so this is sized above their sum.
 */
const PROD_FETCH_TIMEOUT_MS = 600_000;

/**
 * The lightweight `/identity` read does no confirmation or PAM work (just a
 * tokeninfo lookup), so it gets a short cap.
 */
const IDENTITY_FETCH_TIMEOUT_MS = 30_000;

/**
 * Fetch the gate with a backstop timeout, rethrowing an abort as an actionable,
 * URL-bearing error instead of a bare `DOMException` — mirroring the gate's own
 * `pamFetch`, so a wedged socket surfaces "gcp-gate request timed out after
 * Nms: <url>" rather than "The operation timed out". Uses an AbortController +
 * `clearTimeout` so the (multi-minute) timer is released the instant the
 * request settles, rather than lingering — important on the repeatedly-called
 * session-refresh path.
 */
export async function fetchWithGateTimeout(
  fetchFn: typeof globalThis.fetch,
  url: string,
  init: BunRequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchFn(url, { ...init, signal: controller.signal });
  } catch (err) {
    if (err instanceof Error && (err.name === "AbortError" || err.name === "TimeoutError")) {
      throw new Error(`gcp-gate request timed out after ${timeoutMs}ms: ${url}`, { cause: err });
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/** Raised when the gate signals that sessions are disabled on this socket. */
export class SessionNotPermittedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SessionNotPermittedError";
  }
}

/**
 * Parse a gate JSON error body, returning `{}` on malformed payloads. The
 * gate always emits `{error: string, code?: string}`; non-conforming
 * responses fall back to the verbatim text further up the stack.
 */
function parseGateErrorBody(text: string): { code?: string; error?: string } {
  try {
    return JSON.parse(text) as { code?: string; error?: string };
  } catch {
    return {};
  }
}

/**
 * Inspect a gate error response and throw the typed client-side error
 * matching its `code`, if any. Each path in this client surfaces these
 * the same way: a credentials-expired response carries the gate's
 * already-formatted recovery instruction, and a session-not-permitted
 * response triggers the per-request fallback in `with-prod`.
 */
export function throwTypedGateError(text: string): void {
  const body = parseGateErrorBody(text);
  if (body.code === CREDENTIALS_EXPIRED_CODE) {
    throw new CredentialsExpiredError(body.error ?? "gate reported expired gcloud credentials");
  }
  if (body.code === SESSION_NOT_PERMITTED_CODE) {
    throw new SessionNotPermittedError(body.error ?? "Session creation not permitted");
  }
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
  /**
   * Target GCP project for this request. Sent to the gate via the
   * `X-Target-Project` header and recorded in the audit log; not used for
   * any enforcement on the gate side. Empty / unset omits the header.
   */
  targetProject?: string;
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
    const encoded = encodeCommandHeader(options.command);
    if (encoded) headers["X-Wrapped-Command"] = encoded;
  }
  if (options.pendingId) {
    headers["X-Pending-Id"] = options.pendingId;
  }
  if (options.targetProject) {
    headers[TARGET_PROJECT_HEADER] = options.targetProject;
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
  const tokenRes = await fetchWithGateTimeout(
    fetchFn,
    tokenUrl,
    { ...extraOpts, headers },
    PROD_FETCH_TIMEOUT_MS,
  );

  if (!tokenRes.ok) {
    const text = await tokenRes.text();
    throwTypedGateError(text);
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

  const identityRes = await fetchWithGateTimeout(
    fetchFn,
    `${baseUrl}/identity`,
    extraOpts,
    IDENTITY_FETCH_TIMEOUT_MS,
  );
  if (!identityRes.ok) {
    const text = await identityRes.text();
    throwTypedGateError(text);
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
    const encoded = encodeCommandHeader(options.command);
    if (encoded) headers["X-Wrapped-Command"] = encoded;
  }
  if (options.pendingId) {
    headers["X-Pending-Id"] = options.pendingId;
  }
  if (options.targetProject) {
    headers[TARGET_PROJECT_HEADER] = options.targetProject;
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

  const res = await fetchWithGateTimeout(
    fetchFn,
    sessionUrl,
    { ...extraOpts, method: "POST", headers },
    PROD_FETCH_TIMEOUT_MS,
  );

  if (!res.ok) {
    const text = await res.text();
    throwTypedGateError(text);
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
      // Bound the request: this is awaited on the exit path, so a hung or
      // half-open gate socket must not block with-prod from exiting.
      signal: AbortSignal.timeout(REVOKE_TIMEOUT_MS),
    });
  } catch {
    // Best-effort cleanup — swallow errors (including the timeout abort)
  }
}

/** Max time to wait for the best-effort session revoke on exit. */
const REVOKE_TIMEOUT_MS = 2000;
