import {
  SESSION_NOT_PERMITTED_CODE,
  type CachedToken,
  type GateDeps,
  type TokenResponse,
  type SessionResponse,
  type ProjectNumberResponse,
  type UniverseDomainResponse,
  type AuditEntry,
  type ErrorResponse,
  type RequestContext,
} from "./types.ts";
import { CredentialsExpiredError } from "./credentials-error.ts";
import { DRAIN_MARGIN_MS } from "./pam.ts";
import { parseCommandHeader, summarizeCommand } from "./summarize-command.ts";

const JSON_HEADERS = { "Content-Type": "application/json" };

/** Default context for tests and any production caller that hasn't been updated yet. */
const DEFAULT_CTX: RequestContext = { trusted: false, socket: "main" };

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

/**
 * Build the JSON error body for an exception thrown by an ADC-backed
 * operation. `CredentialsExpiredError` carries an actionable message and
 * a `code` field so clients can recognise the condition and surface a
 * tailored error to the engineer; other errors fall through unchanged.
 */
function errorBodyFromException(err: unknown): ErrorResponse {
  if (err instanceof CredentialsExpiredError) {
    return { error: err.message, code: err.code };
  }
  const message = err instanceof Error ? err.message : "Unknown error";
  return { error: message };
}

/**
 * Pure request handler — routes incoming requests and delegates to deps.
 * All responses are JSON. Audit entries are written for token requests.
 *
 * The `ctx` argument carries which socket the request arrived on. Only the
 * operator socket sets `ctx.trusted = true`, which gates the auto-approve
 * path inside `acquireProdAccess`.
 */
export async function handleRequest(
  req: Request,
  deps: GateDeps,
  ctx: RequestContext = DEFAULT_CTX,
): Promise<Response> {
  const url = new URL(req.url, "http://localhost");

  // /session accepts POST (create) and DELETE (revoke)
  if (url.pathname === "/session") {
    if (req.method === "POST") return handleCreateSession(req, url, deps, ctx);
    if (req.method === "DELETE") return handleRevokeSession(url, deps, ctx);
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  if (req.method !== "GET") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  switch (url.pathname) {
    case "/token":
      return handleToken(req, url, deps, ctx);
    case "/identity":
      return handleIdentity(deps);
    case "/project-number":
      return handleProjectNumber(deps);
    case "/universe-domain":
      return handleUniverseDomain(deps);
    case "/health":
      return handleHealth(deps);
    default:
      return jsonResponse({ error: "Not found" }, 404);
  }
}

/** Parse and validate the token_ttl_seconds query param. Returns the value or an error Response. */
function parseTtlParam(
  param: string | null,
  defaultTtl: number,
): { ttlSeconds?: number } | { error: Response } {
  if (param === null) return {};

  const n = Number(param);
  if (!Number.isInteger(n) || n !== n) {
    return { error: jsonResponse({ error: "token_ttl_seconds must be an integer" }, 400) };
  }
  if (n < 60) {
    return { error: jsonResponse({ error: "token_ttl_seconds must be >= 60" }, 400) };
  }
  if (n > defaultTtl) {
    return {
      error: jsonResponse(
        { error: `token_ttl_seconds (${n}) exceeds configured maximum (${defaultTtl})` },
        400,
      ),
    };
  }
  return { ttlSeconds: n };
}

async function handleToken(
  req: Request,
  url: URL,
  deps: GateDeps,
  ctx: RequestContext,
): Promise<Response> {
  // Session-based token refresh: bypass confirmation and rate limiting
  const sessionId = url.searchParams.get("session");
  if (sessionId) {
    return handleSessionTokenRefresh(req, sessionId, deps, ctx);
  }

  const level = url.searchParams.get("level") === "prod" ? "prod" : "dev";
  const scopesParam = url.searchParams.get("scopes");
  const scopes = scopesParam ? scopesParam.split(",") : undefined;
  const pamPolicyParam = url.searchParams.get("pam_policy") ?? undefined;

  const ttlResult = parseTtlParam(
    url.searchParams.get("token_ttl_seconds"),
    deps.defaultTokenTtlSeconds,
  );
  if ("error" in ttlResult) return ttlResult.error;

  if (level === "prod") {
    return handleProdToken(req, deps, ctx, scopes, pamPolicyParam, ttlResult.ttlSeconds);
  }

  return handleDevToken(deps, ctx, scopes, ttlResult.ttlSeconds);
}

/** Mint a fresh prod token using a pre-approved session (no confirmation). */
async function handleSessionTokenRefresh(
  req: Request,
  sessionId: string,
  deps: GateDeps,
  ctx: RequestContext,
): Promise<Response> {
  // Sessions are a main-socket feature only. The operator socket has no
  // session-creation path, so any session_id presented here would have to
  // have been minted elsewhere — reject defensively.
  if (ctx.trusted) {
    return jsonResponse(
      {
        error: "Session refresh not permitted on operator socket",
        code: SESSION_NOT_PERMITTED_CODE,
      },
      403,
    );
  }

  const session = deps.sessionManager.validate(sessionId);
  if (!session) {
    return jsonResponse({ error: "Session expired or invalid" }, 401);
  }

  const commandArr = parseCommandHeader(req.headers.get("X-Wrapped-Command"));
  const commandSummary = commandArr ? summarizeCommand(commandArr) : undefined;

  const auditBase: Pick<
    AuditEntry,
    "endpoint" | "level" | "session_id" | "pam_policy" | "socket" | "command"
  > = {
    endpoint: "/token?session=...",
    level: "prod",
    session_id: sessionId,
    pam_policy: session.pamPolicy,
    socket: ctx.socket,
    command: commandSummary,
  };

  try {
    // Renew PAM grant if the session has a PAM policy (grants expire
    // independently of the session and must be kept alive for the token
    // to carry elevated permissions). Pass the command summary captured
    // at session creation so renewed grants carry the same justification
    // as the initial grant in the GCP PAM audit log.
    let pamAuditFields: Pick<AuditEntry, "pam_grant" | "pam_cached"> = {};
    let pamGrantExpiresAt: Date | undefined;
    if (session.pamPolicy && deps.ensurePamGrant) {
      const grantResult = await deps.ensurePamGrant(session.pamPolicy, session.commandSummary);
      pamAuditFields = {
        pam_grant: grantResult.name,
        pam_cached: grantResult.cached,
      };
      pamGrantExpiresAt = grantResult.expiresAt;
    }

    const cached = await deps.mintProdToken(session.scopes, session.ttlSeconds);
    const expiresIn = expiresInClampedToGrant(cached, pamGrantExpiresAt);

    const body: TokenResponse = {
      access_token: cached.access_token,
      expires_in: expiresIn,
      token_type: "Bearer",
    };

    deps.writeAuditLog({
      ...auditBase,
      ...pamAuditFields,
      timestamp: new Date().toISOString(),
      result: "granted",
      email: session.email,
    });

    return jsonResponse(body);
  } catch (err) {
    const errorBody = errorBodyFromException(err);

    deps.writeAuditLog({
      ...auditBase,
      timestamp: new Date().toISOString(),
      result: "error",
      email: session.email,
      error: errorBody.error,
    });

    return jsonResponse(errorBody, 500);
  }
}

async function handleDevToken(
  deps: GateDeps,
  ctx: RequestContext,
  scopes?: string[],
  ttlSeconds?: number,
): Promise<Response> {
  const auditBase: Pick<AuditEntry, "endpoint" | "level" | "token_ttl_seconds" | "socket"> = {
    endpoint: "/token",
    level: "dev",
    token_ttl_seconds: ttlSeconds,
    socket: ctx.socket,
  };

  try {
    const cached = await deps.mintDevToken(scopes, ttlSeconds);
    const expiresIn = Math.max(0, Math.floor((cached.expires_at.getTime() - Date.now()) / 1000));

    const body: TokenResponse = {
      access_token: cached.access_token,
      expires_in: expiresIn,
      token_type: "Bearer",
    };

    deps.writeAuditLog({
      ...auditBase,
      timestamp: new Date().toISOString(),
      result: "granted",
    });

    return jsonResponse(body);
  } catch (err) {
    const errorBody = errorBodyFromException(err);

    deps.writeAuditLog({
      ...auditBase,
      timestamp: new Date().toISOString(),
      result: "error",
      error: errorBody.error,
    });

    return jsonResponse(errorBody, 500);
  }
}

/** Result of a successful acquireProdAccess call. */
interface ProdAccessGrant {
  email: string;
  effectivePamPolicy?: string;
  /** Redacted, length-bounded summary of the wrapped command, if any. */
  commandSummary?: string;
  pamAuditFields: Pick<AuditEntry, "pam_grant" | "pam_cached">;
  /**
   * Computed PAM grant expiry, when a grant was acquired. Callers must clamp
   * any minted access token to this value so the metadata-proxy cache cannot
   * keep serving a token after its underlying authorization ends.
   */
  pamGrantExpiresAt?: Date;
  auditBase: Pick<
    AuditEntry,
    | "endpoint"
    | "level"
    | "pam_policy"
    | "token_ttl_seconds"
    | "socket"
    | "auto_approved"
    | "command"
  >;
}

/**
 * `expires_in` for a minted prod token, clamped to `grant_expiry - DRAIN_MARGIN_MS`
 * (not to `grant_expiry`). PAM allows only one active grant per
 * (entitlement, requester), so rotation has no overlap window; the drain
 * margin ensures every token minted under the old grant has expired before
 * the gate revokes it during rotation. Concurrent clients therefore see no
 * permission errors as the gate swaps grants.
 */
function expiresInClampedToGrant(token: CachedToken, grantExpiresAt: Date | undefined): number {
  const tokenExpiresMs = token.expires_at.getTime();
  const drainStartMs = grantExpiresAt
    ? grantExpiresAt.getTime() - DRAIN_MARGIN_MS
    : Number.POSITIVE_INFINITY;
  const effectiveMs = Math.min(drainStartMs, tokenExpiresMs);
  return Math.max(0, Math.floor((effectiveMs - Date.now()) / 1000));
}

/**
 * Shared flow for acquiring prod access: resolve PAM policy, check allowlist,
 * rate-limit, confirm (or auto-approve on the operator socket), and ensure
 * PAM grant.
 *
 * Returns a ProdAccessGrant on success or a Response on error.
 * On success the rate limiter has been acquired — the caller MUST call
 * deps.prodRateLimiter.release() in both its success and error paths.
 */
async function acquireProdAccess(
  req: Request,
  deps: GateDeps,
  ctx: RequestContext,
  opts: {
    pamPolicyParam?: string;
    auditEndpoint: string;
    ttlSeconds?: number;
  },
): Promise<ProdAccessGrant | Response> {
  // Resolve effective PAM policy: query param > config default > none
  let effectivePamPolicy: string | undefined;
  if (opts.pamPolicyParam && deps.resolvePamPolicy) {
    try {
      effectivePamPolicy = deps.resolvePamPolicy(opts.pamPolicyParam);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Invalid PAM policy";
      return jsonResponse({ error: message }, 400);
    }
  } else if (opts.pamPolicyParam) {
    effectivePamPolicy = opts.pamPolicyParam;
  } else {
    effectivePamPolicy = deps.pamDefaultPolicy;
  }

  const commandArr = parseCommandHeader(req.headers.get("X-Wrapped-Command"));
  const commandSummary = commandArr ? summarizeCommand(commandArr) : undefined;

  const auditBase: Pick<
    AuditEntry,
    "endpoint" | "level" | "pam_policy" | "token_ttl_seconds" | "socket" | "command"
  > = {
    endpoint: opts.auditEndpoint,
    level: "prod",
    pam_policy: effectivePamPolicy,
    token_ttl_seconds: opts.ttlSeconds,
    socket: ctx.socket,
    command: commandSummary,
  };

  // Allowlist check
  if (effectivePamPolicy && deps.pamAllowedPolicies) {
    if (!deps.pamAllowedPolicies.has(effectivePamPolicy)) {
      deps.writeAuditLog({
        ...auditBase,
        timestamp: new Date().toISOString(),
        result: "denied",
        error: "PAM policy not in allowlist",
      });
      return jsonResponse({ error: "PAM policy not in allowlist" }, 403);
    }
  }

  // Misconfiguration check
  if (effectivePamPolicy && !deps.ensurePamGrant) {
    return jsonResponse({ error: "PAM policy requested but PAM module not configured" }, 500);
  }

  // Out-of-allowlist requests on the operator socket were already rejected
  // by the pam_allowed_policies check above; we deliberately do NOT fall
  // through to a confirmation prompt for them.
  const autoApprove =
    ctx.trusted &&
    effectivePamPolicy !== undefined &&
    deps.autoApprovePamPolicies?.has(effectivePamPolicy) === true;

  // X-Pending-Id is meaningless on the auto-approve path: we never enqueue
  // a pending request, so a client supplying this header indicates client
  // confusion (or attempted protocol misuse).
  if (autoApprove && req.headers.get("X-Pending-Id")) {
    return jsonResponse(
      { error: "X-Pending-Id is not permitted on the operator socket auto-approve path" },
      400,
    );
  }

  // Rate-limit check before showing any confirmation dialog. Auto-approved
  // requests still consume a slot — the limiter is shared across sockets so
  // a flooding agent surfaces as a real rate-limit signal to the operator.
  const gate = deps.prodRateLimiter.acquire();
  if (!gate.allowed) {
    deps.writeAuditLog({
      ...auditBase,
      timestamp: new Date().toISOString(),
      result: "rate_limited",
      error: gate.reason,
    });
    return jsonResponse({ error: gate.reason }, 429);
  }

  try {
    const email = await deps.getIdentityEmail();

    const pendingId = req.headers.get("X-Pending-Id") ?? undefined;

    let approved: boolean;
    if (autoApprove) {
      approved = true;
    } else {
      approved = await deps.confirmProdAccess(email, commandSummary, effectivePamPolicy, pendingId);
    }
    if (!approved) {
      deps.prodRateLimiter.release("denied");
      deps.writeAuditLog({
        ...auditBase,
        timestamp: new Date().toISOString(),
        result: "denied",
        email,
      });
      return jsonResponse({ error: "Prod access denied by user" }, 403);
    }

    // Request PAM grant if a policy is configured
    let pamAuditFields: Pick<AuditEntry, "pam_grant" | "pam_cached"> = {};
    let pamGrantExpiresAt: Date | undefined;
    if (effectivePamPolicy && deps.ensurePamGrant) {
      const grantResult = await deps.ensurePamGrant(effectivePamPolicy, commandSummary);
      pamAuditFields = {
        pam_grant: grantResult.name,
        pam_cached: grantResult.cached,
      };
      pamGrantExpiresAt = grantResult.expiresAt;
    }

    const grantedAuditBase = autoApprove ? { ...auditBase, auto_approved: true } : auditBase;
    return {
      email,
      effectivePamPolicy,
      commandSummary,
      pamAuditFields,
      pamGrantExpiresAt,
      auditBase: grantedAuditBase,
    };
  } catch (err) {
    deps.prodRateLimiter.release("error");

    const errorBody = errorBodyFromException(err);

    deps.writeAuditLog({
      ...auditBase,
      timestamp: new Date().toISOString(),
      result: "error",
      error: errorBody.error,
    });

    return jsonResponse(errorBody, 500);
  }
}

async function handleProdToken(
  req: Request,
  deps: GateDeps,
  ctx: RequestContext,
  scopes?: string[],
  pamPolicyParam?: string,
  ttlSeconds?: number,
): Promise<Response> {
  const grant = await acquireProdAccess(req, deps, ctx, {
    pamPolicyParam,
    auditEndpoint: "/token?level=prod",
    ttlSeconds,
  });
  if (grant instanceof Response) return grant;

  try {
    const cached = await deps.mintProdToken(scopes, ttlSeconds);
    const expiresIn = expiresInClampedToGrant(cached, grant.pamGrantExpiresAt);

    deps.prodRateLimiter.release("granted");

    const body: TokenResponse = {
      access_token: cached.access_token,
      expires_in: expiresIn,
      token_type: "Bearer",
    };

    deps.writeAuditLog({
      ...grant.auditBase,
      ...grant.pamAuditFields,
      timestamp: new Date().toISOString(),
      result: "granted",
      email: grant.email,
    });

    return jsonResponse(body);
  } catch (err) {
    deps.prodRateLimiter.release("error");

    const errorBody = errorBodyFromException(err);

    deps.writeAuditLog({
      ...grant.auditBase,
      timestamp: new Date().toISOString(),
      result: "error",
      email: grant.email,
      error: errorBody.error,
    });

    return jsonResponse(errorBody, 500);
  }
}

/** Parse and validate the session_ttl_seconds query param. */
function parseSessionTtlParam(
  param: string | null,
  defaultTtl: number,
): { sessionTtlSeconds?: number } | { error: Response } {
  if (param === null) return {};

  const n = Number(param);
  if (!Number.isInteger(n) || n !== n) {
    return { error: jsonResponse({ error: "session_ttl_seconds must be an integer" }, 400) };
  }
  if (n < 300) {
    return { error: jsonResponse({ error: "session_ttl_seconds must be >= 300" }, 400) };
  }
  if (n > defaultTtl) {
    return {
      error: jsonResponse(
        { error: `session_ttl_seconds (${n}) exceeds configured maximum (${defaultTtl})` },
        400,
      ),
    };
  }
  return { sessionTtlSeconds: n };
}

/**
 * Create a new prod session with an initial token.
 *
 * Uses acquireProdAccess for the shared confirmation + PAM flow, then creates
 * a session that allows subsequent token refreshes without re-confirmation.
 *
 * Sessions are rejected on the operator socket: the 8-hour bearer-token
 * attack surface they introduce is exactly what auto-approve is designed
 * to avoid. Operators wanting `with-prod` should point it at the operator
 * socket; the client falls back to per-request token mode automatically.
 */
async function handleCreateSession(
  req: Request,
  url: URL,
  deps: GateDeps,
  ctx: RequestContext,
): Promise<Response> {
  if (ctx.trusted) {
    return jsonResponse(
      {
        error: "Session creation not permitted on operator socket",
        code: SESSION_NOT_PERMITTED_CODE,
      },
      403,
    );
  }

  const scopesParam = url.searchParams.get("scopes");
  const scopes = scopesParam ? scopesParam.split(",") : undefined;
  const pamPolicyParam = url.searchParams.get("pam_policy") ?? undefined;

  const ttlResult = parseTtlParam(
    url.searchParams.get("token_ttl_seconds"),
    deps.defaultTokenTtlSeconds,
  );
  if ("error" in ttlResult) return ttlResult.error;

  const sessionTtlResult = parseSessionTtlParam(
    url.searchParams.get("session_ttl_seconds"),
    deps.sessionTtlSeconds,
  );
  if ("error" in sessionTtlResult) return sessionTtlResult.error;

  const grant = await acquireProdAccess(req, deps, ctx, {
    pamPolicyParam,
    auditEndpoint: "/session",
    ttlSeconds: ttlResult.ttlSeconds,
  });
  if (grant instanceof Response) return grant;

  try {
    // Mint the initial token
    const cached = await deps.mintProdToken(scopes, ttlResult.ttlSeconds);
    const expiresIn = expiresInClampedToGrant(cached, grant.pamGrantExpiresAt);

    // Create the session
    const effectiveTokenTtl = ttlResult.ttlSeconds ?? deps.defaultTokenTtlSeconds;
    const effectiveSessionTtl = sessionTtlResult.sessionTtlSeconds ?? deps.sessionTtlSeconds;
    const session = deps.sessionManager.create({
      email: grant.email,
      scopes,
      pamPolicy: grant.effectivePamPolicy,
      commandSummary: grant.commandSummary,
      ttlSeconds: effectiveTokenTtl,
      sessionLifetimeSeconds: effectiveSessionTtl,
    });

    deps.prodRateLimiter.release("granted");

    const body: SessionResponse = {
      session_id: session.id,
      access_token: cached.access_token,
      expires_in: expiresIn,
      token_type: "Bearer",
      email: grant.email,
    };

    deps.writeAuditLog({
      ...grant.auditBase,
      ...grant.pamAuditFields,
      timestamp: new Date().toISOString(),
      result: "granted",
      email: grant.email,
      session_id: session.id,
    });

    return jsonResponse(body);
  } catch (err) {
    deps.prodRateLimiter.release("error");

    const errorBody = errorBodyFromException(err);

    deps.writeAuditLog({
      ...grant.auditBase,
      timestamp: new Date().toISOString(),
      result: "error",
      email: grant.email,
      error: errorBody.error,
    });

    return jsonResponse(errorBody, 500);
  }
}

/** Revoke a prod session by ID. */
function handleRevokeSession(url: URL, deps: GateDeps, ctx: RequestContext): Response {
  const sessionId = url.searchParams.get("id");
  if (!sessionId) {
    return jsonResponse({ error: "Missing session id" }, 400);
  }

  const revoked = deps.sessionManager.revoke(sessionId);
  if (!revoked) {
    return jsonResponse({ error: "Session not found" }, 404);
  }

  deps.writeAuditLog({
    endpoint: "/session",
    level: "prod",
    timestamp: new Date().toISOString(),
    result: "revoked",
    session_id: sessionId,
    socket: ctx.socket,
  });

  return jsonResponse({ status: "revoked" });
}

export function handleResolvePending(
  id: string,
  action: "approve" | "deny",
  deps: GateDeps,
): Response {
  if (!deps.pendingQueue) {
    return jsonResponse({ error: "Pending queue not enabled" }, 501);
  }

  const resolved =
    action === "approve" ? deps.pendingQueue.approve(id) : deps.pendingQueue.deny(id);

  if (!resolved) {
    return jsonResponse({ error: "Request not found or expired" }, 404);
  }

  deps.writeAuditLog({
    endpoint: `/pending/${id}/${action}`,
    level: "prod",
    timestamp: new Date().toISOString(),
    result: action === "approve" ? "granted" : "denied",
    socket: "admin",
  });

  return jsonResponse({ status: action === "approve" ? "approved" : "denied" });
}

async function handleProjectNumber(deps: GateDeps): Promise<Response> {
  try {
    const projectNumber = await deps.getProjectNumber();
    const body: ProjectNumberResponse = { project_number: projectNumber };
    return jsonResponse(body);
  } catch (err) {
    return jsonResponse(errorBodyFromException(err), 500);
  }
}

async function handleUniverseDomain(deps: GateDeps): Promise<Response> {
  try {
    const universeDomain = await deps.getUniverseDomain();
    const body: UniverseDomainResponse = { universe_domain: universeDomain };
    return jsonResponse(body);
  } catch (err) {
    return jsonResponse(errorBodyFromException(err), 500);
  }
}

async function handleIdentity(deps: GateDeps): Promise<Response> {
  try {
    const email = await deps.getIdentityEmail();
    return jsonResponse({ email });
  } catch (err) {
    return jsonResponse(errorBodyFromException(err), 500);
  }
}

function handleHealth(deps: GateDeps): Response {
  const uptimeMs = Date.now() - deps.startTime.getTime();
  return jsonResponse({
    status: "ok",
    uptime_seconds: Math.floor(uptimeMs / 1000),
  });
}
