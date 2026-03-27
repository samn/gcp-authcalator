import type {
  GateDeps,
  TokenResponse,
  SessionResponse,
  ProjectNumberResponse,
  UniverseDomainResponse,
  AuditEntry,
} from "./types.ts";
import { parseCommandHeader, summarizeCommand } from "./summarize-command.ts";

const JSON_HEADERS = { "Content-Type": "application/json" };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

/**
 * Pure request handler — routes incoming requests and delegates to deps.
 * All responses are JSON. Audit entries are written for token requests.
 */
export async function handleRequest(req: Request, deps: GateDeps): Promise<Response> {
  const url = new URL(req.url, "http://localhost");

  // /session accepts POST (create) and DELETE (revoke)
  if (url.pathname === "/session") {
    if (req.method === "POST") return handleCreateSession(req, url, deps);
    if (req.method === "DELETE") return handleRevokeSession(url, deps);
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  if (req.method !== "GET") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  switch (url.pathname) {
    case "/token":
      return handleToken(req, url, deps);
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

async function handleToken(req: Request, url: URL, deps: GateDeps): Promise<Response> {
  // Session-based token refresh: bypass confirmation and rate limiting
  const sessionId = url.searchParams.get("session");
  if (sessionId) {
    return handleSessionTokenRefresh(sessionId, deps);
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
    return handleProdToken(req, deps, scopes, pamPolicyParam, ttlResult.ttlSeconds);
  }

  return handleDevToken(deps, scopes, ttlResult.ttlSeconds);
}

/** Mint a fresh prod token using a pre-approved session (no confirmation). */
async function handleSessionTokenRefresh(sessionId: string, deps: GateDeps): Promise<Response> {
  const session = deps.sessionManager.validate(sessionId);
  if (!session) {
    return jsonResponse({ error: "Session expired or invalid" }, 401);
  }

  const auditBase: Pick<AuditEntry, "endpoint" | "level" | "session_id" | "pam_policy"> = {
    endpoint: "/token?session=...",
    level: "prod",
    session_id: sessionId,
    pam_policy: session.pamPolicy,
  };

  try {
    const cached = await deps.mintProdToken(session.scopes, session.ttlSeconds);
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
      email: session.email,
    });

    return jsonResponse(body);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";

    deps.writeAuditLog({
      ...auditBase,
      timestamp: new Date().toISOString(),
      result: "error",
      email: session.email,
      error: message,
    });

    return jsonResponse({ error: message }, 500);
  }
}

async function handleDevToken(
  deps: GateDeps,
  scopes?: string[],
  ttlSeconds?: number,
): Promise<Response> {
  const auditBase: Pick<AuditEntry, "endpoint" | "level" | "token_ttl_seconds"> = {
    endpoint: "/token",
    level: "dev",
    token_ttl_seconds: ttlSeconds,
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
    const message = err instanceof Error ? err.message : "Unknown error";

    deps.writeAuditLog({
      ...auditBase,
      timestamp: new Date().toISOString(),
      result: "error",
      error: message,
    });

    return jsonResponse({ error: message }, 500);
  }
}

async function handleProdToken(
  req: Request,
  deps: GateDeps,
  scopes?: string[],
  pamPolicyParam?: string,
  ttlSeconds?: number,
): Promise<Response> {
  // Resolve effective PAM policy: query param > config default > none
  // Query params must be resolved to full entitlement paths (with validation)
  let effectivePamPolicy: string | undefined;
  if (pamPolicyParam && deps.resolvePamPolicy) {
    try {
      effectivePamPolicy = deps.resolvePamPolicy(pamPolicyParam);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Invalid PAM policy";
      return jsonResponse({ error: message }, 400);
    }
  } else if (pamPolicyParam) {
    // PAM policy requested but no resolver available (PAM not configured)
    effectivePamPolicy = pamPolicyParam;
  } else {
    effectivePamPolicy = deps.pamDefaultPolicy;
  }

  const auditBase: Pick<AuditEntry, "endpoint" | "level" | "pam_policy" | "token_ttl_seconds"> = {
    endpoint: "/token?level=prod",
    level: "prod",
    pam_policy: effectivePamPolicy,
    token_ttl_seconds: ttlSeconds,
  };

  // Allowlist check: if a PAM policy is specified, it must be in the allowlist
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

  // Misconfiguration check: PAM policy requested but module not wired
  if (effectivePamPolicy && !deps.ensurePamGrant) {
    return jsonResponse({ error: "PAM policy requested but PAM module not configured" }, 500);
  }

  // Rate-limit check before showing any confirmation dialog
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

    // Extract and summarize the command for the confirmation dialog
    const commandArr = parseCommandHeader(req.headers.get("X-Wrapped-Command"));
    const commandSummary = commandArr ? summarizeCommand(commandArr) : undefined;

    const approved = await deps.confirmProdAccess(email, commandSummary, effectivePamPolicy);
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
    if (effectivePamPolicy && deps.ensurePamGrant) {
      const grantResult = await deps.ensurePamGrant(effectivePamPolicy, commandSummary);
      pamAuditFields = {
        pam_grant: grantResult.name,
        pam_cached: grantResult.cached,
      };
    }

    const cached = await deps.mintProdToken(scopes, ttlSeconds);
    const expiresIn = Math.max(0, Math.floor((cached.expires_at.getTime() - Date.now()) / 1000));

    deps.prodRateLimiter.release("granted");

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
      email,
    });

    return jsonResponse(body);
  } catch (err) {
    deps.prodRateLimiter.release("error");

    const message = err instanceof Error ? err.message : "Unknown error";

    deps.writeAuditLog({
      ...auditBase,
      timestamp: new Date().toISOString(),
      result: "error",
      error: message,
    });

    return jsonResponse({ error: message }, 500);
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
 * Follows the same confirmation + PAM flow as handleProdToken, then creates
 * a session that allows subsequent token refreshes without re-confirmation.
 */
async function handleCreateSession(req: Request, url: URL, deps: GateDeps): Promise<Response> {
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

  // Resolve effective PAM policy (same logic as handleProdToken)
  let effectivePamPolicy: string | undefined;
  if (pamPolicyParam && deps.resolvePamPolicy) {
    try {
      effectivePamPolicy = deps.resolvePamPolicy(pamPolicyParam);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Invalid PAM policy";
      return jsonResponse({ error: message }, 400);
    }
  } else if (pamPolicyParam) {
    effectivePamPolicy = pamPolicyParam;
  } else {
    effectivePamPolicy = deps.pamDefaultPolicy;
  }

  const auditBase: Pick<AuditEntry, "endpoint" | "level" | "pam_policy" | "token_ttl_seconds"> = {
    endpoint: "/session",
    level: "prod",
    pam_policy: effectivePamPolicy,
    token_ttl_seconds: ttlResult.ttlSeconds,
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

  if (effectivePamPolicy && !deps.ensurePamGrant) {
    return jsonResponse({ error: "PAM policy requested but PAM module not configured" }, 500);
  }

  // Rate-limit check
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

    const commandArr = parseCommandHeader(req.headers.get("X-Wrapped-Command"));
    const commandSummary = commandArr ? summarizeCommand(commandArr) : undefined;

    const approved = await deps.confirmProdAccess(email, commandSummary, effectivePamPolicy);
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

    // PAM grant
    let pamAuditFields: Pick<AuditEntry, "pam_grant" | "pam_cached"> = {};
    if (effectivePamPolicy && deps.ensurePamGrant) {
      const grantResult = await deps.ensurePamGrant(effectivePamPolicy, commandSummary);
      pamAuditFields = {
        pam_grant: grantResult.name,
        pam_cached: grantResult.cached,
      };
    }

    // Mint the initial token
    const cached = await deps.mintProdToken(scopes, ttlResult.ttlSeconds);
    const expiresIn = Math.max(0, Math.floor((cached.expires_at.getTime() - Date.now()) / 1000));

    // Create the session
    const effectiveTokenTtl = ttlResult.ttlSeconds ?? deps.defaultTokenTtlSeconds;
    const effectiveSessionTtl = sessionTtlResult.sessionTtlSeconds ?? deps.sessionTtlSeconds;
    const session = deps.sessionManager.create({
      email,
      scopes,
      pamPolicy: effectivePamPolicy,
      ttlSeconds: effectiveTokenTtl,
      sessionLifetimeSeconds: effectiveSessionTtl,
    });

    deps.prodRateLimiter.release("granted");

    const body: SessionResponse = {
      session_id: session.id,
      access_token: cached.access_token,
      expires_in: expiresIn,
      token_type: "Bearer",
      email,
    };

    deps.writeAuditLog({
      ...auditBase,
      ...pamAuditFields,
      timestamp: new Date().toISOString(),
      result: "granted",
      email,
      session_id: session.id,
    });

    return jsonResponse(body);
  } catch (err) {
    deps.prodRateLimiter.release("error");

    const message = err instanceof Error ? err.message : "Unknown error";

    deps.writeAuditLog({
      ...auditBase,
      timestamp: new Date().toISOString(),
      result: "error",
      error: message,
    });

    return jsonResponse({ error: message }, 500);
  }
}

/** Revoke a prod session by ID. */
function handleRevokeSession(url: URL, deps: GateDeps): Response {
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
  });

  return jsonResponse({ status: "revoked" });
}

async function handleProjectNumber(deps: GateDeps): Promise<Response> {
  try {
    const projectNumber = await deps.getProjectNumber();
    const body: ProjectNumberResponse = { project_number: projectNumber };
    return jsonResponse(body);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return jsonResponse({ error: message }, 500);
  }
}

async function handleUniverseDomain(deps: GateDeps): Promise<Response> {
  try {
    const universeDomain = await deps.getUniverseDomain();
    const body: UniverseDomainResponse = { universe_domain: universeDomain };
    return jsonResponse(body);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return jsonResponse({ error: message }, 500);
  }
}

async function handleIdentity(deps: GateDeps): Promise<Response> {
  try {
    const email = await deps.getIdentityEmail();
    return jsonResponse({ email });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return jsonResponse({ error: message }, 500);
  }
}

function handleHealth(deps: GateDeps): Response {
  const uptimeMs = Date.now() - deps.startTime.getTime();
  return jsonResponse({
    status: "ok",
    uptime_seconds: Math.floor(uptimeMs / 1000),
  });
}
