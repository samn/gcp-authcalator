import type {
  GateDeps,
  TokenResponse,
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

async function handleToken(req: Request, url: URL, deps: GateDeps): Promise<Response> {
  const level = url.searchParams.get("level") === "prod" ? "prod" : "dev";

  if (level === "prod") {
    return handleProdToken(req, deps);
  }

  return handleDevToken(deps);
}

async function handleDevToken(deps: GateDeps): Promise<Response> {
  const auditBase: Pick<AuditEntry, "endpoint" | "level"> = {
    endpoint: "/token",
    level: "dev",
  };

  try {
    const cached = await deps.mintDevToken();
    const expiresIn = Math.floor((cached.expires_at.getTime() - Date.now()) / 1000);

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

async function handleProdToken(req: Request, deps: GateDeps): Promise<Response> {
  const auditBase: Pick<AuditEntry, "endpoint" | "level"> = {
    endpoint: "/token?level=prod",
    level: "prod",
  };

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

    const approved = await deps.confirmProdAccess(email, commandSummary);
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

    const cached = await deps.mintProdToken();
    const expiresIn = Math.floor((cached.expires_at.getTime() - Date.now()) / 1000);

    deps.prodRateLimiter.release("granted");

    const body: TokenResponse = {
      access_token: cached.access_token,
      expires_in: expiresIn,
      token_type: "Bearer",
    };

    deps.writeAuditLog({
      ...auditBase,
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
