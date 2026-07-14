import { createHash, timingSafeEqual } from "node:crypto";
import type {
  MetadataProxyDeps,
  MetadataTokenResponse,
  OAuthErrorResponse,
  OAuthRefreshResponse,
} from "./types.ts";

const METADATA_FLAVOR_HEADER = "Metadata-Flavor";
const METADATA_FLAVOR_VALUE = "Google";

const METADATA_HEADERS = { [METADATA_FLAVOR_HEADER]: METADATA_FLAVOR_VALUE };

/**
 * Maximum accepted POST /token body size. A legitimate refresh-grant body is
 * ~150 bytes; the cap keeps the one endpoint reachable without the
 * Metadata-Flavor header from being used to force large body buffering.
 */
const MAX_OAUTH_BODY_BYTES = 8192;

function textResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain", ...METADATA_HEADERS },
  });
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...METADATA_HEADERS },
  });
}

/**
 * Pure request handler for the GCE metadata server emulator.
 *
 * - `/` — detection ping (always 200, no header check)
 * - `/computeMetadata/v1/...` — requires `Metadata-Flavor: Google` header
 * - `POST /token` — OAuth2 refresh-token grant against the stubbed refresh token
 * - Other non-GET → 405
 * - Unknown path → 404
 */
export async function handleRequest(req: Request, deps: MetadataProxyDeps): Promise<Response> {
  const url = new URL(req.url, "http://localhost");

  // OAuth2 token-endpoint emulation (mirrors https://oauth2.googleapis.com/token).
  // Exact-path like the real endpoint — every OAuth client uses a fixed token
  // URI, and a wider match would only grow the unauthenticated surface.
  // No Metadata-Flavor check: real OAuth clients don't send the header, and the
  // stubbed refresh token — issued only through the header-gated (and, under
  // with-prod, PID-validated) metadata token endpoint — is the credential here.
  if (req.method === "POST" && url.pathname === "/token") {
    return handleOAuthRefresh(req, deps);
  }

  if (req.method !== "GET") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  // Root detection endpoint — no header check required
  if (url.pathname === "/") {
    return new Response("ok", {
      status: 200,
      headers: { ...METADATA_HEADERS },
    });
  }

  // All /computeMetadata/* paths require the Metadata-Flavor header
  if (url.pathname.startsWith("/computeMetadata/")) {
    if (req.headers.get(METADATA_FLAVOR_HEADER) !== METADATA_FLAVOR_VALUE) {
      return textResponse("Missing Metadata-Flavor:Google header.", 403);
    }

    // Normalize trailing slashes for path matching
    let pathname = url.pathname.replace(/\/+$/, "") || "/";

    // Alias any email-based service account path to "default".
    //
    // This proxy serves a single set of credentials, so all service-account
    // paths are equivalent.  gcloud (and Python google-auth) resolve accounts
    // by email, not by the "default" alias.  The email they use may come from
    // the proxy's own listing, a cached value from a prior metadata-server
    // interaction, or internal library state.  Rather than requiring an exact
    // match, we rewrite any non-"default" identifier to "default" so the
    // request always reaches the right handler.
    const saBase = "/computeMetadata/v1/instance/service-accounts/";
    if (pathname.startsWith(saBase)) {
      const rest = pathname.slice(saBase.length);
      if (rest && !rest.startsWith("default")) {
        const slashIdx = rest.indexOf("/");
        pathname = slashIdx >= 0 ? saBase + "default" + rest.slice(slashIdx) : saBase + "default";
      }
    }

    switch (pathname) {
      case "/computeMetadata/v1/instance":
        return textResponse("service-accounts/\n");
      case "/computeMetadata/v1/instance/service-accounts/default/token":
        return handleToken(deps);
      case "/computeMetadata/v1/project/project-id":
        return handleProjectId(deps);
      case "/computeMetadata/v1/project/numeric-project-id":
        return handleNumericProjectId(deps);
      case "/computeMetadata/v1/universe/universe_domain":
      case "/computeMetadata/v1/universe/universe-domain":
        return handleUniverseDomain(deps);
      case "/computeMetadata/v1/instance/service-accounts/default/email":
        return handleEmail(deps);
      case "/computeMetadata/v1/instance/service-accounts/default/scopes":
        return handleScopes(deps);
      case "/computeMetadata/v1/instance/service-accounts/default/identity":
        return handleIdentity(url);
      case "/computeMetadata/v1/instance/service-accounts/default":
        return handleServiceAccountInfo(url, deps);
      case "/computeMetadata/v1/instance/service-accounts":
        return handleServiceAccounts(url, deps);
      default:
        console.debug(`Unknown path: ${pathname}`);
        return textResponse("Not found", 404);
    }
  }

  return textResponse("Not found", 404);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Unknown error";
}

/**
 * Fetch the current access token from the provider and compute its remaining
 * lifetime. Shared by the GCE token endpoint and the OAuth refresh grant so
 * the expiry math on the two token-serving paths cannot drift.
 */
async function currentToken(
  deps: MetadataProxyDeps,
): Promise<{ access_token: string; expires_in: number }> {
  const cached = await deps.getToken();
  return {
    access_token: cached.access_token,
    expires_in: Math.max(0, Math.floor((cached.expires_at.getTime() - Date.now()) / 1000)),
  };
}

async function handleToken(deps: MetadataProxyDeps): Promise<Response> {
  try {
    const { access_token, expires_in } = await currentToken(deps);

    const body: MetadataTokenResponse = {
      access_token,
      expires_in,
      token_type: "Bearer",
      refresh_token: deps.refreshToken,
    };

    return jsonResponse(body);
  } catch (err) {
    return jsonResponse({ error: errorMessage(err) }, 500);
  }
}

/**
 * OAuth token-endpoint responses must not be cached (RFC 6749 §5.1/§5.2:
 * Cache-Control: no-store) and, unlike the metadata endpoints, carry no
 * Metadata-Flavor header — the emulated oauth2.googleapis.com doesn't either.
 */
function oauthJsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      Pragma: "no-cache",
    },
  });
}

function oauthError(
  error: OAuthErrorResponse["error"],
  description: string,
  status = 400,
): Response {
  const body: OAuthErrorResponse = { error, error_description: description };
  return oauthJsonResponse(body, status);
}

/**
 * Constant-time string comparison. Hashing both sides first avoids
 * timingSafeEqual's equal-length requirement without leaking length.
 */
function safeEqual(a: string, b: string): boolean {
  const hashA = createHash("sha256").update(a).digest();
  const hashB = createHash("sha256").update(b).digest();
  return timingSafeEqual(hashA, hashB);
}

/**
 * Handles POST /token — the OAuth2 refresh-token grant, emulating
 * https://oauth2.googleapis.com/token.
 *
 * Accepts only `grant_type=refresh_token` with this proxy instance's stubbed
 * refresh token, and exchanges it for the current short-lived access token
 * from the token provider (which refreshes via the gate as needed, so all
 * gate-side bounds — session expiry, token TTL, confirmation policy — still
 * apply). Errors follow RFC 6749 §5.2. Like Google's endpoint, the response
 * carries no refresh_token.
 */
async function handleOAuthRefresh(req: Request, deps: MetadataProxyDeps): Promise<Response> {
  const contentType = (req.headers.get("Content-Type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (contentType !== "application/x-www-form-urlencoded") {
    return oauthError("invalid_request", "request body must be application/x-www-form-urlencoded");
  }

  // Cap the body before reading it. This endpoint is reachable without the
  // Metadata-Flavor header, so an unbounded read would let any local process
  // force the proxy to buffer arbitrarily large bodies (chunked uploads are
  // not limited by Bun's maxRequestBodySize). A legitimate refresh request is
  // ~150 bytes; requiring a small declared Content-Length also rejects
  // chunked bodies, which no real OAuth client sends.
  const contentLengthHeader = req.headers.get("Content-Length");
  const contentLength = contentLengthHeader === null ? NaN : Number(contentLengthHeader);
  if (
    !Number.isInteger(contentLength) ||
    contentLength < 0 ||
    contentLength > MAX_OAUTH_BODY_BYTES
  ) {
    return oauthError(
      "invalid_request",
      `request must declare Content-Length of at most ${MAX_OAUTH_BODY_BYTES} bytes`,
    );
  }

  let form: URLSearchParams;
  try {
    form = new URLSearchParams(await req.text());
  } catch {
    return oauthError("invalid_request", "could not read request body");
  }

  const grantType = form.get("grant_type");
  if (!grantType) {
    return oauthError("invalid_request", "grant_type parameter is required");
  }
  if (grantType !== "refresh_token") {
    return oauthError("unsupported_grant_type", "only grant_type refresh_token is supported");
  }

  const refreshToken = form.get("refresh_token");
  if (!refreshToken) {
    return oauthError("invalid_request", "refresh_token parameter is required");
  }
  if (!safeEqual(refreshToken, deps.refreshToken)) {
    return oauthError("invalid_grant", "refresh token was not issued by this metadata proxy");
  }

  try {
    const { access_token, expires_in } = await currentToken(deps);

    const body: OAuthRefreshResponse = {
      access_token,
      expires_in,
      scope: deps.scopes.join(" "),
      token_type: "Bearer",
    };

    return oauthJsonResponse(body);
  } catch (err) {
    // The error member of an OAuth token response is a registered code
    // (RFC 6749 §5.2), not prose — put the provider failure in the description.
    return oauthError("temporarily_unavailable", errorMessage(err), 503);
  }
}

function handleProjectId(deps: MetadataProxyDeps): Response {
  return textResponse(deps.projectId);
}

async function handleNumericProjectId(deps: MetadataProxyDeps): Promise<Response> {
  if (!deps.getNumericProjectId) {
    return textResponse("Not found", 404);
  }

  try {
    const numericId = await deps.getNumericProjectId();
    return textResponse(numericId);
  } catch (err) {
    return jsonResponse({ error: errorMessage(err) }, 500);
  }
}

async function handleUniverseDomain(deps: MetadataProxyDeps): Promise<Response> {
  if (!deps.getUniverseDomain) {
    return textResponse("Not found", 404);
  }

  try {
    const domain = await deps.getUniverseDomain();
    return textResponse(domain);
  } catch (err) {
    return jsonResponse({ error: errorMessage(err) }, 500);
  }
}

function handleEmail(deps: MetadataProxyDeps): Response {
  if (!deps.serviceAccountEmail) {
    return textResponse("Not found", 404);
  }
  return textResponse(deps.serviceAccountEmail);
}

/**
 * Handles GET /computeMetadata/v1/instance/service-accounts/default/scopes
 *
 * Returns the OAuth scopes granted to the service account as a
 * newline-delimited list (mirrors real GCE metadata behavior).
 */
function handleScopes(deps: MetadataProxyDeps): Response {
  return textResponse(deps.scopes.join("\n") + "\n");
}

/**
 * Handles GET /computeMetadata/v1/instance/service-accounts/default/identity
 *
 * On a real GCE VM this returns an OIDC identity token for the given
 * `audience` query parameter.  The metadata-proxy cannot mint identity
 * tokens — it only supports access-token impersonation — so we return
 * an appropriate error.
 *
 * - Missing `audience` → 400 (matches real GCE metadata behavior)
 * - With `audience`   → 404 (identity tokens are not available)
 */
function handleIdentity(url: URL): Response {
  const audience = url.searchParams.get("audience");
  if (!audience) {
    return textResponse("non-empty audience parameter required", 400);
  }
  return textResponse("identity tokens are not supported by the metadata proxy", 404);
}

/**
 * Handles GET /computeMetadata/v1/instance/service-accounts/
 *
 * With `?recursive=true`, returns a JSON object keyed by service account name
 * containing email, aliases, and scopes (mirrors real GCE metadata behavior).
 *
 * Without `recursive=true`, returns a text directory listing of available
 * service accounts.
 *
 * On a real GCE VM the listing includes both `default/` and the email-keyed
 * entry.  gcloud's `Metadata().Accounts()` filters out `default` and only
 * recognises real email addresses, so we must include the email here for
 * gcloud to discover the account as a GCE credential.
 */
function handleServiceAccounts(url: URL, deps: MetadataProxyDeps): Response {
  const recursive = url.searchParams.get("recursive") === "true";
  const email = deps.serviceAccountEmail;

  const saInfo = {
    aliases: ["default"],
    email: email ?? "default",
    scopes: deps.scopes,
  };

  if (recursive) {
    const body: Record<string, typeof saInfo> = { default: saInfo };
    if (email) {
      body[email] = saInfo;
    }
    return jsonResponse(body);
  }

  let listing = "default/\n";
  if (email) {
    listing += `${email}/\n`;
  }
  return textResponse(listing);
}

/**
 * Handles GET /computeMetadata/v1/instance/service-accounts/default/
 *
 * With `?recursive=true`, returns a JSON object with the service account's
 * email, aliases, and scopes (mirrors real GCE metadata behavior).
 * Sensitive entries like `token` and `identity` are excluded.
 *
 * Without `recursive=true`, returns a text directory listing of available
 * sub-endpoints.
 */
function handleServiceAccountInfo(url: URL, deps: MetadataProxyDeps): Response {
  const recursive = url.searchParams.get("recursive") === "true";

  if (recursive) {
    return jsonResponse({
      aliases: ["default"],
      email: deps.serviceAccountEmail ?? "default",
      scopes: deps.scopes,
    });
  }

  // Non-recursive: return a text directory listing (like the real metadata server)
  return textResponse("aliases\nemail\nidentity\nscopes\ntoken\n");
}
