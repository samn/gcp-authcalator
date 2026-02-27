import type { TokenResponse } from "../gate/types.ts";
import type { MetadataProxyDeps } from "./types.ts";

const METADATA_FLAVOR_HEADER = "Metadata-Flavor";
const METADATA_FLAVOR_VALUE = "Google";

const METADATA_HEADERS = { [METADATA_FLAVOR_HEADER]: METADATA_FLAVOR_VALUE };

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
 * - Non-GET → 405
 * - Unknown path → 404
 */
export async function handleRequest(req: Request, deps: MetadataProxyDeps): Promise<Response> {
  const url = new URL(req.url, "http://localhost");

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

async function handleToken(deps: MetadataProxyDeps): Promise<Response> {
  try {
    const cached = await deps.getToken();
    const expiresIn = Math.floor((cached.expires_at.getTime() - Date.now()) / 1000);

    const body: TokenResponse = {
      access_token: cached.access_token,
      expires_in: expiresIn,
      token_type: "Bearer",
    };

    return jsonResponse(body);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return jsonResponse({ error: message }, 500);
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
    const message = err instanceof Error ? err.message : "Unknown error";
    return jsonResponse({ error: message }, 500);
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
    const message = err instanceof Error ? err.message : "Unknown error";
    return jsonResponse({ error: message }, 500);
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
