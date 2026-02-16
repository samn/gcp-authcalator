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
    const pathname = url.pathname.replace(/\/+$/, "") || "/";

    switch (pathname) {
      case "/computeMetadata/v1/instance/service-accounts/default/token":
        return handleToken(deps);
      case "/computeMetadata/v1/project/project-id":
        return handleProjectId(deps);
      case "/computeMetadata/v1/project/numeric-project-id":
        return handleNumericProjectId(deps);
      case "/computeMetadata/v1/universe/universe-domain":
        return handleUniverseDomain(deps);
      case "/computeMetadata/v1/instance/service-accounts/default/email":
        return handleEmail(deps);
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
 * Handles GET /computeMetadata/v1/instance/service-accounts/
 *
 * With `?recursive=true`, returns a JSON object keyed by service account name
 * containing email, aliases, and scopes (mirrors real GCE metadata behavior).
 *
 * Without `recursive=true`, returns a text directory listing of available
 * service accounts. Since we proxy to a single service account via the
 * gateway, this always returns just "default".
 */
function handleServiceAccounts(url: URL, deps: MetadataProxyDeps): Response {
  const recursive = url.searchParams.get("recursive") === "true";

  if (recursive) {
    return jsonResponse({
      default: {
        aliases: ["default"],
        email: deps.serviceAccountEmail ?? "default",
        scopes: ["https://www.googleapis.com/auth/cloud-platform"],
      },
    });
  }

  return textResponse("default/\n");
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
      scopes: ["https://www.googleapis.com/auth/cloud-platform"],
    });
  }

  // Non-recursive: return a text directory listing (like the real metadata server)
  return textResponse("aliases\nemail\nscopes\ntoken\n");
}
