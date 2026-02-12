import type { MetadataProxyDeps } from "./types.ts";
import type { TokenResponse } from "../gate/types.ts";

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

    switch (url.pathname) {
      case "/computeMetadata/v1/instance/service-accounts/default/token":
        return handleToken(deps);
      case "/computeMetadata/v1/project/project-id":
        return handleProjectId(deps);
      case "/computeMetadata/v1/instance/service-accounts/default/email":
        return handleEmail(deps);
      default:
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

function handleEmail(deps: MetadataProxyDeps): Response {
  if (!deps.serviceAccountEmail) {
    return textResponse("Not found", 404);
  }
  return textResponse(deps.serviceAccountEmail);
}
