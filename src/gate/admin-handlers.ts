import type { GateDeps } from "./types.ts";
import { handleResolvePending } from "./handlers.ts";

const JSON_HEADERS = { "Content-Type": "application/json" };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

/**
 * Request handler for the admin socket.
 *
 * Only serves approve/deny and health endpoints. This handler is bound to a
 * separate Unix socket that is NOT mounted into the devcontainer, preventing
 * container processes from self-approving pending requests.
 */
export async function handleAdminRequest(req: Request, deps: GateDeps): Promise<Response> {
  const url = new URL(req.url, "http://localhost");

  if (url.pathname === "/health" && req.method === "GET") {
    const uptimeMs = Date.now() - deps.startTime.getTime();
    return jsonResponse({ status: "ok", uptime_seconds: Math.floor(uptimeMs / 1000) });
  }

  const pendingMatch = url.pathname.match(/^\/pending\/([a-f0-9]+)\/(approve|deny)$/);
  if (pendingMatch && req.method === "POST") {
    return handleResolvePending(pendingMatch[1]!, pendingMatch[2] as "approve" | "deny", deps);
  }

  return jsonResponse({ error: "Not found" }, 404);
}
