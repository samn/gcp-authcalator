import type { GateDeps } from "./types.ts";
import { handleListPending, handleResolvePending, jsonResponse } from "./handlers.ts";

/**
 * Request handler for the admin socket.
 *
 * Only serves pending inspection, approve/deny, and health endpoints. This
 * handler is bound to a separate Unix socket that is NOT mounted into the
 * devcontainer, preventing container processes from self-approving pending
 * requests or reading back the command the operator is being shown.
 */
export async function handleAdminRequest(req: Request, deps: GateDeps): Promise<Response> {
  const url = new URL(req.url, "http://localhost");

  if (url.pathname === "/health" && req.method === "GET") {
    const uptimeMs = Date.now() - deps.startTime.getTime();
    return jsonResponse({ status: "ok", uptime_seconds: Math.floor(uptimeMs / 1000) });
  }

  if (url.pathname === "/pending" && req.method === "GET") {
    return handleListPending(deps);
  }

  const showMatch = url.pathname.match(/^\/pending\/([a-f0-9]{32})$/);
  if (showMatch && req.method === "GET") {
    return handleListPending(deps, showMatch[1]!);
  }

  const pendingMatch = url.pathname.match(/^\/pending\/([a-f0-9]{32})\/(approve|deny)$/);
  if (pendingMatch && req.method === "POST") {
    return handleResolvePending(pendingMatch[1]!, pendingMatch[2] as "approve" | "deny", deps);
  }

  return jsonResponse({ error: "Not found" }, 404);
}
