import type { Config } from "../config.ts";
import { type BunRequestInit, GateTimeoutError, fetchWithGateTimeout } from "../gate/connection.ts";
import type { ErrorResponse } from "../gate/types.ts";

interface ResolveResponse {
  status: string;
}

/**
 * Backstop timeout for the approve/deny CLI's fetch to the admin socket.
 *
 * The pending request itself auto-denies at 120 s, so a wedged admin socket
 * leaves the user's prod command failed AND the approval CLI stuck —
 * confusing in an already-stressful flow. A short cap converts a hung socket
 * into a clear "admin socket not responding" error. Matches the kube-token
 * neighbourhood (5 s); the admin socket is local IPC, so legitimate latency
 * is sub-second.
 */
const ADMIN_FETCH_TIMEOUT_MS = 5_000;

export interface RunApproveOptions {
  deny?: boolean;
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
}

export async function runApprove(
  config: Config,
  positionals: string[],
  flags: RunApproveOptions = {},
): Promise<void> {
  const fetchFn = flags.fetchFn ?? globalThis.fetch;
  const adminSocketPath = config.admin_socket_path;
  const baseUrl = "http://localhost";
  const extraOpts: BunRequestInit = { unix: adminSocketPath };

  const id = positionals[0];

  if (!id) {
    console.log("Usage: gcp-authcalator approve <id>");
    console.log("       gcp-authcalator deny <id>");
    console.log("\nThe pending request ID is printed by with-prod when waiting for CLI approval.");
    return;
  }

  const action = flags.deny ? "deny" : "approve";
  await resolvePending(fetchFn, baseUrl, extraOpts, id, action);
}

async function resolvePending(
  fetchFn: typeof globalThis.fetch,
  baseUrl: string,
  extraOpts: BunRequestInit,
  id: string,
  action: "approve" | "deny",
): Promise<void> {
  let res: Response;
  try {
    res = await fetchWithGateTimeout(
      fetchFn,
      `${baseUrl}/pending/${id}/${action}`,
      { ...extraOpts, method: "POST" },
      ADMIN_FETCH_TIMEOUT_MS,
    );
  } catch (err) {
    if (err instanceof GateTimeoutError) {
      console.error(
        `error: admin socket not responding (timed out after ${ADMIN_FETCH_TIMEOUT_MS / 1000}s)`,
      );
      process.exit(1);
    }
    // Any other fetch failure means the socket couldn't be reached at all — the
    // gate isn't running, or admin_socket_path is wrong. Bun surfaces this as
    // e.g. Error{code:"FailedToOpenSocket", message:"Was there a typo in the
    // url or port?"}; without this branch the user would see that cryptic
    // message instead of the actionable guidance this command exists to give.
    const detail = err instanceof Error ? err.message : String(err);
    console.error(
      `error: could not connect to the admin socket${extraOpts.unix ? ` at ${extraOpts.unix}` : ""} (${detail})\n` +
        `  Is gcp-authcalator running, and does admin_socket_path match the gate's?`,
    );
    process.exit(1);
  }

  if (res.status === 404) {
    console.error(`error: request ${id} not found (may have expired)`);
    process.exit(1);
  }

  if (!res.ok) {
    // The body may not be JSON (e.g. a plain-text 500 from the runtime) —
    // fall back to the HTTP status rather than crashing on the parse.
    const body = (await res.json().catch(() => null)) as ErrorResponse | null;
    console.error(`error: ${body?.error ?? `admin socket returned HTTP ${res.status}`}`);
    process.exit(1);
  }

  // On a 2xx with an unparseable body, trust the action we just performed.
  const body = (await res.json().catch(() => null)) as ResolveResponse | null;
  const status = body?.status ?? (action === "approve" ? "approved" : "denied");
  const verb = status === "approved" ? "Approved" : "Denied";
  console.log(`${verb} request ${id}.`);
}
