import type { Config } from "../config.ts";
import type { ErrorResponse } from "../gate/types.ts";

/** Bun-specific extension of RequestInit with `unix` field. */
type BunRequestInit = RequestInit & { unix?: string };

interface ResolveResponse {
  status: string;
}

export async function runApprove(
  config: Config,
  positionals: string[],
  flags: { deny?: boolean },
): Promise<void> {
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
  await resolvePending(baseUrl, extraOpts, id, action);
}

async function resolvePending(
  baseUrl: string,
  extraOpts: BunRequestInit,
  id: string,
  action: "approve" | "deny",
): Promise<void> {
  const res = await fetch(`${baseUrl}/pending/${id}/${action}`, {
    ...extraOpts,
    method: "POST",
  });

  if (res.status === 404) {
    console.error(`error: request ${id} not found (may have expired)`);
    process.exit(1);
  }

  if (!res.ok) {
    const body = (await res.json()) as ErrorResponse;
    console.error(`error: ${body.error}`);
    process.exit(1);
  }

  const body = (await res.json()) as ResolveResponse;
  const verb = body.status === "approved" ? "Approved" : "Denied";
  console.log(`${verb} request ${id}.`);
}
