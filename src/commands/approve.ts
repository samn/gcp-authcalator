import type { Config } from "../config.ts";
import {
  buildGateConnection,
  connectionFetchOpts,
  type BunRequestInit,
} from "../gate/connection.ts";
import type { ErrorResponse } from "../gate/types.ts";

/** Wire-format of PendingRequest (dates serialized as ISO strings over JSON). */
interface PendingRequestJSON {
  id: string;
  email: string;
  command?: string;
  pamPolicy?: string;
  expiresAt: string;
}

interface PendingListResponse {
  pending: PendingRequestJSON[];
}

interface ResolveResponse {
  status: string;
}

export async function runApprove(
  config: Config,
  positionals: string[],
  flags: { deny?: boolean },
): Promise<void> {
  const conn = await buildGateConnection(config);
  const { baseUrl, extraOpts } = connectionFetchOpts(conn);

  const id = positionals[0];

  if (!id) {
    await listPending(baseUrl, extraOpts);
  } else {
    const action = flags.deny ? "deny" : "approve";
    await resolvePending(baseUrl, extraOpts, id, action);
  }
}

async function listPending(baseUrl: string, extraOpts: BunRequestInit): Promise<void> {
  const res = await fetch(`${baseUrl}/pending`, extraOpts);

  if (!res.ok) {
    const body = (await res.json()) as ErrorResponse;
    console.error(`error: ${body.error}`);
    process.exit(1);
  }

  const body = (await res.json()) as PendingListResponse;

  if (body.pending.length === 0) {
    console.log("No pending approval requests.");
    return;
  }

  console.log("Pending approval requests:\n");
  for (const req of body.pending) {
    const remainingSecs = Math.max(
      0,
      Math.floor((new Date(req.expiresAt).getTime() - Date.now()) / 1000),
    );
    const command = req.command ? `  ${req.command}` : "";
    const pam = req.pamPolicy ? `  [PAM: ${req.pamPolicy}]` : "";
    console.log(`  ${req.id}  ${req.email}${command}${pam}  (expires in ${remainingSecs}s)`);
  }
  console.log(
    "\nUse 'gcp-authcalator approve <id>' to approve or 'gcp-authcalator deny <id>' to deny.",
  );
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
