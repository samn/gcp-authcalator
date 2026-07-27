import type { Config } from "../config.ts";
import type { BunRequestInit } from "../gate/connection.ts";
import type { PendingRequest } from "../gate/pending.ts";
import type { ErrorResponse } from "../gate/types.ts";

interface ResolveResponse {
  status: string;
}

interface ListResponse {
  pending: PendingRequest[];
}

/**
 * `PendingRequest` as it arrives over the wire: JSON has no Date type, so the
 * two timestamps come back as ISO strings.
 */
type WirePendingRequest = Omit<PendingRequest, "createdAt" | "expiresAt"> & {
  createdAt: string;
  expiresAt: string;
};

export interface ApproveFlags {
  deny?: boolean;
  /** Skip the interactive confirmation. Required for non-TTY approval. */
  yes?: boolean;
  /** Override process.stdin.isTTY for testing. */
  isTTY?: boolean;
  /** Override the confirmation reader for testing. `null` models the deadline firing. */
  readLine?: () => Promise<string | null>;
}

export async function runApprove(
  config: Config,
  positionals: string[],
  flags: ApproveFlags,
): Promise<void> {
  const baseUrl = "http://localhost";
  const extraOpts: BunRequestInit = { unix: config.admin_socket_path };

  const id = positionals[0];

  if (!id) {
    console.log("Usage: gcp-authcalator approve <id> [--yes]");
    console.log("       gcp-authcalator deny <id>");
    console.log("\nThe pending request ID is printed by with-prod when waiting for CLI approval.");
    console.log("Run 'gcp-authcalator pending' to list requests and see their full commands.");
    return;
  }

  const action = flags.deny ? "deny" : "approve";

  // Show what is being approved before approving it. Denying needs no such
  // care — the failure mode we're guarding against is a blind yes.
  if (action === "approve") {
    const request = await fetchPending(baseUrl, extraOpts, id);
    printRequest(request);

    if (!(await confirmApproval(flags, Date.parse(request.expiresAt)))) {
      console.error("Aborted.");
      process.exit(1);
    }
  }

  await resolvePending(baseUrl, extraOpts, id, action);
}

/** `gcp-authcalator pending [id]` — inspect the queue without resolving anything. */
export async function runPending(config: Config, positionals: string[]): Promise<void> {
  const baseUrl = "http://localhost";
  const extraOpts: BunRequestInit = { unix: config.admin_socket_path };

  const id = positionals[0];

  if (id) {
    printRequest(await fetchPending(baseUrl, extraOpts, id));
    return;
  }

  const res = await fetch(`${baseUrl}/pending`, extraOpts);
  if (!res.ok) {
    await failFromResponse(res);
  }

  const { pending } = (await res.json()) as ListResponse;
  const requests = pending as unknown as WirePendingRequest[];

  if (requests.length === 0) {
    console.log("No pending requests.");
    return;
  }

  for (const [index, request] of requests.entries()) {
    if (index > 0) console.log("");
    printRequest(request);
  }
}

async function fetchPending(
  baseUrl: string,
  extraOpts: BunRequestInit,
  id: string,
): Promise<WirePendingRequest> {
  const res = await fetch(`${baseUrl}/pending/${id}`, extraOpts);

  if (res.status === 404) {
    // Three different situations arrive as 404 and want different fixes, so
    // don't collapse them into "may have expired":
    //   - the route doesn't exist  → gate daemon predates this subcommand
    //   - no such queued request   → resolved elsewhere, or never queued at
    //                                all because a GUI/TTY prompt handled it
    const body = (await res.json().catch(() => ({}))) as Partial<ErrorResponse>;
    if (body.error === "Not found") {
      console.error(
        `error: this gate does not serve GET /pending/${id}.\n` +
          "       The running gate daemon predates this subcommand — restart it to pick up the new build.",
      );
    } else {
      console.error(
        `error: no queued request ${id}.\n` +
          "       It may have already been approved or denied, expired, or never been queued\n" +
          "       at all — the gate only queues a request when it has no desktop dialog or\n" +
          "       terminal prompt available. Check for an open approval dialog on the host.",
      );
    }
    process.exit(1);
  }

  if (!res.ok) {
    await failFromResponse(res);
  }

  return (await res.json()) as WirePendingRequest;
}

/**
 * Print a request with its command in full. The whole point of this command is
 * that the operator sees every argument, so nothing here abbreviates.
 */
function printRequest(request: WirePendingRequest): void {
  console.log(`Request:  ${request.id}`);
  console.log(`Email:    ${request.email}`);
  if (request.pamPolicy) {
    console.log(`PAM:      ${request.pamPolicy}`);
  }
  // An absolute ISO timestamp alone makes it easy to spend the whole window
  // reading the command, so lead with how long is actually left.
  const remainingMs = Date.parse(request.expiresAt) - Date.now();
  const remaining = Number.isFinite(remainingMs)
    ? ` (${Math.max(0, Math.floor(remainingMs / 1000))}s left)`
    : "";
  console.log(`Expires:  ${request.expiresAt}${remaining}`);

  if (!request.command) {
    console.log("Command:  (none reported)");
    return;
  }

  const plural = request.command.totalArgs === 1 ? "" : "s";
  console.log(`Command:  ${request.command.totalArgs} argument${plural}`);
  for (const line of request.command.lines) {
    console.log(line);
  }
}

async function confirmApproval(flags: ApproveFlags, expiresAtMs: number): Promise<boolean> {
  if (flags.yes) return true;

  const isTTY = flags.isTTY ?? !!process.stdin.isTTY;
  if (!isTTY) {
    console.error("error: refusing to approve without confirmation; re-run with --yes");
    process.exit(1);
  }

  // The request auto-denies on the gate's own schedule, and this command asks
  // the operator to read a command that may be hundreds of lines long. Bound
  // the read by the deadline that actually matters and say what it is, rather
  // than blocking forever and failing with a 404 after they finally answer.
  const remainingMs = Number.isFinite(expiresAtMs) ? expiresAtMs - Date.now() : Number.NaN;
  if (Number.isFinite(remainingMs) && remainingMs <= 0) {
    console.error("error: this request has already expired.");
    process.exit(1);
  }
  const budget = Number.isFinite(remainingMs) ? `within ${Math.floor(remainingMs / 1000)}s` : "now";

  process.stdout.write(`Approve this request? Type 'yes' ${budget} to approve: `);
  const answer = flags.readLine ? await flags.readLine() : await readLine(remainingMs);
  if (answer === null) {
    console.error("\nerror: request expired while waiting for confirmation.");
    process.exit(1);
  }
  return answer.trim().toLowerCase() === "yes";
}

/** Read one line from stdin, or resolve null if `timeoutMs` elapses first. */
function readLine(timeoutMs: number): Promise<string | null> {
  return new Promise<string | null>((resolve) => {
    process.stdin.setRawMode?.(false);
    process.stdin.resume();
    process.stdin.setEncoding("utf-8");

    const timer = Number.isFinite(timeoutMs)
      ? setTimeout(() => finish(null), Math.max(0, timeoutMs))
      : undefined;

    function finish(value: string | null): void {
      clearTimeout(timer);
      process.stdin.pause();
      process.stdin.removeListener("data", onData);
      resolve(value);
    }

    const onData = (data: string) => finish(data.toString());

    process.stdin.on("data", onData);
  });
}

async function failFromResponse(res: Response): Promise<never> {
  const body = (await res.json()) as ErrorResponse;
  console.error(`error: ${body.error}`);
  process.exit(1);
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
    await failFromResponse(res);
  }

  const body = (await res.json()) as ResolveResponse;
  const verb = body.status === "approved" ? "Approved" : "Denied";
  console.log(`${verb} request ${id}.`);
}
