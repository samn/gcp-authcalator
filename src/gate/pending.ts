// ---------------------------------------------------------------------------
// Pending approval queue for CLI-based confirmation fallback.
//
// When GUI dialogs and terminal prompts are unavailable, confirmation
// requests are parked here. A separate CLI command (`gcp-authcalator approve`)
// can list and resolve them via the gate's HTTP API.
// ---------------------------------------------------------------------------

import { randomBytes } from "node:crypto";

/** A confirmation request waiting for external approval. */
export interface PendingRequest {
  /** Short random hex ID (8 chars) for human-friendly CLI use. */
  id: string;
  /** Engineer's email requesting prod access. */
  email: string;
  /** Summarized command, if available. */
  command?: string;
  /** PAM policy, if applicable. */
  pamPolicy?: string;
  /** When this request was enqueued. */
  createdAt: Date;
  /** When this request auto-denies. */
  expiresAt: Date;
}

export interface PendingQueueOptions {
  /** Timeout in ms before auto-deny. Default: 120_000 (2 minutes). */
  timeoutMs?: number;
  /** Override Date.now for deterministic testing. */
  now?: () => number;
}

export interface PendingQueue {
  /** Enqueue a confirmation request. Returns a promise that resolves when approved, denied, or timed out. */
  enqueue(email: string, command?: string, pamPolicy?: string): Promise<boolean>;
  /** List all currently pending requests. */
  list(): PendingRequest[];
  /** Approve a pending request by ID. Returns false if not found or expired. */
  approve(id: string): boolean;
  /** Deny a pending request by ID. Returns false if not found or expired. */
  deny(id: string): boolean;
  /** Deny all pending requests (for shutdown). */
  denyAll(): void;
}

const DEFAULT_TIMEOUT_MS = 120_000;

interface QueueEntry {
  request: PendingRequest;
  resolve: (approved: boolean) => void;
  timer: ReturnType<typeof setTimeout>;
}

export function createPendingQueue(options: PendingQueueOptions = {}): PendingQueue {
  const now = options.now ?? Date.now;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const entries = new Map<string, QueueEntry>();

  function enqueue(email: string, command?: string, pamPolicy?: string): Promise<boolean> {
    const id = randomBytes(4).toString("hex");
    const createdAt = new Date(now());
    const expiresAt = new Date(now() + timeoutMs);

    const request: PendingRequest = { id, email, command, pamPolicy, createdAt, expiresAt };

    const promise = new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        entries.delete(id);
        resolve(false);
      }, timeoutMs);

      // Don't keep the process alive just for this timer
      if (typeof timer === "object" && "unref" in timer) {
        timer.unref();
      }

      entries.set(id, { request, resolve, timer });
    });

    const timeoutSecs = Math.ceil(timeoutMs / 1000);
    const detail = command ? ` (${command})` : "";
    const pam = pamPolicy ? ` [PAM: ${pamPolicy}]` : "";
    console.error(
      `gate: pending approval ${id} — ${email}${detail}${pam} — expires in ${timeoutSecs}s`,
    );
    console.error(
      `gate: run 'gcp-authcalator approve ${id}' to approve, or 'gcp-authcalator approve --deny ${id}' to deny`,
    );

    return promise;
  }

  function list(): PendingRequest[] {
    const result: PendingRequest[] = [];
    for (const [id, entry] of entries) {
      if (entry.request.expiresAt.getTime() <= now()) {
        entries.delete(id);
        continue;
      }
      result.push(entry.request);
    }
    return result;
  }

  function resolve(id: string, approved: boolean): boolean {
    const entry = entries.get(id);
    if (!entry) return false;
    if (entry.request.expiresAt.getTime() <= now()) {
      entries.delete(id);
      return false;
    }
    clearTimeout(entry.timer);
    entries.delete(id);
    entry.resolve(approved);
    return true;
  }

  function approve(id: string): boolean {
    return resolve(id, true);
  }

  function deny(id: string): boolean {
    return resolve(id, false);
  }

  function denyAll(): void {
    for (const [, entry] of entries) {
      clearTimeout(entry.timer);
      entry.resolve(false);
    }
    entries.clear();
  }

  return { enqueue, list, approve, deny, denyAll };
}
