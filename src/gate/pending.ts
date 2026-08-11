// ---------------------------------------------------------------------------
// Pending approval queue for CLI-based confirmation fallback.
//
// When GUI dialogs and terminal prompts are unavailable, confirmation
// requests are parked here. A separate CLI command (`gcp-authcalator approve`)
// can list and resolve them via the gate's HTTP API.
// ---------------------------------------------------------------------------

import { randomBytes } from "node:crypto";
import type { CommandDisplay } from "./summarize-command.ts";

/** Validates a client-provided pending ID: must be exactly 32 lowercase hex chars. */
const PENDING_ID_RE = /^[a-f0-9]{32}$/;

/** Return whether a pending-request ID has the canonical 128-bit hex form. */
export function isValidPendingId(id: string): boolean {
  return PENDING_ID_RE.test(id);
}

/** A confirmation request waiting for external approval. */
export interface PendingRequest {
  /** Random hex ID (32 chars / 128 bits). */
  id: string;
  /** Engineer's email requesting prod access. */
  email: string;
  /**
   * The reported command in full, if available. Held whole — not just the
   * one-line summary — so `gcp-authcalator pending` can show the operator
   * everything they are being asked to approve.
   */
  command?: CommandDisplay;
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
  /** Enqueue a confirmation request. Returns a promise that resolves when approved, denied, or timed out.
   *  If clientId is provided, it must be exactly 32 lowercase hex chars and not already in use. */
  enqueue(
    email: string,
    command?: CommandDisplay,
    pamPolicy?: string,
    clientId?: string,
  ): Promise<boolean>;
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

  function enqueue(
    email: string,
    command?: CommandDisplay,
    pamPolicy?: string,
    clientId?: string,
  ): Promise<boolean> {
    if (clientId !== undefined) {
      if (!isValidPendingId(clientId)) {
        throw new Error(`Invalid pending ID format: must be 32 lowercase hex chars`);
      }
      if (entries.has(clientId)) {
        throw new Error(`Pending ID already in use: ${clientId}`);
      }
    }
    const id = clientId ?? randomBytes(16).toString("hex");
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
    // Only the summary goes to stderr — the full command would flood the log.
    // `gcp-authcalator pending` is where the operator reads the whole thing.
    const detail = command ? ` (${command.summary})` : "";
    const pam = pamPolicy ? ` [PAM: ${pamPolicy}]` : "";
    console.error(
      `gate: pending approval ${id} — ${email}${detail}${pam} — expires in ${timeoutSecs}s`,
    );
    console.error(
      `gate: run 'gcp-authcalator pending ${id}' to see the full command, ` +
        `'gcp-authcalator approve ${id}' to approve, or 'gcp-authcalator deny ${id}' to deny`,
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
