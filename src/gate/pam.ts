import { randomUUID } from "node:crypto";

import { CredentialsExpiredError } from "./credentials-error.ts";

// ---------------------------------------------------------------------------
// GCP Privileged Access Manager (PAM) module
//
// Requests just-in-time PAM grants to temporarily elevate the engineer's
// IAM roles. Grants are cached, withdrawn when stale or expired, and every
// grant known to be owned by this module is best-effort withdrawn on shutdown.
//
// API quirks and how we handle them (see plans/pam-rotation-drain-margin.md
// and plans/pam-withdraw-own-grants.md for the full audit):
//
//   - The gate ends grants with `grants.withdraw`, not `grants.revoke`.
//     Revoke requires `privilegedaccessmanager.grants.revoke` — an
//     approver/admin permission a plain requester doesn't have — while
//     withdraw is the requester's own operation and works on any
//     non-terminal grant (pending, scheduled, and active). The gate only
//     ever ends grants it requested itself, so withdraw is always the
//     right verb. `grants.withdraw` exists only on the v1beta surface
//     (verified 2026-06-11 against the discovery doc); everything else
//     uses v1.
//   - `grants.withdraw` returns a long-running `Operation`.
//     `withdrawGrantAndWait` polls the Operation to `done:true` before its
//     caller retries create — without this, the follow-up createGrant races
//     the withdraw and 409s because PAM still considers the old grant open.
//   - `grants.list` documents a `filter` query parameter but no syntax.
//     Most filter expressions return 400 "invalid list filter"; the two
//     that PAM does accept (`state="ACTIVE"` quoted, and `state:ACTIVE`)
//     silently return 0 grants even when an ACTIVE grant exists. The
//     `grants.search` endpoint exhibits the same broken-filter behavior
//     (verified 2026-05-13 against a real entitlement). So we list
//     unfiltered and bucket client-side. `orderBy=createTime desc` is also
//     rejected as "unsupported sort order".
//   - A Grant has no `expireTime` field — only `createTime` and
//     `requestedDuration`. `computeGrantExpiry` derives expiry from those.
//   - The `state` field can briefly lag actual expiry. The "open Grant" 409
//     / 400 FAILED_PRECONDITION path lands inside that window, so the scan
//     re-checks `createTime + requestedDuration` rather than trusting state.
//   - `grants.list` returns every requester's grants, but PAM's open-grant
//     rule is per `(entitlement, requester)`. On shared entitlements the
//     scan must only consider the gate's own grants — reusing a teammate's
//     grant would carry the wrong identity, and withdrawing one is neither
//     permitted nor wanted. `scanForOpenGrants` filters on
//     `Grant.requester` against the gate's authenticated identity.
//   - "Open Grant" conflicts ship as both 409 Conflict and 400
//     FAILED_PRECONDITION. `isOpenGrantPrecondition` narrowly matches the 400
//     case so unrelated FAILED_PRECONDITION causes surface their original
//     error.
//   - State spelling varies: v1 uses `ACTIVE`, older responses use
//     `ACTIVATED`. `ACTIVE_GRANT_STATES` accepts both.
//   - Terminal states (DENIED, REVOKED, ENDED, EXPIRED, ACTIVATION_FAILED,
//     EXTERNALLY_MODIFIED, WITHDRAWN) bypass polling and surface directly.
//
// Concurrent-client safety (drain margin + single-flight):
//
//   PAM allows only one active grant per `(entitlement, requester)` (the
//   "open Grant" rule), so rotation has no overlap window. To keep
//   concurrent clients from seeing 403s when the gate withdraws-and-recreates,
//   minted prod tokens are clamped to `grant_expiry - DRAIN_MARGIN_MS` in
//   `handlers.ts:expiresInClampedToGrant`. By the time the gate withdraws the
//   old grant, no token minted under it is still valid, so no in-flight call
//   is using the about-to-be-withdrawn authorization. `ensureGrant` is
//   additionally single-flight per entitlement (the gate is single-instance
//   per machine via the socket bind check) so concurrent token requests
//   coalesce onto one rotation rather than racing.
// ---------------------------------------------------------------------------

const PAM_HOST = "https://privilegedaccessmanager.googleapis.com";

const PAM_API_BASE = `${PAM_HOST}/v1`;

/**
 * `grants.withdraw` (and polling of the Operation it returns) lives on the
 * v1beta surface only — v1 ships revoke but not withdraw. Everything else
 * stays on v1.
 */
const PAM_API_BASE_V1BETA = `${PAM_HOST}/v1beta`;

/** Fallback grant duration when not configured (1 hour). */
const FALLBACK_GRANT_DURATION_SECONDS = 3600;

/**
 * Drain margin: the buffer between the start of the rotation window and the
 * grant's actual expiry. Plays two roles:
 *
 *   1. `ensureGrant` rotates a cached grant when its remaining lifetime
 *      drops below this threshold (`hasUsableLifetime` returns false).
 *   2. Minted prod tokens are clamped to `grant_expiry - DRAIN_MARGIN_MS`
 *      (see `expiresInClampedToGrant` in handlers.ts). This leaves a drain
 *      window where no minted token is still valid, so withdraw-and-rotate
 *      has no in-flight tokens to disrupt.
 */
export const DRAIN_MARGIN_MS = 5 * 60 * 1000;

/** Polling: initial delay, max delay, total timeout. */
const POLL_INITIAL_MS = 1_000;
const POLL_MAX_MS = 5_000;
const POLL_TIMEOUT_MS = 120_000;

/**
 * Per-request timeout for an individual PAM API call (create, list, poll-get,
 * withdraw). Without this, a half-open connection (NAT/LB idle-drop, a lost
 * RST, a PAM backend stalled behind IAM-replication lag) leaves the fetch
 * waiting on the OS TCP retransmission timeout — minutes on Linux — and, via
 * the single-flight slot below, blocks every other caller for the entitlement.
 */
const PAM_FETCH_TIMEOUT_MS = 10_000;

/** Maximum time shutdown waits for admitted rotations and withdraw dispatch. */
const PAM_SHUTDOWN_TIMEOUT_MS = 10_000;

/**
 * Overall wall-clock budget for one grant rotation (`doRotateGrant`). A
 * backstop, not a tight SLA, deliberately set ABOVE the worst-case sum of the
 * rotation's own internal deadlines so it never aborts a rotation the code
 * itself still considers in-progress. That worst case is the conflict-recovery
 * path, summing roughly: pre-withdraw LRO (<=`WITHDRAW_OP_TIMEOUT_MS` 30 s) +
 * create (<=`PAM_FETCH_TIMEOUT_MS` 10 s) + a full `LIST_GRANTS_MAX_PAGES` scan
 * (<=10 x 10 s = 100 s) + blocking-grant withdraw (<=30 s) + retry create
 * (<=10 s) + pollGrant (<=`POLL_TIMEOUT_MS` 120 s) ~= 300 s, so the budget sits
 * well past it.
 *
 * The budget still bounds two things the per-request timeout cannot: the
 * cumulative cost of many sequential calls, and the ADC token acquisition that
 * runs before every PAM call (`getAccessToken`, not covered by the fetch
 * signal). When it fires it aborts the rotation's `AbortSignal` (cancelling
 * in-flight PAM fetches) AND rejects, so the single-flight slot is freed and
 * the abandoned rotation cannot keep mutating shared state — see
 * `withRotationBudget`.
 */
const ROTATION_BUDGET_MS = 420_000;

/**
 * LRO polling for grants.withdraw Operations. Observed PAM behavior: ending
 * a grant settles in ~3 s with sub-second polling; these constants give ~3
 * polls in that window without burning RTTs against a not-yet-done Operation.
 */
const WITHDRAW_OP_INITIAL_MS = 500;
const WITHDRAW_OP_MAX_MS = 2_000;
const WITHDRAW_OP_TIMEOUT_MS = 30_000;

/** Valid GCP resource ID pattern for short-form entitlement IDs. */
const ENTITLEMENT_ID_PATTERN = /^[a-z][a-z0-9-]*$/;

const LIST_GRANTS_PAGE_SIZE = 100;
/** Safety bound on pagination when scanning for an active grant. */
const LIST_GRANTS_MAX_PAGES = 10;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NIL_UUID = "00000000-0000-0000-0000-000000000000";

/**
 * Grant states that represent an active (usable) grant. PAM ships both
 * spellings across endpoints — `grants.list` returns "ACTIVE" while older
 * docs and some create responses use "ACTIVATED" — so we accept either.
 */
const ACTIVE_GRANT_STATES = new Set<string>(["ACTIVE", "ACTIVATED"]);

function isActiveState(state: string | undefined): boolean {
  return state !== undefined && ACTIVE_GRANT_STATES.has(state);
}

/**
 * Terminal grant states from the v1beta State enum. A grant in any of
 * these states will never become ACTIVE — polling must surface immediately.
 */
const TERMINAL_GRANT_STATES = new Set<string>([
  "DENIED",
  "REVOKED",
  "ENDED",
  "EXPIRED",
  "ACTIVATION_FAILED",
  "EXTERNALLY_MODIFIED",
  "WITHDRAWN",
]);

function isTerminalState(state: string | undefined): boolean {
  return state !== undefined && TERMINAL_GRANT_STATES.has(state);
}

/** Expected full project-scoped entitlement path. */
const ENTITLEMENT_PATH_PATTERN = /^projects\/([^/]+)\/locations\/([^/]+)\/entitlements\/([^/]+)$/;

/**
 * Folder-scoped entitlement path. Folder IDs are numeric in GCP. A folder
 * grant covers every project inside the folder, so `project_id` is irrelevant
 * to its resolution — the path is consumed verbatim.
 */
const FOLDER_ENTITLEMENT_PATH_PATTERN =
  /^folders\/([0-9]+)\/locations\/([^/]+)\/entitlements\/([^/]+)$/;

/**
 * Organization-scoped entitlement path. Organization IDs are numeric in GCP.
 * An org grant covers every project beneath the org (across all folders), so
 * `project_id` is irrelevant — the path is consumed verbatim. Same shape and
 * rationale as the folder variant, one level up the resource hierarchy.
 */
const ORG_ENTITLEMENT_PATH_PATTERN =
  /^organizations\/([0-9]+)\/locations\/([^/]+)\/entitlements\/([^/]+)$/;

/** Parse protobuf JSON duration seconds, including up to nine fractional digits. */
function parseDurationSeconds(duration?: string): number {
  if (!duration) return 0;
  const match = /^(\d+(?:\.\d{1,9})?)s$/.exec(duration);
  return match ? Number(match[1]) : 0;
}

/**
 * True iff a PAM error body indicates an existing open grant for the same
 * privileged access. PAM has shipped this condition as both 409 Conflict and
 * 400 FAILED_PRECONDITION; this matcher narrows the 400 case so unrelated
 * FAILED_PRECONDITION causes (disabled entitlement, ineligible requester)
 * keep surfacing their original error.
 */
function isOpenGrantPrecondition(body: string): boolean {
  try {
    const parsed = JSON.parse(body) as {
      error?: { status?: unknown; message?: unknown };
    };
    return (
      parsed.error?.status === "FAILED_PRECONDITION" &&
      typeof parsed.error.message === "string" &&
      parsed.error.message.includes("open Grant")
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PamModuleOptions {
  fetchFn?: typeof globalThis.fetch;
  now?: () => number;
  /** Grant duration in seconds. Defaults to 3600. */
  grantDurationSeconds?: number;
  /** Override sleeping inside polling loops; tests pass `() => Promise.resolve()`. */
  sleepFn?: (ms: number) => Promise<void>;
  /** Per-request timeout (ms) for individual PAM API calls. Defaults to PAM_FETCH_TIMEOUT_MS. */
  fetchTimeoutMs?: number;
  /** Overall wall-clock budget (ms) for one grant rotation. Defaults to ROTATION_BUDGET_MS. */
  rotationBudgetMs?: number;
  /** Overall shutdown cleanup budget (ms). Defaults to PAM_SHUTDOWN_TIMEOUT_MS. */
  shutdownTimeoutMs?: number;
  /** UUID factory for grants.create idempotency keys. Tests may inject a deterministic factory. */
  requestIdFactory?: () => string;
  /**
   * Email of the identity the gate requests grants as. When set, the
   * open-grant scan only considers grants whose `requester` matches —
   * required on shared entitlements where `grants.list` returns every
   * team member's grants. Unset means no filtering.
   */
  getRequesterEmail?: () => Promise<string>;
}

export interface PamModule {
  /** Ensure an active PAM grant exists for the entitlement. Caches grants. */
  ensureGrant: (entitlementPath: string, justification?: string) => Promise<PamGrantResult>;
  /** Stop new rotations and best-effort withdraw every known owned grant. */
  withdrawAll: () => Promise<void>;
}

export interface PamGrantResult {
  /** Full grant resource path. */
  name: string;
  /** Grant state ("ACTIVE" or "ACTIVATED" — PAM ships both spellings). */
  state: string;
  /**
   * Computed grant expiry (accessGrantTime + requestedDuration, with a
   * conservative create-time fallback). Callers minting
   * an access token under this grant must clamp the token's TTL — see
   * `expiresInClampedToGrant` in handlers.ts, which subtracts DRAIN_MARGIN_MS
   * before clamping to keep concurrent clients safe across rotation.
   */
  expiresAt: Date;
  /** Whether this was a cache hit. */
  cached: boolean;
}

interface PamGrantResponse {
  name?: string;
  state?: string;
  /** Output only — username of the user who created the grant. */
  requester?: string;
  createTime?: string;
  timeline?: {
    events?: Array<{
      eventTime?: string;
      activated?: Record<string, never>;
    }>;
  };
  auditTrail?: {
    accessGrantTime?: string;
    accessRemoveTime?: string;
  };
  externallyModified?: boolean;
  privilegedAccess?: unknown;
  justification?: unknown;
  requestedDuration?: string;
}

interface PamOperation {
  name?: string;
  done?: boolean;
  error?: { code?: number; message?: string };
}

interface CachedGrant {
  name: string;
  state: string;
  expiresAt: Date;
}

/** Distinguishes requester-identity failures from PAM API failures. */
export class PamRequesterLookupError extends Error {
  constructor(cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    super(
      `could not resolve the gate's requester email for PAM open-grant scan: ${detail}`,
      cause instanceof Error ? { cause } : undefined,
    );
    this.name = "PamRequesterLookupError";
  }
}

/**
 * Marks an HTTP exchange whose outcome is ambiguous: PAM may have processed
 * the request even though the client did not receive the complete response.
 * grants.create retries these failures once with the same requestId.
 */
class PamAmbiguousRequestError extends Error {
  constructor(message: string, cause: unknown) {
    super(message, cause instanceof Error ? { cause } : undefined);
    this.name = "PamAmbiguousRequestError";
  }
}

// ---------------------------------------------------------------------------
// Entitlement path resolution & validation
// ---------------------------------------------------------------------------

/**
 * Resolve a PAM policy value to a full entitlement resource path.
 *
 * - Short-form (e.g. "prod-db-admin") is expanded against project_id + location.
 * - Project-scoped full paths are validated and required to match project_id.
 * - Folder- and organization-scoped full paths
 *   (`folders/{folder}/locations/{loc}/entitlements/{id}`,
 *   `organizations/{org}/locations/{loc}/entitlements/{id}`) are returned
 *   verbatim: a folder or org grant covers every project beneath it, so the
 *   gate's `project_id` is not part of the resolution. This is how multi-
 *   project setups manage one entitlement across many projects.
 *
 * Throws on invalid input to prevent path traversal or cross-project escalation.
 */
export function resolveEntitlementPath(
  policy: string,
  projectId: string,
  location: string = "global",
): string {
  if (policy.includes("/")) {
    // Folder- and org-scoped paths: validate shape, then pass through. We
    // deliberately do not compare against project_id — these grants
    // intentionally span every project beneath the resource.
    if (policy.startsWith("folders/")) {
      if (!FOLDER_ENTITLEMENT_PATH_PATTERN.test(policy)) {
        throw new Error(
          `Invalid PAM folder entitlement path: "${policy}". ` +
            `Expected format: folders/{folder}/locations/{location}/entitlements/{id}`,
        );
      }
      return policy;
    }
    if (policy.startsWith("organizations/")) {
      if (!ORG_ENTITLEMENT_PATH_PATTERN.test(policy)) {
        throw new Error(
          `Invalid PAM organization entitlement path: "${policy}". ` +
            `Expected format: organizations/{org}/locations/{location}/entitlements/{id}`,
        );
      }
      return policy;
    }

    // Project-scoped full path — validate format and project
    const match = ENTITLEMENT_PATH_PATTERN.exec(policy);
    if (!match) {
      throw new Error(
        `Invalid PAM entitlement path: "${policy}". ` +
          `Expected format: projects/{project}/locations/{location}/entitlements/{id}, ` +
          `folders/{folder}/locations/{location}/entitlements/{id}, ` +
          `or organizations/{org}/locations/{location}/entitlements/{id}`,
      );
    }
    if (match[1] !== projectId) {
      throw new Error(
        `PAM entitlement path references project "${match[1]}" but gate is configured for "${projectId}"`,
      );
    }
    return policy;
  }

  // Short-form entitlement ID — validate characters
  if (!ENTITLEMENT_ID_PATTERN.test(policy)) {
    throw new Error(
      `Invalid PAM entitlement ID: "${policy}". ` +
        `Must match ${ENTITLEMENT_ID_PATTERN} (lowercase letters, digits, hyphens)`,
    );
  }

  return `projects/${projectId}/locations/${location}/entitlements/${policy}`;
}

// ---------------------------------------------------------------------------
// PAM module factory
// ---------------------------------------------------------------------------

/**
 * Create a PAM module that manages grant lifecycle.
 *
 * @param getAccessToken - Returns an ADC access token for PAM API calls.
 */
export function createPamModule(
  getAccessToken: () => Promise<string>,
  options: PamModuleOptions = {},
): PamModule {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const now = options.now ?? Date.now;
  const grantDurationSeconds = options.grantDurationSeconds ?? FALLBACK_GRANT_DURATION_SECONDS;
  const grantDuration = `${grantDurationSeconds}s`;
  const sleep =
    options.sleepFn ?? ((ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms)));
  const getRequesterEmail = options.getRequesterEmail;
  const fetchTimeoutMs = options.fetchTimeoutMs ?? PAM_FETCH_TIMEOUT_MS;
  const rotationBudgetMs = options.rotationBudgetMs ?? ROTATION_BUDGET_MS;
  const shutdownTimeoutMs = options.shutdownTimeoutMs ?? PAM_SHUTDOWN_TIMEOUT_MS;
  const requestIdFactory = options.requestIdFactory ?? randomUUID;

  const grantCache = new Map<string, CachedGrant>();
  // Names created by this module, or observed with a requester identity that
  // matches the module's authenticated identity. Shutdown uses this ownership
  // set instead of blindly withdrawing every cached grant: without requester
  // lookup, conflict recovery may reuse a grant whose ownership is unknown.
  const ownedOpenGrantNames = new Set<string>();
  // A withdraw POST can land just before its rotation is superseded while PAM
  // still reports the grant ACTIVE. Remember that local intent immediately so
  // a replacement conflict scan never adopts access that is already being
  // removed. Entries are cleared only after PAM itself reports a terminal
  // state; an LRO completing before grants.list catches up is not sufficient.
  const retiringGrantNames = new Set<string>();
  // Single-flight rotation per entitlement: concurrent `ensureGrant` calls
  // that miss the cache fast-path coalesce onto one rotation. The gate is
  // single-instance per machine (server.ts:91), so in-process coordination
  // is sufficient — no distributed lock needed.
  const inFlightRotations = new Map<string, Promise<PamGrantResult>>();
  // The public rotation promise can reject on its wall-clock budget while its
  // underlying work remains stuck in unabortable access-token acquisition.
  // Shutdown tracks the underlying work separately and waits only within its
  // own bounded cleanup budget.
  const admittedRotationWork = new Set<Promise<PamGrantResult>>();
  // A rotation can outlive its public promise when the wall-clock budget
  // expires while getAccessToken() is wedged (that API is not abortable).
  // Track the latest owner separately from the single-flight promise so the
  // abandoned work cannot mutate state after a replacement rotation starts.
  interface RotationOwner {
    id: number;
    controller: AbortController;
  }
  const rotationOwners = new Map<string, RotationOwner>();
  let nextRotationOwner = 0;
  let shuttingDown = false;
  let shutdownController: AbortController | undefined;
  let shutdownPromise: Promise<void> | undefined;
  const shutdownWithdrawals = new Map<string, Promise<boolean>>();

  function rememberOwnedGrant(grantName: string): void {
    ownedOpenGrantNames.add(grantName);
    if (shuttingDown) scheduleShutdownWithdraw(grantName);
  }

  function isRotationOwner(entitlementPath: string, owner: RotationOwner): boolean {
    return rotationOwners.get(entitlementPath) === owner;
  }

  function rotationStoppedError(
    entitlementPath: string,
    owner: RotationOwner,
    signal?: AbortSignal,
  ): Error {
    if (signal?.aborted) {
      return signal.reason instanceof Error ? signal.reason : new Error(String(signal.reason));
    }
    if (owner.controller.signal.aborted) {
      const { reason } = owner.controller.signal;
      return reason instanceof Error ? reason : new Error(String(reason));
    }
    return new Error(
      `PAM grant rotation for "${entitlementPath}" was superseded (owner ${owner.id})`,
    );
  }

  function assertRotationOwner(
    entitlementPath: string,
    owner: RotationOwner,
    signal?: AbortSignal,
  ): void {
    if (
      signal?.aborted ||
      owner.controller.signal.aborted ||
      !isRotationOwner(entitlementPath, owner)
    ) {
      throw rotationStoppedError(entitlementPath, owner, signal);
    }
  }

  function hasUsableLifetime(expiresAt: Date): boolean {
    // Rotation must begin at the same boundary used to clamp minted tokens.
    // Rotating any earlier could withdraw IAM access while a previously minted
    // token is still within the lifetime we advertised to its caller.
    return expiresAt.getTime() - now() > DRAIN_MARGIN_MS;
  }

  async function pamFetch(
    url: string,
    init?: RequestInit,
    rotationSignal?: AbortSignal,
    beforeRequest?: () => void,
  ): Promise<Response> {
    if (rotationSignal?.aborted) {
      throw rotationSignal.reason instanceof Error
        ? rotationSignal.reason
        : new Error(String(rotationSignal.reason));
    }
    const token = await getAccessToken();
    if (rotationSignal?.aborted) {
      throw rotationSignal.reason instanceof Error
        ? rotationSignal.reason
        : new Error(String(rotationSignal.reason));
    }
    // Ownership may change while the unabortable token lookup is pending.
    // Check immediately before issuing a state-changing cleanup request.
    beforeRequest?.();
    // Combine the per-request timeout with the rotation-wide budget signal (when
    // a rotation is in flight) so the overall budget can cancel an in-flight
    // call, not just the next one. If the budget already fired, the combined
    // signal is born aborted and the fetch rejects immediately.
    const timeoutSignal = AbortSignal.timeout(fetchTimeoutMs);
    const signal = rotationSignal
      ? AbortSignal.any([timeoutSignal, rotationSignal])
      : timeoutSignal;
    try {
      const response = await fetchFn(url, {
        ...init,
        signal,
        headers: {
          ...init?.headers,
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      // fetch() resolves once headers arrive. Buffer the small PAM JSON body
      // before returning so a peer that stalls mid-body remains inside this
      // per-request timeout and receives the same actionable error mapping.
      const body = await response.arrayBuffer();
      return new Response(body.byteLength > 0 ? body : null, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    } catch (err) {
      // A rotation-budget abort surfaces the budget error (the abort reason),
      // not a per-call timeout message — they are different failures.
      if (rotationSignal?.aborted) {
        throw rotationSignal.reason instanceof Error
          ? rotationSignal.reason
          : new Error(String(rotationSignal.reason));
      }
      // Otherwise surface the abort as an actionable message instead of a bare
      // DOMException, so the gate log / client error names the stalled call.
      if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
        throw new PamAmbiguousRequestError(
          `PAM API request timed out after ${fetchTimeoutMs}ms: ${url}`,
          err,
        );
      }
      // A connection failure or truncated response does not reveal whether a
      // mutating request reached PAM. Preserve that distinction so create can
      // safely retry once with its idempotency key; callers of read-only and
      // withdraw operations still receive the original diagnostic as cause.
      throw new PamAmbiguousRequestError(err instanceof Error ? err.message : String(err), err);
    }
  }

  type CreateGrantAttemptResult =
    | { kind: "ok"; grant: PamGrantResponse }
    | { kind: "open-conflict" };

  async function createGrantAttempt(
    entitlementPath: string,
    justification?: string,
    signal?: AbortSignal,
  ): Promise<CreateGrantAttemptResult> {
    const requestId = requestIdFactory();
    if (!UUID_PATTERN.test(requestId) || requestId.toLowerCase() === NIL_UUID) {
      throw new Error(`PAM grants.create requestId factory returned an invalid UUID: ${requestId}`);
    }
    const url = `${PAM_API_BASE}/${entitlementPath}/grants?requestId=${encodeURIComponent(requestId)}`;
    const body = {
      requestedDuration: grantDuration,
      justification: {
        unstructuredJustification: justification ?? "gcp-authcalator prod access",
      },
    };

    let res: Response;
    for (let attempt = 0; ; attempt++) {
      if (signal?.aborted) {
        throw signal.reason instanceof Error ? signal.reason : new Error(String(signal.reason));
      }
      try {
        res = await pamFetch(
          url,
          {
            method: "POST",
            body: JSON.stringify(body),
          },
          signal,
        );
      } catch (err) {
        if (attempt === 0 && err instanceof PamAmbiguousRequestError && !signal?.aborted) {
          continue;
        }
        throw err;
      }

      // PAM explicitly supports idempotent create retries via requestId. One
      // retry covers a transient backend/rate-limit response without turning a
      // persistent outage into a long client wait. Deterministic 4xx responses
      // (including the open-grant conflict handled below) are never retried.
      if (attempt === 0 && (res.status === 429 || res.status >= 500)) {
        continue;
      }
      break;
    }

    if (res.status === 409) {
      return { kind: "open-conflict" };
    }

    if (res.status === 403) {
      const text = await res.text();
      throw new Error(
        `PAM API access denied (403): ${text}\n` +
          `  Check that the engineer has entitlement access for "${entitlementPath}"`,
      );
    }

    if (res.status === 404) {
      throw new Error(
        `PAM entitlement not found (404): "${entitlementPath}"\n` +
          `  Check the pam_policy value and ensure the entitlement exists`,
      );
    }

    if (!res.ok) {
      const text = await res.text();

      if (res.status === 400 && isOpenGrantPrecondition(text)) {
        return { kind: "open-conflict" };
      }

      throw new Error(`PAM API error (${res.status}): ${text}`);
    }

    const grant = (await res.json()) as PamGrantResponse;
    // A successful response to our create request establishes ownership even
    // while the grant is still pending and has not reached the cache. Record
    // it before returning so a concurrent shutdown cannot miss it.
    if (grant.name) rememberOwnedGrant(grant.name);
    return { kind: "ok", grant };
  }

  interface OpenGrantScan {
    /** First active grant with usable remaining lifetime, if any. */
    usable?: PamGrantResponse & { name: string };
    /**
     * Our own non-terminal grants that hold the open-grant slot without
     * being usable: active grants whose computed expiry has passed (PAM's
     * state lag) and still-pending grants (APPROVAL_AWAITED / SCHEDULED /
     * ACTIVATING — e.g. orphaned by a poll timeout in a previous run).
     * These are what's blocking createGrant — the recovery path withdraws
     * them and retries.
     */
    blocking: Array<PamGrantResponse & { name: string }>;
    scanned: number;
    pagesScanned: number;
    /** Non-terminal grants excluded because they belong to other requesters. */
    skippedOtherRequester: number;
  }

  async function scanForOpenGrants(
    entitlementPath: string,
    signal?: AbortSignal,
  ): Promise<OpenGrantScan> {
    // PAM's grants.list endpoint rejects every `filter=` we've tried as
    // "invalid list filter", so we list unfiltered and bucket client-side.
    // ENDED grants stick around in the response, so on a busy entitlement
    // the open grant may not be on the first page — page through up to
    // LIST_GRANTS_MAX_PAGES before giving up. We re-check createTime+duration:
    // PAM's `state` field can lag actual expiry, and the 409/400 "open Grant"
    // path lands us here precisely in that window.
    //
    // The list contains every requester's grants, but the open-grant rule is
    // per (entitlement, requester) — only the gate's own grants can be
    // blocking the create, and they're the only ones withdraw may touch.
    // Grants with no requester field are skipped: never end a grant we
    // can't attribute to ourselves.
    let requester: string | undefined;
    if (getRequesterEmail) {
      try {
        requester = (await getRequesterEmail()).toLowerCase();
      } catch (err) {
        // Preserve the typed credential error used by the gate/client re-auth
        // path. Other lookup failures get their own diagnosable classification.
        if (err instanceof CredentialsExpiredError) throw err;
        throw new PamRequesterLookupError(err);
      }
    }
    const isOwnGrant = (g: PamGrantResponse): boolean =>
      requester === undefined || g.requester?.toLowerCase() === requester;

    const baseUrl = `${PAM_API_BASE}/${entitlementPath}/grants?pageSize=${LIST_GRANTS_PAGE_SIZE}`;
    const blocking: Array<PamGrantResponse & { name: string }> = [];
    let scanned = 0;
    let pagesScanned = 0;
    let skippedOtherRequester = 0;
    let pageToken: string | undefined;

    for (let page = 0; page < LIST_GRANTS_MAX_PAGES; page++) {
      const url = pageToken ? `${baseUrl}&pageToken=${encodeURIComponent(pageToken)}` : baseUrl;
      const res = await pamFetch(url, undefined, signal);

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`PAM API error listing grants (${res.status}): ${text}`);
      }

      const data = (await res.json()) as {
        grants?: PamGrantResponse[];
        nextPageToken?: string;
      };
      const grants = data.grants ?? [];
      pagesScanned++;
      scanned += grants.length;

      // Once we find a usable grant we're done — the caller wants to reuse
      // it directly without withdrawing the blocking ones (they'll age out
      // on their own once we stop conflicting with them).
      for (const g of grants) {
        if (typeof g.name !== "string") continue;
        if (isTerminalState(g.state)) {
          retiringGrantNames.delete(g.name);
          ownedOpenGrantNames.delete(g.name);
          continue;
        }
        if (!g.state) continue;
        if (!isOwnGrant(g)) {
          skippedOtherRequester++;
          continue;
        }
        const named = g as PamGrantResponse & { name: string };
        // Only a resolved, matching requester proves that a grant discovered
        // by list belongs to this module. With no requester lookup configured,
        // legacy callers may still reuse it, but shutdown must not withdraw it.
        if (requester !== undefined) rememberOwnedGrant(g.name);
        if (retiringGrantNames.has(g.name)) {
          blocking.push(named);
          continue;
        }
        const expiry = computeGrantExpiry(named);
        if (
          isActiveState(g.state) &&
          !g.externallyModified &&
          expiry !== null &&
          hasUsableLifetime(expiry)
        ) {
          return { usable: named, blocking, scanned, pagesScanned, skippedOtherRequester };
        }
        // Active-but-expired (state lag) or still pending — either way it
        // holds the open-grant slot and withdraw can clear it.
        blocking.push(named);
      }

      if (!data.nextPageToken) break;
      pageToken = data.nextPageToken;
    }

    return { blocking, scanned, pagesScanned, skippedOtherRequester };
  }

  async function createGrantWithRecovery(
    entitlementPath: string,
    justification?: string,
    signal?: AbortSignal,
  ): Promise<PamGrantResponse> {
    const first = await createGrantAttempt(entitlementPath, justification, signal);
    if (first.kind === "ok") return first.grant;

    // 409 / 400 FAILED_PRECONDITION ("open Grant"): another grant of ours is
    // open for the same privileged access. Scan to learn whether it's usable
    // (reuse it) or merely blocking (expired-but-laggy or stuck pending —
    // withdraw and retry). withdrawGrantAndWait polls the LRO so a single
    // retry suffices.
    const scan = await scanForOpenGrants(entitlementPath, signal);
    if (scan.usable) return scan.usable;

    if (scan.blocking.length === 0) {
      const otherNote =
        scan.skippedOtherRequester > 0
          ? `; ${scan.skippedOtherRequester} open grant(s) belong to other requesters`
          : "";
      throw new Error(
        `PAM grant conflict but no open grant of ours found for "${entitlementPath}" ` +
          `(scanned ${scan.scanned} grant(s) across ${scan.pagesScanned} page(s)${otherNote})`,
      );
    }

    const withdrawn = (
      await Promise.all(
        scan.blocking.map((g) =>
          withdrawGrantAndWait(
            g.name,
            "clearing blocking grant on retry",
            WITHDRAW_OP_TIMEOUT_MS,
            signal,
          ),
        ),
      )
    ).filter(Boolean).length;

    const retry = await createGrantAttempt(entitlementPath, justification, signal);
    if (retry.kind === "ok") return retry.grant;

    // The retry still conflicts after we waited for withdraw to complete.
    // Surface a distinct error so this doesn't look like the original
    // "no open grant found" deadlock, and don't claim withdrawals that
    // never landed — the withdraw failures themselves are in the gate log.
    const detail =
      withdrawn === scan.blocking.length
        ? `after withdrawing ${scan.blocking.length} blocking grant(s)`
        : `and only ${withdrawn} of ${scan.blocking.length} blocking grant(s) could be withdrawn ` +
          `(see gate log for withdraw errors)`;
    throw new Error(`PAM grant conflict persists ${detail} for "${entitlementPath}"`);
  }

  /**
   * Thrown when a polled grant lands in a terminal state. Distinguished so
   * the rotation cleanup path knows the grant is already closed and skips
   * the best-effort withdraw it performs for still-pending grants.
   */
  class GrantTerminalStateError extends Error {}

  async function pollGrant(grantName: string, signal?: AbortSignal): Promise<PamGrantResponse> {
    const deadline = now() + POLL_TIMEOUT_MS;
    let delay = POLL_INITIAL_MS;

    while (now() < deadline) {
      // The rotation budget can fire mid-poll; stop promptly rather than
      // polling out the full POLL_TIMEOUT_MS after the caller has given up.
      if (signal?.aborted) {
        throw signal.reason instanceof Error ? signal.reason : new Error(String(signal.reason));
      }
      await sleep(delay);
      delay = Math.min(delay * 2, POLL_MAX_MS);

      const url = `${PAM_API_BASE}/${grantName}`;
      const res = await pamFetch(url, undefined, signal);

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`PAM API error polling grant (${res.status}): ${text}`);
      }

      const grant = (await res.json()) as PamGrantResponse;

      if (isActiveState(grant.state)) {
        return grant;
      }

      if (isTerminalState(grant.state)) {
        ownedOpenGrantNames.delete(grantName);
        throw new GrantTerminalStateError(
          `PAM grant entered terminal state ${grant.state}: ${grantName}`,
        );
      }

      // Still pending (APPROVAL_AWAITED, ACTIVATING, SCHEDULED, etc.) —
      // continue polling.
    }

    throw new Error(
      `PAM grant was not activated within ${POLL_TIMEOUT_MS / 1000}s: ${grantName}\n` +
        `  The entitlement may require manual approval`,
    );
  }

  function computeGrantExpiry(grant: PamGrantResponse): Date | null {
    // Access duration starts when PAM grants access, which may be well after
    // createTime on approval-based entitlements. Prefer the explicit audit
    // timestamp, then the activated timeline event. createTime is a safe
    // conservative fallback: it can rotate early but cannot overstate access.
    const durationMs = parseDurationSeconds(grant.requestedDuration) * 1000;
    const activatedEvent = grant.timeline?.events?.find((event) => event.activated !== undefined);
    const anchor =
      grant.auditTrail?.accessGrantTime ?? activatedEvent?.eventTime ?? grant.createTime;
    const anchorMs = anchor ? new Date(anchor).getTime() : NaN;

    if (durationMs > 0 && !isNaN(anchorMs)) {
      return new Date(anchorMs + durationMs);
    }

    return null;
  }

  function cacheGrant(
    entitlementPath: string,
    grant: PamGrantResponse,
    requestedAtMs: number,
  ): CachedGrant {
    const entry: CachedGrant = {
      name: grant.name!,
      state: grant.state!,
      // A newly-created response may omit timestamps/duration. Anchor the
      // fallback at request start (never cache time after a long activation)
      // and use the duration we sent. Activation cannot precede this anchor,
      // so the result remains conservative without forcing multi-hour grants
      // through needless 15-minute IAM-propagation churn.
      expiresAt: computeGrantExpiry(grant) ?? new Date(requestedAtMs + grantDurationSeconds * 1000),
    };
    grantCache.set(entitlementPath, entry);
    return entry;
  }

  /**
   * Run a rotation under the overall wall-clock budget. On expiry the budget
   * both (a) aborts the rotation's `AbortSignal` — cancelling any in-flight PAM
   * fetch and making every later one reject immediately, so the abandoned
   * rotation stops issuing calls and stops mutating shared state (grantCache) —
   * and (b) rejects the race, so `ensureGrant` settles and frees the
   * single-flight slot even if the rotation is wedged in `getAccessToken` (the
   * one step no signal can cancel). `Promise.race` keeps an internal reaction
   * on `work`, so its eventual rejection is handled (no unhandledRejection).
   * `doRotateGrant` also re-checks the signal before writing the cache and
   * best-effort withdraws any grant it created post-abort, so a budget hit
   * neither clobbers a newer rotation's cache entry nor leaks an open grant.
   */
  function withRotationBudget(
    run: (signal: AbortSignal) => Promise<PamGrantResult>,
  ): Promise<PamGrantResult> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        const err = new Error(`PAM grant rotation exceeded its ${rotationBudgetMs}ms budget`);
        controller.abort(err);
        reject(err);
      }, rotationBudgetMs);
      timer.unref?.();
    });
    return Promise.race([run(controller.signal), deadline]).finally(() => clearTimeout(timer));
  }

  async function ensureGrant(
    entitlementPath: string,
    justification?: string,
  ): Promise<PamGrantResult> {
    if (shuttingDown) {
      throw new Error("PAM module is shutting down; new grant requests are disabled");
    }

    const cached = grantCache.get(entitlementPath);
    if (cached && hasUsableLifetime(cached.expiresAt)) {
      return {
        name: cached.name,
        state: cached.state,
        expiresAt: cached.expiresAt,
        cached: true,
      };
    }

    const pending = inFlightRotations.get(entitlementPath);
    if (pending) return pending;

    const previousOwner = rotationOwners.get(entitlementPath);
    const owner: RotationOwner = {
      id: ++nextRotationOwner,
      controller: new AbortController(),
    };
    previousOwner?.controller.abort(
      new Error(`PAM grant rotation for "${entitlementPath}" was superseded by owner ${owner.id}`),
    );
    rotationOwners.set(entitlementPath, owner);
    const rotation = withRotationBudget((budgetSignal) => {
      const signal = AbortSignal.any([budgetSignal, owner.controller.signal]);
      const work = doRotateGrant(entitlementPath, justification, cached, owner, signal);
      admittedRotationWork.add(work);
      const forgetWork = (): void => {
        admittedRotationWork.delete(work);
      };
      void work.then(forgetWork, forgetWork);
      return work;
    });
    inFlightRotations.set(entitlementPath, rotation);
    try {
      return await rotation;
    } catch (err) {
      // The thrown error reaches the requesting client and the audit log,
      // but not the gate's console — without this line a failed rotation
      // looks silent in the daemon log.
      console.error(
        `pam: grant rotation failed for ${entitlementPath}: ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
      throw err;
    } finally {
      if (inFlightRotations.get(entitlementPath) === rotation) {
        inFlightRotations.delete(entitlementPath);
      }
    }
  }

  async function doRotateGrant(
    entitlementPath: string,
    justification: string | undefined,
    cached: CachedGrant | undefined,
    owner: RotationOwner,
    signal?: AbortSignal,
  ): Promise<PamGrantResult> {
    assertRotationOwner(entitlementPath, owner, signal);
    // Withdraw the cached grant before re-creating. Even when our computed
    // expiry has passed, PAM's state can lag and leave the grant in an "open"
    // state that 409s the immediate createGrant. withdrawGrantAndWait polls
    // the LRO so the follow-up create doesn't race the withdraw.
    if (cached) {
      await withdrawGrantAndWait(
        cached.name,
        "renewing before expiry",
        WITHDRAW_OP_TIMEOUT_MS,
        signal,
      );
    }
    // The withdraw path is best-effort and can swallow a budget abort. Recheck
    // ownership after it returns: an older rotation must not delete the cache
    // entry installed by its replacement while token acquisition was stuck.
    assertRotationOwner(entitlementPath, owner, signal);
    if (grantCache.get(entitlementPath) === cached) {
      grantCache.delete(entitlementPath);
    }

    // If PAM omits expiry fields, this request-start timestamp is a safe
    // conservative anchor; activation can only happen at or after it.
    const requestedAt = now();
    const grant = await createGrantWithRecovery(entitlementPath, justification, signal);
    assertRotationOwner(entitlementPath, owner, signal);

    if (!grant.name) {
      throw new Error("PAM API returned a grant with no resource name");
    }

    let activated = grant;
    if (!isActiveState(grant.state)) {
      try {
        activated = await pollGrant(grant.name, signal);
      } catch (err) {
        // A grant that never activated (poll timeout or API failure) still
        // holds the open-grant slot and would 409-block every follow-up
        // create. Withdraw it best-effort before surfacing the failure;
        // terminal grants are already closed and need no cleanup.
        if (!(err instanceof GrantTerminalStateError) && isRotationOwner(entitlementPath, owner)) {
          await withdrawGrantAndWait(
            grant.name,
            "cleaning up grant that failed to activate",
            WITHDRAW_OP_TIMEOUT_MS,
            owner.controller.signal,
            () => assertRotationOwner(entitlementPath, owner),
          );
        }
        throw err;
      }
    }

    // The budget may have fired in the no-await gap between pollGrant returning
    // and this point. If so, the caller has already received the budget error
    // and freed the single-flight slot, and a newer rotation may now own the
    // cache entry — writing here would clobber it (stale TTL) or resurrect a
    // grant a later rotation already withdrew. Best-effort withdraw the grant
    // we just created under the separate ownership signal, which lets a newer
    // rotation cancel this cleanup before adopting the grant. Then surface the
    // budget error. (See withRotationBudget.)
    if (signal?.aborted || !isRotationOwner(entitlementPath, owner)) {
      if (isRotationOwner(entitlementPath, owner)) {
        await withdrawGrantAndWait(
          grant.name,
          "rotation aborted by budget after activation",
          WITHDRAW_OP_TIMEOUT_MS,
          owner.controller.signal,
          () => assertRotationOwner(entitlementPath, owner),
        );
      }
      throw rotationStoppedError(entitlementPath, owner, signal);
    }

    assertRotationOwner(entitlementPath, owner, signal);
    const entry = cacheGrant(entitlementPath, activated, requestedAt);

    return {
      name: entry.name,
      state: entry.state,
      expiresAt: entry.expiresAt,
      cached: false,
    };
  }

  async function pollWithdrawOperation(
    operationName: string,
    deadlineMs: number,
    signal?: AbortSignal,
  ): Promise<void> {
    const deadline = now() + deadlineMs;
    let delay = WITHDRAW_OP_INITIAL_MS;

    while (now() < deadline) {
      // Sleep first: the initial withdraw response already reported
      // `done:false`, so the operation cannot have settled in the
      // microseconds since.
      await sleep(delay);
      delay = Math.min(delay * 2, WITHDRAW_OP_MAX_MS);

      // The Operation was created on the v1beta surface, so poll it there.
      const res = await pamFetch(`${PAM_API_BASE_V1BETA}/${operationName}`, undefined, signal);

      if (res.ok) {
        const op = (await res.json().catch(() => ({}))) as PamOperation;
        if (op.done) {
          if (op.error) {
            // Already-terminal grant or harmless tail-end error. Don't throw —
            // withdraw is best-effort, the goal state is reached.
            console.error(
              `pam: withdraw operation ${operationName} returned error: ${JSON.stringify(op.error)}`,
            );
          }
          return;
        }
        continue;
      }

      if (res.status === 404) {
        // Operation already garbage-collected; the withdraw completed earlier.
        return;
      }

      if (res.status >= 400 && res.status < 500) {
        console.error(
          `pam: withdraw operation ${operationName} polling gave up after ${res.status}`,
        );
        return;
      }
      // 5xx — keep retrying within the deadline budget.
    }

    console.error(
      `pam: withdraw operation ${operationName} did not complete within ${deadlineMs}ms`,
    );
  }

  /**
   * End one of our own grants via `grants:withdraw` and wait for the LRO.
   * `reason` is local log context only — WithdrawGrantRequest has no fields,
   * so the request body must be empty.
   *
   * Best-effort: never throws. Returns whether PAM accepted the withdraw
   * request, so callers can report failures accurately (LRO confirmation
   * remains best-effort and does not affect the result).
   */
  async function withdrawGrantAndWait(
    grantName: string,
    reason: string,
    deadlineMs: number = WITHDRAW_OP_TIMEOUT_MS,
    signal?: AbortSignal,
    beforeRequest?: () => void,
  ): Promise<boolean> {
    const startedAt = now();
    try {
      const url = `${PAM_API_BASE_V1BETA}/${grantName}:withdraw`;
      const res = await pamFetch(url, { method: "POST" }, signal, () => {
        // Run the ownership fence after the unabortable access-token lookup,
        // then mark immediately before fetch dispatch. Marking at function
        // entry would poison a grant even when token lookup fails or a newer
        // rotation supersedes this cleanup before any withdraw POST is sent.
        beforeRequest?.();
        retiringGrantNames.add(grantName);
      });

      if (!res.ok) {
        const text = await res.text();
        console.error(`pam: withdraw ${grantName} (${reason}) failed: ${res.status} ${text}`);
        return false;
      }

      const op = (await res.json().catch(() => ({}))) as PamOperation;
      // PAM accepted the withdraw. Unless it immediately reports an operation
      // error, this grant is no longer an open grant that shutdown must issue
      // another request for. `retiringGrantNames` remains until list observes
      // a terminal state, preventing stale ACTIVE responses from being reused.
      if (!op.error) ownedOpenGrantNames.delete(grantName);
      if (op.done || !op.name) {
        // Synchronous withdraw or untrackable response — assume done.
        if (op.error) {
          console.error(
            `pam: withdraw ${grantName} (${reason}) operation error: ${JSON.stringify(op.error)}`,
          );
        }
        return true;
      }

      const remaining = deadlineMs - (now() - startedAt);
      if (remaining > 0) {
        await pollWithdrawOperation(op.name, remaining, signal);
      }
      return true;
    } catch (err) {
      console.error(
        `pam: withdraw ${grantName} (${reason}) threw: ${err instanceof Error ? err.message : String(err)}`,
      );
      return false;
    }
  }

  // Fire-and-forget: deadline 0 means withdrawGrantAndWait POSTs the
  // withdraw, reads its Operation response, and skips polling. Used on
  // shutdown where we want the request landed but not the LRO confirmation.
  function withdrawGrantFireAndForget(
    grantName: string,
    reason: string,
    signal?: AbortSignal,
  ): Promise<boolean> {
    return withdrawGrantAndWait(grantName, reason, 0, signal);
  }

  function scheduleShutdownWithdraw(grantName: string): void {
    if (!shutdownController || shutdownWithdrawals.has(grantName)) return;
    const withdrawal = withdrawGrantFireAndForget(grantName, "shutdown", shutdownController.signal);
    shutdownWithdrawals.set(grantName, withdrawal);
  }

  async function runShutdown(admittedWork: Promise<PamGrantResult>[]): Promise<void> {
    for (const grantName of ownedOpenGrantNames) scheduleShutdownWithdraw(grantName);

    const cleanup = (async (): Promise<void> => {
      // Wait for the underlying rotation work, not just its budgeted public
      // promise. A response that arrives after shutdown began can reveal a
      // pending grant name; rememberOwnedGrant schedules it immediately.
      await Promise.allSettled(admittedWork);
      for (const grantName of ownedOpenGrantNames) scheduleShutdownWithdraw(grantName);
      await Promise.allSettled([...shutdownWithdrawals.values()]);
    })();

    let timer: ReturnType<typeof setTimeout> | undefined;
    let timedOut = false;
    const deadline = new Promise<void>((resolve) => {
      timer = setTimeout(() => {
        timedOut = true;
        shutdownController?.abort(
          new Error(`PAM shutdown cleanup exceeded its ${shutdownTimeoutMs}ms budget`),
        );
        resolve();
      }, shutdownTimeoutMs);
      timer.unref?.();
    });

    await Promise.race([cleanup, deadline]);
    clearTimeout(timer);
    if (timedOut) {
      console.error(`pam: shutdown cleanup exceeded its ${shutdownTimeoutMs}ms budget`);
    }
  }

  function withdrawAll(): Promise<void> {
    if (shutdownPromise) return shutdownPromise;

    shuttingDown = true;
    shutdownController = new AbortController();
    const admittedWork = [...admittedRotationWork];
    const shutdownError = new Error("PAM module is shutting down");
    for (const owner of rotationOwners.values()) owner.controller.abort(shutdownError);
    rotationOwners.clear();
    grantCache.clear();

    if (ownedOpenGrantNames.size > 0) {
      console.log(`pam: withdrawing ${ownedOpenGrantNames.size} owned grant(s)...`);
    }
    shutdownPromise = runShutdown(admittedWork);
    return shutdownPromise;
  }

  return { ensureGrant, withdrawAll };
}
