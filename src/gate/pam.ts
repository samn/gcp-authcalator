// ---------------------------------------------------------------------------
// GCP Privileged Access Manager (PAM) module
//
// Requests just-in-time PAM grants to temporarily elevate the engineer's
// IAM roles. Grants are cached, revoked when stale or expired, and
// best-effort revoked on shutdown.
//
// API quirks and how we handle them (see plans/pam-rotation-drain-margin.md
// for the full audit):
//
//   - `grants.revoke` returns a long-running `Operation`. `revokeGrantAndWait`
//     polls the Operation to `done:true` before its caller retries create —
//     without this, the follow-up createGrant races the revoke and 409s
//     because PAM still considers the old grant open.
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
//   concurrent clients from seeing 403s when the gate revokes-and-recreates,
//   minted prod tokens are clamped to `grant_expiry - DRAIN_MARGIN_MS` in
//   `handlers.ts:expiresInClampedToGrant`. By the time the gate revokes the
//   old grant, no token minted under it is still valid, so no in-flight call
//   is using the about-to-be-revoked authorization. `ensureGrant` is
//   additionally single-flight per entitlement (the gate is single-instance
//   per machine via the socket bind check) so concurrent token requests
//   coalesce onto one rotation rather than racing.
// ---------------------------------------------------------------------------

const PAM_API_BASE = "https://privilegedaccessmanager.googleapis.com/v1";

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
 *      window where no minted token is still valid, so revoke-and-rotate
 *      has no in-flight tokens to disrupt.
 */
export const DRAIN_MARGIN_MS = 5 * 60 * 1000;

/** Polling: initial delay, max delay, total timeout. */
const POLL_INITIAL_MS = 1_000;
const POLL_MAX_MS = 5_000;
const POLL_TIMEOUT_MS = 120_000;

/**
 * LRO polling for grants.revoke Operations. Observed PAM behavior: revoke
 * settles in ~3 s with sub-second polling; these constants give ~3 polls in
 * that window without burning RTTs against a not-yet-done Operation.
 */
const REVOKE_OP_INITIAL_MS = 500;
const REVOKE_OP_MAX_MS = 2_000;
const REVOKE_OP_TIMEOUT_MS = 30_000;

/** Valid GCP resource ID pattern for short-form entitlement IDs. */
const ENTITLEMENT_ID_PATTERN = /^[a-z][a-z0-9-]*$/;

const LIST_GRANTS_PAGE_SIZE = 100;
/** Safety bound on pagination when scanning for an active grant. */
const LIST_GRANTS_MAX_PAGES = 10;

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

/** Expected full resource path pattern. */
const ENTITLEMENT_PATH_PATTERN = /^projects\/([^/]+)\/locations\/([^/]+)\/entitlements\/([^/]+)$/;

/** Parse a GCP duration string (e.g. "3600s") to seconds. Returns 0 on failure. */
function parseDurationSeconds(duration?: string): number {
  if (!duration) return 0;
  const match = /^(\d+)s$/.exec(duration);
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
}

export interface PamModule {
  /** Ensure an active PAM grant exists for the entitlement. Caches grants. */
  ensureGrant: (entitlementPath: string, justification?: string) => Promise<PamGrantResult>;
  /** Best-effort revoke all cached active grants. Called on shutdown. */
  revokeAll: () => Promise<void>;
}

export interface PamGrantResult {
  /** Full grant resource path. */
  name: string;
  /** Grant state ("ACTIVE" or "ACTIVATED" — PAM ships both spellings). */
  state: string;
  /**
   * Computed grant expiry (createTime + requestedDuration). Callers minting
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
  createTime?: string;
  timeline?: {
    events?: Array<{
      activateTime?: string;
      eventTime?: string;
    }>;
  };
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

// ---------------------------------------------------------------------------
// Entitlement path resolution & validation
// ---------------------------------------------------------------------------

/**
 * Resolve a PAM policy value to a full entitlement resource path.
 *
 * - Short-form (e.g. "prod-db-admin") is expanded using project_id and location.
 * - Full paths are validated against the expected pattern and project_id.
 *
 * Throws on invalid input to prevent path traversal or cross-project escalation.
 */
export function resolveEntitlementPath(
  policy: string,
  projectId: string,
  location: string = "global",
): string {
  if (policy.includes("/")) {
    // Full resource path — validate format and project
    const match = ENTITLEMENT_PATH_PATTERN.exec(policy);
    if (!match) {
      throw new Error(
        `Invalid PAM entitlement path: "${policy}". ` +
          `Expected format: projects/{project}/locations/{location}/entitlements/{id}`,
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
  const grantDuration = `${options.grantDurationSeconds ?? FALLBACK_GRANT_DURATION_SECONDS}s`;
  const sleep =
    options.sleepFn ?? ((ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms)));

  const grantCache = new Map<string, CachedGrant>();
  // Single-flight rotation per entitlement: concurrent `ensureGrant` calls
  // that miss the cache fast-path coalesce onto one rotation. The gate is
  // single-instance per machine (server.ts:91), so in-process coordination
  // is sufficient — no distributed lock needed.
  const inFlightRotations = new Map<string, Promise<PamGrantResult>>();

  function hasUsableLifetime(expiresAt: Date): boolean {
    return expiresAt.getTime() - now() > DRAIN_MARGIN_MS;
  }

  async function pamFetch(url: string, init?: RequestInit): Promise<Response> {
    const token = await getAccessToken();
    return fetchFn(url, {
      ...init,
      headers: {
        ...init?.headers,
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
  }

  type CreateGrantOnceResult = { kind: "ok"; grant: PamGrantResponse } | { kind: "open-conflict" };

  async function createGrantOnce(
    entitlementPath: string,
    justification?: string,
  ): Promise<CreateGrantOnceResult> {
    const url = `${PAM_API_BASE}/${entitlementPath}/grants`;
    const body = {
      requestedDuration: grantDuration,
      justification: {
        unstructuredJustification: justification ?? "gcp-authcalator prod access",
      },
    };

    const res = await pamFetch(url, {
      method: "POST",
      body: JSON.stringify(body),
    });

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

    return { kind: "ok", grant: (await res.json()) as PamGrantResponse };
  }

  interface OpenGrantScan {
    /** First active grant with usable remaining lifetime, if any. */
    usable?: PamGrantResponse & { name: string };
    /**
     * Active grants whose computed expiry has already passed. These are
     * what's blocking createGrant via PAM's state lag — the recovery path
     * revokes them and retries.
     */
    stale: Array<PamGrantResponse & { name: string }>;
    scanned: number;
  }

  async function scanForOpenGrants(entitlementPath: string): Promise<OpenGrantScan> {
    // PAM's grants.list endpoint rejects every `filter=` we've tried as
    // "invalid list filter", so we list unfiltered and bucket client-side.
    // ENDED grants stick around in the response, so on a busy entitlement
    // the open grant may not be on the first page — page through up to
    // LIST_GRANTS_MAX_PAGES before giving up. We re-check createTime+duration:
    // PAM's `state` field can lag actual expiry, and the 409/400 "open Grant"
    // path lands us here precisely in that window.
    const baseUrl = `${PAM_API_BASE}/${entitlementPath}/grants?pageSize=${LIST_GRANTS_PAGE_SIZE}`;
    const stale: Array<PamGrantResponse & { name: string }> = [];
    let scanned = 0;
    let pageToken: string | undefined;

    for (let page = 0; page < LIST_GRANTS_MAX_PAGES; page++) {
      const url = pageToken ? `${baseUrl}&pageToken=${encodeURIComponent(pageToken)}` : baseUrl;
      const res = await pamFetch(url);

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`PAM API error listing grants (${res.status}): ${text}`);
      }

      const data = (await res.json()) as {
        grants?: PamGrantResponse[];
        nextPageToken?: string;
      };
      const grants = data.grants ?? [];
      scanned += grants.length;

      // Once we find a usable grant we're done — the caller wants to reuse
      // it directly without revoking the stale ones (they'll age out on
      // their own and don't block anything).
      for (const g of grants) {
        if (!isActiveState(g.state) || typeof g.name !== "string") continue;
        const named = g as PamGrantResponse & { name: string };
        if (hasUsableLifetime(computeGrantExpiry(named))) {
          return { usable: named, stale, scanned };
        }
        stale.push(named);
      }

      if (!data.nextPageToken) break;
      pageToken = data.nextPageToken;
    }

    return { stale, scanned };
  }

  async function createGrantWithRecovery(
    entitlementPath: string,
    justification?: string,
  ): Promise<PamGrantResponse> {
    const first = await createGrantOnce(entitlementPath, justification);
    if (first.kind === "ok") return first.grant;

    // 409 / 400 FAILED_PRECONDITION ("open Grant"): another grant is open
    // for the same privileged access. Scan to learn whether it's usable
    // (reuse it) or stale (PAM's state lags actual expiry — revoke and
    // retry). revokeGrantAndWait polls the LRO so a single retry suffices.
    const scan = await scanForOpenGrants(entitlementPath);
    if (scan.usable) return scan.usable;

    if (scan.stale.length === 0) {
      throw new Error(
        `PAM grant conflict but no active grant found for "${entitlementPath}" ` +
          `(scanned ${scan.scanned} grant(s) across ${LIST_GRANTS_MAX_PAGES} page(s))`,
      );
    }

    await Promise.allSettled(
      scan.stale.map((g) => revokeGrantAndWait(g.name, "clearing stale grant before retry")),
    );

    const retry = await createGrantOnce(entitlementPath, justification);
    if (retry.kind === "ok") return retry.grant;

    // The retry still conflicts after we waited for revoke to complete.
    // Surface a distinct error so this doesn't look like the original
    // "no active grant found" deadlock.
    throw new Error(
      `PAM grant conflict persists after revoking ${scan.stale.length} stale grant(s) ` +
        `for "${entitlementPath}"`,
    );
  }

  async function pollGrant(grantName: string): Promise<PamGrantResponse> {
    const deadline = now() + POLL_TIMEOUT_MS;
    let delay = POLL_INITIAL_MS;

    while (now() < deadline) {
      await sleep(delay);
      delay = Math.min(delay * 2, POLL_MAX_MS);

      const url = `${PAM_API_BASE}/${grantName}`;
      const res = await pamFetch(url);

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`PAM API error polling grant (${res.status}): ${text}`);
      }

      const grant = (await res.json()) as PamGrantResponse;

      if (isActiveState(grant.state)) {
        return grant;
      }

      if (isTerminalState(grant.state)) {
        throw new Error(`PAM grant entered terminal state ${grant.state}: ${grantName}`);
      }

      // Still pending (APPROVAL_AWAITED, ACTIVATING, SCHEDULED, etc.) —
      // continue polling.
    }

    throw new Error(
      `PAM grant was not activated within ${POLL_TIMEOUT_MS / 1000}s: ${grantName}\n` +
        `  The entitlement may require manual approval`,
    );
  }

  function computeGrantExpiry(grant: PamGrantResponse): Date {
    // Derive expiry from the grant's actual creation time + requested duration.
    // This is critical for the 409 conflict path where we reuse a pre-existing
    // grant that may have been created well before this process found it.
    const durationMs = parseDurationSeconds(grant.requestedDuration) * 1000;
    const createMs = grant.createTime ? new Date(grant.createTime).getTime() : NaN;

    if (durationMs > 0 && !isNaN(createMs)) {
      return new Date(createMs + durationMs);
    }

    // Fallback: conservative 15-minute TTL when API fields are missing
    return new Date(now() + 15 * 60 * 1000);
  }

  function cacheGrant(entitlementPath: string, grant: PamGrantResponse): CachedGrant {
    const entry: CachedGrant = {
      name: grant.name!,
      state: grant.state!,
      expiresAt: computeGrantExpiry(grant),
    };
    grantCache.set(entitlementPath, entry);
    return entry;
  }

  async function ensureGrant(
    entitlementPath: string,
    justification?: string,
  ): Promise<PamGrantResult> {
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

    const rotation = doRotateGrant(entitlementPath, justification, cached);
    inFlightRotations.set(entitlementPath, rotation);
    try {
      return await rotation;
    } finally {
      inFlightRotations.delete(entitlementPath);
    }
  }

  async function doRotateGrant(
    entitlementPath: string,
    justification: string | undefined,
    cached: CachedGrant | undefined,
  ): Promise<PamGrantResult> {
    // Revoke the cached grant before re-creating. Even when our computed
    // expiry has passed, PAM's state can lag and leave the grant in an "open"
    // state that 409s the immediate createGrant. revokeGrantAndWait polls the
    // LRO so the follow-up create doesn't race the revoke.
    if (cached) {
      await revokeGrantAndWait(cached.name, "renewing before expiry");
    }
    grantCache.delete(entitlementPath);

    const grant = await createGrantWithRecovery(entitlementPath, justification);

    if (!grant.name) {
      throw new Error("PAM API returned a grant with no resource name");
    }

    const activated = isActiveState(grant.state) ? grant : await pollGrant(grant.name);
    const entry = cacheGrant(entitlementPath, activated);

    return {
      name: entry.name,
      state: entry.state,
      expiresAt: entry.expiresAt,
      cached: false,
    };
  }

  async function pollRevokeOperation(operationName: string, deadlineMs: number): Promise<void> {
    const deadline = now() + deadlineMs;
    let delay = REVOKE_OP_INITIAL_MS;

    while (now() < deadline) {
      // Sleep first: the initial revoke response already reported `done:false`,
      // so the operation cannot have settled in the microseconds since.
      await sleep(delay);
      delay = Math.min(delay * 2, REVOKE_OP_MAX_MS);

      const res = await pamFetch(`${PAM_API_BASE}/${operationName}`);

      if (res.ok) {
        const op = (await res.json().catch(() => ({}))) as PamOperation;
        if (op.done) {
          if (op.error) {
            // Already-terminal grant or harmless tail-end error. Don't throw —
            // revoke is best-effort, the goal state is reached.
            console.error(
              `pam: revoke operation ${operationName} returned error: ${JSON.stringify(op.error)}`,
            );
          }
          return;
        }
        continue;
      }

      if (res.status === 404) {
        // Operation already garbage-collected; the revoke completed earlier.
        return;
      }

      if (res.status >= 400 && res.status < 500) {
        console.error(`pam: revoke operation ${operationName} polling gave up after ${res.status}`);
        return;
      }
      // 5xx — keep retrying within the deadline budget.
    }

    console.error(`pam: revoke operation ${operationName} did not complete within ${deadlineMs}ms`);
  }

  async function revokeGrantAndWait(
    grantName: string,
    reason: string,
    deadlineMs: number = REVOKE_OP_TIMEOUT_MS,
  ): Promise<void> {
    const startedAt = now();
    try {
      const url = `${PAM_API_BASE}/${grantName}:revoke`;
      const res = await pamFetch(url, {
        method: "POST",
        body: JSON.stringify({ reason: `gcp-authcalator: ${reason}` }),
      });

      if (!res.ok) {
        const text = await res.text();
        console.error(`pam: revoke ${grantName} failed: ${res.status} ${text}`);
        return;
      }

      const op = (await res.json().catch(() => ({}))) as PamOperation;
      if (op.done || !op.name) {
        // Synchronous revoke or untrackable response — assume done.
        if (op.error) {
          console.error(`pam: revoke ${grantName} operation error: ${JSON.stringify(op.error)}`);
        }
        return;
      }

      const remaining = deadlineMs - (now() - startedAt);
      if (remaining > 0) {
        await pollRevokeOperation(op.name, remaining);
      }
    } catch (err) {
      console.error(
        `pam: revoke ${grantName} threw: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  // Fire-and-forget: deadline 0 means revokeGrantAndWait POSTs the revoke,
  // reads its Operation response, and skips polling. Used on shutdown where
  // we want the request landed but not the LRO confirmation.
  function revokeGrantFireAndForget(grantName: string, reason: string): Promise<void> {
    return revokeGrantAndWait(grantName, reason, 0);
  }

  async function revokeAll(): Promise<void> {
    const entries = [...grantCache.values()];
    grantCache.clear();

    if (entries.length === 0) return;

    console.log(`pam: revoking ${entries.length} active grant(s)...`);
    // Shutdown path: fire-and-forget. We don't poll the LRO because the
    // process is exiting and we just want the request landed on PAM's side.
    await Promise.allSettled(
      entries.map((entry) => revokeGrantFireAndForget(entry.name, "shutdown")),
    );
  }

  return { ensureGrant, revokeAll };
}
