// ---------------------------------------------------------------------------
// GCP Privileged Access Manager (PAM) module
//
// Requests just-in-time PAM grants to temporarily elevate the engineer's
// IAM roles. Grants are cached and best-effort revoked on shutdown.
// ---------------------------------------------------------------------------

const PAM_API_BASE = "https://privilegedaccessmanager.googleapis.com/v1";

/** Fallback grant duration when not configured (1 hour). */
const FALLBACK_GRANT_DURATION_SECONDS = 3600;

/** Minimum remaining lifetime before we re-request a cached grant (5 minutes). */
const CACHE_MARGIN_MS = 5 * 60 * 1000;

/** Polling: initial delay, max delay, total timeout. */
const POLL_INITIAL_MS = 1_000;
const POLL_MAX_MS = 5_000;
const POLL_TIMEOUT_MS = 120_000;

/** Valid GCP resource ID pattern for short-form entitlement IDs. */
const ENTITLEMENT_ID_PATTERN = /^[a-z][a-z0-9-]*$/;

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
  /** Grant state (should be "ACTIVATED"). */
  state: string;
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

  const grantCache = new Map<string, CachedGrant>();

  function isCacheValid(cached: CachedGrant | undefined): cached is CachedGrant {
    if (!cached) return false;
    return cached.expiresAt.getTime() - now() > CACHE_MARGIN_MS;
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

  async function createGrant(
    entitlementPath: string,
    justification?: string,
  ): Promise<PamGrantResponse> {
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
      // Grant already exists — try to find and reuse the active one
      return findActiveGrant(entitlementPath);
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
        return findActiveGrant(entitlementPath);
      }

      throw new Error(`PAM API error (${res.status}): ${text}`);
    }

    return (await res.json()) as PamGrantResponse;
  }

  async function findActiveGrant(entitlementPath: string): Promise<PamGrantResponse> {
    const url = `${PAM_API_BASE}/${entitlementPath}/grants?filter=state%3D%22ACTIVATED%22`;
    const res = await pamFetch(url);

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`PAM API error listing grants (${res.status}): ${text}`);
    }

    const data = (await res.json()) as { grants?: PamGrantResponse[] };
    const active = data.grants?.[0];

    if (!active?.name) {
      throw new Error(`PAM grant conflict but no active grant found for "${entitlementPath}"`);
    }

    return active;
  }

  async function pollGrant(grantName: string): Promise<PamGrantResponse> {
    const deadline = now() + POLL_TIMEOUT_MS;
    let delay = POLL_INITIAL_MS;

    while (now() < deadline) {
      await new Promise((r) => setTimeout(r, delay));
      delay = Math.min(delay * 2, POLL_MAX_MS);

      const url = `${PAM_API_BASE}/${grantName}`;
      const res = await pamFetch(url);

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`PAM API error polling grant (${res.status}): ${text}`);
      }

      const grant = (await res.json()) as PamGrantResponse;

      if (grant.state === "ACTIVATED") {
        return grant;
      }

      if (grant.state === "DENIED" || grant.state === "REVOKED" || grant.state === "ENDED") {
        throw new Error(`PAM grant was ${grant.state}: ${grantName}`);
      }

      // Still pending (APPROVAL_AWAITED, ACTIVATING, etc.) — continue polling
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

  function cacheGrant(entitlementPath: string, grant: PamGrantResponse): void {
    grantCache.set(entitlementPath, {
      name: grant.name!,
      state: grant.state!,
      expiresAt: computeGrantExpiry(grant),
    });
  }

  async function ensureGrant(
    entitlementPath: string,
    justification?: string,
  ): Promise<PamGrantResult> {
    // Check cache first
    const cached = grantCache.get(entitlementPath);
    if (isCacheValid(cached)) {
      return { name: cached.name, state: cached.state, cached: true };
    }

    // Request a new grant
    const grant = await createGrant(entitlementPath, justification);

    if (!grant.name) {
      throw new Error("PAM API returned a grant with no resource name");
    }

    let activated: PamGrantResponse;

    if (grant.state === "ACTIVATED") {
      activated = grant;
    } else {
      // Poll until activated
      activated = await pollGrant(grant.name);
    }

    cacheGrant(entitlementPath, activated);

    return { name: activated.name!, state: activated.state!, cached: false };
  }

  async function revokeGrant(grantName: string): Promise<void> {
    try {
      const url = `${PAM_API_BASE}/${grantName}:revoke`;
      const res = await pamFetch(url, {
        method: "POST",
        body: JSON.stringify({ reason: "gcp-authcalator shutdown" }),
      });

      if (!res.ok) {
        const text = await res.text();
        console.error(`pam: failed to revoke grant ${grantName}: ${res.status} ${text}`);
      }
    } catch (err) {
      console.error(
        `pam: failed to revoke grant ${grantName}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  async function revokeAll(): Promise<void> {
    const entries = [...grantCache.values()];
    grantCache.clear();

    if (entries.length === 0) return;

    console.log(`pam: revoking ${entries.length} active grant(s)...`);
    await Promise.allSettled(entries.map((entry) => revokeGrant(entry.name)));
  }

  return { ensureGrant, revokeAll };
}
