// ---------------------------------------------------------------------------
// Cloud Resource Manager v3 client — folder-membership verification
//
// In folder mode the gate must verify that a per-request `?project=` value
// names a descendant of the configured folder before minting a token for it.
// We walk the project's ancestry via CRM v3 `GET /v3/projects/{id}` (reading
// each resource's `parent`) up to a configured hop limit.
//
// Caching:
// - Positive results (project IS a descendant) are cached for 10 minutes.
//   Ancestry rarely changes, and the gate's natural lifetime is hours.
// - Negative results are cached for 30 seconds, so a freshly-moved project
//   becomes routable quickly without us holding a long-tail deny.
// - On CRM 5xx, a previously-confirmed positive is served stale for up to
//   STALE_OK_WINDOW_MS past its expiry. Keeps engineers unblocked through
//   transient CRM outages; the relationship being checked was authoritative
//   at the time of last confirmation. Negatives are never served stale.
//
// Failure modes:
// - 403/404: treated as "not allowed". Defense-in-depth: if the engineer's
//   ADC can't see the project, the gate shouldn't route to it either.
// - 5xx with no stale positive: thrown so the handler surfaces a 503.
// - Single-flight by projectId: concurrent lookups for the same project
//   coalesce onto one in-flight Promise.
// ---------------------------------------------------------------------------

const CRM_API_BASE = "https://cloudresourcemanager.googleapis.com/v3";

const POSITIVE_TTL_MS = 10 * 60 * 1000;
const NEGATIVE_TTL_MS = 30 * 1000;
const STALE_OK_WINDOW_MS = 5 * 60 * 1000;
const MAX_ANCESTRY_HOPS = 8;

export interface FolderMembershipChecker {
  /** Resolves true iff `projectId` is a descendant of the configured folder. */
  isProjectInFolder(projectId: string): Promise<boolean>;
}

export interface FolderMembershipOptions {
  fetchFn?: typeof globalThis.fetch;
  now?: () => number;
}

interface CacheEntry {
  allowed: boolean;
  /** When this cache entry expires (a positive can be served stale beyond this). */
  expiresAt: number;
  /** Hard deadline for serving a stale positive on CRM 5xx. */
  staleUntil: number;
}

export function createFolderMembershipChecker(
  folderId: string,
  getAccessToken: () => Promise<string>,
  options: FolderMembershipOptions = {},
): FolderMembershipChecker {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const now = options.now ?? Date.now;
  const cache = new Map<string, CacheEntry>();
  const inFlight = new Map<string, Promise<boolean>>();
  const targetFolder = `folders/${folderId}`;

  async function walkAncestry(projectId: string): Promise<boolean> {
    const token = await getAccessToken();
    let cursor = `projects/${projectId}`;
    for (let hops = 0; hops < MAX_ANCESTRY_HOPS; hops++) {
      const res = await fetchFn(`${CRM_API_BASE}/${cursor}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      // 403/404 → treat as not-allowed. The engineer's ADC could not see
      // the project, so the gate should not broker access either.
      if (res.status === 403 || res.status === 404) return false;
      if (res.status >= 500) {
        throw new Error(`CRM ${cursor} returned ${res.status}: ${await res.text()}`);
      }
      if (!res.ok) {
        // 4xx (other than 403/404) — bad request, malformed projectId, etc.
        // Treat as not-allowed; the caller will surface 400-equivalent to
        // the client.
        return false;
      }
      const body = (await res.json()) as { parent?: string };
      if (!body.parent) return false; // hit organization root without matching folder
      if (body.parent === targetFolder) return true;
      // Only continue walking through folders. Crossing into organizations/
      // means we've left the folder subtree.
      if (!body.parent.startsWith("folders/")) return false;
      cursor = body.parent;
    }
    throw new Error(
      `CRM ancestry walk exceeded ${MAX_ANCESTRY_HOPS} hops for project "${projectId}"`,
    );
  }

  async function isProjectInFolder(projectId: string): Promise<boolean> {
    const t = now();
    const hit = cache.get(projectId);
    if (hit && hit.expiresAt > t) return hit.allowed;

    const pending = inFlight.get(projectId);
    if (pending) return pending;

    const work = (async () => {
      try {
        const allowed = await walkAncestry(projectId);
        const cachedAt = now();
        cache.set(projectId, {
          allowed,
          expiresAt: cachedAt + (allowed ? POSITIVE_TTL_MS : NEGATIVE_TTL_MS),
          // Stale-OK applies only to positives; negatives keep their hard expiry.
          staleUntil: allowed ? cachedAt + POSITIVE_TTL_MS + STALE_OK_WINDOW_MS : 0,
        });
        return allowed;
      } catch (err) {
        // CRM 5xx: extend a confirmed positive within the stale-OK window
        // so a brief outage doesn't pause folder-mode prod access.
        if (hit && hit.allowed && hit.staleUntil > now()) {
          return true;
        }
        throw err;
      } finally {
        inFlight.delete(projectId);
      }
    })();
    inFlight.set(projectId, work);
    return work;
  }

  return { isProjectInFolder };
}
