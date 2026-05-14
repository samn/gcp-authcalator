import { GoogleAuth } from "google-auth-library";
import { Impersonated } from "google-auth-library";
import type { AuthClient } from "google-auth-library";
import { DEFAULT_SCOPES, type GateConfig } from "../config.ts";
import { CredentialsExpiredError, mapAdcError } from "./credentials-error.ts";
import type { CachedToken } from "./types.ts";

/** Minimum remaining lifetime before we re-mint a cached token (5 minutes). */
const CACHE_MARGIN_MS = 5 * 60 * 1000;

/** Fallback token lifetime when not configured (1 hour). */
const FALLBACK_LIFETIME = 3600;

/**
 * Extract the OAuth-style `error` field from a non-OK response and format
 * it as a suffix to append to the thrown error message. Returns `""` if
 * the body is missing, malformed, or omits the field, so the caller's
 * status-code message remains the fallback. Cap at 200 chars to bound the
 * audit-log / stderr cost when the upstream returns an unexpectedly large
 * payload.
 */
async function readOAuthErrorDetail(resp: Response): Promise<string> {
  let text: string;
  try {
    text = await resp.text();
  } catch {
    return "";
  }
  if (!text) return "";
  try {
    const body = JSON.parse(text) as { error?: unknown };
    if (typeof body.error === "string" && body.error.length > 0) {
      const error = body.error.slice(0, 200);
      return `: ${error}`;
    }
  } catch {
    // Non-JSON body — fall through to the truncated raw text.
  }
  return `: ${text.slice(0, 200)}`;
}

export interface AuthModuleOptions {
  /** Pre-built source client (ADC) — for testing. */
  sourceClient?: AuthClient;
  /** Pre-built impersonated client — for testing. */
  impersonatedClient?: AuthClient;
  /** Override fetch for tokeninfo calls — for testing. */
  fetchFn?: typeof globalThis.fetch;
}

export interface AuthModule {
  mintDevToken: (scopes?: string[], ttlSeconds?: number) => Promise<CachedToken>;
  mintProdToken: (scopes?: string[], ttlSeconds?: number) => Promise<CachedToken>;
  getIdentityEmail: () => Promise<string>;
  /**
   * Resolve the numeric project ID for a project. Cached per project. The
   * gate calls this lazily — in project mode with the configured project,
   * in folder mode with the per-request `?project=` value (after the
   * folder-membership check passes).
   */
  getProjectNumber: (projectId: string) => Promise<string>;
  getUniverseDomain: () => Promise<string>;
  /** Expose the ADC source client (needed for PAM API calls). */
  getSourceClient: () => Promise<AuthClient>;
  /**
   * Mint a fresh ADC access token for PAM/internal use, with reauth/invalid_grant
   * errors normalised to `CredentialsExpiredError` and the cached source client
   * reset on failure. Prefer this over `getSourceClient().getAccessToken()`.
   */
  getSourceAccessToken: () => Promise<string>;
}

/**
 * Create the authentication module.
 *
 * - mintDevToken: impersonated service account token (cached per scope set, re-minted at <5 min remaining)
 * - mintProdToken: engineer's own ADC token (uncached — always fresh)
 * - getIdentityEmail: email from the ADC identity (cached for daemon lifetime)
 * - getProjectNumber: numeric project ID from Cloud Resource Manager (cached permanently)
 * - getUniverseDomain: GCP universe domain from GoogleAuth (cached permanently)
 */
export function createAuthModule(config: GateConfig, options: AuthModuleOptions = {}): AuthModule {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const configTtl = config.token_ttl_seconds ?? FALLBACK_LIFETIME;

  // Lazily initialized clients
  let sourceClient: AuthClient | null = options.sourceClient ?? null;

  // Per-scope-and-ttl caches for dev tokens (impersonated)
  const devTokenCaches = new Map<string, CachedToken>();
  const impersonatedClients = new Map<string, AuthClient>();

  // Default impersonated client (from options, for testing)
  const defaultImpersonatedClient: AuthClient | null = options.impersonatedClient ?? null;

  // Other caches
  let emailCache: string | null = null;
  // Numeric project IDs are immutable once a project exists. Cache for the
  // gate's lifetime — in folder mode the gate may resolve many projects.
  const projectNumberCache = new Map<string, string>();
  let universeDomainCache: string | null = null;

  /**
   * Run an ADC-touching operation, normalising reauth/invalid_grant errors
   * into `CredentialsExpiredError`. On a credentials-expired result we drop
   * the cached source + impersonated clients so a follow-up call (after the
   * engineer reruns `gcloud auth application-default login` on the host)
   * re-reads `application_default_credentials.json` without a daemon
   * restart. Token caches are cleared too — they were minted with a
   * refresh token that is now known to be dead.
   *
   * An injected source client (test fixture) is preserved so the reset
   * path doesn't blow away the mock the test depends on.
   */
  async function withAdcMapping<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (err) {
      const mapped = mapAdcError(err);
      if (mapped instanceof CredentialsExpiredError) {
        if (!options.sourceClient) sourceClient = null;
        impersonatedClients.clear();
        devTokenCaches.clear();
      }
      throw mapped;
    }
  }

  /** Build a stable cache key from a scope set and TTL. */
  function cacheKey(scopes: string[], ttl: number): string {
    return [...scopes].sort().join(",") + ":" + ttl;
  }

  async function getSourceClient(): Promise<AuthClient> {
    if (!sourceClient) {
      const auth = new GoogleAuth({ scopes: DEFAULT_SCOPES });
      sourceClient = await auth.getClient();
    }
    return sourceClient;
  }

  async function getImpersonatedClient(scopes: string[], ttl: number): Promise<AuthClient> {
    const key = cacheKey(scopes, ttl);

    // Use the injected client for default scopes + default TTL (testing support)
    if (defaultImpersonatedClient && key === cacheKey(DEFAULT_SCOPES, configTtl)) {
      return defaultImpersonatedClient;
    }

    let client = impersonatedClients.get(key);
    if (!client) {
      // service_account is required for dev tokens. The schema guarantees it
      // is set whenever mintDevToken is reachable (project mode with
      // service_account configured); folder mode has no dev tier and rejects
      // service_account at config-validation time.
      if (!config.service_account) {
        throw new Error(
          "Internal error: getImpersonatedClient requires a configured service_account",
        );
      }
      const source = await getSourceClient();
      client = new Impersonated({
        sourceClient: source,
        targetPrincipal: config.service_account,
        targetScopes: scopes,
        lifetime: ttl,
      });
      impersonatedClients.set(key, client);
    }
    return client;
  }

  function isCacheValid(cached: CachedToken | null | undefined): cached is CachedToken {
    if (!cached) return false;
    return cached.expires_at.getTime() - Date.now() > CACHE_MARGIN_MS;
  }

  /** Extract expiry from the client's credentials, falling back to configured TTL. */
  function expiryFromCredentials(client: AuthClient, ttl: number): Date {
    const expMs = client.credentials?.expiry_date;
    if (expMs) return new Date(expMs);
    return new Date(Date.now() + ttl * 1000);
  }

  async function mintDevToken(scopes?: string[], ttlSeconds?: number): Promise<CachedToken> {
    const effectiveScopes = scopes ?? DEFAULT_SCOPES;
    const effectiveTtl = ttlSeconds ?? configTtl;
    const key = cacheKey(effectiveScopes, effectiveTtl);

    const cached = devTokenCaches.get(key);
    if (isCacheValid(cached)) {
      return cached;
    }

    return withAdcMapping(async () => {
      const client = await getImpersonatedClient(effectiveScopes, effectiveTtl);
      const { token } = await client.getAccessToken();

      if (!token) {
        throw new Error("Failed to mint dev token: no access token returned");
      }

      const result: CachedToken = {
        access_token: token,
        expires_at: expiryFromCredentials(client, effectiveTtl),
      };
      devTokenCaches.set(key, result);
      return result;
    });
  }

  async function mintProdToken(scopes?: string[], ttlSeconds?: number): Promise<CachedToken> {
    // Prod tokens use the engineer's own ADC credentials (not impersonated).
    // Never cached — always mint a fresh one.
    const effectiveScopes = scopes ?? DEFAULT_SCOPES;
    const effectiveTtl = ttlSeconds ?? configTtl;

    return withAdcMapping(async () => {
      let client: AuthClient;
      const scopesSorted = [...effectiveScopes].sort().join(",");
      const defaultSorted = [...DEFAULT_SCOPES].sort().join(",");

      if (scopesSorted === defaultSorted) {
        // Default scopes — reuse the cached source client
        client = await getSourceClient();
      } else {
        // Custom scopes — create a fresh GoogleAuth with those scopes
        const auth = new GoogleAuth({ scopes: effectiveScopes });
        client = await auth.getClient();
      }

      const { token } = await client.getAccessToken();

      if (!token) {
        throw new Error("Failed to mint prod token: no access token returned");
      }

      // Cap expires_at to the effective TTL. The underlying ADC token may remain
      // valid at Google beyond this time, but gcp-authcalator will treat it as
      // expired once the cap is reached.
      const credentialExpiry = expiryFromCredentials(client, effectiveTtl);
      const ttlCap = new Date(Date.now() + effectiveTtl * 1000);
      const expires_at = credentialExpiry < ttlCap ? credentialExpiry : ttlCap;

      return {
        access_token: token,
        expires_at,
      };
    });
  }

  async function getIdentityEmail(): Promise<string> {
    if (emailCache) return emailCache;

    return withAdcMapping(async () => {
      const client = await getSourceClient();
      const { token } = await client.getAccessToken();

      if (!token) {
        throw new Error("Failed to get identity: no access token available");
      }

      const resp = await fetchFn(
        `https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(token)}`,
      );

      if (!resp.ok) {
        // Surface the OAuth structured error (e.g. `invalid_token`) so
        // `mapAdcError` can recognise a revoked access token and convert
        // the failure into `CredentialsExpiredError`. The cached access
        // token can still look locally valid after `gcloud auth
        // application-default revoke` — only tokeninfo notices.
        const detail = await readOAuthErrorDetail(resp);
        throw new Error(`Failed to get identity: tokeninfo returned ${resp.status}${detail}`);
      }

      const data = (await resp.json()) as { email?: string };

      if (!data.email) {
        throw new Error("Failed to get identity: no email in tokeninfo response");
      }

      emailCache = data.email;
      return emailCache;
    });
  }

  async function getProjectNumber(projectId: string): Promise<string> {
    const cached = projectNumberCache.get(projectId);
    if (cached) return cached;

    return withAdcMapping(async () => {
      const client = await getSourceClient();
      const { token } = await client.getAccessToken();

      if (!token) {
        throw new Error("Failed to get project number: no access token available");
      }

      const resp = await fetchFn(
        `https://cloudresourcemanager.googleapis.com/v3/projects/${encodeURIComponent(projectId)}`,
        { headers: { Authorization: `Bearer ${token}` } },
      );

      if (!resp.ok) {
        const detail = await readOAuthErrorDetail(resp);
        throw new Error(`Failed to get project number: CRM API returned ${resp.status}${detail}`);
      }

      const data = (await resp.json()) as { name?: string };

      if (!data.name) {
        throw new Error("Failed to get project number: no name in CRM API response");
      }

      const parts = data.name.split("/");
      const number = parts[1];

      if (!number) {
        throw new Error(`Failed to get project number: unexpected name format "${data.name}"`);
      }

      projectNumberCache.set(projectId, number);
      return number;
    });
  }

  async function getUniverseDomain(): Promise<string> {
    if (universeDomainCache) return universeDomainCache;

    return withAdcMapping(async () => {
      const client = await getSourceClient();
      universeDomainCache = client.universeDomain;
      return universeDomainCache;
    });
  }

  async function getSourceAccessToken(): Promise<string> {
    return withAdcMapping(async () => {
      const client = await getSourceClient();
      const { token } = await client.getAccessToken();
      if (!token) {
        throw new Error("Failed to get ADC access token: no token returned");
      }
      return token;
    });
  }

  return {
    mintDevToken,
    mintProdToken,
    getIdentityEmail,
    getProjectNumber,
    getUniverseDomain,
    getSourceClient,
    getSourceAccessToken,
  };
}
