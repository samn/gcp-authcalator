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
  getProjectNumber: () => Promise<string>;
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
  // When a source client is injected via options (tests), preserve it across
  // credentials-expired errors so the test fixture survives the reset path.
  const sourceClientInjected = options.sourceClient !== undefined;

  // Per-scope-and-ttl caches for dev tokens (impersonated)
  const devTokenCaches = new Map<string, CachedToken>();
  const impersonatedClients = new Map<string, AuthClient>();

  // Default impersonated client (from options, for testing)
  const defaultImpersonatedClient: AuthClient | null = options.impersonatedClient ?? null;

  // Other caches
  let emailCache: string | null = null;
  let projectNumberCache: string | null = null;
  let universeDomainCache: string | null = null;

  /**
   * Run an ADC-touching operation, normalising reauth/invalid_grant errors
   * into `CredentialsExpiredError`. On a credentials-expired result we drop
   * the cached source + impersonated clients so a follow-up call (after the
   * engineer reruns `gcloud auth application-default login` on the host)
   * re-reads `application_default_credentials.json` without a daemon
   * restart. Token caches are cleared too — they were minted with a
   * refresh token that is now known to be dead.
   */
  async function withAdcMapping<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (err) {
      const mapped = mapAdcError(err);
      if (mapped instanceof CredentialsExpiredError) {
        if (!sourceClientInjected) sourceClient = null;
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
        throw new Error(`Failed to get identity: tokeninfo returned ${resp.status}`);
      }

      const data = (await resp.json()) as { email?: string };

      if (!data.email) {
        throw new Error("Failed to get identity: no email in tokeninfo response");
      }

      emailCache = data.email;
      return emailCache;
    });
  }

  async function getProjectNumber(): Promise<string> {
    if (projectNumberCache) return projectNumberCache;

    return withAdcMapping(async () => {
      const client = await getSourceClient();
      const { token } = await client.getAccessToken();

      if (!token) {
        throw new Error("Failed to get project number: no access token available");
      }

      const resp = await fetchFn(
        `https://cloudresourcemanager.googleapis.com/v3/projects/${encodeURIComponent(config.project_id)}`,
        { headers: { Authorization: `Bearer ${token}` } },
      );

      if (!resp.ok) {
        throw new Error(`Failed to get project number: CRM API returned ${resp.status}`);
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

      projectNumberCache = number;
      return projectNumberCache;
    });
  }

  async function getUniverseDomain(): Promise<string> {
    if (universeDomainCache) return universeDomainCache;

    const client = await getSourceClient();
    universeDomainCache = client.universeDomain;
    return universeDomainCache;
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
