import { GoogleAuth } from "google-auth-library";
import { Impersonated } from "google-auth-library";
import type { AuthClient } from "google-auth-library";
import { DEFAULT_SCOPES, type GateConfig } from "../config.ts";
import type { CachedToken } from "./types.ts";

/** Minimum remaining lifetime before we re-mint a cached token (5 minutes). */
const CACHE_MARGIN_MS = 5 * 60 * 1000;

/** Default token lifetime for impersonated tokens (1 hour). */
const DEFAULT_LIFETIME = 3600;

export interface AuthModuleOptions {
  /** Pre-built source client (ADC) — for testing. */
  sourceClient?: AuthClient;
  /** Pre-built impersonated client — for testing. */
  impersonatedClient?: AuthClient;
  /** Override fetch for tokeninfo calls — for testing. */
  fetchFn?: typeof globalThis.fetch;
}

export interface AuthModule {
  mintDevToken: (scopes?: string[]) => Promise<CachedToken>;
  mintProdToken: (scopes?: string[]) => Promise<CachedToken>;
  getIdentityEmail: () => Promise<string>;
  getProjectNumber: () => Promise<string>;
  getUniverseDomain: () => Promise<string>;
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

  // Lazily initialized clients
  let sourceClient: AuthClient | null = options.sourceClient ?? null;

  // Per-scope caches for dev tokens (impersonated)
  const devTokenCaches = new Map<string, CachedToken>();
  const impersonatedClients = new Map<string, AuthClient>();

  // Default impersonated client (from options, for testing)
  const defaultImpersonatedClient: AuthClient | null = options.impersonatedClient ?? null;

  // Other caches
  let emailCache: string | null = null;
  let projectNumberCache: string | null = null;
  let universeDomainCache: string | null = null;

  /** Build a stable cache key from a scope set. */
  function scopeKey(scopes: string[]): string {
    return [...scopes].sort().join(",");
  }

  async function getSourceClient(): Promise<AuthClient> {
    if (!sourceClient) {
      const auth = new GoogleAuth({ scopes: DEFAULT_SCOPES });
      sourceClient = await auth.getClient();
    }
    return sourceClient;
  }

  async function getImpersonatedClient(scopes: string[]): Promise<AuthClient> {
    const key = scopeKey(scopes);

    // Use the injected client for default scopes (testing support)
    if (defaultImpersonatedClient && key === scopeKey(DEFAULT_SCOPES)) {
      return defaultImpersonatedClient;
    }

    let client = impersonatedClients.get(key);
    if (!client) {
      const source = await getSourceClient();
      client = new Impersonated({
        sourceClient: source,
        targetPrincipal: config.service_account,
        targetScopes: scopes,
        lifetime: DEFAULT_LIFETIME,
      });
      impersonatedClients.set(key, client);
    }
    return client;
  }

  function isCacheValid(cached: CachedToken | null | undefined): cached is CachedToken {
    if (!cached) return false;
    return cached.expires_at.getTime() - Date.now() > CACHE_MARGIN_MS;
  }

  /** Extract expiry from the client's credentials, falling back to DEFAULT_LIFETIME. */
  function expiryFromCredentials(client: AuthClient): Date {
    const expMs = client.credentials?.expiry_date;
    if (expMs) return new Date(expMs);
    return new Date(Date.now() + DEFAULT_LIFETIME * 1000);
  }

  async function mintDevToken(scopes?: string[]): Promise<CachedToken> {
    const effectiveScopes = scopes ?? DEFAULT_SCOPES;
    const key = scopeKey(effectiveScopes);

    const cached = devTokenCaches.get(key);
    if (isCacheValid(cached)) {
      return cached;
    }

    const client = await getImpersonatedClient(effectiveScopes);
    const { token } = await client.getAccessToken();

    if (!token) {
      throw new Error("Failed to mint dev token: no access token returned");
    }

    const result: CachedToken = {
      access_token: token,
      expires_at: expiryFromCredentials(client),
    };
    devTokenCaches.set(key, result);
    return result;
  }

  async function mintProdToken(scopes?: string[]): Promise<CachedToken> {
    // Prod tokens use the engineer's own ADC credentials (not impersonated).
    // Never cached — always mint a fresh one.
    let client: AuthClient;
    const effectiveScopes = scopes ?? DEFAULT_SCOPES;

    if (scopeKey(effectiveScopes) === scopeKey(DEFAULT_SCOPES)) {
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

    return {
      access_token: token,
      expires_at: expiryFromCredentials(client),
    };
  }

  async function getIdentityEmail(): Promise<string> {
    if (emailCache) return emailCache;

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
  }

  async function getProjectNumber(): Promise<string> {
    if (projectNumberCache) return projectNumberCache;

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
  }

  async function getUniverseDomain(): Promise<string> {
    if (universeDomainCache) return universeDomainCache;

    const client = await getSourceClient();
    universeDomainCache = client.universeDomain;
    return universeDomainCache;
  }

  return { mintDevToken, mintProdToken, getIdentityEmail, getProjectNumber, getUniverseDomain };
}
