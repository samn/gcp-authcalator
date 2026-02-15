import { GoogleAuth } from "google-auth-library";
import { Impersonated } from "google-auth-library";
import type { AuthClient } from "google-auth-library";
import type { GateConfig } from "../config.ts";
import type { CachedToken } from "./types.ts";

/** Minimum remaining lifetime before we re-mint a cached token (5 minutes). */
const CACHE_MARGIN_MS = 5 * 60 * 1000;

/** Default token lifetime for impersonated tokens (1 hour). */
const DEFAULT_LIFETIME = 3600;

/** Default scopes for impersonated (dev) tokens. */
const DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"];

export interface AuthModuleOptions {
  /** Pre-built source client (ADC) — for testing. */
  sourceClient?: AuthClient;
  /** Pre-built impersonated client — for testing. */
  impersonatedClient?: AuthClient;
  /** Override fetch for tokeninfo calls — for testing. */
  fetchFn?: typeof globalThis.fetch;
}

export interface AuthModule {
  mintDevToken: () => Promise<CachedToken>;
  mintProdToken: () => Promise<CachedToken>;
  getIdentityEmail: () => Promise<string>;
}

/**
 * Create the authentication module.
 *
 * - mintDevToken: impersonated service account token (cached, re-minted at <5 min remaining)
 * - mintProdToken: engineer's own ADC token (uncached — always fresh)
 * - getIdentityEmail: email from the ADC identity (cached for daemon lifetime)
 */
export function createAuthModule(config: GateConfig, options: AuthModuleOptions = {}): AuthModule {
  const fetchFn = options.fetchFn ?? globalThis.fetch;

  // Lazily initialized clients
  let sourceClient: AuthClient | null = options.sourceClient ?? null;
  let impersonatedClient: AuthClient | null = options.impersonatedClient ?? null;

  // Caches
  let devTokenCache: CachedToken | null = null;
  let emailCache: string | null = null;

  async function getSourceClient(): Promise<AuthClient> {
    if (!sourceClient) {
      const auth = new GoogleAuth({ scopes: DEFAULT_SCOPES });
      sourceClient = await auth.getClient();
    }
    return sourceClient;
  }

  async function getImpersonatedClient(): Promise<AuthClient> {
    if (!impersonatedClient) {
      const source = await getSourceClient();
      impersonatedClient = new Impersonated({
        sourceClient: source,
        targetPrincipal: config.service_account,
        targetScopes: DEFAULT_SCOPES,
        lifetime: DEFAULT_LIFETIME,
      });
    }
    return impersonatedClient;
  }

  function isCacheValid(cached: CachedToken | null): cached is CachedToken {
    if (!cached) return false;
    return cached.expires_at.getTime() - Date.now() > CACHE_MARGIN_MS;
  }

  /** Extract expiry from the client's credentials, falling back to DEFAULT_LIFETIME. */
  function expiryFromCredentials(client: AuthClient): Date {
    const expMs = client.credentials?.expiry_date;
    if (expMs) return new Date(expMs);
    return new Date(Date.now() + DEFAULT_LIFETIME * 1000);
  }

  async function mintDevToken(): Promise<CachedToken> {
    if (isCacheValid(devTokenCache)) {
      return devTokenCache;
    }

    const client = await getImpersonatedClient();
    const { token } = await client.getAccessToken();

    if (!token) {
      throw new Error("Failed to mint dev token: no access token returned");
    }

    devTokenCache = {
      access_token: token,
      expires_at: expiryFromCredentials(client),
    };
    return devTokenCache;
  }

  async function mintProdToken(): Promise<CachedToken> {
    // Prod tokens use the engineer's own ADC credentials (not impersonated).
    // Never cached — always mint a fresh one.
    const client = await getSourceClient();
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

  return { mintDevToken, mintProdToken, getIdentityEmail };
}
