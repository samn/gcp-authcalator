import { GoogleAuth } from "google-auth-library";
import { Impersonated } from "google-auth-library";
import type { AuthClient } from "google-auth-library";
import { DEFAULT_SCOPES, type GateConfig } from "../config.ts";
import { CredentialsExpiredError, mapAdcError } from "./credentials-error.ts";
import type { CachedToken } from "./types.ts";
import { tokenRefreshAt } from "../token-cache.ts";

/** Fallback token lifetime when not configured (1 hour). */
const FALLBACK_LIFETIME = 3600;

/**
 * Wall-clock limit for one authentication operation. GoogleAuth has its own
 * transport retries, but it does not provide a deadline that bounds every ADC
 * discovery and token-refresh path. Keeping the deadline here prevents one
 * wedged credential provider or Google API response from occupying a gate
 * request indefinitely.
 */
const AUTH_OPERATION_TIMEOUT_MS = 30_000;

/** A Google authentication operation exceeded its wall-clock deadline. */
export class AuthTimeoutError extends Error {
  constructor(
    readonly operation: string,
    readonly timeoutMs: number,
  ) {
    super(
      `Authentication timed out after ${timeoutMs}ms while ${operation}. ` +
        "Check network connectivity from the gate host to Google APIs, then retry.",
    );
    this.name = "AuthTimeoutError";
  }
}

/**
 * Bound work from APIs which do not accept an AbortSignal (notably
 * google-auth-library). Promise.race installs rejection handlers on both
 * promises, so a late rejection from abandoned library work is still handled.
 */
async function withAuthTimeout<T>(
  operation: string,
  timeoutMs: number,
  work: () => Promise<T>,
  onTimeout?: () => void,
): Promise<T> {
  const timeoutError = new AuthTimeoutError(operation, timeoutMs);
  let timer: ReturnType<typeof setTimeout> | undefined;

  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      // Reject first so an AbortError raised synchronously by onTimeout cannot
      // win the race and obscure the actionable timeout error.
      reject(timeoutError);
      onTimeout?.();
    }, timeoutMs);
    timer.unref?.();
  });

  try {
    return await Promise.race([Promise.resolve().then(work), timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

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
  /** Override GoogleAuth construction — for testing ADC discovery. */
  googleAuthFactory?: (scopes: string[]) => { getClient: () => Promise<AuthClient> };
  /** Override the wall-clock deadline for each auth operation — for testing. */
  operationTimeoutMs?: number;
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
  const operationTimeoutMs = options.operationTimeoutMs ?? AUTH_OPERATION_TIMEOUT_MS;
  const googleAuthFactory =
    options.googleAuthFactory ?? ((scopes: string[]) => new GoogleAuth({ scopes }));

  if (!Number.isFinite(operationTimeoutMs) || operationTimeoutMs <= 0) {
    throw new Error("Authentication operation timeout must be a positive finite number");
  }

  /** Fetch and fully buffer a small Google API response under one deadline. */
  async function fetchAuthResponse(
    url: string,
    init: RequestInit,
    operation: string,
  ): Promise<Response> {
    const controller = new AbortController();
    return withAuthTimeout(
      operation,
      operationTimeoutMs,
      async () => {
        const response = await fetchFn(url, { ...init, signal: controller.signal });
        // fetch() resolves at headers. Buffering here keeps a peer that stalls
        // mid-body under the same wall-clock deadline.
        const body = await response.arrayBuffer();
        return new Response(body.byteLength > 0 ? body : null, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      },
      () => controller.abort(),
    );
  }

  // Lazily initialized clients
  let sourceClient: AuthClient | null = options.sourceClient ?? null;
  let sourceClientInitialization: Promise<{
    client: AuthClient;
    generation: number;
  }> | null = null;
  let sourceClientGeneration = 0;

  // Per-scope-and-ttl caches for dev tokens (impersonated)
  const devTokenCaches = new Map<string, CachedToken>();
  const devTokenRefreshTimes = new Map<string, number>();
  const devTokenRefreshes = new Map<string, Promise<CachedToken>>();
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
   * refresh token that is now known to be dead. The identity email cache
   * is also dropped: the engineer may re-login as a different account, and
   * the email feeds audit attribution and PAM requester filtering, so it
   * must re-resolve against the new credentials.
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
        if (!options.sourceClient) {
          // Fence any ADC discovery which began before this failure. The
          // underlying google-auth-library work cannot be cancelled, so a
          // late result must not repopulate the cache with the superseded
          // credentials.
          sourceClientGeneration++;
          sourceClient = null;
          sourceClientInitialization = null;
        }
        impersonatedClients.clear();
        devTokenCaches.clear();
        devTokenRefreshTimes.clear();
        devTokenRefreshes.clear();
        emailCache = null;
      }
      throw mapped;
    }
  }

  /** Build a stable cache key from a scope set and TTL. */
  function cacheKey(scopes: string[], ttl: number): string {
    return [...scopes].sort().join(",") + ":" + ttl;
  }

  async function getSourceClient(): Promise<AuthClient> {
    while (!sourceClient) {
      let initialization = sourceClientInitialization;
      if (!initialization) {
        const generation = sourceClientGeneration;
        const auth = googleAuthFactory(DEFAULT_SCOPES);
        initialization = withAuthTimeout(
          "loading Application Default Credentials",
          operationTimeoutMs,
          () => auth.getClient(),
        ).then((client) => ({ client, generation }));
        sourceClientInitialization = initialization;
      }

      try {
        const initialized = await initialization;
        if (initialized.generation === sourceClientGeneration) {
          sourceClient = initialized.client;
        }
      } finally {
        // Promise identity matters when a credentials-expired reset starts a
        // replacement discovery before superseded work has settled.
        if (sourceClientInitialization === initialization) {
          sourceClientInitialization = null;
        }
      }
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

  function isCacheValid(
    cached: CachedToken | null | undefined,
    refreshAt: number | undefined,
  ): cached is CachedToken {
    if (!cached) return false;
    return refreshAt !== undefined && Date.now() < refreshAt;
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
    if (isCacheValid(cached, devTokenRefreshTimes.get(key))) {
      return cached;
    }

    const existingRefresh = devTokenRefreshes.get(key);
    if (existingRefresh) return existingRefresh;

    const refresh = withAdcMapping(async () => {
      const client = await getImpersonatedClient(effectiveScopes, effectiveTtl);
      const { token } = await withAuthTimeout(
        "minting an impersonated development token",
        operationTimeoutMs,
        () => client.getAccessToken(),
      );

      if (!token) {
        throw new Error("Failed to mint dev token: no access token returned");
      }

      const result: CachedToken = {
        access_token: token,
        expires_at: expiryFromCredentials(client, effectiveTtl),
      };
      devTokenCaches.set(key, result);
      devTokenRefreshTimes.set(key, tokenRefreshAt(result.expires_at.getTime(), Date.now()));
      return result;
    });
    devTokenRefreshes.set(key, refresh);
    try {
      return await refresh;
    } finally {
      if (devTokenRefreshes.get(key) === refresh) {
        devTokenRefreshes.delete(key);
      }
    }
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
        const auth = googleAuthFactory(effectiveScopes);
        client = await withAuthTimeout(
          "loading Application Default Credentials for custom scopes",
          operationTimeoutMs,
          () => auth.getClient(),
        );
      }

      const { token } = await withAuthTimeout(
        "minting a production access token",
        operationTimeoutMs,
        () => client.getAccessToken(),
      );

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
      const { token } = await withAuthTimeout(
        "loading an access token for identity lookup",
        operationTimeoutMs,
        () => client.getAccessToken(),
      );

      if (!token) {
        throw new Error("Failed to get identity: no access token available");
      }

      const resp = await fetchAuthResponse(
        `https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(token)}`,
        {},
        "querying the OAuth tokeninfo endpoint",
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

  async function getProjectNumber(): Promise<string> {
    if (projectNumberCache) return projectNumberCache;

    return withAdcMapping(async () => {
      const client = await getSourceClient();
      const { token } = await withAuthTimeout(
        "loading an access token for project lookup",
        operationTimeoutMs,
        () => client.getAccessToken(),
      );

      if (!token) {
        throw new Error("Failed to get project number: no access token available");
      }

      const resp = await fetchAuthResponse(
        `https://cloudresourcemanager.googleapis.com/v3/projects/${encodeURIComponent(config.project_id)}`,
        { headers: { Authorization: `Bearer ${token}` } },
        "querying the Cloud Resource Manager API",
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

      projectNumberCache = number;
      return projectNumberCache;
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
      const { token } = await withAuthTimeout(
        "loading an Application Default Credentials access token",
        operationTimeoutMs,
        () => client.getAccessToken(),
      );
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
