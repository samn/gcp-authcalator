import { type GateConnection, connectionFetchOpts } from "../gate/connection.ts";
import type { CachedToken, TokenProvider } from "../metadata-proxy/types.ts";

/** Minimum remaining lifetime before we re-fetch a cached token (5 minutes). */
const CACHE_MARGIN_MS = 5 * 60 * 1000;

export interface SessionTokenProviderOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
  /** Called after each successful token refresh (e.g., to update gcloud's token file). */
  onRefresh?: (token: CachedToken) => void;
}

/**
 * Create a TokenProvider that refreshes prod tokens via a gate session.
 *
 * The session ID is the authorization to mint fresh prod tokens without
 * re-confirmation. It stays in this closure — the subprocess never sees it.
 *
 * The initial token (from session creation) is seeded into the cache so the
 * first getToken() call returns immediately without hitting the gate.
 */
export function createSessionTokenProvider(
  conn: GateConnection,
  sessionId: string,
  initialToken: CachedToken,
  options: SessionTokenProviderOptions = {},
): TokenProvider {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const { baseUrl, extraOpts } = connectionFetchOpts(conn);

  let tokenCache: CachedToken = initialToken;

  function isCacheValid(): boolean {
    return tokenCache.expires_at.getTime() - Date.now() > CACHE_MARGIN_MS;
  }

  async function getToken(): Promise<CachedToken> {
    if (isCacheValid()) {
      return tokenCache;
    }

    const url = `${baseUrl}/token?session=${encodeURIComponent(sessionId)}`;
    const res = await fetchFn(url, extraOpts);

    if (res.status === 401) {
      const text = await res.text().catch(() => "");
      throw new Error(
        `Prod session expired or revoked${text ? `: ${text}` : ""}. ` +
          "The gcp-gate daemon may have restarted. Re-run with-prod to start a new session.",
      );
    }

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`gcp-gate returned ${res.status}: ${text}`);
    }

    const body = (await res.json()) as { access_token?: string; expires_in?: number };

    if (!body.access_token) {
      throw new Error("gcp-gate returned no access_token");
    }

    const expiresIn = body.expires_in ?? 3600;
    tokenCache = {
      access_token: body.access_token,
      expires_at: new Date(Date.now() + expiresIn * 1000),
    };

    options.onRefresh?.(tokenCache);

    return tokenCache;
  }

  return { getToken };
}
