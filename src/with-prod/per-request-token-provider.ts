import type { GateConnection } from "../gate/connection.ts";
import type { CachedToken, TokenProvider } from "../metadata-proxy/types.ts";
import { fetchProdToken, type FetchProdTokenOptions } from "./fetch-prod-token.ts";

/** Minimum remaining lifetime before we re-fetch a cached token (5 minutes). */
const CACHE_MARGIN_MS = 5 * 60 * 1000;

export interface PerRequestTokenProviderOptions extends FetchProdTokenOptions {
  /** Called after each successful token refresh (e.g. to update gcloud's token file). */
  onRefresh?: (token: CachedToken) => void;
}

/**
 * Token provider used when `with-prod` points at the operator socket and the
 * gate has rejected session creation. Each refresh hits `/token?level=prod`
 * directly, which the gate auto-approves on the operator socket if the PAM
 * policy is allowlisted. No bearer-token refresh credential is held in
 * memory between refreshes.
 */
export function createPerRequestTokenProvider(
  conn: GateConnection,
  initialToken: CachedToken,
  options: PerRequestTokenProviderOptions = {},
): TokenProvider {
  let tokenCache: CachedToken = initialToken;

  function isCacheValid(): boolean {
    return tokenCache.expires_at.getTime() - Date.now() > CACHE_MARGIN_MS;
  }

  async function getToken(): Promise<CachedToken> {
    if (isCacheValid()) return tokenCache;

    const result = await fetchProdToken(conn, options);
    tokenCache = {
      access_token: result.access_token,
      expires_at: new Date(Date.now() + result.expires_in * 1000),
    };
    options.onRefresh?.(tokenCache);
    return tokenCache;
  }

  return { getToken };
}
