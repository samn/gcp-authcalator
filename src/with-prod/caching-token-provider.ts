import type { CachedToken, TokenProvider } from "../metadata-proxy/types.ts";

/** Re-fetch when the cached token has less than 5 minutes left. */
const CACHE_MARGIN_MS = 5 * 60 * 1000;

/**
 * Wrap a refresh function in the standard cache-with-margin pattern used by
 * both session-based and per-request prod token providers.
 */
export function createCachingTokenProvider(
  initialToken: CachedToken,
  onRefresh: ((token: CachedToken) => void) | undefined,
  refresh: () => Promise<CachedToken>,
): TokenProvider {
  let tokenCache: CachedToken = initialToken;

  return {
    async getToken(): Promise<CachedToken> {
      if (tokenCache.expires_at.getTime() - Date.now() > CACHE_MARGIN_MS) {
        return tokenCache;
      }
      tokenCache = await refresh();
      onRefresh?.(tokenCache);
      return tokenCache;
    },
  };
}
