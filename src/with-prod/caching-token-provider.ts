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
  // The single in-flight refresh, shared by all concurrent callers. Cleared
  // once it settles so the next stale read starts a fresh refresh.
  let inflight: Promise<CachedToken> | null = null;

  return {
    async getToken(): Promise<CachedToken> {
      if (tokenCache.expires_at.getTime() - Date.now() > CACHE_MARGIN_MS) {
        return tokenCache;
      }
      // Coalesce concurrent refreshes: the first caller starts the refresh and
      // every other caller awaits the same promise, so a stale window can't
      // fan out into N duplicate gate round-trips (and N audit entries).
      inflight ??= (async () => {
        try {
          const token = await refresh();
          tokenCache = token;
          onRefresh?.(token);
          return token;
        } finally {
          inflight = null;
        }
      })();
      return inflight;
    },
  };
}
