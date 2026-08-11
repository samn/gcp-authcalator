import type { CachedToken, TokenProvider } from "../metadata-proxy/types.ts";
import { tokenRefreshAt } from "../token-cache.ts";

/**
 * Wrap a refresh function in the standard cache-with-margin pattern used by
 * both session-based and per-request prod token providers.
 */
export function createCachingTokenProvider(
  initialToken: CachedToken,
  onRefresh: ((token: CachedToken) => void) | undefined,
  refresh: () => Promise<CachedToken>,
  now: () => number = Date.now,
): TokenProvider {
  let tokenCache: CachedToken = initialToken;
  let refreshAt = tokenRefreshAt(tokenCache.expires_at.getTime(), now());
  // The single in-flight refresh, shared by all concurrent callers. Cleared
  // once it settles so the next stale read starts a fresh refresh.
  let inflight: Promise<CachedToken> | null = null;

  return {
    async getToken(): Promise<CachedToken> {
      if (now() < refreshAt) {
        return tokenCache;
      }
      // Coalesce concurrent refreshes: the first caller starts the refresh and
      // every other caller awaits the same promise, so a stale window can't
      // fan out into N duplicate gate round-trips (and N audit entries).
      inflight ??= (async () => {
        try {
          const token = await refresh();
          // Persist side effects (notably gcloud's access_token_file) before
          // committing the in-memory cache. If this throws, the next request
          // must retry both the refresh and callback instead of serving a token
          // that only the metadata proxy knows about.
          onRefresh?.(token);
          tokenCache = token;
          refreshAt = tokenRefreshAt(token.expires_at.getTime(), now());
          return token;
        } finally {
          inflight = null;
        }
      })();
      return inflight;
    },
  };
}
