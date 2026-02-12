import type { TokenProvider, CachedToken } from "../metadata-proxy/types.ts";

/**
 * Create a TokenProvider that always returns the same fixed token.
 *
 * Used by with-prod to serve a one-shot prod token through a temporary
 * metadata proxy without needing a live gate client connection.
 */
export function createStaticTokenProvider(accessToken: string, expiresAt: Date): TokenProvider {
  const cached: CachedToken = { access_token: accessToken, expires_at: expiresAt };

  return {
    getToken: async () => cached,
  };
}
