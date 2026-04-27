import type { GateConnection } from "../gate/connection.ts";
import type { CachedToken, TokenProvider } from "../metadata-proxy/types.ts";
import { fetchProdAccessToken, type FetchProdTokenOptions } from "./fetch-prod-token.ts";
import { createCachingTokenProvider } from "./caching-token-provider.ts";

export interface PerRequestTokenProviderOptions extends FetchProdTokenOptions {
  /** Called after each successful token refresh (e.g. to update gcloud's token file). */
  onRefresh?: (token: CachedToken) => void;
}

/**
 * Token provider used when `with-prod` points at the operator socket and the
 * gate has rejected session creation. Each refresh hits `/token?level=prod`
 * directly (auto-approved by the gate when the PAM policy is allowlisted)
 * and skips `/identity` — the email was captured at startup and doesn't
 * change.
 */
export function createPerRequestTokenProvider(
  conn: GateConnection,
  initialToken: CachedToken,
  options: PerRequestTokenProviderOptions = {},
): TokenProvider {
  return createCachingTokenProvider(initialToken, options.onRefresh, async () => {
    const result = await fetchProdAccessToken(conn, options);
    return {
      access_token: result.access_token,
      expires_at: new Date(Date.now() + result.expires_in * 1000),
    };
  });
}
