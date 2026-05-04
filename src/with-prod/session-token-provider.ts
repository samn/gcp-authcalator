import { type GateConnection, connectionFetchOpts } from "../gate/connection.ts";
import { CredentialsExpiredError } from "../gate/credentials-error.ts";
import type { CachedToken, TokenProvider } from "../metadata-proxy/types.ts";
import { createCachingTokenProvider } from "./caching-token-provider.ts";
import { maybeThrowCredentialsExpired } from "./fetch-prod-token.ts";

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

  return createCachingTokenProvider(initialToken, options.onRefresh, async () => {
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
      // Throws CredentialsExpiredError if the gate flagged the failure as
      // credentials_expired so the engineer sees the gcloud reauth
      // instruction on with-prod's stderr (the metadata proxy's
      // 5xx response would otherwise be swallowed by gcloud).
      try {
        maybeThrowCredentialsExpired(text);
      } catch (err) {
        if (err instanceof CredentialsExpiredError) {
          console.error(`with-prod: ${err.message}`);
          throw err;
        }
        throw err;
      }
      throw new Error(`gcp-gate returned ${res.status}: ${text}`);
    }

    const body = (await res.json()) as { access_token?: string; expires_in?: number };
    if (!body.access_token) {
      throw new Error("gcp-gate returned no access_token");
    }

    return {
      access_token: body.access_token,
      expires_at: new Date(Date.now() + (body.expires_in ?? 3600) * 1000),
    };
  });
}
