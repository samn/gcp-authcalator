import { type GateConnection, connectionFetchOpts } from "../gate/connection.ts";
import { CredentialsExpiredError } from "../gate/credentials-error.ts";
import { TARGET_PROJECT_HEADER } from "../gate/types.ts";
import type { CachedToken, TokenProvider } from "../metadata-proxy/types.ts";
import { createCachingTokenProvider } from "./caching-token-provider.ts";
import { fetchWithGateTimeout, throwTypedGateError } from "./fetch-prod-token.ts";

/**
 * Backstop timeout for a session token refresh. No confirmation happens on this
 * path (the session is pre-approved); the gate's work is a PAM grant renewal
 * (bounded by its rotation budget) plus a token mint. Sized above that — and
 * above the acquisition cap is unnecessary since there is no confirmation here
 * — so a wedged gate surfaces as an error instead of silently stalling the
 * wrapped command, while never aborting a legitimately slow PAM rotation.
 */
const SESSION_REFRESH_TIMEOUT_MS = 480_000;

export interface SessionTokenProviderOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
  /** Called after each successful token refresh (e.g., to update gcloud's token file). */
  onRefresh?: (token: CachedToken) => void;
  /**
   * Target GCP project for this session's refresh requests. Sent as
   * `X-Target-Project` so the audit log on each refresh records the same
   * target as the original session.
   */
  targetProject?: string;
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

  const refreshHeaders = options.targetProject
    ? { [TARGET_PROJECT_HEADER]: options.targetProject }
    : undefined;

  return createCachingTokenProvider(initialToken, options.onRefresh, async () => {
    const url = `${baseUrl}/token?session=${encodeURIComponent(sessionId)}`;
    const res = await fetchWithGateTimeout(
      fetchFn,
      url,
      { ...extraOpts, ...(refreshHeaders ? { headers: refreshHeaders } : {}) },
      SESSION_REFRESH_TIMEOUT_MS,
    );

    if (res.status === 401) {
      const text = await res.text().catch(() => "");
      throw new Error(
        `Prod session expired or revoked${text ? `: ${text}` : ""}. ` +
          "The gcp-gate daemon may have restarted. Re-run with-prod to start a new session.",
      );
    }
    if (!res.ok) {
      const text = await res.text();
      try {
        throwTypedGateError(text);
      } catch (err) {
        // Echo the gate's reauth instruction to with-prod's stderr so the
        // user sees it even when the wrapped command swallows the
        // metadata-proxy 5xx.
        if (err instanceof CredentialsExpiredError) {
          console.error(`with-prod: ${err.message}`);
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
