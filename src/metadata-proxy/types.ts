// ---------------------------------------------------------------------------
// Shared interfaces for the metadata-proxy server
// ---------------------------------------------------------------------------

import type { CachedToken, TokenResponse } from "../gate/types.ts";

export type { CachedToken };

/**
 * Token JSON served by the proxy's GCE token endpoint. Extends the gate's
 * response with a stubbed refresh token: an opaque value minted by (and only
 * meaningful to) this proxy instance — never a GCP credential. Real GCE
 * metadata responses don't carry a refresh_token; known clients ignore the
 * extra field.
 */
export interface MetadataTokenResponse extends TokenResponse {
  refresh_token: string;
}

/**
 * Response for the OAuth2 refresh-token grant (`POST /token`). Mirrors
 * https://oauth2.googleapis.com/token, which does not return a new
 * refresh_token on refresh grants.
 */
export interface OAuthRefreshResponse extends TokenResponse {
  scope: string;
}

/** OAuth2 error response per RFC 6749 §5.2. */
export interface OAuthErrorResponse {
  error: "invalid_request" | "invalid_grant" | "unsupported_grant_type" | "temporarily_unavailable";
  error_description: string;
}

/** Provides access tokens by fetching from the gcp-gate daemon. */
export interface TokenProvider {
  getToken: () => Promise<CachedToken>;
}

/** Provides both tokens and project metadata from the gcp-gate daemon. */
export interface GateClient extends TokenProvider {
  getNumericProjectId: () => Promise<string>;
  getUniverseDomain: () => Promise<string>;
}

/**
 * Dependency injection interface for metadata-proxy request handlers.
 * Allows handlers to be tested without a real gate daemon.
 */
export interface MetadataProxyDeps {
  getToken: () => Promise<CachedToken>;
  getNumericProjectId?: () => Promise<string>;
  getUniverseDomain?: () => Promise<string>;
  projectId: string;
  serviceAccountEmail: string | undefined;
  scopes: string[];
  startTime: Date;
  /**
   * Stubbed refresh token for this proxy instance: crypto-random, held in
   * memory only, and honored solely by this proxy's `POST /token` endpoint.
   * It is not a GCP credential — the real refresh capability (ADC refresh
   * token, gate session ID) never enters the container — so exfiltrating it
   * grants nothing and cannot extend the session beyond gate-enforced bounds.
   */
  refreshToken: string;
}
