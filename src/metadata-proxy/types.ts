// ---------------------------------------------------------------------------
// Shared interfaces for the metadata-proxy server
// ---------------------------------------------------------------------------

import type { CachedToken } from "../gate/types.ts";

export type { CachedToken };

/** Provides access tokens by fetching from the gcp-gate daemon. */
export interface TokenProvider {
  getToken: () => Promise<CachedToken>;
  /**
   * Verify that the authority backing this provider is still usable without
   * minting a token. Session providers validate their exact gate session;
   * per-request providers verify that the gate is reachable.
   */
  checkHealth?: () => Promise<void>;
}

/** Provides both tokens and project metadata from the gcp-gate daemon. */
export interface GateClient extends TokenProvider {
  getNumericProjectId: () => Promise<string>;
  getUniverseDomain: () => Promise<string>;
  /** The authenticated engineer's email, resolved via the gate's `/identity`. */
  getIdentity: () => Promise<string>;
}

/**
 * Dependency injection interface for metadata-proxy request handlers.
 * Allows handlers to be tested without a real gate daemon.
 */
export interface MetadataProxyDeps {
  getToken: () => Promise<CachedToken>;
  /** Non-mutating authority check used only for nested with-prod reuse. */
  checkHealth?: () => Promise<void>;
  getNumericProjectId?: () => Promise<string>;
  getUniverseDomain?: () => Promise<string>;
  /**
   * Resolves the authenticated engineer's email from the gate's `/identity`
   * route. Optional: only wired when a gate client backs the proxy (a custom
   * `tokenProvider` has no identity source), in which case the endpoint 404s.
   */
  getIdentity?: () => Promise<string>;
  projectId: string;
  serviceAccountEmail: string | undefined;
  scopes: string[];
  startTime: Date;
}
