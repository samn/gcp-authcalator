// ---------------------------------------------------------------------------
// Shared interfaces for the metadata-proxy server
// ---------------------------------------------------------------------------

import type { CachedToken } from "../gate/types.ts";

export type { CachedToken };

/** Provides access tokens by fetching from the gcp-gate daemon. */
export interface TokenProvider {
  getToken: () => Promise<CachedToken>;
}

/**
 * Dependency injection interface for metadata-proxy request handlers.
 * Allows handlers to be tested without a real gate daemon.
 */
export interface MetadataProxyDeps {
  getToken: () => Promise<CachedToken>;
  projectId: string;
  serviceAccountEmail: string | undefined;
  startTime: Date;
}
