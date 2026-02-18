// ---------------------------------------------------------------------------
// Shared interfaces for the metadata-proxy server
// ---------------------------------------------------------------------------

import type { CachedToken } from "../gate/types.ts";

export type { CachedToken };

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
}
