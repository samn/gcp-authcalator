// ---------------------------------------------------------------------------
// Shared interfaces for the gcp-gate token daemon
// ---------------------------------------------------------------------------

import type { ProdRateLimiter } from "./rate-limit.ts";

/** A cached GCP access token with its expiry time. */
export interface CachedToken {
  access_token: string;
  expires_at: Date;
}

/** JSON response for token requests. */
export interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: "Bearer";
}

/** JSON response for identity requests. */
export interface IdentityResponse {
  email: string;
}

/** JSON response for project number requests. */
export interface ProjectNumberResponse {
  project_number: string;
}

/** JSON response for universe domain requests. */
export interface UniverseDomainResponse {
  universe_domain: string;
}

/** JSON response for health checks. */
export interface HealthResponse {
  status: "ok";
  uptime_seconds: number;
}

/** JSON error response. */
export interface ErrorResponse {
  error: string;
}

/** Audit log entry written as a JSON line. */
export interface AuditEntry {
  timestamp: string;
  endpoint: string;
  level: "dev" | "prod";
  result: "granted" | "denied" | "error" | "rate_limited";
  email?: string;
  error?: string;
}

/**
 * Dependency injection interface for request handlers.
 * Allows handlers to be tested without real GCP calls.
 */
export interface GateDeps {
  mintDevToken: (scopes?: string[]) => Promise<CachedToken>;
  mintProdToken: (scopes?: string[]) => Promise<CachedToken>;
  getIdentityEmail: () => Promise<string>;
  getProjectNumber: () => Promise<string>;
  getUniverseDomain: () => Promise<string>;
  confirmProdAccess: (email: string, command?: string) => Promise<boolean>;
  writeAuditLog: (entry: AuditEntry) => void;
  prodRateLimiter: ProdRateLimiter;
  startTime: Date;
}
