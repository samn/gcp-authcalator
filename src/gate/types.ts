// ---------------------------------------------------------------------------
// Shared interfaces for the gcp-gate token daemon
// ---------------------------------------------------------------------------

import type { ProdRateLimiter } from "./rate-limit.ts";
import type { PamGrantResult } from "./pam.ts";
import type { SessionManager } from "./session.ts";
import type { PendingQueue } from "./pending.ts";

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

/** JSON error response. The optional `code` discriminates errors that clients want to handle programmatically. */
export interface ErrorResponse {
  error: string;
  code?: string;
}

/** JSON response for session creation. */
export interface SessionResponse {
  session_id: string;
  access_token: string;
  expires_in: number;
  token_type: "Bearer";
  email: string;
}

/** Audit log entry written as a JSON line. */
export interface AuditEntry {
  timestamp: string;
  endpoint: string;
  level: "dev" | "prod";
  result: "granted" | "denied" | "error" | "rate_limited" | "revoked";
  email?: string;
  error?: string;
  pam_policy?: string;
  pam_grant?: string;
  pam_cached?: boolean;
  token_ttl_seconds?: number;
  session_id?: string;
  /** Which gate socket the request arrived on. */
  socket?: "main" | "operator" | "tcp" | "admin";
  /** True iff the prod request bypassed the confirmation prompt via the operator-socket allowlist. */
  auto_approved?: boolean;
}

/** Per-request metadata threaded through the handler chain. */
export interface RequestContext {
  /** True if the connecting socket has been pre-authorised for auto-approve via filesystem permissions. */
  trusted: boolean;
  socket: "main" | "operator" | "tcp" | "admin";
}

/**
 * Dependency injection interface for request handlers.
 * Allows handlers to be tested without real GCP calls.
 */
export interface GateDeps {
  mintDevToken: (scopes?: string[], ttlSeconds?: number) => Promise<CachedToken>;
  mintProdToken: (scopes?: string[], ttlSeconds?: number) => Promise<CachedToken>;
  getIdentityEmail: () => Promise<string>;
  getProjectNumber: () => Promise<string>;
  getUniverseDomain: () => Promise<string>;
  confirmProdAccess: (
    email: string,
    command?: string,
    pamPolicy?: string,
    pendingId?: string,
  ) => Promise<boolean>;
  writeAuditLog: (entry: AuditEntry) => void;
  prodRateLimiter: ProdRateLimiter;
  startTime: Date;
  /** Ensure a PAM grant is active for the given entitlement path. */
  ensurePamGrant?: (entitlementPath: string, justification?: string) => Promise<PamGrantResult>;
  /** Allowlist of resolved entitlement paths. Query param values must be in this set. */
  pamAllowedPolicies?: Set<string>;
  /**
   * Resolved entitlement paths that auto-approve when the request arrives on
   * the operator socket (`ctx.trusted === true`). Must be a subset of
   * `pamAllowedPolicies`. Empty/undefined means auto-approve is disabled.
   */
  autoApprovePamPolicies?: Set<string>;
  /** Default resolved entitlement path from config. */
  pamDefaultPolicy?: string;
  /** Resolve a raw PAM policy value (short-form or full path) to a validated full entitlement path. */
  resolvePamPolicy?: (policy: string) => string;
  /** Default token TTL in seconds from config. Used to validate TTL overrides. */
  defaultTokenTtlSeconds: number;
  /** Session manager for prod session lifecycle. */
  sessionManager: SessionManager;
  /** Default session TTL in seconds from config. */
  sessionTtlSeconds: number;
  /** Pending approval queue for CLI-based confirmation fallback. */
  pendingQueue?: PendingQueue;
}
