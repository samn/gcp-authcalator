// ---------------------------------------------------------------------------
// Shared interfaces for the gcp-gate token daemon
// ---------------------------------------------------------------------------

import type { Scope } from "../config.ts";
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

/** Code emitted when sessions are disabled on the operator socket. */
export const SESSION_NOT_PERMITTED_CODE = "session_not_permitted_on_operator_socket";

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
  /**
   * Summary of the wrapped command (from `X-Wrapped-Command`) for prod-path
   * requests. PAM grants outlive a single command and PAM's grant
   * justification can't be amended, so this captures per-invocation context
   * the gate is uniquely positioned to record.
   */
  command?: string;
  /**
   * Target project for the request. In folder mode this is the per-request
   * `?project=` value (after folder-membership verification); in project
   * mode it is the configured project. Logged on every prod-path entry for
   * cross-mode grep symmetry.
   */
  project_id?: string;
}

/** Per-request metadata threaded through the handler chain. */
export interface RequestContext {
  /** True if the connecting socket has been pre-authorised for auto-approve via filesystem permissions. */
  trusted: boolean;
  socket: "main" | "operator" | "tcp" | "admin";
}

/**
 * Thrown by `resolveProject` when the requested project is not in scope:
 * in project mode when the param mismatches the configured project, or in
 * folder mode when the param is missing or not a descendant of the folder.
 * Handlers map this to a 400 response.
 */
export class ProjectNotInScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProjectNotInScopeError";
  }
}

/**
 * Dependency injection interface for request handlers.
 * Allows handlers to be tested without real GCP calls.
 */
export interface GateDeps {
  /** Resource the gate is bound to: a single project, or a folder (per-request project). */
  scope: Scope;
  mintDevToken: (scopes?: string[], ttlSeconds?: number) => Promise<CachedToken>;
  mintProdToken: (scopes?: string[], ttlSeconds?: number) => Promise<CachedToken>;
  getIdentityEmail: () => Promise<string>;
  getProjectNumber: (projectId: string) => Promise<string>;
  getUniverseDomain: () => Promise<string>;
  /**
   * Resolve and validate the project for a request. In project mode an
   * undefined or matching param returns the configured project; a mismatch
   * throws `ProjectNotInScopeError`. In folder mode the param is required
   * and must be a descendant of the configured folder (verified via CRM,
   * with caching); otherwise throws.
   *
   * CRM 5xx (no usable stale cache) bubbles up as a generic Error — handlers
   * surface it as 503.
   */
  resolveProject: (requestedProjectId: string | undefined) => Promise<string>;
  confirmProdAccess: (
    email: string,
    projectId: string,
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
