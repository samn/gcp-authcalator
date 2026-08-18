import { randomBytes } from "node:crypto";

/** A prod session that allows token refreshes without re-confirmation. */
export interface ProdSession {
  /** Crypto-random session identifier (64-char hex string). */
  id: string;
  /** Engineer's email captured at session creation. */
  email: string;
  /** OAuth scopes for tokens minted within this session. */
  scopes?: string[];
  /** Resolved PAM policy (if any). */
  pamPolicy?: string;
  /**
   * Summarized wrapped command captured at session creation. Used as the
   * PAM grant justification on subsequent refreshes so renewed grants
   * carry the same context as the initial grant.
   */
  commandSummary?: string;
  /** Per-token TTL in seconds. */
  ttlSeconds: number;
  /** When the session was created. */
  createdAt: Date;
  /** When the session expires (createdAt + sessionLifetimeSeconds). */
  expiresAt: Date;
}

export interface CreateSessionParams {
  email: string;
  scopes?: string[];
  pamPolicy?: string;
  commandSummary?: string;
  ttlSeconds: number;
  sessionLifetimeSeconds: number;
}

export interface SessionManager {
  /** Create a new prod session. Returns the session with a crypto-random ID. */
  create(params: CreateSessionParams): ProdSession;
  /** Look up a session by ID. Returns null if expired or not found. */
  validate(id: string): ProdSession | null;
  /** Revoke a session by ID. Returns true if the session existed. */
  revoke(id: string): boolean;
  /** Revoke all sessions (for gate shutdown). */
  revokeAll(): void;
}

export interface SessionManagerOptions {
  /** Override Date.now for deterministic testing. */
  now?: () => number;
}

export function createSessionManager(options: SessionManagerOptions = {}): SessionManager {
  const now = options.now ?? Date.now;
  const sessions = new Map<string, ProdSession>();

  function pruneExpired(atMs: number): void {
    for (const [id, session] of sessions) {
      if (session.expiresAt.getTime() <= atMs) sessions.delete(id);
    }
  }

  function create(params: CreateSessionParams): ProdSession {
    const createdAtMs = now();
    // Expired sessions are otherwise retained forever when clients exit
    // without revoking them. Sweep at creation so a long-lived daemon's map is
    // bounded by sessions that can still authorize a request.
    pruneExpired(createdAtMs);
    const id = randomBytes(32).toString("hex");
    const createdAt = new Date(createdAtMs);
    const expiresAt = new Date(createdAtMs + params.sessionLifetimeSeconds * 1000);

    const session: ProdSession = {
      id,
      email: params.email,
      scopes: params.scopes,
      pamPolicy: params.pamPolicy,
      commandSummary: params.commandSummary,
      ttlSeconds: params.ttlSeconds,
      createdAt,
      expiresAt,
    };

    sessions.set(id, session);
    return session;
  }

  function validate(id: string): ProdSession | null {
    const session = sessions.get(id);
    if (!session) return null;
    if (session.expiresAt.getTime() <= now()) {
      sessions.delete(id);
      return null;
    }
    return session;
  }

  function revoke(id: string): boolean {
    return sessions.delete(id);
  }

  function revokeAll(): void {
    sessions.clear();
  }

  return { create, validate, revoke, revokeAll };
}
