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

  function create(params: CreateSessionParams): ProdSession {
    const id = randomBytes(32).toString("hex");
    const createdAt = new Date(now());
    const expiresAt = new Date(now() + params.sessionLifetimeSeconds * 1000);

    const session: ProdSession = {
      id,
      email: params.email,
      scopes: params.scopes,
      pamPolicy: params.pamPolicy,
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
