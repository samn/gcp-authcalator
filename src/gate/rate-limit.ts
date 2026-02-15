// ---------------------------------------------------------------------------
// Rate limiter for prod token confirmation flow.
//
// Three layers of protection:
//   1. Single-flight — only one confirmation dialog at a time
//   2. Cooldown — 5 s pause after a denied request
//   3. Sliding window — max 5 attempts per 1-minute window
// ---------------------------------------------------------------------------

/** Tunables (intentionally not user-configurable). */
const DENIAL_COOLDOWN_MS = 5_000;
const WINDOW_MS = 1 * 60 * 1000;
const MAX_ATTEMPTS_PER_WINDOW = 5;

export type AcquireResult = { allowed: true } | { allowed: false; reason: string };

/**
 * Rate limiter interface injected into GateDeps.
 *
 * Call `acquire()` before showing the confirmation dialog.
 * Call `release()` once the dialog resolves (or errors).
 */
export interface ProdRateLimiter {
  acquire(): AcquireResult;
  release(result: "granted" | "denied" | "error"): void;
}

export interface ProdRateLimiterOptions {
  /** Override Date.now for deterministic testing. */
  now?: () => number;
  /** Override denial cooldown (ms) for testing. */
  denialCooldownMs?: number;
  /** Override sliding window size (ms) for testing. */
  windowMs?: number;
  /** Override max attempts per window for testing. */
  maxAttemptsPerWindow?: number;
}

export function createProdRateLimiter(options: ProdRateLimiterOptions = {}): ProdRateLimiter {
  const now = options.now ?? Date.now;
  const denialCooldownMs = options.denialCooldownMs ?? DENIAL_COOLDOWN_MS;
  const windowMs = options.windowMs ?? WINDOW_MS;
  const maxAttemptsPerWindow = options.maxAttemptsPerWindow ?? MAX_ATTEMPTS_PER_WINDOW;

  let pending = false;
  let cooldownUntil = 0;
  const attempts: number[] = [];

  function pruneWindow(): void {
    const cutoff = now() - windowMs;
    while (attempts.length > 0 && attempts[0]! < cutoff) {
      attempts.shift();
    }
  }

  function acquire(): AcquireResult {
    // 1. Single-flight: reject if a dialog is already open
    if (pending) {
      return { allowed: false, reason: "A prod confirmation dialog is already pending" };
    }

    // 2. Cooldown: reject if we're in a post-denial cooldown
    const remaining = cooldownUntil - now();
    if (remaining > 0) {
      const secs = Math.ceil(remaining / 1000);
      return {
        allowed: false,
        reason: `Prod access denied recently; retry in ${secs}s`,
      };
    }

    // 3. Sliding window: reject if too many recent attempts
    pruneWindow();
    if (attempts.length >= maxAttemptsPerWindow) {
      return {
        allowed: false,
        reason: `Rate limit exceeded: max ${maxAttemptsPerWindow} prod attempts per ${Math.floor(windowMs / 60_000)} minutes`,
      };
    }

    // Allowed — record the attempt and mark as pending
    attempts.push(now());
    pending = true;
    return { allowed: true };
  }

  function release(result: "granted" | "denied" | "error"): void {
    pending = false;

    if (result === "denied") {
      cooldownUntil = now() + denialCooldownMs;
    }
  }

  return { acquire, release };
}
