/**
 * Error class + detector for "the gate's gcloud Application Default
 * Credentials need re-authentication" conditions.
 *
 * `google-auth-library` raises `invalid_grant` (and a handful of related
 * RAPT/reauth strings) whenever the engineer's refresh token has been
 * revoked, expired, or the org's reauth window has elapsed. The raw
 * message is opaque to anyone who hasn't memorised OAuth error codes,
 * so we wrap it in a typed error with an actionable instruction and
 * detect it consistently from one place.
 */

/** Discriminator value emitted in JSON error responses (`{code}`). */
export const CREDENTIALS_EXPIRED_CODE = "credentials_expired";

/** Single source of truth for the user-facing recovery instruction. */
export const REAUTH_INSTRUCTION =
  "Run `gcloud auth application-default login` on the host running gcp-authcalator gate, then retry. " +
  "The gate picks up refreshed credentials automatically — no restart needed.";

/**
 * Cap on the rendered error message. The gate's own formatted message
 * is ~250 chars; anything longer is either an unusual google-auth
 * payload or an attacker-controlled wire response. 1 KiB is generous
 * but bounds the cost of printing the message to stderr or writing
 * it to the audit log.
 */
const MAX_MESSAGE_LENGTH = 1024;

/**
 * Strip control characters (terminal escapes, NULs, etc.) and cap the
 * length. The error message is printed to a TTY via `console.error`
 * in `with-prod`, where escape sequences could redraw the screen, set
 * the window title, or otherwise mislead the engineer. Mirrors the
 * sanitisation in `summarize-command.ts`.
 */
function sanitizeMessage(s: string): string {
  // eslint-disable-next-line no-control-regex
  const stripped = s.replace(/[\u0000-\u001f\u007f]/g, " ");
  if (stripped.length <= MAX_MESSAGE_LENGTH) return stripped;
  return `${stripped.slice(0, MAX_MESSAGE_LENGTH - 1)}…`;
}

/**
 * Build the standard, action-oriented error message from the underlying
 * google-auth detail line. Centralised so gate-side and client-side
 * messages match exactly.
 */
export function formatCredentialsExpiredMessage(detail: string): string {
  return `gcloud credentials on the gate host need re-authentication: ${detail}. ${REAUTH_INSTRUCTION}`;
}

/**
 * Raised when the gate cannot mint tokens because the engineer's ADC
 * refresh token has expired, been revoked, or requires reauth (RAPT).
 *
 * The message passed to the constructor is preserved verbatim (modulo
 * control-character stripping and length cap) — callers format it via
 * `formatCredentialsExpiredMessage` (gate side) or forward the gate's
 * already-formatted message unchanged (client side). This avoids
 * double-prefixing across the wire while still defending the engineer's
 * terminal from any escape characters that might leak in via the
 * underlying OAuth response or a malicious response body.
 */
export class CredentialsExpiredError extends Error {
  readonly code = CREDENTIALS_EXPIRED_CODE;

  constructor(message: string, options?: { cause?: unknown }) {
    super(sanitizeMessage(message));
    this.name = "CredentialsExpiredError";
    if (options?.cause !== undefined) {
      // Standard Error.cause is supported in modern runtimes, but assigning
      // explicitly keeps the field present even when the constructor option
      // path is not honoured (e.g. when a transpiler drops it).
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

/**
 * Patterns that identify reauth/invalid_grant errors raised by
 * `google-auth-library` (and the underlying OAuth endpoints). Kept
 * intentionally broad: the cost of a false positive (a clearer
 * message) is much smaller than the cost of a false negative
 * (cryptic 500 reaches the user).
 */
const REAUTH_PATTERNS: readonly RegExp[] = [
  /invalid_grant/i,
  /reauth[ _-]?required/i,
  /rapt[ _-]?required/i,
  /invalid[ _-]?rapt/i,
  /reauthentication[ _]?(?:is[ _]?)?required/i,
  /token has been expired or revoked/i,
  /refresh token .*(?:revoked|expired|invalid)/i,
];

/** True iff `message` looks like a reauth/invalid_grant signal. */
export function isCredentialsExpiredMessage(message: string): boolean {
  return REAUTH_PATTERNS.some((p) => p.test(message));
}

/**
 * Convert any thrown value into either a `CredentialsExpiredError` (if
 * it matches a known reauth pattern) or pass it through unchanged.
 *
 * The original value is preserved as the `cause` so debug logging
 * can still recover the underlying OAuth response.
 */
export function mapAdcError(err: unknown): unknown {
  if (err instanceof CredentialsExpiredError) return err;

  const message = err instanceof Error ? err.message : String(err);
  if (!isCredentialsExpiredMessage(message)) return err;

  // Use only the first line of the message — google-auth-library
  // sometimes includes a multi-line stack-style payload.
  const firstLine = message.split("\n")[0]!.trim();
  return new CredentialsExpiredError(formatCredentialsExpiredMessage(firstLine), { cause: err });
}
