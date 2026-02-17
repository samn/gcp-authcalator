// ---------------------------------------------------------------------------
// Summarize a command for display in the permission dialog.
//
// Goals:
//   - Always show the binary name so users know what they're approving
//   - Truncate long commands to keep the dialog readable
//   - Redact values that look like credentials or secrets
// ---------------------------------------------------------------------------

import { basename } from "node:path";

/** Maximum length for the full summarized command string. */
const MAX_SUMMARY_LENGTH = 80;

/**
 * Patterns that suggest an argument value is a secret.
 *
 * Matches:
 *   - Long base64-ish strings (40+ chars of [A-Za-z0-9+/=_-])
 *   - Key=value pairs where the key contains a sensitive word
 */
const SECRET_VALUE_RE = /^[A-Za-z0-9+/=_-]{40,}$/;
const SECRET_KEY_RE =
  /^-*(?:.*(?:password|passwd|secret|token|key|credential|auth|api[_-]?key|private).*)[=:]/i;

/** Strip control characters (newlines, tabs, etc.) that could manipulate dialog layout. */
function stripControlChars(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u001f\u007f]/g, " ");
}

/** Redact an argument if it looks like a secret value. */
function redactArg(arg: string): string {
  // Redact long random-looking values (likely tokens/keys)
  if (SECRET_VALUE_RE.test(arg)) {
    return "***";
  }

  // Redact the value portion of key=value pairs with sensitive keys
  if (SECRET_KEY_RE.test(arg)) {
    const sepIdx = arg.indexOf("=");
    if (sepIdx >= 0) {
      return arg.slice(0, sepIdx + 1) + "***";
    }
  }

  return arg;
}

/**
 * Summarize a command for safe display in a permission dialog.
 *
 * - Always includes the binary name (basename only, no path).
 * - Includes redacted arguments, truncated to {@link MAX_SUMMARY_LENGTH}.
 * - Returns `undefined` if the input is empty.
 */
export function summarizeCommand(command: string[]): string | undefined {
  if (command.length === 0) return undefined;

  const binaryPath = command[0]!;
  const binary = basename(binaryPath);

  if (command.length === 1) return stripControlChars(binary);

  const redactedArgs = command.slice(1).map(redactArg);
  const full = stripControlChars(`${binary} ${redactedArgs.join(" ")}`);

  if (full.length <= MAX_SUMMARY_LENGTH) return full;

  return `${full.slice(0, MAX_SUMMARY_LENGTH - 1)}\u2026`;
}

/**
 * Parse the `X-Wrapped-Command` header value into a command array.
 *
 * Returns `undefined` if the header is missing, empty, or invalid JSON.
 */
export function parseCommandHeader(headerValue: string | null): string[] | undefined {
  if (!headerValue) return undefined;

  try {
    const parsed: unknown = JSON.parse(headerValue);

    if (!Array.isArray(parsed)) return undefined;
    if (!parsed.every((v) => typeof v === "string")) return undefined;
    if (parsed.length === 0) return undefined;

    return parsed as string[];
  } catch {
    return undefined;
  }
}
