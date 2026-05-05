// Sanitisation helpers shared across gate-side dialog rendering, command
// summarisation, and error formatting. Centralised so the regex (and any
// future tightening of it) lives in one place rather than being copied
// into every consumer.

/**
 * Replace every C0/C1 control character (NUL through 0x1f, plus DEL) with
 * a space. Everything that the operator might see — confirmation-dialog
 * strings, command summaries, error messages echoed to a TTY — flows
 * through this so an embedded ANSI escape, NUL, or newline cannot
 * redraw the screen, set the window title, or split a log line.
 */
export function stripControlChars(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u001f\u007f]/g, " ");
}
