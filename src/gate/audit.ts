import { mkdirSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import type { AuditEntry } from "./types.ts";
import { getDefaultRuntimeDir } from "../config.ts";

const LOG_FILENAME = "audit.log";

/**
 * Create an audit logger that writes JSON lines to the runtime directory's audit.log.
 * Uses $XDG_RUNTIME_DIR when available, falls back to ~/.gcp-authcalator/.
 * Failures are logged to stderr but never break token serving.
 */
export function createAuditModule(logDir: string = getDefaultRuntimeDir()): {
  writeAuditLog: (entry: AuditEntry) => void;
} {
  const logPath = join(logDir, LOG_FILENAME);

  // Ensure directory exists with owner-only permissions (0o700).
  // The audit log contains timestamps, access decisions, and email addresses
  // — restrict directory access so other local users cannot read it.
  try {
    mkdirSync(logDir, { recursive: true, mode: 0o700 });
  } catch (err) {
    console.error(`audit: failed to create log directory ${logDir}:`, err);
  }

  function writeAuditLog(entry: AuditEntry): void {
    try {
      appendFileSync(logPath, JSON.stringify(entry) + "\n");
    } catch (err) {
      console.error("audit: failed to write log entry:", err);
    }
  }

  return { writeAuditLog };
}
