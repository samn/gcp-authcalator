import { mkdirSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { AuditEntry } from "./types.ts";

const DEFAULT_LOG_DIR = join(homedir(), ".gcp-gate");
const LOG_FILENAME = "audit.log";

/**
 * Create an audit logger that writes JSON lines to ~/.gcp-gate/audit.log.
 * Failures are logged to stderr but never break token serving.
 */
export function createAuditModule(logDir: string = DEFAULT_LOG_DIR): {
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
