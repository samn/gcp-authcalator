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

  // Ensure directory exists on creation
  try {
    mkdirSync(logDir, { recursive: true });
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
