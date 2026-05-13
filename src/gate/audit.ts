import { appendFileSync } from "node:fs";
import { join } from "node:path";
import type { AuditEntry } from "./types.ts";
import { getDefaultRuntimeDir } from "../config.ts";
import { ensurePrivateDir, chooseSocketDirMode } from "./dir-utils.ts";

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

  // The audit log file itself is owner-only (0o600 via the gate's startup
  // umask), so the directory mode only affects listdir, not log readability.
  // We use chooseSocketDirMode here to stay consistent with the gate socket
  // dir mode — typically the same directory in non-XDG deployments.
  try {
    ensurePrivateDir(logDir, chooseSocketDirMode(logDir));
  } catch (err) {
    console.error(`audit: failed to ensure log directory ${logDir}:`, err);
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
