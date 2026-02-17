import { describe, expect, test, beforeEach } from "bun:test";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createAuditModule } from "../../gate/audit.ts";
import type { AuditEntry } from "../../gate/types.ts";

describe("createAuditModule", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "audit-test-"));
  });

  test("creates log directory if it does not exist", () => {
    const logDir = join(tempDir, "nested", "dir");
    createAuditModule(logDir);
    expect(existsSync(logDir)).toBe(true);
  });

  test("writes a single audit entry as JSON line", () => {
    const { writeAuditLog } = createAuditModule(tempDir);
    const entry: AuditEntry = {
      timestamp: "2025-01-01T00:00:00.000Z",
      endpoint: "/token",
      level: "dev",
      result: "granted",
      email: "user@example.com",
    };

    writeAuditLog(entry);

    const content = readFileSync(join(tempDir, "audit.log"), "utf-8");
    const parsed = JSON.parse(content.trim());
    expect(parsed).toEqual(entry);
  });

  test("appends multiple entries as separate lines", () => {
    const { writeAuditLog } = createAuditModule(tempDir);
    const entry1: AuditEntry = {
      timestamp: "2025-01-01T00:00:00.000Z",
      endpoint: "/token",
      level: "dev",
      result: "granted",
    };
    const entry2: AuditEntry = {
      timestamp: "2025-01-01T00:01:00.000Z",
      endpoint: "/token",
      level: "prod",
      result: "denied",
      email: "user@example.com",
    };

    writeAuditLog(entry1);
    writeAuditLog(entry2);

    const content = readFileSync(join(tempDir, "audit.log"), "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]!)).toEqual(entry1);
    expect(JSON.parse(lines[1]!)).toEqual(entry2);
  });

  test("includes error field when present", () => {
    const { writeAuditLog } = createAuditModule(tempDir);
    const entry: AuditEntry = {
      timestamp: "2025-01-01T00:00:00.000Z",
      endpoint: "/token",
      level: "dev",
      result: "error",
      error: "something went wrong",
    };

    writeAuditLog(entry);

    const content = readFileSync(join(tempDir, "audit.log"), "utf-8");
    const parsed = JSON.parse(content.trim());
    expect(parsed.error).toBe("something went wrong");
    expect(parsed.result).toBe("error");
  });

  test("does not throw when log directory is unwritable", () => {
    // Suppress expected console.error from the error-handling code paths
    const orig = console.error;
    console.error = () => {};
    try {
      const { writeAuditLog } = createAuditModule("/nonexistent/path/that/should/fail");
      const entry: AuditEntry = {
        timestamp: "2025-01-01T00:00:00.000Z",
        endpoint: "/token",
        level: "dev",
        result: "granted",
      };

      // Should not throw, just log to stderr
      expect(() => writeAuditLog(entry)).not.toThrow();
    } finally {
      console.error = orig;
    }
  });
});
