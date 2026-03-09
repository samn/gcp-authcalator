import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runInitTls } from "../../commands/init-tls.ts";
import { loadTlsFiles } from "../../tls/store.ts";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "init-tls-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  tempDirs.length = 0;
});

describe("runInitTls", () => {
  test("generates TLS certificates in specified directory", async () => {
    const tlsDir = join(makeTempDir(), "tls");
    await runInitTls({ tlsDir });

    expect(existsSync(join(tlsDir, "ca.pem"))).toBe(true);
    expect(existsSync(join(tlsDir, "server.pem"))).toBe(true);
    expect(existsSync(join(tlsDir, "client.pem"))).toBe(true);
    expect(existsSync(join(tlsDir, "client-bundle.pem"))).toBe(true);
  });

  test("force-regenerates certs on subsequent calls", async () => {
    const tlsDir = join(makeTempDir(), "tls");
    await runInitTls({ tlsDir });
    const first = loadTlsFiles(tlsDir);

    await runInitTls({ tlsDir });
    const second = loadTlsFiles(tlsDir);

    // Should have regenerated (different certs)
    expect(first.caCert).not.toBe(second.caCert);
    expect(first.serverCert).not.toBe(second.serverCert);
  });

  test("--show-path prints directory and returns early", async () => {
    const tlsDir = join(makeTempDir(), "tls");
    const logs: string[] = [];
    const origLog = console.log;
    console.log = (...args: unknown[]) => logs.push(args.join(" "));

    try {
      await runInitTls({ showPath: true, tlsDir });
    } finally {
      console.log = origLog;
    }

    expect(logs).toHaveLength(1);
    expect(logs[0]).toBe(tlsDir);
    // Should NOT have generated any files
    expect(existsSync(tlsDir)).toBe(false);
  });

  test("--bundle-b64 prints base64-encoded bundle", async () => {
    const tlsDir = join(makeTempDir(), "tls");
    const logs: string[] = [];
    const origLog = console.log;
    console.log = (...args: unknown[]) => logs.push(args.join(" "));

    try {
      await runInitTls({ bundleB64: true, tlsDir });
    } finally {
      console.log = origLog;
    }

    // Last log entry should be a base64 string
    const b64 = logs[logs.length - 1]!;
    const decoded = Buffer.from(b64, "base64").toString("utf-8");
    expect(decoded).toContain("-----BEGIN CERTIFICATE-----");
    expect(decoded).toContain("-----BEGIN PRIVATE KEY-----");
  });
});
