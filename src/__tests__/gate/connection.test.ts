import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildGateConnection } from "../../gate/connection.ts";
import { ensureTlsFiles, getClientBundleBase64 } from "../../tls/store.ts";

describe("buildGateConnection", () => {
  const tempDirs: string[] = [];

  function makeTempDir(): string {
    const dir = mkdtempSync(join(tmpdir(), "gate-conn-test-"));
    tempDirs.push(dir);
    return dir;
  }

  afterEach(() => {
    for (const dir of tempDirs) {
      rmSync(dir, { recursive: true, force: true });
    }
    tempDirs.length = 0;
    delete process.env.GCP_AUTHCALATOR_TLS_BUNDLE_B64;
  });

  test("returns unix mode when no gate_url is configured", () => {
    const conn = buildGateConnection({ socket_path: "/tmp/test.sock" }, {});

    expect(conn.mode).toBe("unix");
    if (conn.mode === "unix") {
      expect(conn.socketPath).toBe("/tmp/test.sock");
    }
  });

  test("returns tcp mode when gate_url is in config", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);

    const conn = buildGateConnection(
      { socket_path: "/tmp/test.sock", gate_url: "https://localhost:8174" },
      { GCP_AUTHCALATOR_TLS_BUNDLE_B64: b64 },
    );

    expect(conn.mode).toBe("tcp");
    if (conn.mode === "tcp") {
      expect(conn.gateUrl).toBe("https://localhost:8174");
      expect(conn.caCert).toContain("-----BEGIN CERTIFICATE-----");
      expect(conn.clientCert).toContain("-----BEGIN CERTIFICATE-----");
      expect(conn.clientKey).toContain("-----BEGIN PRIVATE KEY-----");
    }
  });

  test("returns tcp mode when gate_url is in env var", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);

    const conn = buildGateConnection(
      { socket_path: "/tmp/test.sock" },
      {
        GCP_AUTHCALATOR_GATE_URL: "https://localhost:8174",
        GCP_AUTHCALATOR_TLS_BUNDLE_B64: b64,
      },
    );

    expect(conn.mode).toBe("tcp");
    if (conn.mode === "tcp") {
      expect(conn.gateUrl).toBe("https://localhost:8174");
    }
  });

  test("throws when gate_url is set but no client bundle is available", () => {
    expect(() =>
      buildGateConnection(
        { socket_path: "/tmp/test.sock", gate_url: "https://localhost:8174" },
        {},
      ),
    ).toThrow(/no TLS client bundle/);
  });

  test("config gate_url takes precedence over env var", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);

    const conn = buildGateConnection(
      { socket_path: "/tmp/test.sock", gate_url: "https://localhost:9999" },
      {
        GCP_AUTHCALATOR_GATE_URL: "https://localhost:8174",
        GCP_AUTHCALATOR_TLS_BUNDLE_B64: b64,
      },
    );

    expect(conn.mode).toBe("tcp");
    if (conn.mode === "tcp") {
      expect(conn.gateUrl).toBe("https://localhost:9999");
    }
  });
});
