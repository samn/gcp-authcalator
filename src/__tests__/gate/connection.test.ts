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

  test("returns unix mode when no gate_url is configured", async () => {
    const conn = await buildGateConnection({ socket_path: "/tmp/test.sock" }, {});

    expect(conn.mode).toBe("unix");
    if (conn.mode === "unix") {
      expect(conn.socketPath).toBe("/tmp/test.sock");
    }
  });

  test("returns tcp mode when gate_url is in config", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);

    const conn = await buildGateConnection(
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

    const conn = await buildGateConnection(
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

  test("returns tcp mode when gate_url and tls_dir are set", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const conn = await buildGateConnection(
      { socket_path: "/tmp/test.sock", gate_url: "https://localhost:8174", tls_dir: dir },
      {},
    );

    expect(conn.mode).toBe("tcp");
    if (conn.mode === "tcp") {
      expect(conn.gateUrl).toBe("https://localhost:8174");
      expect(conn.caCert).toContain("-----BEGIN CERTIFICATE-----");
      expect(conn.clientCert).toContain("-----BEGIN CERTIFICATE-----");
      expect(conn.clientKey).toContain("-----BEGIN PRIVATE KEY-----");
    }
  });

  test("throws when gate_url is set but no client bundle is available", async () => {
    await expect(
      buildGateConnection(
        { socket_path: "/tmp/test.sock", gate_url: "https://localhost:8174" },
        {},
      ),
    ).rejects.toThrow(/no TLS client bundle/);
  });

  test("config gate_url takes precedence over env var", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);

    const conn = await buildGateConnection(
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

  test("throws when client bundle has expired CA cert", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Build a bundle with an expired CA cert
    const x509 = await import("@peculiar/x509");
    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const expiredCA = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=expired",
      notBefore: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
    });

    // Read real bundle to get valid client cert/key, replace CA with expired one
    const { loadClientBundleFromBase64 } = await import("../../tls/store.ts");
    const b64 = getClientBundleBase64(dir);
    const realBundle = loadClientBundleFromBase64(b64);

    const fakeBundle = expiredCA.toString("pem") + realBundle.clientCert + realBundle.clientKey;
    const fakeB64 = Buffer.from(fakeBundle).toString("base64");

    await expect(
      buildGateConnection(
        { socket_path: "/tmp/test.sock", gate_url: "https://localhost:8174" },
        { GCP_AUTHCALATOR_TLS_BUNDLE_B64: fakeB64 },
      ),
    ).rejects.toThrow(/CA certificate has expired/);
  });

  test("throws when client bundle cert is not signed by bundle CA", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Generate a completely separate CA + client cert
    const { generateCA } = await import("../../tls/ca.ts");
    const { generateClientCert } = await import("../../tls/certs.ts");
    const otherCA = await generateCA();
    const otherClient = await generateClientCert(otherCA.caCert, otherCA.caKey);

    // Read the original bundle CA and pair it with the other client cert
    const { loadClientBundleFromBase64 } = await import("../../tls/store.ts");
    const b64 = getClientBundleBase64(dir);
    const realBundle = loadClientBundleFromBase64(b64);

    const mismatchedBundle = realBundle.caCert + otherClient.cert + otherClient.key;
    const mismatchedB64 = Buffer.from(mismatchedBundle).toString("base64");

    await expect(
      buildGateConnection(
        { socket_path: "/tmp/test.sock", gate_url: "https://localhost:8174" },
        { GCP_AUTHCALATOR_TLS_BUNDLE_B64: mismatchedB64 },
      ),
    ).rejects.toThrow(/client certificate signature is invalid/);
  });
});
