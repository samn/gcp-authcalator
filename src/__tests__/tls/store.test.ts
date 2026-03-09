import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, existsSync, statSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  ensureTlsFiles,
  loadTlsFiles,
  loadClientBundle,
  loadClientBundleFromBase64,
  getClientBundleBase64,
} from "../../tls/store.ts";

// Shared temp directory tracking for all describe blocks
const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tls-store-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  tempDirs.length = 0;
});

describe("ensureTlsFiles", () => {
  test("creates all TLS files when directory is empty", async () => {
    const dir = join(makeTempDir(), "tls");
    const files = await ensureTlsFiles(dir);

    expect(files.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(files.caKey).toContain("-----BEGIN PRIVATE KEY-----");
    expect(files.serverCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(files.serverKey).toContain("-----BEGIN PRIVATE KEY-----");
    expect(files.clientCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(files.clientKey).toContain("-----BEGIN PRIVATE KEY-----");

    // Check files exist on disk
    expect(existsSync(join(dir, "ca.pem"))).toBe(true);
    expect(existsSync(join(dir, "ca-key.pem"))).toBe(true);
    expect(existsSync(join(dir, "server.pem"))).toBe(true);
    expect(existsSync(join(dir, "server-key.pem"))).toBe(true);
    expect(existsSync(join(dir, "client.pem"))).toBe(true);
    expect(existsSync(join(dir, "client-key.pem"))).toBe(true);
    expect(existsSync(join(dir, "client-bundle.pem"))).toBe(true);
  });

  test("creates directory with 0700 permissions", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const stats = statSync(dir);
    expect(stats.mode & 0o777).toBe(0o700);
  });

  test("creates files with 0600 permissions", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    for (const file of [
      "ca.pem",
      "ca-key.pem",
      "server.pem",
      "server-key.pem",
      "client.pem",
      "client-key.pem",
      "client-bundle.pem",
    ]) {
      const stats = statSync(join(dir, file));
      expect(stats.mode & 0o777).toBe(0o600);
    }
  });

  test("is idempotent — does not regenerate valid certs", async () => {
    const dir = join(makeTempDir(), "tls");

    const first = await ensureTlsFiles(dir);
    const second = await ensureTlsFiles(dir);

    // Same certs should be returned
    expect(first.caCert).toBe(second.caCert);
    expect(first.serverCert).toBe(second.serverCert);
    expect(first.clientCert).toBe(second.clientCert);
  });

  test("force=true regenerates all certs even when valid", async () => {
    const dir = join(makeTempDir(), "tls");

    const first = await ensureTlsFiles(dir);
    const second = await ensureTlsFiles(dir, true);

    // New certs should be generated
    expect(first.caCert).not.toBe(second.caCert);
    expect(first.serverCert).not.toBe(second.serverCert);
    expect(first.clientCert).not.toBe(second.clientCert);
  });

  test("regenerates when CA cert is expired", async () => {
    const dir = join(makeTempDir(), "tls");
    const first = await ensureTlsFiles(dir);

    // Replace the CA cert file with an already-expired cert to trigger regeneration
    const x509 = await import("@peculiar/x509");

    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const expiredCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=expired",
      notBefore: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
    });
    writeFileSync(join(dir, "ca.pem"), expiredCert.toString("pem"));

    const second = await ensureTlsFiles(dir);

    // Should have regenerated
    expect(second.caCert).not.toBe(first.caCert);
    expect(second.serverCert).not.toBe(first.serverCert);
  });
});

describe("loadTlsFiles", () => {
  test("loads previously generated TLS files", async () => {
    const dir = join(makeTempDir(), "tls");
    const generated = await ensureTlsFiles(dir);
    const loaded = loadTlsFiles(dir);

    expect(loaded.caCert).toBe(generated.caCert);
    expect(loaded.serverCert).toBe(generated.serverCert);
    expect(loaded.clientCert).toBe(generated.clientCert);
  });

  test("throws when files are missing", () => {
    expect(() => loadTlsFiles("/tmp/nonexistent-tls-dir")).toThrow();
  });
});

describe("loadClientBundle", () => {
  test("parses client-bundle.pem into CA cert, client cert, client key", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const bundle = loadClientBundle(join(dir, "client-bundle.pem"));

    expect(bundle.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientKey).toContain("-----BEGIN PRIVATE KEY-----");

    // CA cert should be different from client cert
    expect(bundle.caCert).not.toBe(bundle.clientCert);
  });

  test("auto-detects and decodes a base64-encoded bundle file", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Write a base64-encoded copy of the bundle
    const b64 = getClientBundleBase64(dir);
    const b64Path = join(dir, "client-bundle.b64");
    writeFileSync(b64Path, b64);

    const bundle = loadClientBundle(b64Path);

    expect(bundle.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientKey).toContain("-----BEGIN PRIVATE KEY-----");

    // Should match the PEM-loaded bundle
    const pemBundle = loadClientBundle(join(dir, "client-bundle.pem"));
    expect(bundle.caCert).toBe(pemBundle.caCert);
    expect(bundle.clientCert).toBe(pemBundle.clientCert);
    expect(bundle.clientKey).toBe(pemBundle.clientKey);
  });
});

describe("loadClientBundleFromBase64", () => {
  test("round-trips correctly with getClientBundleBase64", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const b64 = getClientBundleBase64(dir);
    const bundle = loadClientBundleFromBase64(b64);

    expect(bundle.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientKey).toContain("-----BEGIN PRIVATE KEY-----");

    // Verify the decoded values match the original files
    const originalBundle = loadClientBundle(join(dir, "client-bundle.pem"));
    expect(bundle.caCert).toBe(originalBundle.caCert);
    expect(bundle.clientCert).toBe(originalBundle.clientCert);
    expect(bundle.clientKey).toBe(originalBundle.clientKey);
  });

  test("throws on invalid base64 content", () => {
    const invalidB64 = Buffer.from("not a PEM bundle").toString("base64");
    expect(() => loadClientBundleFromBase64(invalidB64)).toThrow(/Invalid client bundle/);
  });

  test("throws when bundle has only 1 PEM block", () => {
    const oneCert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const b64 = Buffer.from(oneCert).toString("base64");
    expect(() => loadClientBundleFromBase64(b64)).toThrow(/expected 3 PEM blocks/);
  });

  test("throws when bundle has only 2 PEM blocks", () => {
    const twoCerts =
      "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" +
      "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n";
    const b64 = Buffer.from(twoCerts).toString("base64");
    expect(() => loadClientBundleFromBase64(b64)).toThrow(/expected 3 PEM blocks/);
  });

  test("throws when bundle has 3 certs but no key", () => {
    const threeCerts =
      "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" +
      "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n" +
      "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----\n";
    const b64 = Buffer.from(threeCerts).toString("base64");
    expect(() => loadClientBundleFromBase64(b64)).toThrow(/expected 2 CERTIFICATE blocks/);
  });

  test("throws when bundle has unexpected PEM block type", () => {
    const badBundle =
      "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" +
      "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n" +
      "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n";
    const b64 = Buffer.from(badBundle).toString("base64");
    expect(() => loadClientBundleFromBase64(b64)).toThrow(/unexpected PEM block type/);
  });

  test("parses correctly regardless of PEM block order", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Read the original bundle and rearrange: key first, then certs
    const originalBundle = loadClientBundle(join(dir, "client-bundle.pem"));
    const reordered = originalBundle.clientKey + originalBundle.caCert + originalBundle.clientCert;
    const b64 = Buffer.from(reordered).toString("base64");

    const bundle = loadClientBundleFromBase64(b64);

    expect(bundle.caCert).toBe(originalBundle.caCert);
    expect(bundle.clientCert).toBe(originalBundle.clientCert);
    expect(bundle.clientKey).toBe(originalBundle.clientKey);
  });
});
