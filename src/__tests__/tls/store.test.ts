import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, existsSync, statSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  ensureTlsFiles,
  loadTlsFiles,
  loadClientBundle,
  loadClientBundleFromBase64,
  getClientBundleBase64,
} from "../../tls/store.ts";

describe("ensureTlsFiles", () => {
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
});

describe("loadTlsFiles", () => {
  test("loads previously generated TLS files", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "tls-load-")), "tls");
    const generated = await ensureTlsFiles(dir);
    const loaded = loadTlsFiles(dir);

    expect(loaded.caCert).toBe(generated.caCert);
    expect(loaded.serverCert).toBe(generated.serverCert);
    expect(loaded.clientCert).toBe(generated.clientCert);

    rmSync(dir, { recursive: true, force: true });
  });

  test("throws when files are missing", () => {
    expect(() => loadTlsFiles("/tmp/nonexistent-tls-dir")).toThrow();
  });
});

describe("loadClientBundle", () => {
  test("parses client-bundle.pem into CA cert, client cert, client key", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "tls-bundle-")), "tls");
    await ensureTlsFiles(dir);

    const bundle = loadClientBundle(join(dir, "client-bundle.pem"));

    expect(bundle.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientKey).toContain("-----BEGIN PRIVATE KEY-----");

    // CA cert should be different from client cert
    expect(bundle.caCert).not.toBe(bundle.clientCert);

    rmSync(dir, { recursive: true, force: true });
  });
});

describe("loadClientBundleFromBase64", () => {
  test("round-trips correctly with getClientBundleBase64", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "tls-b64-")), "tls");
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

    rmSync(dir, { recursive: true, force: true });
  });

  test("throws on invalid base64 content", () => {
    const invalidB64 = Buffer.from("not a PEM bundle").toString("base64");
    expect(() => loadClientBundleFromBase64(invalidB64)).toThrow(/Invalid client bundle/);
  });
});
