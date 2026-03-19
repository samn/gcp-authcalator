import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { resolveClientBundle } from "../../tls/bundle.ts";
import { ensureTlsFiles, getClientBundleBase64 } from "../../tls/store.ts";

describe("resolveClientBundle", () => {
  const tempDirs: string[] = [];

  function makeTempDir(): string {
    const dir = mkdtempSync(join(tmpdir(), "tls-bundle-test-"));
    tempDirs.push(dir);
    return dir;
  }

  afterEach(() => {
    for (const dir of tempDirs) {
      rmSync(dir, { recursive: true, force: true });
    }
    tempDirs.length = 0;
  });

  test("returns null when nothing is configured", () => {
    const result = resolveClientBundle({}, {});
    expect(result).toBeNull();
  });

  test("resolves from base64 env var", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);

    const env: Record<string, string | undefined> = {
      GCP_AUTHCALATOR_TLS_BUNDLE_B64: b64,
    };

    const result = resolveClientBundle({}, env);

    expect(result).not.toBeNull();
    expect(result!.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(result!.clientCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(result!.clientKey).toContain("-----BEGIN PRIVATE KEY-----");
  });

  test("resolves from tls_bundle file path", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const bundlePath = join(dir, "client-bundle.pem");

    const result = resolveClientBundle({ tls_bundle: bundlePath }, {});

    expect(result).not.toBeNull();
    expect(result!.caCert).toContain("-----BEGIN CERTIFICATE-----");
  });

  test("prefers env var over file path", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);
    const bundlePath = join(dir, "client-bundle.pem");

    const env: Record<string, string | undefined> = {
      GCP_AUTHCALATOR_TLS_BUNDLE_B64: b64,
    };

    const result = resolveClientBundle({ tls_bundle: bundlePath }, env);

    expect(result).not.toBeNull();
    expect(result!.caCert).toContain("-----BEGIN CERTIFICATE-----");
  });

  test("resolves from tls_dir containing client-bundle.pem", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const result = resolveClientBundle({ tls_dir: dir }, {});

    expect(result).not.toBeNull();
    expect(result!.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(result!.clientCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(result!.clientKey).toContain("-----BEGIN PRIVATE KEY-----");
  });

  test("returns null when tls_dir has no client-bundle.pem", () => {
    const dir = makeTempDir();
    const result = resolveClientBundle({ tls_dir: dir }, {});
    expect(result).toBeNull();
  });

  test("prefers tls_bundle over tls_dir", async () => {
    const dir1 = join(makeTempDir(), "tls1");
    const dir2 = join(makeTempDir(), "tls2");
    await ensureTlsFiles(dir1);
    await ensureTlsFiles(dir2);
    const bundlePath = join(dir1, "client-bundle.pem");

    const result = resolveClientBundle({ tls_bundle: bundlePath, tls_dir: dir2 }, {});

    expect(result).not.toBeNull();
    expect(result!.caCert).toContain("-----BEGIN CERTIFICATE-----");
  });

  test("clears env var after reading", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);

    // Set it on process.env directly
    process.env.GCP_AUTHCALATOR_TLS_BUNDLE_B64 = b64;

    const env: Record<string, string | undefined> = {
      GCP_AUTHCALATOR_TLS_BUNDLE_B64: b64,
    };

    resolveClientBundle({}, env);

    expect(process.env.GCP_AUTHCALATOR_TLS_BUNDLE_B64).toBeUndefined();
  });
});
