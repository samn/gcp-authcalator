import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  resolveClientBundle,
  captureAndDeleteTlsBundleEnv,
  _resetCapturedTlsBundleForTesting,
} from "../../tls/bundle.ts";
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
    _resetCapturedTlsBundleForTesting();
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

// F4: capture-and-delete-at-startup. The CLI calls
// captureAndDeleteTlsBundleEnv() at module init so the bundle is no longer
// in process.env by the time anything spawns a subprocess
// (e.g. `git rev-parse` inside formatVersion()).
describe("captureAndDeleteTlsBundleEnv", () => {
  const tempDirs: string[] = [];

  function makeTempDir(): string {
    const dir = mkdtempSync(join(tmpdir(), "tls-bundle-cap-"));
    tempDirs.push(dir);
    return dir;
  }

  afterEach(() => {
    _resetCapturedTlsBundleForTesting();
    delete process.env.GCP_AUTHCALATOR_TLS_BUNDLE_B64;
    for (const dir of tempDirs) {
      rmSync(dir, { recursive: true, force: true });
    }
    tempDirs.length = 0;
  });

  test("removes the env var from the supplied env object", async () => {
    _resetCapturedTlsBundleForTesting();
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);

    const env: NodeJS.ProcessEnv = { GCP_AUTHCALATOR_TLS_BUNDLE_B64: b64 };

    const captured = captureAndDeleteTlsBundleEnv(env);
    expect(captured).toBe(b64);
    expect(env.GCP_AUTHCALATOR_TLS_BUNDLE_B64).toBeUndefined();
  });

  test("removes the env var from process.env by default", async () => {
    _resetCapturedTlsBundleForTesting();
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);

    process.env.GCP_AUTHCALATOR_TLS_BUNDLE_B64 = b64;

    captureAndDeleteTlsBundleEnv();

    expect(process.env.GCP_AUTHCALATOR_TLS_BUNDLE_B64).toBeUndefined();
  });

  test("returns undefined when env var is not set", () => {
    _resetCapturedTlsBundleForTesting();
    delete process.env.GCP_AUTHCALATOR_TLS_BUNDLE_B64;
    const result = captureAndDeleteTlsBundleEnv({});
    expect(result).toBeUndefined();
  });

  test("subsequent resolveClientBundle uses the captured value", async () => {
    _resetCapturedTlsBundleForTesting();
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);

    process.env.GCP_AUTHCALATOR_TLS_BUNDLE_B64 = b64;
    captureAndDeleteTlsBundleEnv();
    expect(process.env.GCP_AUTHCALATOR_TLS_BUNDLE_B64).toBeUndefined();

    // The env arg is empty — but resolveClientBundle still finds the
    // captured value.
    const result = resolveClientBundle({}, {});
    expect(result).not.toBeNull();
    expect(result!.caCert).toContain("-----BEGIN CERTIFICATE-----");
  });

  test("idempotent: a second capture does not overwrite the first", async () => {
    _resetCapturedTlsBundleForTesting();
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const b64 = getClientBundleBase64(dir);

    captureAndDeleteTlsBundleEnv({ GCP_AUTHCALATOR_TLS_BUNDLE_B64: b64 });
    // No env var set on the second call — captured slot remains.
    const result = captureAndDeleteTlsBundleEnv({});
    expect(result).toBe(b64);
  });
});
