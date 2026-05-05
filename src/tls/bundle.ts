import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ClientBundle } from "./store.ts";
import { loadClientBundle, loadClientBundleFromBase64 } from "./store.ts";

const TLS_BUNDLE_B64_ENV = "GCP_AUTHCALATOR_TLS_BUNDLE_B64";

/**
 * Snapshot of the bundle env var, captured before any subprocess can be
 * spawned. `captureAndDeleteTlsBundleEnv` is called from `main()` as its
 * first action so that `process.env` no longer carries the secret by the
 * time anything runs `Bun.spawn`/`spawnSync` (e.g. the `git rev-parse`
 * call in `formatVersion`). A child process that inherits `process.env`
 * after this point will not see the bundle.
 */
let capturedTlsBundleB64: string | undefined;

/**
 * Pull `GCP_AUTHCALATOR_TLS_BUNDLE_B64` out of `process.env` into a
 * module-private slot and delete it from the env. Idempotent: subsequent
 * calls are no-ops if the env var has already been consumed.
 *
 * Call this as the first line of `main()` — before module-level
 * initialisation runs anything that could spawn a child process.
 */
export function captureAndDeleteTlsBundleEnv(
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  const b64 = env[TLS_BUNDLE_B64_ENV];
  if (b64 !== undefined) {
    capturedTlsBundleB64 = b64;
    delete env[TLS_BUNDLE_B64_ENV];
  }
  return capturedTlsBundleB64;
}

/**
 * Test-only: clear the captured bundle slot so a fresh capture can be
 * verified. Not part of the public surface; not exported via index.
 */
export function _resetCapturedTlsBundleForTesting(): void {
  capturedTlsBundleB64 = undefined;
}

/**
 * Resolve the client bundle from available sources, in priority order:
 *
 * 1. Captured `GCP_AUTHCALATOR_TLS_BUNDLE_B64` value (deleted from env at
 *    process startup by `captureAndDeleteTlsBundleEnv`)
 * 2. `GCP_AUTHCALATOR_TLS_BUNDLE_B64` still in env (fallback for callers
 *    that bypassed `main()`, e.g. tests; deleted on read)
 * 3. `tls_bundle` config / CLI option (file path)
 * 4. `tls_dir` — load `client-bundle.pem` from the TLS directory
 * 5. null (no bundle → Unix socket mode)
 */
export function resolveClientBundle(
  config: { tls_bundle?: string; tls_dir?: string },
  env: Record<string, string | undefined> = process.env,
): ClientBundle | null {
  // Priority 1: previously captured base64 env value
  if (capturedTlsBundleB64) {
    return loadClientBundleFromBase64(capturedTlsBundleB64);
  }

  // Priority 2: still-live env var (defensive — main() should already
  // have captured it). Delete on read so it doesn't linger.
  const b64 = env[TLS_BUNDLE_B64_ENV];
  if (b64) {
    const bundle = loadClientBundleFromBase64(b64);
    delete process.env[TLS_BUNDLE_B64_ENV];
    return bundle;
  }

  // Priority 3: file path from config
  if (config.tls_bundle) {
    return loadClientBundle(config.tls_bundle);
  }

  // Priority 4: client-bundle.pem inside tls_dir
  if (config.tls_dir) {
    const bundlePath = join(config.tls_dir, "client-bundle.pem");
    if (existsSync(bundlePath)) {
      return loadClientBundle(bundlePath);
    }
  }

  // No bundle available
  return null;
}
