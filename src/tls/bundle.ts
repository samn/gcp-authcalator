import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ClientBundle } from "./store.ts";
import { loadClientBundle, loadClientBundleFromBase64 } from "./store.ts";

const TLS_BUNDLE_B64_ENV = "GCP_AUTHCALATOR_TLS_BUNDLE_B64";

let capturedTlsBundleB64: string | undefined;

/**
 * Move `GCP_AUTHCALATOR_TLS_BUNDLE_B64` out of `process.env` into a
 * module-private slot. Call before any subprocess can be spawned so the
 * bundle is no longer visible via `/proc/<pid>/environ`. Idempotent.
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

/** Test-only: clear the captured bundle slot. */
export function _resetCapturedTlsBundleForTesting(): void {
  capturedTlsBundleB64 = undefined;
}

/**
 * Resolve the client bundle. Priority: captured env value > live env
 * var (test fallback) > `tls_bundle` path > `tls_dir/client-bundle.pem`
 * > null (Unix-socket mode).
 */
export function resolveClientBundle(
  config: { tls_bundle?: string; tls_dir?: string },
  env: Record<string, string | undefined> = process.env,
): ClientBundle | null {
  if (capturedTlsBundleB64) {
    return loadClientBundleFromBase64(capturedTlsBundleB64);
  }

  // Tests that import this module without going through cli.ts can still
  // resolve from the live env var. Production callers never hit this
  // branch because main() captures the value first.
  const b64 = env[TLS_BUNDLE_B64_ENV];
  if (b64) {
    const bundle = loadClientBundleFromBase64(b64);
    delete process.env[TLS_BUNDLE_B64_ENV];
    return bundle;
  }

  if (config.tls_bundle) {
    return loadClientBundle(config.tls_bundle);
  }

  if (config.tls_dir) {
    const bundlePath = join(config.tls_dir, "client-bundle.pem");
    if (existsSync(bundlePath)) {
      return loadClientBundle(bundlePath);
    }
  }

  return null;
}
