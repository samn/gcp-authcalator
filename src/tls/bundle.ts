import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ClientBundle } from "./store.ts";
import { loadClientBundle, loadClientBundleFromBase64 } from "./store.ts";

const TLS_BUNDLE_B64_ENV = "GCP_AUTHCALATOR_TLS_BUNDLE_B64";

/**
 * Resolve the client bundle from available sources, in priority order:
 *
 * 1. `GCP_AUTHCALATOR_TLS_BUNDLE_B64` env var (base64-encoded)
 * 2. `tls_bundle` config / CLI option (file path)
 * 3. `tls_dir` — load `client-bundle.pem` from the TLS directory
 * 4. null (no bundle → Unix socket mode)
 *
 * After resolving from the env var, it is deleted from process.env to
 * mitigate /proc/&lt;pid&gt;/environ exposure.
 */
export function resolveClientBundle(
  config: { tls_bundle?: string; tls_dir?: string },
  env: Record<string, string | undefined> = process.env,
): ClientBundle | null {
  // Priority 1: base64-encoded env var
  const b64 = env[TLS_BUNDLE_B64_ENV];
  if (b64) {
    const bundle = loadClientBundleFromBase64(b64);
    // Clear from process env to prevent inheritance by child processes
    delete process.env[TLS_BUNDLE_B64_ENV];
    return bundle;
  }

  // Priority 2: file path from config
  if (config.tls_bundle) {
    return loadClientBundle(config.tls_bundle);
  }

  // Priority 3: client-bundle.pem inside tls_dir
  if (config.tls_dir) {
    const bundlePath = join(config.tls_dir, "client-bundle.pem");
    if (existsSync(bundlePath)) {
      return loadClientBundle(bundlePath);
    }
  }

  // No bundle available
  return null;
}
