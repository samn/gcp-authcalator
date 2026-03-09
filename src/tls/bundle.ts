import type { ClientBundle } from "./store.ts";
import { loadClientBundle, loadClientBundleFromBase64 } from "./store.ts";

const TLS_BUNDLE_B64_ENV = "GCP_AUTHCALATOR_TLS_BUNDLE_B64";

/**
 * Resolve the client bundle from available sources, in priority order:
 *
 * 1. `GCP_AUTHCALATOR_TLS_BUNDLE_B64` env var (base64-encoded)
 * 2. `tls_bundle` config / CLI option (file path)
 * 3. null (no bundle → Unix socket mode)
 *
 * After resolving from the env var, it is deleted from process.env to
 * mitigate /proc/&lt;pid&gt;/environ exposure.
 */
export function resolveClientBundle(
  config: { tls_bundle?: string },
  env: Record<string, string | undefined> = process.env,
): ClientBundle | null {
  // Priority 1: base64-encoded env var
  const b64 = env[TLS_BUNDLE_B64_ENV];
  if (b64) {
    const bundle = loadClientBundleFromBase64(b64);
    // Clear from process env to limit exposure via /proc/*/environ
    delete process.env[TLS_BUNDLE_B64_ENV];
    return bundle;
  }

  // Priority 2: file path from config
  if (config.tls_bundle) {
    return loadClientBundle(config.tls_bundle);
  }

  // No bundle available
  return null;
}
