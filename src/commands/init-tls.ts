import { ensureTlsFiles, getClientBundleBase64, getDefaultTlsDir } from "../tls/store.ts";
import { expandTilde } from "../config.ts";

export interface InitTlsOptions {
  bundleB64?: boolean;
  showPath?: boolean;
  tlsDir?: string;
}

/**
 * Force-regenerate TLS certificates or display bundle/path info.
 */
export async function runInitTls(options: InitTlsOptions = {}): Promise<void> {
  const tlsDir = options.tlsDir ? expandTilde(options.tlsDir) : getDefaultTlsDir();

  if (options.showPath) {
    console.log(tlsDir);
    return;
  }

  // Always regenerate when init-tls is called explicitly
  await ensureTlsFiles(tlsDir);

  if (options.bundleB64) {
    const b64 = getClientBundleBase64(tlsDir);
    console.log(b64);
    return;
  }

  console.log("init-tls: TLS certificates generated");
  console.log(`  directory: ${tlsDir}`);
  console.log("  files:");
  console.log("    ca.pem          — CA certificate");
  console.log("    ca-key.pem      — CA private key");
  console.log("    server.pem      — server certificate");
  console.log("    server-key.pem  — server private key");
  console.log("    client.pem      — client certificate");
  console.log("    client-key.pem  — client private key");
  console.log("    client-bundle.pem — combined CA + client cert + key");
  console.log("");
  console.log("To get the base64-encoded client bundle for remote environments:");
  console.log("  gcp-authcalator init-tls --bundle-b64");
}
