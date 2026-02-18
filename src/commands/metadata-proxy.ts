import type { Config } from "../config.ts";
import { MetadataProxyConfigSchema } from "../config.ts";
import { startMetadataProxyServer } from "../metadata-proxy/server.ts";
import { checkGateSocket } from "../metadata-proxy/gate-client.ts";

export interface RunMetadataProxyOptions {
  /** Override fetch for the connectivity check (testing). */
  checkFetchFn?: typeof globalThis.fetch;
}

export async function runMetadataProxy(
  config: Config,
  options: RunMetadataProxyOptions = {},
): Promise<void> {
  const proxyConfig = MetadataProxyConfigSchema.parse(config);

  try {
    await checkGateSocket(proxyConfig.socket_path, options.checkFetchFn);
  } catch (err) {
    console.error(`metadata-proxy: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }

  startMetadataProxyServer(proxyConfig, { scopes: proxyConfig.scopes });
}
