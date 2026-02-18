import type { Config } from "../config.ts";
import { MetadataProxyConfigSchema } from "../config.ts";
import { startMetadataProxyServer } from "../metadata-proxy/server.ts";
import { checkGateConnection } from "../metadata-proxy/gate-client.ts";
import { buildGateConnection, type GateConnection } from "../gate/connection.ts";

export interface RunMetadataProxyOptions {
  /** Override fetch for the connectivity check (testing). */
  checkFetchFn?: typeof globalThis.fetch;
}

export async function runMetadataProxy(
  config: Config,
  options: RunMetadataProxyOptions = {},
): Promise<void> {
  const proxyConfig = MetadataProxyConfigSchema.parse(config);

  const conn: GateConnection = await buildGateConnection(proxyConfig);

  try {
    await checkGateConnection(conn, options.checkFetchFn);
  } catch (err) {
    console.error(`metadata-proxy: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }

  startMetadataProxyServer(proxyConfig, { gateConnection: conn, scopes: proxyConfig.scopes });
}
