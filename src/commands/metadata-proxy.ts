import type { Config } from "../config.ts";
import { MetadataProxyConfigSchema } from "../config.ts";
import { startMetadataProxyServer } from "../metadata-proxy/server.ts";

export async function runMetadataProxy(config: Config): Promise<void> {
  const proxyConfig = MetadataProxyConfigSchema.parse(config);
  startMetadataProxyServer(proxyConfig);
}
