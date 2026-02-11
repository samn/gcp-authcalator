import type { Config } from "../config.ts";
import { MetadataProxyConfigSchema } from "../config.ts";

export function runMetadataProxy(config: Config): void {
  const proxyConfig = MetadataProxyConfigSchema.parse(config);

  console.log("metadata-proxy: starting GCE metadata server emulator");
  console.log(`  project:     ${proxyConfig.project_id}`);
  console.log(`  port:        ${proxyConfig.port}`);
  console.log(`  socket path: ${proxyConfig.socket_path}`);
  console.log("  endpoints:");
  console.log("    /computeMetadata/v1/project/project-id");
  console.log("    /computeMetadata/v1/instance/service-accounts/default/token");
  console.log("    /computeMetadata/v1/instance/service-accounts/default/email");
  console.log("[STUB] Not yet implemented.");
}
