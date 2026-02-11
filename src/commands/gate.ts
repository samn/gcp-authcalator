import type { Config } from "../config.ts";
import { GateConfigSchema } from "../config.ts";

export function runGate(config: Config): void {
  const gateConfig = GateConfigSchema.parse(config);

  console.log("gate: starting gcp-gate token daemon");
  console.log(`  project:         ${gateConfig.project_id}`);
  console.log(`  service account: ${gateConfig.service_account}`);
  console.log(`  socket path:     ${gateConfig.socket_path}`);
  console.log("  endpoints:");
  console.log("    GET /token          → dev-scoped access token");
  console.log("    GET /token?level=prod → prod token (with confirmation)");
  console.log("    GET /identity       → authenticated user email");
  console.log("    GET /health         → health check");
  console.log("[STUB] Not yet implemented.");
}
