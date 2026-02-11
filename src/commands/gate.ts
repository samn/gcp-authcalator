import type { Config } from "../config.ts";
import { GateConfigSchema } from "../config.ts";
import { startGateServer } from "../gate/server.ts";

export async function runGate(config: Config): Promise<void> {
  const gateConfig = GateConfigSchema.parse(config);
  await startGateServer(gateConfig);
}
