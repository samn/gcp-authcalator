import type { Config } from "../config.ts";
import { WithProdConfigSchema } from "../config.ts";

export function runWithProd(config: Config, wrappedCommand: string[]): void {
  if (wrappedCommand.length === 0) {
    console.error("error: with-prod requires a command to wrap");
    console.error("usage: gcp-authcalator with-prod -- <command> [args...]");
    process.exit(1);
  }

  const wpConfig = WithProdConfigSchema.parse(config);

  console.log("with-prod: wrapping command with prod credentials");
  console.log(`  project:     ${wpConfig.project_id}`);
  console.log(`  socket path: ${wpConfig.socket_path}`);
  console.log(`  command:     ${wrappedCommand.join(" ")}`);
  console.log("  steps:");
  console.log("    1. Request prod-level token from gcp-gate (with confirmation)");
  console.log("    2. Start temporary metadata proxy on random port");
  console.log("    3. Set GCE_METADATA_HOST for subprocess");
  console.log("    4. Execute wrapped command");
  console.log("    5. Shut down temporary proxy on exit");
  console.log("[STUB] Not yet implemented.");
}
