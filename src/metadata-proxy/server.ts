import type { MetadataProxyConfig } from "../config.ts";
import type { MetadataProxyDeps } from "./types.ts";
import { createGateClient, type GateClientOptions } from "./gate-client.ts";
import { handleRequest } from "./handlers.ts";

export interface MetadataProxyServerResult {
  server: ReturnType<typeof Bun.serve>;
  stop: () => void;
}

export interface StartMetadataProxyServerOptions {
  gateClientOptions?: GateClientOptions;
}

/**
 * Start the GCE metadata server emulator on a TCP port.
 *
 * 1. Creates a gate client for fetching tokens from gcp-gate
 * 2. Builds MetadataProxyDeps and wires the handler
 * 3. Starts Bun.serve on 127.0.0.1:<port>
 * 4. Registers SIGTERM / SIGINT handlers for graceful shutdown
 */
export function startMetadataProxyServer(
  config: MetadataProxyConfig,
  options: StartMetadataProxyServerOptions = {},
): MetadataProxyServerResult {
  const gateClient = createGateClient(config.socket_path, options.gateClientOptions);

  const deps: MetadataProxyDeps = {
    getToken: gateClient.getToken,
    projectId: config.project_id,
    serviceAccountEmail: config.service_account,
    startTime: new Date(),
  };

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: config.port,
    fetch(req) {
      return handleRequest(req, deps);
    },
  });

  function stop() {
    try {
      server.stop(true);
    } catch {
      // Already stopped
    }
  }

  const onSignal = () => {
    console.log("\nmetadata-proxy: shutting down...");
    stop();
    process.exit(0);
  };
  process.on("SIGTERM", onSignal);
  process.on("SIGINT", onSignal);

  console.log("metadata-proxy: starting GCE metadata server emulator");
  console.log(`  project:     ${config.project_id}`);
  console.log(`  port:        ${config.port}`);
  console.log(`  socket path: ${config.socket_path}`);
  console.log("  endpoints:");
  console.log("    GET /                                                        → detection ping");
  console.log("    GET /computeMetadata/v1/instance/service-accounts/default/token → access token");
  console.log("    GET /computeMetadata/v1/project/project-id                    → project ID");
  console.log("    GET /computeMetadata/v1/instance/service-accounts/default/email → SA email");

  return { server, stop };
}
