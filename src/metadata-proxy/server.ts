import { DEFAULT_SCOPES, type MetadataProxyConfig } from "../config.ts";
import type { MetadataProxyDeps, TokenProvider } from "./types.ts";
import { createGateClient, type GateClientOptions } from "./gate-client.ts";
import { handleRequest } from "./handlers.ts";
import { getOwnerPid, isDescendantOf } from "./pid-validator.ts";

export interface MetadataProxyServerResult {
  server: ReturnType<typeof Bun.serve>;
  stop: () => void;
}

export interface StartMetadataProxyServerOptions {
  gateClientOptions?: GateClientOptions;
  /** If provided, use this instead of creating a gate client. */
  tokenProvider?: TokenProvider;
  /** Whether to install SIGTERM/SIGINT handlers (default: true). */
  installSignalHandlers?: boolean;
  /** Suppress startup logging (default: false). */
  quiet?: boolean;
  /** If set, only processes that are descendants of this PID may request tokens. */
  allowedAncestorPid?: number;
  /** OAuth scopes for token requests. Defaults to cloud-platform. */
  scopes?: string[];
}

/**
 * Start the GCE metadata server emulator on a TCP port.
 *
 * 1. Creates a gate client for fetching tokens from gcp-gate (or uses provided tokenProvider)
 * 2. Builds MetadataProxyDeps and wires the handler
 * 3. Starts Bun.serve on 127.0.0.1:<port>
 * 4. Optionally registers SIGTERM / SIGINT handlers for graceful shutdown
 */
export function startMetadataProxyServer(
  config: MetadataProxyConfig,
  options: StartMetadataProxyServerOptions = {},
): MetadataProxyServerResult {
  const effectiveScopes = options.scopes ?? DEFAULT_SCOPES;
  const gateClientOpts = { ...options.gateClientOptions, scopes: effectiveScopes };
  const gateClient = options.tokenProvider
    ? null
    : createGateClient(config.socket_path, gateClientOpts);
  const provider: TokenProvider = options.tokenProvider ?? gateClient!;

  const deps: MetadataProxyDeps = {
    getToken: provider.getToken,
    getNumericProjectId: gateClient?.getNumericProjectId,
    getUniverseDomain: gateClient?.getUniverseDomain,
    projectId: config.project_id,
    serviceAccountEmail: config.service_account,
    scopes: effectiveScopes,
    startTime: new Date(),
  };

  const ancestorPid = options.allowedAncestorPid;

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: config.port,
    fetch(req, server) {
      if (ancestorPid !== undefined) {
        const addr = server.requestIP(req);
        if (!addr) {
          return new Response("Forbidden", { status: 403 });
        }
        const ownerPid = getOwnerPid(addr.port);
        if (ownerPid === null || !isDescendantOf(ownerPid, ancestorPid)) {
          return new Response("Forbidden", { status: 403 });
        }
      }
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

  const installSignalHandlers = options.installSignalHandlers ?? true;
  if (installSignalHandlers) {
    const onSignal = () => {
      console.log("\nmetadata-proxy: shutting down...");
      stop();
      process.exit(0);
    };
    process.on("SIGTERM", onSignal);
    process.on("SIGINT", onSignal);
  }

  const quiet = options.quiet ?? false;
  if (!quiet) {
    console.log("metadata-proxy: starting GCE metadata server emulator");
    console.log(`  project:     ${config.project_id}`);
    console.log(`  port:        ${server.port}`);
    console.log(`  socket path: ${config.socket_path}`);
    console.log("  endpoints:");
    console.log(
      "    GET /                                                        → detection ping",
    );
    console.log(
      "    GET /computeMetadata/v1/instance/service-accounts/default/token → access token",
    );
    console.log("    GET /computeMetadata/v1/project/project-id                    → project ID");
    console.log(
      "    GET /computeMetadata/v1/project/numeric-project-id            → numeric project ID",
    );
    console.log("    GET /computeMetadata/v1/instance/service-accounts/default/email → SA email");
    console.log("    GET /computeMetadata/v1/instance/service-accounts               → SA listing");
    console.log(
      "    GET /computeMetadata/v1/universe/universe_domain                → universe domain",
    );
  }

  return { server, stop };
}
