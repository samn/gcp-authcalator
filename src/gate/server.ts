import { unlinkSync, existsSync, chmodSync } from "node:fs";
import type { GateConfig } from "../config.ts";
import type { GateDeps } from "./types.ts";
import { createAuthModule, type AuthModuleOptions } from "./auth.ts";
import { createConfirmModule, type ConfirmOptions } from "./confirm.ts";
import { createAuditModule } from "./audit.ts";
import { handleRequest } from "./handlers.ts";

export interface GateServerResult {
  server: ReturnType<typeof Bun.serve>;
  stop: () => void;
}

export interface StartGateServerOptions {
  authOptions?: AuthModuleOptions;
  confirmOptions?: ConfirmOptions;
  auditLogDir?: string;
}

/**
 * Start the gcp-gate token daemon on a Unix domain socket.
 *
 * 1. Creates auth / confirm / audit modules and wires them into GateDeps
 * 2. Removes stale socket file (crash recovery)
 * 3. Starts Bun.serve on the Unix socket
 * 4. Registers SIGTERM / SIGINT handlers for graceful shutdown
 */
export async function startGateServer(
  config: GateConfig,
  options: StartGateServerOptions = {},
): Promise<GateServerResult> {
  const auth = createAuthModule(config, options.authOptions);
  const confirm = createConfirmModule(options.confirmOptions);
  const audit = createAuditModule(options.auditLogDir);

  const deps: GateDeps = {
    mintDevToken: auth.mintDevToken,
    mintProdToken: auth.mintProdToken,
    getIdentityEmail: auth.getIdentityEmail,
    confirmProdAccess: confirm.confirmProdAccess,
    writeAuditLog: audit.writeAuditLog,
    startTime: new Date(),
  };

  // Remove stale socket from a previous crash
  if (existsSync(config.socket_path)) {
    try {
      unlinkSync(config.socket_path);
    } catch {
      // Ignore — may already be gone
    }
  }

  const server = Bun.serve({
    unix: config.socket_path,
    fetch(req) {
      return handleRequest(req, deps);
    },
  });

  // Restrict socket to owner-only access (rw-------).
  // This is the primary security boundary — without it any local user can
  // connect and request tokens.
  chmodSync(config.socket_path, 0o600);

  function stop() {
    try {
      server.stop(true);
    } catch {
      // Already stopped
    }
    try {
      if (existsSync(config.socket_path)) {
        unlinkSync(config.socket_path);
      }
    } catch {
      // Ignore cleanup errors
    }
  }

  // Graceful shutdown on signals
  const onSignal = () => {
    console.log("\ngate: shutting down...");
    stop();
    process.exit(0);
  };
  process.on("SIGTERM", onSignal);
  process.on("SIGINT", onSignal);

  console.log("gate: starting gcp-gate token daemon");
  console.log(`  project:         ${config.project_id}`);
  console.log(`  service account: ${config.service_account}`);
  console.log(`  socket path:     ${config.socket_path}`);
  console.log("  endpoints:");
  console.log("    GET /token            → dev-scoped access token");
  console.log("    GET /token?level=prod → prod token (with confirmation)");
  console.log("    GET /identity         → authenticated user email");
  console.log("    GET /health           → health check");

  return { server, stop };
}
