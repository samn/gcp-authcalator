import { unlinkSync, existsSync, chmodSync, lstatSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { GateConfig } from "../config.ts";
import type { GateDeps } from "./types.ts";
import { createAuthModule, type AuthModuleOptions } from "./auth.ts";
import { createConfirmModule, type ConfirmOptions } from "./confirm.ts";
import { createAuditModule } from "./audit.ts";
import { createProdRateLimiter } from "./rate-limit.ts";
import { createSessionManager } from "./session.ts";
import { handleRequest } from "./handlers.ts";
import { loadAndValidateTlsFiles } from "../tls/store.ts";
import type { BunRequestInit } from "./connection.ts";
import { createPamModule, resolveEntitlementPath, type PamModule } from "./pam.ts";
import { createPendingQueue } from "./pending.ts";

export interface GateServerResult {
  server: ReturnType<typeof Bun.serve>;
  tcpServer?: ReturnType<typeof Bun.serve>;
  stop: () => void;
}

export interface StartGateServerOptions {
  authOptions?: AuthModuleOptions;
  confirmOptions?: ConfirmOptions;
  auditLogDir?: string;
}

/**
 * Start the gate token daemon on a Unix domain socket.
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
  const pendingQueue = createPendingQueue();
  const confirm = createConfirmModule({
    ...options.confirmOptions,
    pendingQueue,
  });
  const audit = createAuditModule(options.auditLogDir);
  const prodRateLimiter = createProdRateLimiter();

  const defaultTokenTtlSeconds = config.token_ttl_seconds ?? 3600;
  const sessionTtlSeconds = config.session_ttl_seconds ?? 28800;
  const sessionManager = createSessionManager();

  // PAM setup: resolve entitlement paths and build allowlist
  let pam: PamModule | undefined;
  let pamDefaultPolicy: string | undefined;
  let pamAllowedPolicies: Set<string> | undefined;

  if (config.pam_policy) {
    const pamLocation = config.pam_location ?? "global";

    pam = createPamModule(
      async () => {
        const { token } = await (await auth.getSourceClient()).getAccessToken();
        if (!token) throw new Error("Failed to get ADC token for PAM API");
        return token;
      },
      { grantDurationSeconds: defaultTokenTtlSeconds },
    );

    pamDefaultPolicy = resolveEntitlementPath(config.pam_policy, config.project_id, pamLocation);

    // Build allowlist: default policy + any additional allowed policies
    const allowed = new Set<string>([pamDefaultPolicy]);
    if (config.pam_allowed_policies) {
      for (const p of config.pam_allowed_policies) {
        allowed.add(resolveEntitlementPath(p, config.project_id, pamLocation));
      }
    }
    pamAllowedPolicies = allowed;
  }

  const deps: GateDeps = {
    mintDevToken: auth.mintDevToken,
    mintProdToken: auth.mintProdToken,
    getIdentityEmail: auth.getIdentityEmail,
    getProjectNumber: auth.getProjectNumber,
    getUniverseDomain: auth.getUniverseDomain,
    confirmProdAccess: confirm.confirmProdAccess,
    writeAuditLog: audit.writeAuditLog,
    prodRateLimiter,
    startTime: new Date(),
    ensurePamGrant: pam?.ensureGrant,
    pamAllowedPolicies,
    pamDefaultPolicy,
    resolvePamPolicy: config.pam_policy
      ? (policy: string) =>
          resolveEntitlementPath(policy, config.project_id, config.pam_location ?? "global")
      : undefined,
    defaultTokenTtlSeconds,
    sessionManager,
    sessionTtlSeconds,
    pendingQueue,
  };

  // Ensure the socket directory exists with owner-only permissions (0o700).
  // For $XDG_RUNTIME_DIR the directory already exists; for the ~/.gcp-authcalator
  // fallback this creates it.  mode only applies to newly created dirs so
  // we never alter permissions on a pre-existing $XDG_RUNTIME_DIR.
  const socketDir = dirname(config.socket_path);
  mkdirSync(socketDir, { recursive: true, mode: 0o700 });

  // Remove stale socket from a previous crash — with ownership verification
  if (existsSync(config.socket_path)) {
    const stat = lstatSync(config.socket_path);

    // Refuse to follow symlinks (prevents attacker-placed symlink pointing
    // to a file they want deleted).
    if (stat.isSymbolicLink()) {
      throw new Error(`gate: socket path is a symlink — refusing to remove: ${config.socket_path}`);
    }

    // Only remove actual Unix sockets, never regular files or directories.
    if (!stat.isSocket()) {
      throw new Error(
        `gate: socket path exists but is not a socket — refusing to remove: ${config.socket_path}`,
      );
    }

    // Verify the socket is owned by the current user.
    if (stat.uid !== process.getuid!()) {
      throw new Error(
        `gate: socket is owned by uid ${stat.uid}, not current user (${process.getuid!()}) — refusing to remove: ${config.socket_path}`,
      );
    }

    // Check whether another gate instance is still alive on this socket.
    try {
      const probe = await fetch("http://localhost/health", {
        unix: config.socket_path,
        signal: AbortSignal.timeout(1000),
      } as BunRequestInit);
      if (probe.ok) {
        throw new Error(`gate: another instance is already running on ${config.socket_path}`);
      }
    } catch (e: unknown) {
      // Re-throw our own "already running" error.
      if (e instanceof Error && e.message.startsWith("gate:")) {
        throw e;
      }
      // Connection refused / timeout = stale socket, safe to remove.
    }

    unlinkSync(config.socket_path);
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

  // Optional TCP+mTLS server for remote devcontainer support
  let tcpServer: ReturnType<typeof Bun.serve> | undefined;
  if (config.gate_tls_port !== undefined) {
    const tlsFiles = await loadAndValidateTlsFiles(config.tls_dir);
    tcpServer = Bun.serve({
      hostname: "127.0.0.1",
      port: config.gate_tls_port,
      tls: {
        cert: tlsFiles.serverCert,
        key: tlsFiles.serverKey,
        ca: tlsFiles.caCert,
        requestCert: true,
        rejectUnauthorized: true,
      },
      fetch(req) {
        return handleRequest(req, deps);
      },
    });
  }

  // Capture the inode so stop() only removes the socket we created,
  // not one created by a replacement instance.
  const socketIno = lstatSync(config.socket_path).ino;

  function stop() {
    try {
      server.stop(true);
    } catch {
      // Already stopped
    }
    try {
      tcpServer?.stop(true);
    } catch {
      // Already stopped
    }
    try {
      if (existsSync(config.socket_path)) {
        const current = lstatSync(config.socket_path);
        if (current.ino === socketIno && !current.isSymbolicLink()) {
          unlinkSync(config.socket_path);
        }
      }
    } catch {
      // Ignore cleanup errors
    }
  }

  // Graceful shutdown on signals
  const onSignal = async () => {
    console.log("\ngate: shutting down...");
    pendingQueue.denyAll();
    sessionManager.revokeAll();
    if (pam) {
      await pam.revokeAll();
    }
    stop();
    process.exit(0);
  };
  process.on("SIGTERM", () => void onSignal());
  process.on("SIGINT", () => void onSignal());

  console.log("gate: starting gcp-gate token daemon");
  console.log(`  project:         ${config.project_id}`);
  console.log(`  service account: ${config.service_account ?? "(none — dev tokens disabled)"}`);
  console.log(`  token TTL:       ${defaultTokenTtlSeconds}s`);
  console.log(`  session TTL:     ${sessionTtlSeconds}s`);
  console.log(`  socket path:     ${config.socket_path}`);
  if (tcpServer) {
    console.log(`  tcp listener:    127.0.0.1:${config.gate_tls_port} (mTLS)`);
  }
  if (pamDefaultPolicy) {
    console.log(`  pam policy:      ${config.pam_policy} (default)`);
    console.log(`  pam allowlist:   ${pamAllowedPolicies!.size} entitlement(s)`);
  }
  console.log("  endpoints:");
  console.log("    GET /token                   → dev-scoped access token");
  console.log("    GET /token?level=prod        → prod token (with confirmation)");
  console.log("    GET /identity                → authenticated user email");
  console.log("    GET /project-number          → numeric project ID");
  console.log("    GET /universe-domain         → GCP universe domain");
  console.log("    POST /session                → create prod session (with confirmation)");
  console.log("    DELETE /session              → revoke prod session");
  console.log("    GET /pending                 → list pending approval requests");
  console.log("    POST /pending/:id/approve    → approve pending request");
  console.log("    POST /pending/:id/deny       → deny pending request");
  console.log("    GET /health                  → health check");

  return { server, tcpServer, stop };
}
