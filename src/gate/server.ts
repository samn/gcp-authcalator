import { unlinkSync, existsSync, chmodSync, chownSync, lstatSync } from "node:fs";
import { dirname } from "node:path";
import type { GateConfig } from "../config.ts";
import type { GateDeps } from "./types.ts";
import { createAuthModule, type AuthModuleOptions } from "./auth.ts";
import { createConfirmModule, type ConfirmOptions } from "./confirm.ts";
import { createAuditModule } from "./audit.ts";
import { createProdRateLimiter } from "./rate-limit.ts";
import { createSessionManager } from "./session.ts";
import { handleRequest } from "./handlers.ts";
import { handleAdminRequest } from "./admin-handlers.ts";
import { loadAndValidateTlsFiles } from "../tls/store.ts";
import type { BunRequestInit } from "./connection.ts";
import { createPamModule, resolveEntitlementPath, type PamModule } from "./pam.ts";
import { createPendingQueue } from "./pending.ts";
import {
  lookupGroup,
  loadUnixGroupDb,
  resolveAgentUid,
  getGroupsForUid,
  isUidInPasswd,
} from "./unix-group.ts";
import { ensurePrivateDir } from "./dir-utils.ts";

// Bun's max idleTimeout (255s). Prod flows (POST /session, GET /token?level=prod)
// can wait on the pending-approval queue (120s) and PAM grant polling (120s)
// before the server writes a response; Bun's 10s default would close the
// connection mid-request.
const SOCKET_IDLE_TIMEOUT_SECONDS = 255;

export interface GateServerResult {
  server: ReturnType<typeof Bun.serve>;
  tcpServer?: ReturnType<typeof Bun.serve>;
  adminServer: ReturnType<typeof Bun.serve>;
  operatorServer?: ReturnType<typeof Bun.serve>;
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
/**
 * Verify a socket path is safe to remove and remove it. Mirrors the existing
 * symlink/socket/uid checks used for all three sockets the gate creates.
 *
 * If `probeForRunning` is true, also probes the socket for a live HTTP
 * health endpoint and refuses to remove it if another instance answers.
 * Only the main socket needs that — the admin and operator sockets are
 * always tied to a main-socket bind that has already been released.
 */
async function cleanStaleSocket(
  socketPath: string,
  label: string,
  opts: { probeForRunning?: boolean } = {},
): Promise<void> {
  if (!existsSync(socketPath)) return;

  const stat = lstatSync(socketPath);
  if (stat.isSymbolicLink()) {
    throw new Error(`gate: ${label} path is a symlink — refusing to remove: ${socketPath}`);
  }
  if (!stat.isSocket()) {
    throw new Error(
      `gate: ${label} path exists but is not a socket — refusing to remove: ${socketPath}`,
    );
  }
  if (stat.uid !== process.getuid!()) {
    throw new Error(
      `gate: ${label} is owned by uid ${stat.uid}, not current user (${process.getuid!()}) — refusing to remove: ${socketPath}`,
    );
  }

  if (opts.probeForRunning) {
    try {
      const probe = await fetch("http://localhost/health", {
        unix: socketPath,
        signal: AbortSignal.timeout(1000),
      } as BunRequestInit);
      if (probe.ok) {
        throw new Error(`gate: another instance is already running on ${socketPath}`);
      }
    } catch (e: unknown) {
      if (e instanceof Error && e.message.startsWith("gate:")) {
        throw e;
      }
      // Connection refused / timeout = stale socket, safe to remove.
    }
  }

  unlinkSync(socketPath);
}

interface OperatorSocketAccess {
  /** Socket file mode (0o600 in UID mode, 0o660 in group mode). */
  sockMode: number;
  /** Containing-directory mode (0o700 in UID mode, 0o750 in group mode). */
  dirMode: number;
  /** Group GID for chown; undefined in UID mode (no group ownership). */
  gid: number | undefined;
}

/**
 * Resolve how the operator socket should be created.
 *
 * Group mode (operator_socket_group set) additionally enforces that the agent
 * UID is not a member of the operator group — a guardrail beyond what the
 * kernel enforces, which the UID-mode path doesn't need.
 */
function resolveOperatorSocketAccess(
  groupName: string | undefined,
  agentUid: number,
  unixDb: ReturnType<typeof loadUnixGroupDb>,
): OperatorSocketAccess {
  if (!groupName) {
    return { sockMode: 0o600, dirMode: 0o700, gid: undefined };
  }
  const grp = lookupGroup(groupName, unixDb);
  if (!grp) {
    throw new Error(
      `gate: operator socket group '${groupName}' not found in /etc/group — refusing to start`,
    );
  }
  // getGroupsForUid silently returns [] for any UID not in /etc/passwd, which
  // would make the membership check below a no-op for NSS/LDAP/SSSD users.
  // Refuse to start rather than silently bypass the guardrail.
  if (!isUidInPasswd(agentUid, unixDb)) {
    throw new Error(
      `gate: agent_uid (${agentUid}) is not present in /etc/passwd. ` +
        `In group mode the gate must enumerate the agent's group memberships ` +
        `to verify it is not in operator group '${grp.name}', and that lookup ` +
        `consults /etc/passwd and /etc/group directly — NSS/LDAP/SSSD-managed ` +
        `users are not visible. Pass a numeric UID that exists in /etc/passwd, ` +
        `or switch to UID mode (unset operator_socket_group).`,
    );
  }
  if (getGroupsForUid(agentUid, unixDb).includes(grp.gid)) {
    throw new Error(
      `gate: agent uid ${agentUid} is a member of operator group '${grp.name}' (gid ${grp.gid}) — refusing to start. ` +
        `Remove the agent uid from the group, or unset operator_socket_path.`,
    );
  }
  return { sockMode: 0o660, dirMode: 0o750, gid: grp.gid };
}

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

    pam = createPamModule(auth.getSourceAccessToken, {
      grantDurationSeconds: defaultTokenTtlSeconds,
    });

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

  // Resolve auto-approve policies through the same canonicalisation as the
  // pam_allowed_policies set, so the operator socket's auto-approve check
  // compares full entitlement paths. The schema refinement guarantees every
  // entry is also in pam_allowed_policies (or equals pam_policy).
  let autoApprovePamPolicies: Set<string> | undefined;
  if (config.auto_approve_pam_policies?.length) {
    const pamLocation = config.pam_location ?? "global";
    autoApprovePamPolicies = new Set<string>(
      config.auto_approve_pam_policies.map((p) =>
        resolveEntitlementPath(p, config.project_id, pamLocation),
      ),
    );
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
    autoApprovePamPolicies,
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

  // Bun.serve binds the AF_UNIX socket using the inherited umask, so a
  // tight one closes the window between bind and the explicit chmod.
  process.umask(0o077);

  const socketDir = dirname(config.socket_path);
  ensurePrivateDir(socketDir, 0o700);

  await cleanStaleSocket(config.socket_path, "socket", { probeForRunning: true });

  const server = Bun.serve({
    unix: config.socket_path,
    idleTimeout: SOCKET_IDLE_TIMEOUT_SECONDS,
    fetch(req) {
      return handleRequest(req, deps, { trusted: false, socket: "main" });
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
      idleTimeout: SOCKET_IDLE_TIMEOUT_SECONDS,
      tls: {
        cert: tlsFiles.serverCert,
        key: tlsFiles.serverKey,
        ca: tlsFiles.caCert,
        requestCert: true,
        rejectUnauthorized: true,
      },
      fetch(req) {
        return handleRequest(req, deps, { trusted: false, socket: "tcp" });
      },
    });
  }

  // --- Admin socket (for approve/deny — NOT mounted into containers) ---
  const adminSocketDir = dirname(config.admin_socket_path);
  ensurePrivateDir(adminSocketDir, 0o700);

  await cleanStaleSocket(config.admin_socket_path, "admin socket");

  const adminServer = Bun.serve({
    unix: config.admin_socket_path,
    fetch(req) {
      return handleAdminRequest(req, deps);
    },
  });

  chmodSync(config.admin_socket_path, 0o600);

  // --- Operator socket (auto-approve eligible) ---
  let operatorServer: ReturnType<typeof Bun.serve> | undefined;
  let operatorSocketIno: number | undefined;
  if (config.operator_socket_path) {
    // Schema refinement guarantees agent_uid is set when operator_socket_path is.
    const gateUid = process.getuid!();
    const unixDb = loadUnixGroupDb();
    const agentUid = resolveAgentUid(config.agent_uid!, unixDb);

    if (agentUid === gateUid) {
      throw new Error(
        `gate: agent_uid (${agentUid}) equals gate uid — operator-socket trust boundary cannot exist`,
      );
    }

    const access = resolveOperatorSocketAccess(config.operator_socket_group, agentUid, unixDb);

    const operatorSocketDir = dirname(config.operator_socket_path);
    ensurePrivateDir(operatorSocketDir, access.dirMode);
    if (access.gid !== undefined) {
      chownSync(operatorSocketDir, gateUid, access.gid);
    }

    await cleanStaleSocket(config.operator_socket_path, "operator socket");

    operatorServer = Bun.serve({
      unix: config.operator_socket_path,
      idleTimeout: SOCKET_IDLE_TIMEOUT_SECONDS,
      fetch(req) {
        return handleRequest(req, deps, { trusted: true, socket: "operator" });
      },
    });

    // chown before chmod: chown clears setgid/setuid bits on some kernels.
    if (access.gid !== undefined) {
      chownSync(config.operator_socket_path, gateUid, access.gid);
    }
    chmodSync(config.operator_socket_path, access.sockMode);
    operatorSocketIno = lstatSync(config.operator_socket_path).ino;
  }

  // Capture inodes so stop() only removes the sockets we created,
  // not ones created by a replacement instance.
  const socketIno = lstatSync(config.socket_path).ino;
  const adminSocketIno = lstatSync(config.admin_socket_path).ino;

  function unlinkIfOurs(path: string, ino: number) {
    try {
      if (existsSync(path)) {
        const current = lstatSync(path);
        if (current.ino === ino && !current.isSymbolicLink()) {
          unlinkSync(path);
        }
      }
    } catch {
      // Ignore cleanup errors
    }
  }

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
      adminServer.stop(true);
    } catch {
      // Already stopped
    }
    try {
      operatorServer?.stop(true);
    } catch {
      // Already stopped
    }
    unlinkIfOurs(config.socket_path, socketIno);
    unlinkIfOurs(config.admin_socket_path, adminSocketIno);
    if (operatorSocketIno !== undefined && config.operator_socket_path) {
      unlinkIfOurs(config.operator_socket_path, operatorSocketIno);
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
  console.log(`  admin socket:    ${config.admin_socket_path}`);
  if (tcpServer) {
    console.log(`  tcp listener:    127.0.0.1:${config.gate_tls_port} (mTLS)`);
  }
  if (pamDefaultPolicy) {
    console.log(`  pam policy:      ${config.pam_policy} (default)`);
    console.log(`  pam allowlist:   ${pamAllowedPolicies!.size} entitlement(s)`);
  }
  if (operatorServer) {
    console.log(`  operator socket: ${config.operator_socket_path}`);
    if (config.operator_socket_group) {
      console.log(
        `  operator group:  ${config.operator_socket_group} (mode 0660; sessions disabled)`,
      );
    } else {
      console.log(`  operator mode:   0600 (gate UID owner; sessions disabled)`);
    }
    console.log(
      `  auto-approve:    ${autoApprovePamPolicies?.size ?? 0} PAM entitlement(s) (operator socket only)`,
    );
  }
  console.log("  endpoints (main socket):");
  console.log("    GET /token                   → dev-scoped access token");
  console.log("    GET /token?level=prod        → prod token (with confirmation)");
  console.log("    GET /identity                → authenticated user email");
  console.log("    GET /project-number          → numeric project ID");
  console.log("    GET /universe-domain         → GCP universe domain");
  console.log("    POST /session                → create prod session (with confirmation)");
  console.log("    DELETE /session              → revoke prod session");
  console.log("    GET /health                  → health check");
  console.log("  endpoints (admin socket):");
  console.log("    POST /pending/:id/approve    → approve pending request");
  console.log("    POST /pending/:id/deny       → deny pending request");
  console.log("    GET /health                  → health check");
  if (operatorServer) {
    console.log("  endpoints (operator socket):");
    console.log("    GET /token?level=prod        → prod token (auto-approve if allowlisted)");
    console.log("    POST /session                → 403 (sessions disabled)");
    console.log("    GET /token?session=...       → 403 (sessions disabled)");
    console.log("    (other endpoints same as main socket)");
  }

  return { server, tcpServer, adminServer, operatorServer, stop };
}
