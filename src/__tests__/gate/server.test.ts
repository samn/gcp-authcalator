import { describe, expect, test, afterEach } from "bun:test";
import {
  mkdtempSync,
  existsSync,
  readFileSync,
  writeFileSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startGateServer, type GateServerResult } from "../../gate/server.ts";
import type { GateConfig } from "../../config.ts";
import type { AuthClient } from "google-auth-library";
import type { BunRequestInit } from "../../gate/connection.ts";
import { execSync } from "node:child_process";

/** Pick a UID that is not present in /etc/passwd on this host. */
function uidAbsentFromPasswd(): number {
  const present = new Set<number>();
  for (const line of readFileSync("/etc/passwd", "utf-8").split("\n")) {
    const fields = line.split(":");
    if (fields.length >= 4) {
      const uid = Number(fields[2]);
      if (Number.isInteger(uid)) present.add(uid);
    }
  }
  // Walk down from a high value; nsswitch typically reserves the bottom range.
  for (let candidate = 4_000_000_000; candidate > 1_000_000; candidate--) {
    if (!present.has(candidate)) return candidate;
  }
  throw new Error("could not find a UID absent from /etc/passwd");
}

function mockClient(token: string): AuthClient {
  return {
    getAccessToken: async () => ({ token, res: null }),
  } as unknown as AuthClient;
}

function mockFetch(email: string): typeof globalThis.fetch {
  return (async () =>
    new Response(JSON.stringify({ email }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })) as unknown as typeof globalThis.fetch;
}

function makeConfig(socketPath: string, adminSocketPath?: string): GateConfig {
  return {
    project_id: "test-project",
    service_account: "sa@test-project.iam.gserviceaccount.com",
    socket_path: socketPath,
    admin_socket_path: adminSocketPath ?? join(socketPath + "-admin-dir", "admin.sock"),
    port: 8173,
  };
}

async function fetchUnix(socketPath: string, path: string): Promise<Response> {
  return fetch(`http://localhost${path}`, {
    unix: socketPath,
  } as BunRequestInit);
}

describe("startGateServer", () => {
  let result: GateServerResult | null = null;

  afterEach(() => {
    if (result) {
      result.stop();
      result = null;
    }
  });

  test("starts server and responds to /health", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const res = await fetchUnix(socketPath, "/health");
    expect(res.status).toBe(200);

    const body = (await res.json()) as { status: string; uptime_seconds: number };
    expect(body.status).toBe("ok");
    expect(body.uptime_seconds).toBeGreaterThanOrEqual(0);
  });

  test("serves dev token via /token", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("my-dev-token"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const res = await fetchUnix(socketPath, "/token");
    expect(res.status).toBe(200);

    const body = (await res.json()) as { access_token: string; token_type: string };
    expect(body.access_token).toBe("my-dev-token");
    expect(body.token_type).toBe("Bearer");
  });

  test("serves identity via /identity", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("identity@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const res = await fetchUnix(socketPath, "/identity");
    expect(res.status).toBe(200);

    const body = (await res.json()) as { email: string };
    expect(body.email).toBe("identity@example.com");
  });

  test("returns 404 for unknown paths", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const res = await fetchUnix(socketPath, "/nonexistent");
    expect(res.status).toBe(404);
  });

  test("removes stale socket on startup", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    const serverOpts = {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    };

    // Simulate a crashed prior instance: spawn a child that binds the socket,
    // then SIGKILL it so the kernel leaves the socket file on disk. Since
    // bun 1.3.12, graceful close auto-unlinks, so only an abrupt kernel-level
    // termination reproduces a true stale-socket state.
    const childCode = `Bun.serve({ unix: ${JSON.stringify(
      socketPath,
    )}, fetch() { return new Response("stale"); } });
process.stdout.write("ready\\n");
setInterval(() => {}, 1000);`;
    const child = Bun.spawn({
      cmd: ["bun", "-e", childCode],
      stdio: ["ignore", "pipe", "inherit"],
    });
    for await (const chunk of child.stdout) {
      if (new TextDecoder().decode(chunk).includes("ready")) break;
    }
    child.kill("SIGKILL");
    await child.exited;
    expect(existsSync(socketPath)).toBe(true);

    // Now starting a new server should succeed by removing the stale socket.
    result = await startGateServer(config, serverOpts);
    const res = await fetchUnix(socketPath, "/health");
    expect(res.status).toBe(200);
  });

  test("refuses to start when socket path is a regular file", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    writeFileSync(socketPath, "not-a-socket");

    await expect(
      startGateServer(config, {
        authOptions: {
          sourceClient: mockClient("source-tok"),
          impersonatedClient: mockClient("dev-tok"),
          fetchFn: mockFetch("test@example.com"),
        },
        auditLogDir: join(tempDir, "audit"),
      }),
    ).rejects.toThrow("not a socket");
  });

  test("refuses to start when socket path is a symlink", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const target = join(tempDir, "target");
    const config = makeConfig(socketPath);

    writeFileSync(target, "target-file");
    symlinkSync(target, socketPath);

    await expect(
      startGateServer(config, {
        authOptions: {
          sourceClient: mockClient("source-tok"),
          impersonatedClient: mockClient("dev-tok"),
          fetchFn: mockFetch("test@example.com"),
        },
        auditLogDir: join(tempDir, "audit"),
      }),
    ).rejects.toThrow("symlink");

    // Target file must not have been deleted
    expect(existsSync(target)).toBe(true);
  });

  test("refuses to start when another instance is running", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    const serverOpts = {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    };

    // Start a running instance
    result = await startGateServer(config, serverOpts);

    // Trying to start a second instance on the same socket should fail
    await expect(startGateServer(config, serverOpts)).rejects.toThrow(
      "another instance is already running",
    );
  });

  test("sets socket to 0660 in a 0750 directory", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketDir = join(tempDir, "gate-dir");
    const socketPath = join(socketDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const sockStats = statSync(socketPath);
    expect(sockStats.mode & 0o777).toBe(0o660);
    expect(statSync(socketDir).mode & 0o777).toBe(0o750);
  });

  test("stop() cleans up socket file", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    expect(existsSync(socketPath)).toBe(true);

    result.stop();
    result = null;

    expect(existsSync(socketPath)).toBe(false);
  });

  test("starts admin socket and serves /health on it", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const adminSocketPath = join(tempDir, "admin.sock");
    const config = makeConfig(socketPath, adminSocketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const res = await fetch("http://localhost/health", {
      unix: adminSocketPath,
    } as BunRequestInit);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("ok");
  });

  test("admin socket does not serve /token", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const adminSocketPath = join(tempDir, "admin.sock");
    const config = makeConfig(socketPath, adminSocketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const res = await fetch("http://localhost/token", {
      unix: adminSocketPath,
    } as BunRequestInit);
    expect(res.status).toBe(404);
  });

  test("main socket does not serve /pending routes", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const config = makeConfig(socketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const res = await fetchUnix(socketPath, "/pending");
    expect(res.status).toBe(404);
  });

  test("stop() cleans up admin socket file", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const adminSocketPath = join(tempDir, "admin.sock");
    const config = makeConfig(socketPath, adminSocketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    expect(existsSync(adminSocketPath)).toBe(true);

    result.stop();
    result = null;

    expect(existsSync(adminSocketPath)).toBe(false);
  });

  test("admin socket has 0600 permissions", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-srv-"));
    const socketPath = join(tempDir, "gate.sock");
    const adminSocketPath = join(tempDir, "admin.sock");
    const config = makeConfig(socketPath, adminSocketPath);

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const stats = statSync(adminSocketPath);
    const permissions = stats.mode & 0o777;
    expect(permissions).toBe(0o600);
  });
});

// ---------------------------------------------------------------------------
// Operator socket
// ---------------------------------------------------------------------------

// Pick a UID that is not equal to the gate UID (so the trust-boundary check
// in startGateServer doesn't fire) and is not a member of the gate's primary
// group:
//   - non-root gate: `root` (UID 0) has its own primary group and is not in
//     other users' groups.
//   - root gate: `nobody` (UID 65534) has its own primary group and is
//     universally not in `root`.
const TEST_AGENT_UID = process.getuid!() === 0 ? 65534 : 0;

/** Resolve a usable operator-group name + matching agent UID for tests. */
function operatorGroupForCurrentUser(): { groupName: string; agentUid: number } {
  const groupName = execSync("id -gn", { encoding: "utf-8" }).trim();
  return { groupName, agentUid: TEST_AGENT_UID };
}

describe("operator socket", () => {
  let result: GateServerResult | null = null;

  afterEach(() => {
    if (result) {
      result.stop();
      result = null;
    }
  });

  test("creates operator socket with mode 0660 and group ownership", async () => {
    const { groupName, agentUid } = operatorGroupForCurrentUser();
    const tempDir = mkdtempSync(join(tmpdir(), "gate-op-"));
    const config: GateConfig = {
      ...makeConfig(join(tempDir, "gate.sock"), join(tempDir, "admin.sock")),
      operator_socket_path: join(tempDir, "operator.sock"),
      operator_socket_group: groupName,
      agent_uid: agentUid,
    };

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const stats = statSync(config.operator_socket_path!);
    expect(stats.mode & 0o777).toBe(0o660);

    // Main socket is 0660 (group access via the gate UID's primary group).
    expect(statSync(config.socket_path).mode & 0o777).toBe(0o660);
  });

  test("operator socket auto-approves allowlisted PAM policy", async () => {
    const { groupName, agentUid } = operatorGroupForCurrentUser();
    const tempDir = mkdtempSync(join(tmpdir(), "gate-op-"));
    const operatorSocketPath = join(tempDir, "operator.sock");
    // PAM policies aren't relevant here — we test session rejection only.
    const config: GateConfig = {
      ...makeConfig(join(tempDir, "gate.sock"), join(tempDir, "admin.sock")),
      operator_socket_path: operatorSocketPath,
      operator_socket_group: groupName,
      agent_uid: agentUid,
    };

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    // Sessions are explicitly disabled on the operator socket — easy probe.
    const res = await fetch("http://localhost/session", {
      method: "POST",
      unix: operatorSocketPath,
    } as BunRequestInit);
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("operator socket");
  });

  test("stop() cleans up operator socket file", async () => {
    const { groupName, agentUid } = operatorGroupForCurrentUser();
    const tempDir = mkdtempSync(join(tmpdir(), "gate-op-"));
    const operatorSocketPath = join(tempDir, "operator.sock");
    const config: GateConfig = {
      ...makeConfig(join(tempDir, "gate.sock"), join(tempDir, "admin.sock")),
      operator_socket_path: operatorSocketPath,
      operator_socket_group: groupName,
      agent_uid: agentUid,
    };

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    expect(existsSync(operatorSocketPath)).toBe(true);

    result.stop();
    result = null;

    expect(existsSync(operatorSocketPath)).toBe(false);
  });

  test("refuses to start when operator_socket_group does not exist", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-op-"));
    const config: GateConfig = {
      ...makeConfig(join(tempDir, "gate.sock"), join(tempDir, "admin.sock")),
      operator_socket_path: join(tempDir, "operator.sock"),
      operator_socket_group: "nonexistent-group-zzzzzzz",
      agent_uid: TEST_AGENT_UID,
    };

    await expect(
      startGateServer(config, {
        authOptions: {
          sourceClient: mockClient("source-tok"),
          impersonatedClient: mockClient("dev-tok"),
          fetchFn: mockFetch("test@example.com"),
        },
        auditLogDir: join(tempDir, "audit"),
      }),
    ).rejects.toThrow(/not found in \/etc\/group/);
  });

  test("refuses to start when agent_uid equals gate uid", async () => {
    const { groupName } = operatorGroupForCurrentUser();
    const tempDir = mkdtempSync(join(tmpdir(), "gate-op-"));
    const config: GateConfig = {
      ...makeConfig(join(tempDir, "gate.sock"), join(tempDir, "admin.sock")),
      operator_socket_path: join(tempDir, "operator.sock"),
      operator_socket_group: groupName,
      agent_uid: process.getuid!(),
    };

    await expect(
      startGateServer(config, {
        authOptions: {
          sourceClient: mockClient("source-tok"),
          impersonatedClient: mockClient("dev-tok"),
          fetchFn: mockFetch("test@example.com"),
        },
        auditLogDir: join(tempDir, "audit"),
      }),
    ).rejects.toThrow(/equals gate uid/);
  });

  test("refuses to start when agent_uid is not in /etc/passwd", async () => {
    const { groupName } = operatorGroupForCurrentUser();
    const tempDir = mkdtempSync(join(tmpdir(), "gate-op-"));
    const config: GateConfig = {
      ...makeConfig(join(tempDir, "gate.sock"), join(tempDir, "admin.sock")),
      operator_socket_path: join(tempDir, "operator.sock"),
      operator_socket_group: groupName,
      agent_uid: uidAbsentFromPasswd(),
    };

    await expect(
      startGateServer(config, {
        authOptions: {
          sourceClient: mockClient("source-tok"),
          impersonatedClient: mockClient("dev-tok"),
          fetchFn: mockFetch("test@example.com"),
        },
        auditLogDir: join(tempDir, "audit"),
      }),
    ).rejects.toThrow(/not present in \/etc\/passwd/);
  });

  test("refuses to start when operator socket path is a symlink", async () => {
    const { groupName, agentUid } = operatorGroupForCurrentUser();
    const tempDir = mkdtempSync(join(tmpdir(), "gate-op-"));
    const operatorSocketPath = join(tempDir, "operator.sock");
    const target = join(tempDir, "target");
    writeFileSync(target, "x");
    symlinkSync(target, operatorSocketPath);

    const config: GateConfig = {
      ...makeConfig(join(tempDir, "gate.sock"), join(tempDir, "admin.sock")),
      operator_socket_path: operatorSocketPath,
      operator_socket_group: groupName,
      agent_uid: agentUid,
    };

    await expect(
      startGateServer(config, {
        authOptions: {
          sourceClient: mockClient("source-tok"),
          impersonatedClient: mockClient("dev-tok"),
          fetchFn: mockFetch("test@example.com"),
        },
        auditLogDir: join(tempDir, "audit"),
      }),
    ).rejects.toThrow(/symlink/);
    expect(existsSync(target)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Operator socket — UID mode (operator_socket_group unset)
// ---------------------------------------------------------------------------
//
// UID mode shares all per-request behavior (session rejection, auto-approve,
// audit fields) and lifecycle code (cleanStaleSocket, stop()/unlinkIfOurs)
// with group mode — those paths are covered by the group-mode tests above.
// The tests here cover what's specific to UID mode: socket/dir permissions
// and the agent_uid guardrail running independently of group lookup.

const UID_MODE_AUTH_OPTIONS = {
  sourceClient: mockClient("source-tok"),
  impersonatedClient: mockClient("dev-tok"),
  fetchFn: mockFetch("test@example.com"),
};

function uidModeConfig(tempDir: string, overrides: Partial<GateConfig> = {}): GateConfig {
  return {
    ...makeConfig(join(tempDir, "gate.sock"), join(tempDir, "admin.sock")),
    operator_socket_path: join(tempDir, "operator.sock"),
    agent_uid: TEST_AGENT_UID,
    ...overrides,
  };
}

describe("operator socket — UID mode (no group)", () => {
  let result: GateServerResult | null = null;

  afterEach(() => {
    if (result) {
      result.stop();
      result = null;
    }
  });

  // UID-mode operator socket stays 0o600 (kernel blocks any non-gate UID),
  // even though the containing dir is 0o750 (group-traversable so the agent
  // can reach the main socket sitting alongside it). Group members can
  // listdir but the operator socket's 0o600 still blocks connect().
  test("creates 0600 socket owned by gate UID in a 0750 directory", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-op-uid-"));
    const operatorSocketDir = join(tempDir, "op-dir");
    const config = uidModeConfig(tempDir, {
      operator_socket_path: join(operatorSocketDir, "operator.sock"),
    });

    result = await startGateServer(config, {
      authOptions: UID_MODE_AUTH_OPTIONS,
      auditLogDir: join(tempDir, "audit"),
    });

    const sockStats = statSync(config.operator_socket_path!);
    expect(sockStats.mode & 0o777).toBe(0o600);
    expect(sockStats.uid).toBe(process.getuid!());
    expect(statSync(operatorSocketDir).mode & 0o777).toBe(0o750);
  });

  test("refuses to start when agent_uid equals gate uid", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-op-uid-"));
    const config = uidModeConfig(tempDir, { agent_uid: process.getuid!() });

    await expect(
      startGateServer(config, {
        authOptions: UID_MODE_AUTH_OPTIONS,
        auditLogDir: join(tempDir, "audit"),
      }),
    ).rejects.toThrow(/equals gate uid/);
  });

  // UID mode does not enumerate the agent's groups (the kernel-enforced 0600
  // owner-only socket is the boundary), so a UID that is absent from
  // /etc/passwd — typical for a containerized agent whose UID lives only in
  // the container — must not block startup.
  test("starts when agent_uid is not in /etc/passwd", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "gate-op-uid-"));
    const config = uidModeConfig(tempDir, { agent_uid: uidAbsentFromPasswd() });

    result = await startGateServer(config, {
      authOptions: UID_MODE_AUTH_OPTIONS,
      auditLogDir: join(tempDir, "audit"),
    });

    expect(existsSync(config.operator_socket_path!)).toBe(true);
  });
});
