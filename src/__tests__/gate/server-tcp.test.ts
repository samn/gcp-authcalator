import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startGateServer, type GateServerResult } from "../../gate/server.ts";
import type { GateConfig } from "../../config.ts";
import type { AuthClient } from "google-auth-library";
import { ensureTlsFiles } from "../../tls/store.ts";
import type { BunRequestInit } from "../../gate/connection.ts";
import { generateCA } from "../../tls/ca.ts";
import { generateClientCert } from "../../tls/certs.ts";

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

describe("Gate TCP+mTLS server", () => {
  let result: GateServerResult | null = null;
  const tempDirs: string[] = [];

  function makeTempDir(): string {
    const dir = mkdtempSync(join(tmpdir(), "gate-tcp-test-"));
    tempDirs.push(dir);
    return dir;
  }

  afterEach(() => {
    if (result) {
      result.stop();
      result = null;
    }
    for (const dir of tempDirs) {
      rmSync(dir, { recursive: true, force: true });
    }
    tempDirs.length = 0;
  });

  test("starts TCP+mTLS server and responds to /health with valid client cert", async () => {
    const tempDir = makeTempDir();
    const socketPath = join(tempDir, "gate.sock");
    const tlsDir = join(tempDir, "tls");
    const tlsFiles = await ensureTlsFiles(tlsDir);

    const config: GateConfig = {
      project_id: "test-project",
      service_account: "sa@test-project.iam.gserviceaccount.com",
      socket_path: socketPath,
      admin_socket_path: join(socketPath + "-admin-dir", "admin.sock"),
      port: 8173,
      gate_tls_port: 0, // random port
      tls_dir: tlsDir,
    };

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    expect(result.tcpServer).toBeDefined();

    const port = result.tcpServer!.port;
    const res = await fetch(`https://localhost:${port}/health`, {
      tls: {
        cert: tlsFiles.clientCert,
        key: tlsFiles.clientKey,
        ca: tlsFiles.caCert,
      },
    } as BunRequestInit);

    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("ok");
  });

  test("serves dev token via TCP+mTLS /token endpoint", async () => {
    const tempDir = makeTempDir();
    const socketPath = join(tempDir, "gate.sock");
    const tlsDir = join(tempDir, "tls");
    const tlsFiles = await ensureTlsFiles(tlsDir);

    const config: GateConfig = {
      project_id: "test-project",
      service_account: "sa@test-project.iam.gserviceaccount.com",
      socket_path: socketPath,
      admin_socket_path: join(socketPath + "-admin-dir", "admin.sock"),
      port: 8173,
      gate_tls_port: 0,
      tls_dir: tlsDir,
    };

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("tcp-dev-token"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const port = result.tcpServer!.port;
    const res = await fetch(`https://localhost:${port}/token`, {
      tls: {
        cert: tlsFiles.clientCert,
        key: tlsFiles.clientKey,
        ca: tlsFiles.caCert,
      },
    } as BunRequestInit);

    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string };
    expect(body.access_token).toBe("tcp-dev-token");
  });

  test("rejects connection without client certificate", async () => {
    const tempDir = makeTempDir();
    const socketPath = join(tempDir, "gate.sock");
    const tlsDir = join(tempDir, "tls");
    const tlsFiles = await ensureTlsFiles(tlsDir);

    const config: GateConfig = {
      project_id: "test-project",
      service_account: "sa@test-project.iam.gserviceaccount.com",
      socket_path: socketPath,
      admin_socket_path: join(socketPath + "-admin-dir", "admin.sock"),
      port: 8173,
      gate_tls_port: 0,
      tls_dir: tlsDir,
    };

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const port = result.tcpServer!.port;

    // Try to connect with CA cert (to trust server) but without providing a client cert
    try {
      await fetch(`https://localhost:${port}/health`, {
        tls: { ca: tlsFiles.caCert },
      } as BunRequestInit);
      // If it didn't throw, fail the test
      expect(true).toBe(false);
    } catch {
      // Expected: connection rejected due to missing client cert
    }
  });

  test("rejects connection with wrong CA client cert", async () => {
    const tempDir = makeTempDir();
    const socketPath = join(tempDir, "gate.sock");
    const tlsDir = join(tempDir, "tls");
    const tlsFiles = await ensureTlsFiles(tlsDir);

    const config: GateConfig = {
      project_id: "test-project",
      service_account: "sa@test-project.iam.gserviceaccount.com",
      socket_path: socketPath,
      admin_socket_path: join(socketPath + "-admin-dir", "admin.sock"),
      port: 8173,
      gate_tls_port: 0,
      tls_dir: tlsDir,
    };

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    const port = result.tcpServer!.port;

    // Generate a cert from a different CA
    const wrongCA = await generateCA();
    const wrongClient = await generateClientCert(wrongCA.caCert, wrongCA.caKey);

    try {
      await fetch(`https://localhost:${port}/health`, {
        tls: {
          cert: wrongClient.cert,
          key: wrongClient.key,
          ca: tlsFiles.caCert, // Trust the server's CA
        },
      } as BunRequestInit);
      expect(true).toBe(false);
    } catch {
      // Expected: connection rejected due to untrusted client cert
    }
  });

  test("fails with helpful error when TLS certs are missing", async () => {
    const tempDir = makeTempDir();
    const socketPath = join(tempDir, "gate.sock");
    const tlsDir = join(tempDir, "tls"); // empty, no certs generated

    const config: GateConfig = {
      project_id: "test-project",
      service_account: "sa@test-project.iam.gserviceaccount.com",
      socket_path: socketPath,
      admin_socket_path: join(socketPath + "-admin-dir", "admin.sock"),
      port: 8173,
      gate_tls_port: 0,
      tls_dir: tlsDir,
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
    ).rejects.toThrow(/init-tls/);
  });

  test("does not start TCP server when gate_tls_port is not configured", async () => {
    const tempDir = makeTempDir();
    const socketPath = join(tempDir, "gate.sock");

    const config: GateConfig = {
      project_id: "test-project",
      service_account: "sa@test-project.iam.gserviceaccount.com",
      socket_path: socketPath,
      admin_socket_path: join(socketPath + "-admin-dir", "admin.sock"),
      port: 8173,
      // No gate_tls_port
    };

    result = await startGateServer(config, {
      authOptions: {
        sourceClient: mockClient("source-tok"),
        impersonatedClient: mockClient("dev-tok"),
        fetchFn: mockFetch("test@example.com"),
      },
      auditLogDir: join(tempDir, "audit"),
    });

    expect(result.tcpServer).toBeUndefined();
  });
});
