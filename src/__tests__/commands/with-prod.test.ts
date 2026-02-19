import { describe, expect, test, beforeEach, afterEach, spyOn } from "bun:test";
import { existsSync, readFileSync, statSync } from "node:fs";
import { z } from "zod";
import { runWithProd } from "../../commands/with-prod.ts";
import { PROD_SESSION_ENV_VAR } from "../../with-prod/detect-nested-session.ts";
import type { Subprocess } from "bun";

/**
 * URL-aware mock that returns different responses for /token and /identity
 * endpoints, mirroring the real gcp-gate API.
 */
function mockGateFetch(
  tokenBody: Record<string, unknown> = { access_token: "prod-token-abc", expires_in: 1800 },
  identityBody: Record<string, unknown> = { email: "eng@example.com" },
): typeof globalThis.fetch {
  return (async (url: string) => {
    const parsed = new URL(url);
    if (parsed.pathname === "/token") {
      return new Response(JSON.stringify(tokenBody), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (parsed.pathname === "/identity") {
      return new Response(JSON.stringify(identityBody), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  }) as unknown as typeof globalThis.fetch;
}

/**
 * Mock fetch that responds to both proxy health-check URLs (for nested
 * detection) and gate URLs (for normal token fetch). The proxy URLs are
 * distinguished by having a port in the host (e.g., 127.0.0.1:54321).
 */
function mockCombinedFetch(opts?: {
  /** Proxy health check responses */
  proxyRootStatus?: number;
  proxyRootHeaders?: Record<string, string>;
  proxyTokenStatus?: number;
  proxyTokenBody?: Record<string, unknown>;
  proxyEmailStatus?: number;
  proxyEmailBody?: string;
  proxyProjectStatus?: number;
  proxyProjectBody?: string;
  /** Gate responses (for fallback to normal flow) */
  gateTokenBody?: Record<string, unknown>;
  gateTokenStatus?: number;
  gateIdentityBody?: Record<string, unknown>;
  gateIdentityStatus?: number;
}): typeof globalThis.fetch {
  return (async (url: string) => {
    const parsed = new URL(url);
    const isProxyRequest = parsed.host !== "localhost";

    if (isProxyRequest) {
      // Proxy health-check endpoints (nested detection)
      const path = parsed.pathname;
      if (path === "/") {
        return new Response("ok", {
          status: opts?.proxyRootStatus ?? 200,
          headers: opts?.proxyRootHeaders ?? { "Metadata-Flavor": "Google" },
        });
      }
      if (path === "/computeMetadata/v1/instance/service-accounts/default/token") {
        return new Response(
          JSON.stringify(
            opts?.proxyTokenBody ?? {
              access_token: "ya29.parent-token",
              expires_in: 3000,
              token_type: "Bearer",
            },
          ),
          {
            status: opts?.proxyTokenStatus ?? 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      }
      if (path === "/computeMetadata/v1/instance/service-accounts/default/email") {
        return new Response(opts?.proxyEmailBody ?? "eng@example.com", {
          status: opts?.proxyEmailStatus ?? 200,
        });
      }
      if (path === "/computeMetadata/v1/project/project-id") {
        return new Response(opts?.proxyProjectBody ?? "parent-project", {
          status: opts?.proxyProjectStatus ?? 200,
        });
      }
      return new Response("Not found", { status: 404 });
    }

    // Gate endpoints (normal flow)
    if (parsed.pathname === "/token") {
      return new Response(
        JSON.stringify(opts?.gateTokenBody ?? { access_token: "prod-token-abc", expires_in: 1800 }),
        {
          status: opts?.gateTokenStatus ?? 200,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
    if (parsed.pathname === "/identity") {
      return new Response(JSON.stringify(opts?.gateIdentityBody ?? { email: "eng@example.com" }), {
        status: opts?.gateIdentityStatus ?? 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  }) as unknown as typeof globalThis.fetch;
}

function mockSpawnCapture() {
  let capturedCmd: string[] = [];
  let capturedEnv: Record<string, string | undefined> = {};
  const mockSpawnFn = (cmd: string[], opts: { env: Record<string, string | undefined> }) => {
    capturedCmd = cmd;
    capturedEnv = opts.env;
    return {
      exited: Promise.resolve(0),
      kill: () => {},
    } as unknown as Subprocess;
  };
  return { mockSpawnFn, getCapturedCmd: () => capturedCmd, getCapturedEnv: () => capturedEnv };
}

describe("runWithProd", () => {
  let logSpy: ReturnType<typeof spyOn>;
  let exitSpy: ReturnType<typeof spyOn>;
  let errorSpy: ReturnType<typeof spyOn>;

  beforeEach(() => {
    logSpy = spyOn(console, "log").mockImplementation(() => {});
    errorSpy = spyOn(console, "error").mockImplementation(() => {});
    exitSpy = spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    exitSpy.mockRestore();
  });

  test("exits 1 when wrapped command is empty", async () => {
    await expect(
      runWithProd(
        {
          project_id: "test-proj",
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        [],
      ),
    ).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(errorOutput).toContain("with-prod requires a command to wrap");
  });

  test("throws ZodError when project_id is missing", async () => {
    await expect(
      runWithProd(
        {
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        ["python", "script.py"],
      ),
    ).rejects.toThrow(z.ZodError);
  });

  test("happy path: fetches token + identity, spawns command with correct env vars", async () => {
    const mockFetchFn = mockGateFetch();

    let capturedCmd: string[] = [];
    let capturedEnv: Record<string, string | undefined> = {};
    const mockSpawnFn = (cmd: string[], opts: { env: Record<string, string | undefined> }) => {
      capturedCmd = cmd;
      capturedEnv = opts.env;
      return {
        exited: Promise.resolve(0),
        kill: () => {},
      } as unknown as Subprocess;
    };

    await expect(
      runWithProd(
        {
          project_id: "my-proj",
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        ["echo", "hello"],
        {
          fetchOptions: { fetchFn: mockFetchFn },
          spawnFn: mockSpawnFn,
        },
      ),
    ).rejects.toThrow("process.exit called");

    // Verify the command was passed through
    expect(capturedCmd).toEqual(["echo", "hello"]);

    // Verify metadata proxy env vars are set, raw tokens are NOT exposed
    expect(capturedEnv.GCE_METADATA_HOST).toMatch(/^127\.0\.0\.1:\d+$/);
    expect(capturedEnv.GCE_METADATA_IP).toMatch(/^127\.0\.0\.1:\d+$/);
    expect(capturedEnv.GCE_METADATA_IP).toBe(capturedEnv.GCE_METADATA_HOST);
    expect("CLOUDSDK_AUTH_ACCESS_TOKEN" in capturedEnv).toBe(false);
    expect("CPL_GS_BEARER" in capturedEnv).toBe(false);

    // Verify CLOUDSDK_CONFIG points to a temporary directory (gcloud isolation)
    expect(capturedEnv.CLOUDSDK_CONFIG).toBeDefined();
    expect(capturedEnv.CLOUDSDK_CONFIG).toContain("gcp-authcalator-gcloud-");

    // Verify gcloud-specific env vars are set to the engineer's identity
    expect(capturedEnv.CLOUDSDK_CORE_ACCOUNT).toBe("eng@example.com");
    expect(capturedEnv.CLOUDSDK_CORE_PROJECT).toBe("my-proj");

    // Verify exit code propagated (0)
    expect(exitSpy).toHaveBeenCalledWith(0);

    // Verify log messages include the engineer's email
    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("requesting prod-level token");
    expect(logOutput).toContain("prod token acquired for eng@example.com");
  });

  test("sets gcloudConfigDir permissions to 0o700 (owner-only)", async () => {
    const mockFetchFn = mockGateFetch();

    let capturedMode: number | undefined;
    const mockSpawnFn = (_cmd: string[], opts: { env: Record<string, string | undefined> }) => {
      const configDir = opts.env.CLOUDSDK_CONFIG ?? "";
      if (configDir) {
        capturedMode = statSync(configDir).mode & 0o777;
      }
      return {
        exited: Promise.resolve(0),
        kill: () => {},
      } as unknown as Subprocess;
    };

    try {
      await runWithProd(
        {
          project_id: "my-proj",
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        ["echo", "test"],
        {
          fetchOptions: { fetchFn: mockFetchFn },
          spawnFn: mockSpawnFn,
        },
      );
    } catch {
      // process.exit mock throws
    }

    expect(capturedMode).toBe(0o700);
  });

  test("writes access_token file with mode 0600 containing the prod token", async () => {
    const mockFetchFn = mockGateFetch();

    let tokenContent = "";
    let tokenMode: number | undefined;
    const mockSpawnFn = (_cmd: string[], opts: { env: Record<string, string | undefined> }) => {
      const configDir = opts.env.CLOUDSDK_CONFIG ?? "";
      const tokenPath = `${configDir}/access_token`;
      tokenContent = readFileSync(tokenPath, "utf-8");
      tokenMode = statSync(tokenPath).mode & 0o777;
      return {
        exited: Promise.resolve(0),
        kill: () => {},
      } as unknown as Subprocess;
    };

    try {
      await runWithProd(
        {
          project_id: "my-proj",
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        ["echo", "test"],
        {
          fetchOptions: { fetchFn: mockFetchFn },
          spawnFn: mockSpawnFn,
        },
      );
    } catch {
      // process.exit mock throws
    }

    expect(tokenContent).toBe("prod-token-abc");
    expect(tokenMode).toBe(0o600);
  });

  test("writes gcloud properties file with access_token_file pointing to token", async () => {
    const mockFetchFn = mockGateFetch();

    let propertiesContent = "";
    let propertiesMode: number | undefined;
    let configDir = "";
    const mockSpawnFn = (_cmd: string[], opts: { env: Record<string, string | undefined> }) => {
      configDir = opts.env.CLOUDSDK_CONFIG ?? "";
      const propsPath = `${configDir}/properties`;
      propertiesContent = readFileSync(propsPath, "utf-8");
      propertiesMode = statSync(propsPath).mode & 0o777;
      return {
        exited: Promise.resolve(0),
        kill: () => {},
      } as unknown as Subprocess;
    };

    try {
      await runWithProd(
        {
          project_id: "my-proj",
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        ["echo", "test"],
        {
          fetchOptions: { fetchFn: mockFetchFn },
          spawnFn: mockSpawnFn,
        },
      );
    } catch {
      // process.exit mock throws
    }

    expect(propertiesContent).toContain("[auth]");
    expect(propertiesContent).toContain(`access_token_file = ${configDir}/access_token`);
    expect(propertiesMode).toBe(0o600);
  });

  test("cleans up temp CLOUDSDK_CONFIG directory after child exits", async () => {
    const mockFetchFn = mockGateFetch();

    let capturedConfigDir = "";
    const mockSpawnFn = (_cmd: string[], opts: { env: Record<string, string | undefined> }) => {
      capturedConfigDir = opts.env.CLOUDSDK_CONFIG ?? "";
      return {
        exited: Promise.resolve(0),
        kill: () => {},
      } as unknown as Subprocess;
    };

    try {
      await runWithProd(
        {
          project_id: "my-proj",
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        ["echo", "test"],
        {
          fetchOptions: { fetchFn: mockFetchFn },
          spawnFn: mockSpawnFn,
        },
      );
    } catch {
      // process.exit mock throws
    }

    expect(capturedConfigDir).toBeTruthy();
    expect(existsSync(capturedConfigDir)).toBe(false);
  });

  test("strips all credential-related env vars from child process", async () => {
    const originalEnv = { ...process.env };
    process.env.CLOUDSDK_AUTH_ACCESS_TOKEN = "leaked-token";
    process.env.CPL_GS_BEARER = "leaked-bearer";
    process.env.GOOGLE_APPLICATION_CREDENTIALS = "/path/to/key.json";
    process.env.GOOGLE_OAUTH_ACCESS_TOKEN = "leaked-oauth";
    process.env.CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE = "/path/to/creds";
    process.env.CLOUDSDK_CORE_ACCOUNT = "sneaky@example.com";
    process.env.CLOUDSDK_CONFIG = "/home/user/.config/gcloud";

    const mockFetchFn = mockGateFetch();

    let capturedEnv: Record<string, string | undefined> = {};
    const mockSpawnFn = (_cmd: string[], opts: { env: Record<string, string | undefined> }) => {
      capturedEnv = opts.env;
      return {
        exited: Promise.resolve(0),
        kill: () => {},
      } as unknown as Subprocess;
    };

    try {
      await runWithProd(
        {
          project_id: "my-proj",
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        ["echo", "test"],
        {
          fetchOptions: { fetchFn: mockFetchFn },
          spawnFn: mockSpawnFn,
        },
      );
    } catch {
      // process.exit mock throws
    }

    // Verify credential env vars are stripped (raw tokens never leak)
    expect("CLOUDSDK_AUTH_ACCESS_TOKEN" in capturedEnv).toBe(false);
    expect("CPL_GS_BEARER" in capturedEnv).toBe(false);
    expect("GOOGLE_APPLICATION_CREDENTIALS" in capturedEnv).toBe(false);
    expect("GOOGLE_OAUTH_ACCESS_TOKEN" in capturedEnv).toBe(false);
    expect("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE" in capturedEnv).toBe(false);

    // CLOUDSDK_CORE_ACCOUNT is overridden with the engineer's email (not the original value)
    expect(capturedEnv.CLOUDSDK_CORE_ACCOUNT).toBe("eng@example.com");
    expect(capturedEnv.CLOUDSDK_CORE_ACCOUNT).not.toBe("sneaky@example.com");

    // CLOUDSDK_CONFIG should be set to a NEW temp dir, not the original value
    expect(capturedEnv.CLOUDSDK_CONFIG).toBeDefined();
    expect(capturedEnv.CLOUDSDK_CONFIG).not.toBe("/home/user/.config/gcloud");
    expect(capturedEnv.CLOUDSDK_CONFIG).toContain("gcp-authcalator-gcloud-");

    // Verify metadata proxy env vars ARE set
    expect(capturedEnv.GCE_METADATA_HOST).toMatch(/^127\.0\.0\.1:\d+$/);
    expect(capturedEnv.GCE_METADATA_IP).toMatch(/^127\.0\.0\.1:\d+$/);
    expect(capturedEnv.GCE_METADATA_IP).toBe(capturedEnv.GCE_METADATA_HOST);

    // Restore original env
    process.env = originalEnv;
  });

  test("exits 1 with error message when token fetch fails", async () => {
    const mockFetchFn = (async () =>
      new Response("denied", { status: 403 })) as unknown as typeof globalThis.fetch;

    await expect(
      runWithProd(
        {
          project_id: "my-proj",
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        ["echo", "hello"],
        {
          fetchOptions: { fetchFn: mockFetchFn },
        },
      ),
    ).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(errorOutput).toContain("failed to acquire prod token");
  });

  test("propagates non-zero exit code from child process", async () => {
    const mockFetchFn = mockGateFetch({ access_token: "tok", expires_in: 3600 });

    const mockSpawnFn = (_cmd: string[]) => {
      return {
        exited: Promise.resolve(42),
        kill: () => {},
      } as unknown as Subprocess;
    };

    await expect(
      runWithProd(
        {
          project_id: "my-proj",
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        ["failing-command"],
        {
          fetchOptions: { fetchFn: mockFetchFn },
          spawnFn: mockSpawnFn,
        },
      ),
    ).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(42);
  });

  test("normal flow sets GCP_AUTHCALATOR_PROD_SESSION in child env", async () => {
    const mockFetchFn = mockGateFetch();
    const { mockSpawnFn, getCapturedEnv } = mockSpawnCapture();

    try {
      await runWithProd(
        {
          project_id: "my-proj",
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        ["echo", "test"],
        {
          fetchOptions: { fetchFn: mockFetchFn },
          spawnFn: mockSpawnFn,
        },
      );
    } catch {
      // process.exit mock throws
    }

    const env = getCapturedEnv();
    expect(env[PROD_SESSION_ENV_VAR]).toBeDefined();
    expect(env[PROD_SESSION_ENV_VAR]).toMatch(/^127\.0\.0\.1:\d+$/);
    // Sentinel should match the metadata host
    expect(env[PROD_SESSION_ENV_VAR]).toBe(env.GCE_METADATA_HOST);
  });
});

describe("runWithProd nested sessions", () => {
  let logSpy: ReturnType<typeof spyOn>;
  let exitSpy: ReturnType<typeof spyOn>;
  let errorSpy: ReturnType<typeof spyOn>;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    logSpy = spyOn(console, "log").mockImplementation(() => {});
    errorSpy = spyOn(console, "error").mockImplementation(() => {});
    exitSpy = spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
  });

  afterEach(() => {
    process.env = originalEnv;
    logSpy.mockRestore();
    errorSpy.mockRestore();
    exitSpy.mockRestore();
  });

  test("reuses existing prod session without fetching new token", async () => {
    // Set sentinel to simulate being inside a with-prod session
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";
    process.env.GCE_METADATA_HOST = "127.0.0.1:54321";
    process.env.GCE_METADATA_IP = "127.0.0.1:54321";
    process.env.CLOUDSDK_CONFIG = "/tmp/parent-gcloud-config";
    process.env.CLOUDSDK_CORE_ACCOUNT = "eng@example.com";
    process.env.CLOUDSDK_CORE_PROJECT = "parent-project";

    // Gate returns 403 — if nested detection works, gate should never be called
    const mockFetchFn = mockCombinedFetch({
      proxyProjectBody: "parent-project",
      gateTokenStatus: 403,
    });
    const { mockSpawnFn, getCapturedCmd } = mockSpawnCapture();

    await expect(
      runWithProd({ socket_path: "/tmp/gate.sock", port: 8173 }, ["echo", "hello"], {
        fetchOptions: { fetchFn: mockFetchFn },
        spawnFn: mockSpawnFn,
      }),
    ).rejects.toThrow("process.exit called");

    expect(getCapturedCmd()).toEqual(["echo", "hello"]);
    expect(exitSpy).toHaveBeenCalledWith(0);

    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("reusing existing prod session");
    expect(logOutput).not.toContain("requesting prod-level token");
  });

  test("passes through GCE_METADATA_HOST from parent session", async () => {
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";
    process.env.GCE_METADATA_HOST = "127.0.0.1:54321";

    const mockFetchFn = mockCombinedFetch({ proxyProjectBody: "parent-project" });
    const { mockSpawnFn, getCapturedEnv } = mockSpawnCapture();

    try {
      await runWithProd({ socket_path: "/tmp/gate.sock", port: 8173 }, ["echo", "test"], {
        fetchOptions: { fetchFn: mockFetchFn },
        spawnFn: mockSpawnFn,
      });
    } catch {
      // process.exit mock throws
    }

    const env = getCapturedEnv();
    expect(env.GCE_METADATA_HOST).toBe("127.0.0.1:54321");
    expect(env.GCE_METADATA_IP).toBe("127.0.0.1:54321");
  });

  test("passes through CLOUDSDK_CONFIG from parent session", async () => {
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";
    process.env.CLOUDSDK_CONFIG = "/tmp/parent-gcloud-config";

    const mockFetchFn = mockCombinedFetch({ proxyProjectBody: "parent-project" });
    const { mockSpawnFn, getCapturedEnv } = mockSpawnCapture();

    try {
      await runWithProd({ socket_path: "/tmp/gate.sock", port: 8173 }, ["echo", "test"], {
        fetchOptions: { fetchFn: mockFetchFn },
        spawnFn: mockSpawnFn,
      });
    } catch {
      // process.exit mock throws
    }

    expect(getCapturedEnv().CLOUDSDK_CONFIG).toBe("/tmp/parent-gcloud-config");
  });

  test("passes through CLOUDSDK_CORE_ACCOUNT and CLOUDSDK_CORE_PROJECT from parent", async () => {
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";

    const mockFetchFn = mockCombinedFetch({
      proxyEmailBody: "eng@example.com",
      proxyProjectBody: "parent-project",
    });
    const { mockSpawnFn, getCapturedEnv } = mockSpawnCapture();

    try {
      await runWithProd({ socket_path: "/tmp/gate.sock", port: 8173 }, ["echo", "test"], {
        fetchOptions: { fetchFn: mockFetchFn },
        spawnFn: mockSpawnFn,
      });
    } catch {
      // process.exit mock throws
    }

    const env = getCapturedEnv();
    expect(env.CLOUDSDK_CORE_ACCOUNT).toBe("eng@example.com");
    expect(env.CLOUDSDK_CORE_PROJECT).toBe("parent-project");
  });

  test("preserves sentinel env var in nested child env", async () => {
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";

    const mockFetchFn = mockCombinedFetch({ proxyProjectBody: "parent-project" });
    const { mockSpawnFn, getCapturedEnv } = mockSpawnCapture();

    try {
      await runWithProd({ socket_path: "/tmp/gate.sock", port: 8173 }, ["echo", "test"], {
        fetchOptions: { fetchFn: mockFetchFn },
        spawnFn: mockSpawnFn,
      });
    } catch {
      // process.exit mock throws
    }

    expect(getCapturedEnv()[PROD_SESSION_ENV_VAR]).toBe("127.0.0.1:54321");
  });

  test("strips credential env vars even when nested", async () => {
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";
    process.env.CLOUDSDK_AUTH_ACCESS_TOKEN = "leaked-token";
    process.env.CPL_GS_BEARER = "leaked-bearer";
    process.env.GOOGLE_APPLICATION_CREDENTIALS = "/path/to/key.json";
    process.env.GOOGLE_OAUTH_ACCESS_TOKEN = "leaked-oauth";
    process.env.CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE = "/path/to/creds";

    const mockFetchFn = mockCombinedFetch({ proxyProjectBody: "parent-project" });
    const { mockSpawnFn, getCapturedEnv } = mockSpawnCapture();

    try {
      await runWithProd({ socket_path: "/tmp/gate.sock", port: 8173 }, ["echo", "test"], {
        fetchOptions: { fetchFn: mockFetchFn },
        spawnFn: mockSpawnFn,
      });
    } catch {
      // process.exit mock throws
    }

    const env = getCapturedEnv();
    expect("CLOUDSDK_AUTH_ACCESS_TOKEN" in env).toBe(false);
    expect("CPL_GS_BEARER" in env).toBe(false);
    expect("GOOGLE_APPLICATION_CREDENTIALS" in env).toBe(false);
    expect("GOOGLE_OAUTH_ACCESS_TOKEN" in env).toBe(false);
    expect("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE" in env).toBe(false);
  });

  test("propagates exit code in nested session", async () => {
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";

    const mockFetchFn = mockCombinedFetch({ proxyProjectBody: "parent-project" });
    const mockSpawnFn = () =>
      ({
        exited: Promise.resolve(42),
        kill: () => {},
      }) as unknown as Subprocess;

    await expect(
      runWithProd({ socket_path: "/tmp/gate.sock", port: 8173 }, ["failing-cmd"], {
        fetchOptions: { fetchFn: mockFetchFn },
        spawnFn: mockSpawnFn,
      }),
    ).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(42);
  });

  test("falls back to normal flow when proxy is dead", async () => {
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";

    // Proxy is dead (connection refused), gate works normally
    const mockFetchFn = mockCombinedFetch({ proxyRootStatus: 503 });
    const { mockSpawnFn, getCapturedEnv } = mockSpawnCapture();

    try {
      await runWithProd(
        { project_id: "my-proj", socket_path: "/tmp/gate.sock", port: 8173 },
        ["echo", "test"],
        { fetchOptions: { fetchFn: mockFetchFn }, spawnFn: mockSpawnFn },
      );
    } catch {
      // process.exit mock throws
    }

    // Should have gone through normal flow (new token fetch)
    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("requesting prod-level token");
    expect(logOutput).not.toContain("reusing existing prod session");

    // Should have new metadata proxy, not the parent's
    const env = getCapturedEnv();
    expect(env.GCE_METADATA_HOST).toMatch(/^127\.0\.0\.1:\d+$/);
    expect(env.GCE_METADATA_HOST).not.toBe("127.0.0.1:54321");
  });

  test("falls back to normal flow when project-id differs from parent session", async () => {
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";

    // Parent proxy is healthy but serves a different project
    const mockFetchFn = mockCombinedFetch({ proxyProjectBody: "parent-project" });
    const { mockSpawnFn, getCapturedEnv } = mockSpawnCapture();

    try {
      await runWithProd(
        { project_id: "different-project", socket_path: "/tmp/gate.sock", port: 8173 },
        ["echo", "test"],
        { fetchOptions: { fetchFn: mockFetchFn }, spawnFn: mockSpawnFn },
      );
    } catch {
      // process.exit mock throws
    }

    // Should have gone through normal flow
    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("differs from active session");
    expect(logOutput).toContain("requesting prod-level token");
    expect(logOutput).not.toContain("reusing existing prod session");

    // New metadata proxy should be started
    const env = getCapturedEnv();
    expect(env.GCE_METADATA_HOST).toMatch(/^127\.0\.0\.1:\d+$/);
    expect(env.GCE_METADATA_HOST).not.toBe("127.0.0.1:54321");
  });

  test("reuses session when project-id matches parent session", async () => {
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";

    const mockFetchFn = mockCombinedFetch({
      proxyProjectBody: "same-project",
      gateTokenStatus: 403,
    });
    const { mockSpawnFn, getCapturedEnv } = mockSpawnCapture();

    try {
      await runWithProd(
        { project_id: "same-project", socket_path: "/tmp/gate.sock", port: 8173 },
        ["echo", "test"],
        { fetchOptions: { fetchFn: mockFetchFn }, spawnFn: mockSpawnFn },
      );
    } catch {
      // process.exit mock throws
    }

    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("reusing existing prod session");

    // Should use parent's proxy
    expect(getCapturedEnv().GCE_METADATA_HOST).toBe("127.0.0.1:54321");
  });

  test("reuses session when project-id is not specified", async () => {
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";

    const mockFetchFn = mockCombinedFetch({
      proxyProjectBody: "parent-project",
      gateTokenStatus: 403,
    });
    const { mockSpawnFn, getCapturedEnv } = mockSpawnCapture();

    try {
      await runWithProd({ socket_path: "/tmp/gate.sock", port: 8173 }, ["echo", "test"], {
        fetchOptions: { fetchFn: mockFetchFn },
        spawnFn: mockSpawnFn,
      });
    } catch {
      // process.exit mock throws
    }

    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("reusing existing prod session");

    // Should use parent's proxy, not start a new one
    expect(getCapturedEnv().GCE_METADATA_HOST).toBe("127.0.0.1:54321");
  });

  test("logs reuse message with proxy address", async () => {
    process.env[PROD_SESSION_ENV_VAR] = "127.0.0.1:54321";

    const mockFetchFn = mockCombinedFetch({ proxyProjectBody: "parent-project" });
    const { mockSpawnFn } = mockSpawnCapture();

    try {
      await runWithProd({ socket_path: "/tmp/gate.sock", port: 8173 }, ["echo", "test"], {
        fetchOptions: { fetchFn: mockFetchFn },
        spawnFn: mockSpawnFn,
      });
    } catch {
      // process.exit mock throws
    }

    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("reusing existing prod session (proxy at 127.0.0.1:54321)");
  });
});
