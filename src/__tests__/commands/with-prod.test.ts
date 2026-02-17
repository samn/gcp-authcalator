import { describe, expect, test, beforeEach, afterEach, spyOn } from "bun:test";
import { existsSync, statSync } from "node:fs";
import { z } from "zod";
import { runWithProd } from "../../commands/with-prod.ts";
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

  test("calls setNonDumpable by default", async () => {
    const mockFetchFn = mockGateFetch();

    let prctlCalled = false;
    const mockSetNonDumpable = () => {
      prctlCalled = true;
    };

    const mockSpawnFn = (_cmd: string[], _opts: { env: Record<string, string | undefined> }) => {
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
          setNonDumpableFn: mockSetNonDumpable,
        },
      );
    } catch {
      // process.exit mock throws
    }

    expect(prctlCalled).toBe(true);
    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("process protection enabled (non-dumpable)");
  });

  test("skips setNonDumpable when dumpable option is true", async () => {
    const mockFetchFn = mockGateFetch();

    let prctlCalled = false;
    const mockSetNonDumpable = () => {
      prctlCalled = true;
    };

    const mockSpawnFn = (_cmd: string[], _opts: { env: Record<string, string | undefined> }) => {
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
          dumpable: true,
          setNonDumpableFn: mockSetNonDumpable,
        },
      );
    } catch {
      // process.exit mock throws
    }

    expect(prctlCalled).toBe(false);
    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).not.toContain("process protection enabled");
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
});
