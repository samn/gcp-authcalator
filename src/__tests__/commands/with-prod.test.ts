import { describe, expect, test, beforeEach, afterEach, spyOn } from "bun:test";
import { z } from "zod";
import { runWithProd } from "../../commands/with-prod.ts";
import type { Subprocess } from "bun";

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

  test("happy path: fetches token, spawns command with correct env vars, propagates exit code", async () => {
    const mockFetchFn = (async () =>
      new Response(JSON.stringify({ access_token: "prod-token-abc", expires_in: 1800 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as unknown as typeof globalThis.fetch;

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

    // Verify env vars are set
    expect(capturedEnv.GCE_METADATA_HOST).toMatch(/^127\.0\.0\.1:\d+$/);
    expect(capturedEnv.CLOUDSDK_AUTH_ACCESS_TOKEN).toBe("prod-token-abc");
    expect(capturedEnv.CPL_GS_BEARER).toBe("prod-token-abc");

    // Verify exit code propagated (0)
    expect(exitSpy).toHaveBeenCalledWith(0);

    // Verify log messages
    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("requesting prod-level token");
    expect(logOutput).toContain("prod token acquired");
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
    const mockFetchFn = (async () =>
      new Response(JSON.stringify({ access_token: "tok", expires_in: 3600 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as unknown as typeof globalThis.fetch;

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
