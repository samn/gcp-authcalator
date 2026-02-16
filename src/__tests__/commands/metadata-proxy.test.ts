import { describe, expect, test, spyOn } from "bun:test";
import { z } from "zod";
import { runMetadataProxy } from "../../commands/metadata-proxy.ts";

describe("runMetadataProxy", () => {
  test("throws ZodError when project_id is missing", async () => {
    await expect(
      runMetadataProxy({
        socket_path: "/tmp/gate.sock",
        port: 8173,
      }),
    ).rejects.toThrow(z.ZodError);
  });

  test("exits with error when socket does not exist", async () => {
    const errorSpy = spyOn(console, "error").mockImplementation(() => {});
    const exitSpy = spyOn(process, "exit").mockImplementation((code?: number) => {
      throw new Error(`process.exit(${code})`);
    });

    try {
      await expect(
        runMetadataProxy({
          project_id: "test-project",
          socket_path: "/tmp/nonexistent-test-gate.sock",
          port: 19999,
        }),
      ).rejects.toThrow("process.exit(1)");

      const output = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
      expect(output).toContain("socket not found");
      expect(output).toContain("gcp-authcalator gate");
    } finally {
      errorSpy.mockRestore();
      exitSpy.mockRestore();
    }
  });

  test("exits with error when health check fails", async () => {
    const { mkdtempSync, rmSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");

    const errorSpy = spyOn(console, "error").mockImplementation(() => {});
    const exitSpy = spyOn(process, "exit").mockImplementation((code?: number) => {
      throw new Error(`process.exit(${code})`);
    });

    const tmpDir = mkdtempSync(join(tmpdir(), "mp-cmd-test-"));
    const socketPath = join(tmpDir, "test.sock");
    const tempServer = Bun.serve({
      unix: socketPath,
      fetch() {
        return new Response("ok");
      },
    });
    tempServer.stop(true);

    try {
      await expect(
        runMetadataProxy({
          project_id: "test-project",
          socket_path: socketPath,
          port: 19999,
        }),
      ).rejects.toThrow("process.exit(1)");

      const output = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
      expect(output).toContain("not responding");
    } finally {
      errorSpy.mockRestore();
      exitSpy.mockRestore();
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
