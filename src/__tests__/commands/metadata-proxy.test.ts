import { describe, expect, test, beforeEach, afterEach, spyOn } from "bun:test";
import { z } from "zod";
import { runMetadataProxy } from "../../commands/metadata-proxy.ts";

describe("runMetadataProxy", () => {
  let logSpy: ReturnType<typeof spyOn>;

  beforeEach(() => {
    logSpy = spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  test("logs expected output with valid config", () => {
    runMetadataProxy({
      project_id: "test-proj",
      socket_path: "/tmp/gate.sock",
      port: 9090,
    });

    const output = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(output).toContain("metadata-proxy: starting GCE metadata server emulator");
    expect(output).toContain("test-proj");
    expect(output).toContain("9090");
    expect(output).toContain("/tmp/gate.sock");
    expect(output).toContain("/computeMetadata/v1/");
    expect(output).toContain("[STUB] Not yet implemented.");
  });

  test("throws ZodError when project_id is missing", () => {
    expect(() =>
      runMetadataProxy({
        socket_path: "/tmp/gate.sock",
        port: 8173,
      }),
    ).toThrow(z.ZodError);
  });
});
