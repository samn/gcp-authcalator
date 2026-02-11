import { describe, expect, test, beforeEach, afterEach, spyOn } from "bun:test";
import { z } from "zod";
import { runGate } from "../../commands/gate.ts";

describe("runGate", () => {
  let logSpy: ReturnType<typeof spyOn>;

  beforeEach(() => {
    logSpy = spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  test("logs expected output with valid config", () => {
    runGate({
      project_id: "test-proj",
      service_account: "sa@test-proj.iam.gserviceaccount.com",
      socket_path: "/tmp/gate.sock",
      port: 8173,
    });

    const output = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(output).toContain("gate: starting gcp-gate token daemon");
    expect(output).toContain("test-proj");
    expect(output).toContain("sa@test-proj.iam.gserviceaccount.com");
    expect(output).toContain("/tmp/gate.sock");
    expect(output).toContain("GET /token");
    expect(output).toContain("GET /health");
    expect(output).toContain("[STUB] Not yet implemented.");
  });

  test("throws ZodError when project_id is missing", () => {
    expect(() =>
      runGate({
        socket_path: "/tmp/gate.sock",
        port: 8173,
      }),
    ).toThrow(z.ZodError);
  });

  test("throws ZodError when service_account is missing", () => {
    expect(() =>
      runGate({
        project_id: "test-proj",
        socket_path: "/tmp/gate.sock",
        port: 8173,
      }),
    ).toThrow(z.ZodError);
  });
});
