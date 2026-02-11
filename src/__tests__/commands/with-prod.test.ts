import { describe, expect, test, beforeEach, afterEach, spyOn } from "bun:test";
import { z } from "zod";
import { runWithProd } from "../../commands/with-prod.ts";

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

  test("logs expected output with valid config and command", () => {
    runWithProd(
      {
        project_id: "test-proj",
        socket_path: "/tmp/gate.sock",
        port: 8173,
      },
      ["python", "script.py"],
    );

    const output = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(output).toContain("with-prod: wrapping command with prod credentials");
    expect(output).toContain("test-proj");
    expect(output).toContain("/tmp/gate.sock");
    expect(output).toContain("python script.py");
    expect(output).toContain("[STUB] Not yet implemented.");
  });

  test("exits 1 when wrapped command is empty", () => {
    expect(() =>
      runWithProd(
        {
          project_id: "test-proj",
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        [],
      ),
    ).toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(errorOutput).toContain("with-prod requires a command to wrap");
  });

  test("throws ZodError when project_id is missing", () => {
    expect(() =>
      runWithProd(
        {
          socket_path: "/tmp/gate.sock",
          port: 8173,
        },
        ["python", "script.py"],
      ),
    ).toThrow(z.ZodError);
  });
});
