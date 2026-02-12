import { describe, expect, test } from "bun:test";
import { createConfirmModule } from "../../gate/confirm.ts";

/** Create a mock spawn function that returns a process with the given exit code. */
function mockSpawn(exitCode: number) {
  return () => {
    return {
      exited: Promise.resolve(exitCode),
      pid: 12345,
      stdin: null,
      stdout: null,
      stderr: null,
      exitCode: null,
      signalCode: null,
      killed: false,
      kill: () => {},
      ref: () => {},
      unref: () => {},
      [Symbol.asyncDispose]: async () => {},
    } as unknown as ReturnType<typeof Bun.spawn>;
  };
}

describe("createConfirmModule", () => {
  describe("zenity approval", () => {
    test("returns true when zenity exits with 0", async () => {
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0),
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(true);
    });

    test("returns false when zenity exits with 1 (denied)", async () => {
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(1),
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });

    test("returns false when zenity exits with 5 (timeout)", async () => {
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(5),
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });
  });

  describe("zenity not available", () => {
    test("returns false when zenity exits 127 and stdin is not TTY", async () => {
      // When zenity exits 127 (not found) and stdin is not TTY, should deny
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(127),
      });
      // In test environment, stdin is not a TTY, so fallback should deny
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });
  });

  describe("spawn passes correct arguments", () => {
    test("passes correct zenity arguments", async () => {
      let capturedCmd: string[] = [];
      const spawnFn = (cmd: string[]) => {
        capturedCmd = cmd;
        return {
          exited: Promise.resolve(0),
          pid: 12345,
          stdin: null,
          stdout: null,
          stderr: null,
          exitCode: null,
          signalCode: null,
          killed: false,
          kill: () => {},
          ref: () => {},
          unref: () => {},
          [Symbol.asyncDispose]: async () => {},
        } as unknown as ReturnType<typeof Bun.spawn>;
      };

      const { confirmProdAccess } = createConfirmModule({ spawn: spawnFn });
      await confirmProdAccess("user@example.com");

      expect(capturedCmd[0]).toBe("zenity");
      expect(capturedCmd).toContain("--question");
      expect(capturedCmd).toContain("--title=gcp-gate: Prod Access");
      expect(capturedCmd.some((arg) => arg.includes("user@example.com"))).toBe(true);
      expect(capturedCmd).toContain("--timeout=60");
    });
  });
});
