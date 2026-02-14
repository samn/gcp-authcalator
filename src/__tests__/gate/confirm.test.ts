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
        platform: "linux",
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(true);
    });

    test("returns false when zenity exits with 1 (denied)", async () => {
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(1),
        platform: "linux",
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });

    test("returns false when zenity exits with 5 (timeout)", async () => {
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(5),
        platform: "linux",
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
        platform: "linux",
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

      const { confirmProdAccess } = createConfirmModule({
        spawn: spawnFn,
        platform: "linux",
      });
      await confirmProdAccess("user@example.com");

      expect(capturedCmd[0]).toBe("zenity");
      expect(capturedCmd).toContain("--question");
      expect(capturedCmd).toContain("--title=gcp-gate: Prod Access");
      expect(capturedCmd.some((arg) => arg.includes("user@example.com"))).toBe(true);
      expect(capturedCmd).toContain("--timeout=60");
    });
  });

  describe("osascript approval (macOS)", () => {
    test("returns true when osascript exits with 0", async () => {
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0),
        platform: "darwin",
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(true);
    });

    test("returns false when osascript exits with 1 (denied)", async () => {
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(1),
        platform: "darwin",
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });
  });

  describe("osascript not available", () => {
    test("returns false when osascript exits 127 and stdin is not TTY", async () => {
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(127),
        platform: "darwin",
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });
  });

  describe("osascript arguments and escaping", () => {
    test("passes correct osascript arguments", async () => {
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

      const { confirmProdAccess } = createConfirmModule({
        spawn: spawnFn,
        platform: "darwin",
      });
      await confirmProdAccess("user@example.com");

      expect(capturedCmd[0]).toBe("osascript");
      expect(capturedCmd).toContain("-e");
      expect(capturedCmd.some((arg) => arg.includes("display dialog"))).toBe(true);
      expect(capturedCmd.some((arg) => arg.includes("user@example.com"))).toBe(true);
    });

    test("escapes double quotes in email", async () => {
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

      const { confirmProdAccess } = createConfirmModule({
        spawn: spawnFn,
        platform: "darwin",
      });
      await confirmProdAccess('user"@example.com');

      const scriptArg = capturedCmd.find((arg) => arg.includes("display dialog"));
      expect(scriptArg).toBeDefined();
      expect(scriptArg).toContain('user\\"@example.com');
    });

    test("escapes backslashes in email", async () => {
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

      const { confirmProdAccess } = createConfirmModule({
        spawn: spawnFn,
        platform: "darwin",
      });
      await confirmProdAccess("user\\@example.com");

      const scriptArg = capturedCmd.find((arg) => arg.includes("display dialog"));
      expect(scriptArg).toBeDefined();
      expect(scriptArg).toContain("user\\\\@example.com");
    });
  });

  describe("platform routing", () => {
    test("uses osascript on darwin", async () => {
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

      const { confirmProdAccess } = createConfirmModule({
        spawn: spawnFn,
        platform: "darwin",
      });
      await confirmProdAccess("user@example.com");
      expect(capturedCmd[0]).toBe("osascript");
    });

    test("uses zenity on linux", async () => {
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

      const { confirmProdAccess } = createConfirmModule({
        spawn: spawnFn,
        platform: "linux",
      });
      await confirmProdAccess("user@example.com");
      expect(capturedCmd[0]).toBe("zenity");
    });
  });
});
