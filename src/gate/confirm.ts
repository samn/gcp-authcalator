import type { Subprocess } from "bun";
import type { PendingQueue } from "./pending.ts";
import { stripControlChars } from "./sanitize.ts";
import type { CommandDisplay } from "./summarize-command.ts";

type SpawnFn = (
  cmd: string[],
  opts?: { stdin?: "pipe" | "inherit"; stderr?: "pipe" | "inherit" },
) => Subprocess;

export interface ConfirmOptions {
  /** Override Bun.spawn for testing. */
  spawn?: SpawnFn;
  /** Override process.platform for testing. */
  platform?: string;
  /** Override process.stdin.isTTY for testing. */
  isTTY?: boolean;
  /** Optional pending queue for CLI-based approval when no GUI/TTY is available. */
  pendingQueue?: PendingQueue;
  /** Override the parent-side dialog deadline for testing. */
  dialogBackstopMs?: number;
}

/** Dialog title shared by every GUI surface. */
const DIALOG_TITLE = "gcp-gate: Prod Access";

/** Checkbox the operator must tick before zenity enables the Allow button. */
const READ_ACK_LABEL = "I have read the full command";

/** Seconds before a dialog auto-denies, where the dialog supports it natively. */
const DIALOG_TIMEOUT_SECONDS = 60;

/**
 * Parent-side deadline, slightly longer than the native one. `choose from list`
 * has no AppleScript timeout, and a dialog that never returns would hold the
 * prod rate limiter's single-flight lock forever.
 */
const DIALOG_BACKSTOP_MS = 65_000;

/**
 * Create a confirmation module for prod token access.
 *
 * Primary: platform-specific GUI dialog (osascript on macOS, zenity on Linux).
 * Fallback: terminal prompt on stdin (if TTY).
 * Default: deny if no interactive method is available.
 *
 * When a command was reported, every surface shows it in full, one argument per
 * line. Approving a command you cannot read is not consent, so nothing here
 * elides without saying that it did.
 */
export function createConfirmModule(options: ConfirmOptions = {}): {
  confirmProdAccess: (
    email: string,
    command?: CommandDisplay,
    pamPolicy?: string,
    pendingId?: string,
  ) => Promise<boolean>;
} {
  const spawnFn = options.spawn ?? (Bun.spawn as unknown as SpawnFn);
  const platform = options.platform ?? process.platform;
  const isTTY = options.isTTY ?? !!process.stdin.isTTY;
  const pendingQueue = options.pendingQueue;
  const runDialog = createDialogRunner(spawnFn, options.dialogBackstopMs ?? DIALOG_BACKSTOP_MS);

  async function confirmProdAccess(
    email: string,
    command?: CommandDisplay,
    pamPolicy?: string,
    pendingId?: string,
  ): Promise<boolean> {
    // Sanitise every operator-visible string before it reaches a dialog.
    // `command` is already stripped per element by describeCommand().
    const safeEmail = stripControlChars(email);
    const safePamPolicy = pamPolicy !== undefined ? stripControlChars(pamPolicy) : undefined;

    const tryGui = platform === "darwin" ? tryOsascript : tryZenity;

    try {
      const result = await tryGui(safeEmail, runDialog, command, safePamPolicy);
      if (result !== null) return result;
    } catch {
      // GUI not available, fall through to terminal
    }

    // Fallback to terminal prompt if TTY is available
    if (isTTY) {
      return tryTerminalPrompt(safeEmail, command, safePamPolicy);
    }

    // Fallback to pending queue for CLI-based approval
    if (pendingQueue) {
      console.error("confirm: no interactive method available, queuing for CLI approval");
      return pendingQueue.enqueue(safeEmail, command, safePamPolicy, pendingId);
    }

    console.error("confirm: no interactive method available, denying prod access");
    return false;
  }

  return { confirmProdAccess };
}

/** The question being asked, without the command body. */
function headline(email: string, pamPolicy?: string): string {
  return pamPolicy
    ? `Grant prod-level GCP access to ${email} via PAM entitlement '${pamPolicy}'?`
    : `Grant prod-level GCP access to ${email}?`;
}

/** Heading above the numbered argument list. */
export function commandHeading(command: CommandDisplay): string {
  const plural = command.totalArgs === 1 ? "" : "s";
  return `Full command (${command.totalArgs} argument${plural}):`;
}

/** Outcome of running a dialog subprocess. */
interface DialogResult {
  /** Exit code, or "timeout" if the parent-side deadline fired first. */
  code: number | "timeout";
  /**
   * True if the child rejected our command line (unknown/unsupported option)
   * rather than reaching a decision. Such a child is unusable, not a "deny".
   */
  unsupportedOption: boolean;
}

/** Spawns a dialog and resolves to its outcome. */
type DialogRunner = (cmd: string[], options?: { stdinText?: string }) => Promise<DialogResult>;

/**
 * Detect a rejection of our command line by the dialog binary itself.
 *
 * The exit code can't carry this: zenity 4.0.1 exits 255 for an unsupported
 * option, which is otherwise indistinguishable from a crash, and older builds
 * surface GOption failures as exit 1 — the same code as "user pressed Deny".
 * Only stderr separates "this binary can't run our dialog" from a decision.
 *
 * Wordings covered (verified against zenity 4.0.1 for the first):
 *   "This option is not available. Please see --help for all possible usages."
 *   "Unknown option --checkbox"        (GLib GOption, older zenity/GTK3)
 *   "Unrecognized option ..."          (GLib, some locales/versions)
 */
const UNSUPPORTED_OPTION_RE =
  /this option is not available|unknown option|unrecogni[sz]ed option|option parsing failed/i;

/**
 * Build a dialog runner: spawn, optionally feed stdin, and bound the whole
 * interaction with a parent-side deadline, killing the child if it overruns.
 * The deadline is not optional — a dialog that never returns would hold the
 * prod rate limiter's single-flight lock indefinitely, wedging every later
 * request. It is armed *before* the stdin write, because a child that never
 * drains stdin would otherwise wedge the flush itself, outside the deadline
 * that exists to prevent exactly that.
 */
function createDialogRunner(spawnFn: SpawnFn, backstopMs: number): DialogRunner {
  return async (cmd, options = {}) => {
    const wantsStdin = options.stdinText !== undefined;
    const proc = spawnFn(cmd, wantsStdin ? { stdin: "pipe", stderr: "pipe" } : { stderr: "pipe" });

    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), backstopMs);
      // Don't keep the process alive just for this timer
      if (typeof timer === "object" && "unref" in timer) timer.unref();
    });

    try {
      if (wantsStdin) {
        const sink = proc.stdin;
        if (sink && typeof sink === "object" && "write" in sink) {
          // A child that exits before reading gives us EPIPE here; that's a
          // failed dialog, not a decision, so let the exit code speak.
          const flushed = (async () => {
            try {
              sink.write(options.stdinText!);
              await sink.end();
            } catch {
              // fall through to the exit-code read below
            }
          })();
          if ((await Promise.race([flushed, deadline])) === "timeout") {
            proc.kill();
            return { code: "timeout", unsupportedOption: false };
          }
        }
      }

      const result = await Promise.race([proc.exited, deadline]);
      if (result === "timeout") {
        proc.kill();
        return { code: "timeout", unsupportedOption: false };
      }

      return { code: result, unsupportedOption: await rejectedOurOptions(proc) };
    } finally {
      clearTimeout(timer);
    }
  };
}

/** Read the child's stderr (if piped) and look for an option-parse rejection. */
async function rejectedOurOptions(proc: Subprocess): Promise<boolean> {
  const stderr = proc.stderr;
  if (!stderr || typeof stderr !== "object") return false;
  try {
    const text = await new Response(stderr as ReadableStream).text();
    return UNSUPPORTED_OPTION_RE.test(text);
  } catch {
    return false;
  }
}

/**
 * Map a zenity result to a decision.
 *
 * Exit 0 = approved, 1 = denied, 5 = timeout (denied), 127 = zenity not found.
 * `null` means "no usable GUI", so the caller falls through to the terminal
 * prompt and then the pending queue. A zenity that is present but rejects our
 * options must map to `null` too: mapping it to `false` would silently deny
 * every prod request on that host with no fallback and no way to approve.
 */
function zenityDecision(result: DialogResult): boolean | null {
  if (result.unsupportedOption) return null;
  const { code } = result;
  if (code === "timeout") return false;
  if (code === 0) return true;
  if (code === 1 || code === 5) return false;
  if (code === 127) return null;
  // Unexpected exit code — deny rather than guess.
  return false;
}

async function tryZenity(
  email: string,
  runDialog: DialogRunner,
  command?: CommandDisplay,
  pamPolicy?: string,
): Promise<boolean | null> {
  const text = headline(email, pamPolicy);

  // No command reported: nothing to scroll, so keep the compact question
  // dialog, which defaults to Cancel on Escape.
  if (!command) {
    return zenityDecision(
      await runDialog([
        "zenity",
        "--question",
        "--no-markup",
        `--title=${DIALOG_TITLE}`,
        `--text=${text}`,
        "--width=500",
        `--timeout=${DIALOG_TIMEOUT_SECONDS}`,
      ]),
    );
  }

  // A command was reported: show all of it in a scrollable, read-only text
  // view. --text-info reads the body from stdin when --filename is absent, so
  // no part of the command lands in argv or on disk. --checkbox keeps Allow
  // disabled until the operator acknowledges having read it. Never pass
  // --html (would let the command render markup) or --editable.
  const body = [text, "", commandHeading(command), ...command.lines].join("\n");

  return zenityDecision(
    await runDialog(
      [
        "zenity",
        "--text-info",
        `--title=${DIALOG_TITLE}`,
        "--width=700",
        "--height=500",
        "--ok-label=Allow",
        "--cancel-label=Deny",
        `--checkbox=${READ_ACK_LABEL}`,
        `--timeout=${DIALOG_TIMEOUT_SECONDS}`,
      ],
      { stdinText: body },
    ),
  );
}

/** Escape a string for embedding in an AppleScript double-quoted literal. */
function escapeAppleScript(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/**
 * Map an osascript result to a decision.
 *
 * Exit 0 = approved, 1 = denied/cancelled/timed out, 127 = not found.
 */
function osascriptDecision(result: DialogResult): boolean | null {
  if (result.unsupportedOption) return null;
  const { code } = result;
  if (code === "timeout") return false;
  if (code === 0) return true;
  if (code === 1) return false;
  if (code === 127) return null;
  return false;
}

async function tryOsascript(
  email: string,
  runDialog: DialogRunner,
  command?: CommandDisplay,
  pamPolicy?: string,
): Promise<boolean | null> {
  const text = escapeAppleScript(headline(email, pamPolicy));

  // No command reported: keep `display dialog`, which gives us a caution icon,
  // `default button "Deny"`, and a native timeout.
  if (!command) {
    return osascriptDecision(
      await runDialog([
        "osascript",
        "-e",
        `set r to display dialog "${text}" buttons {"Deny", "Allow"} default button "Deny" with icon caution giving up after ${DIALOG_TIMEOUT_SECONDS}`,
        "-e",
        'if button returned of r is not "Allow" or gave up of r is true then error "denied"',
      ]),
    );
  }

  // A command was reported. `choose from list` is the only AppleScript dialog
  // that scrolls, so the full argv goes in the list and the question goes in
  // the prompt.
  //
  // Two clauses here are load-bearing and easy to "clean up" into a hole:
  //
  //   `default items {}` — without it AppleScript selects the FIRST row by
  //   default, which leaves the renamed OK button ("Allow") enabled and made
  //   the default button, so a single stray Return would approve. Selecting
  //   nothing is what keeps Allow disabled until the operator clicks a line.
  //
  //   omitting `empty selection allowed` — with it, Allow would be clickable
  //   with nothing selected, undoing the same guard from the other direction.
  //
  // Together they restore the "Return cannot approve by accident" property
  // that `default button "Deny"` gives the compact dialog above.
  const items = command.lines.map((line) => `"${escapeAppleScript(line)}"`).join(", ");
  const prompt = [
    text,
    "",
    escapeAppleScript(commandHeading(command)),
    "Select any line to enable Allow.",
  ].join("\\n");
  const script = [
    `set r to choose from list {${items}} with title "${DIALOG_TITLE}" with prompt "${prompt}" default items {} OK button name "Allow" cancel button name "Deny"`,
    'if r is false then error "denied"',
  ].join("\n");

  // The script goes in on stdin (`osascript -`), not as `-e` arguments: an
  // argv-borne script puts the whole command in the host process table, where
  // any local user could read it out of `ps` while the dialog is open. This
  // mirrors the zenity path above.
  return osascriptDecision(await runDialog(["osascript", "-"], { stdinText: script }));
}

async function tryTerminalPrompt(
  email: string,
  command?: CommandDisplay,
  pamPolicy?: string,
): Promise<boolean> {
  // Scrollback is the scroll affordance here, so print every line.
  if (command) {
    process.stdout.write(`gcp-gate: ${commandHeading(command)}\n`);
    for (const line of command.lines) {
      process.stdout.write(`${line}\n`);
    }
  }

  // Requiring the whole word mirrors zenity's acknowledgement checkbox: a
  // reflexive "y" shouldn't approve a command the operator hasn't read.
  const question = headline(email, pamPolicy);
  const suffix = command ? "Type 'yes' to approve: " : "[y/N] ";
  process.stdout.write(`gcp-gate: ${question} ${suffix}`);

  return new Promise<boolean>((resolve) => {
    process.stdin.setRawMode?.(false);
    process.stdin.resume();
    process.stdin.setEncoding("utf-8");

    // One shared budget across the re-prompt, so an unattended terminal still
    // auto-denies on schedule.
    const timeout = setTimeout(() => {
      finish(false, "\nconfirm: timed out waiting for response, denying prod access");
    }, DIALOG_TIMEOUT_SECONDS * 1000);

    let reprompted = false;

    function finish(approved: boolean, message?: string): void {
      clearTimeout(timeout);
      process.stdin.pause();
      process.stdin.removeListener("data", onData);
      if (message) console.log(message);
      resolve(approved);
    }

    const onData = (data: string) => {
      const answer = data.toString().trim().toLowerCase();

      if (!command) {
        finish(answer === "y" || answer === "yes");
        return;
      }

      if (answer === "yes") {
        finish(true);
        return;
      }

      // A bare "y" was the accepted answer before the full word was required,
      // so denying it outright would throw away the operator's whole
      // invocation over a habit. Ask once more, then take them at their word.
      if (!reprompted && answer !== "" && answer !== "n" && answer !== "no") {
        reprompted = true;
        process.stdout.write("gcp-gate: please type 'yes' in full to approve, or 'n' to deny: ");
        return;
      }

      finish(false);
    };

    process.stdin.on("data", onData);
  });
}
