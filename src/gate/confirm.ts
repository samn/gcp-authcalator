import type { Subprocess } from "bun";
import type { PendingQueue } from "./pending.ts";
import { stripControlChars } from "./sanitize.ts";

type SpawnFn = (cmd: string[], opts?: { stdin?: "pipe" | "inherit" }) => Subprocess;

export interface ConfirmOptions {
  /** Override Bun.spawn for testing. */
  spawn?: SpawnFn;
  /** Override process.platform for testing. */
  platform?: string;
  /** Override process.stdin.isTTY for testing. */
  isTTY?: boolean;
  /** Optional pending queue for CLI-based approval when no GUI/TTY is available. */
  pendingQueue?: PendingQueue;
}

/**
 * Create a confirmation module for prod token access.
 *
 * Primary: platform-specific GUI dialog (osascript on macOS, zenity on Linux).
 * Fallback: terminal prompt on stdin (if TTY).
 * Default: deny if no interactive method is available.
 */
export function createConfirmModule(options: ConfirmOptions = {}): {
  confirmProdAccess: (
    email: string,
    projectId: string,
    command?: string,
    pamPolicy?: string,
    pendingId?: string,
  ) => Promise<boolean>;
} {
  const spawnFn = options.spawn ?? (Bun.spawn as unknown as SpawnFn);
  const platform = options.platform ?? process.platform;
  const isTTY = options.isTTY ?? !!process.stdin.isTTY;
  const pendingQueue = options.pendingQueue;

  async function confirmProdAccess(
    email: string,
    projectId: string,
    command?: string,
    pamPolicy?: string,
    pendingId?: string,
  ): Promise<boolean> {
    // Sanitise every operator-visible string before it reaches a dialog.
    const safeEmail = stripControlChars(email);
    const safeProject = stripControlChars(projectId);
    const safeCommand = command !== undefined ? stripControlChars(command) : undefined;
    const safePamPolicy = pamPolicy !== undefined ? stripControlChars(pamPolicy) : undefined;

    const tryGui = platform === "darwin" ? tryOsascript : tryZenity;

    try {
      const result = await tryGui(safeEmail, safeProject, spawnFn, safeCommand, safePamPolicy);
      if (result !== null) return result;
    } catch {
      // GUI not available, fall through to terminal
    }

    // Fallback to terminal prompt if TTY is available
    if (isTTY) {
      return tryTerminalPrompt(safeEmail, safeProject, safeCommand, safePamPolicy);
    }

    // Fallback to pending queue for CLI-based approval
    if (pendingQueue) {
      console.error("confirm: no interactive method available, queuing for CLI approval");
      return pendingQueue.enqueue(safeEmail, safeProject, safeCommand, safePamPolicy, pendingId);
    }

    console.error("confirm: no interactive method available, denying prod access");
    return false;
  }

  return { confirmProdAccess };
}

async function tryZenity(
  email: string,
  projectId: string,
  spawnFn: SpawnFn,
  command?: string,
  pamPolicy?: string,
): Promise<boolean | null> {
  let text = pamPolicy
    ? `Grant prod-level GCP access to ${email} via PAM entitlement '${pamPolicy}'?`
    : `Grant prod-level GCP access to ${email}?`;
  text += `\n\nProject: ${projectId}`;
  if (command) {
    text += `\nReported command: ${command}`;
  }

  const proc = spawnFn([
    "zenity",
    "--question",
    "--no-markup",
    "--title=gcp-gate: Prod Access",
    `--text=${text}`,
    "--width=500",
    "--timeout=60",
  ]);

  const exitCode = await proc.exited;

  // Exit 0 = approved, exit 1 = denied, exit 5 = timeout (denied)
  // If zenity isn't found, the spawn itself will fail
  if (exitCode === 0) return true;
  if (exitCode === 1 || exitCode === 5) return false;

  // Unexpected exit code — treat as "zenity not available"
  // (e.g., exit 127 = command not found on some systems)
  if (exitCode === 127) return null;
  return false;
}

/** Escape backslashes and double quotes to prevent AppleScript injection. */
function escapeForAppleScript(s: string): string;
function escapeForAppleScript(s: string | undefined): string | undefined;
function escapeForAppleScript(s: string | undefined): string | undefined {
  return s?.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

async function tryOsascript(
  email: string,
  projectId: string,
  spawnFn: SpawnFn,
  command?: string,
  pamPolicy?: string,
): Promise<boolean | null> {
  const escaped = escapeForAppleScript(email);
  const escapedProject = escapeForAppleScript(projectId);
  const escapedCommand = escapeForAppleScript(command);
  const escapedPam = escapeForAppleScript(pamPolicy);

  let message = escapedPam
    ? `Grant prod-level GCP access to ${escaped} via PAM entitlement '${escapedPam}'?`
    : `Grant prod-level GCP access to ${escaped}?`;
  message += `\\n\\nProject: ${escapedProject}`;
  if (escapedCommand) {
    message += `\\nReported command: ${escapedCommand}`;
  }

  const proc = spawnFn([
    "osascript",
    "-e",
    `set r to display dialog "${message}" buttons {"Deny", "Allow"} default button "Deny" with icon caution giving up after 60`,
    "-e",
    'if button returned of r is not "Allow" or gave up of r is true then error "denied"',
  ]);

  const exitCode = await proc.exited;

  // Exit 0 = Allow clicked, exit 1 = Deny/timeout/escape, exit 127 = not found
  if (exitCode === 0) return true;
  if (exitCode === 1) return false;
  if (exitCode === 127) return null;
  return false;
}

async function tryTerminalPrompt(
  email: string,
  projectId: string,
  command?: string,
  pamPolicy?: string,
): Promise<boolean> {
  process.stdout.write(`gcp-gate: Project: ${projectId}\n`);
  if (command) {
    process.stdout.write(`gcp-gate: Reported command: ${command}\n`);
  }
  const pamSuffix = pamPolicy ? ` via PAM entitlement '${pamPolicy}'` : "";
  process.stdout.write(`gcp-gate: Grant prod-level GCP access to ${email}${pamSuffix}? [y/N] `);

  return new Promise<boolean>((resolve) => {
    process.stdin.setRawMode?.(false);
    process.stdin.resume();
    process.stdin.setEncoding("utf-8");

    const timeout = setTimeout(() => {
      process.stdin.pause();
      process.stdin.removeListener("data", onData);
      console.log("\nconfirm: timed out waiting for response, denying prod access");
      resolve(false);
    }, 60_000);

    const onData = (data: string) => {
      clearTimeout(timeout);
      process.stdin.pause();
      process.stdin.removeListener("data", onData);
      const answer = data.toString().trim().toLowerCase();
      resolve(answer === "y" || answer === "yes");
    };

    process.stdin.on("data", onData);
  });
}
