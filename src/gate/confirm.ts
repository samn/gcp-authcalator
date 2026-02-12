import type { Subprocess } from "bun";

type SpawnFn = (cmd: string[], opts?: { stdin?: "pipe" | "inherit" }) => Subprocess;

export interface ConfirmOptions {
  /** Override Bun.spawn for testing. */
  spawn?: SpawnFn;
}

/**
 * Create a confirmation module for prod token access.
 *
 * Primary: zenity GUI dialog with 60s timeout.
 * Fallback: terminal prompt on stdin (if TTY).
 * Default: deny if no interactive method is available.
 */
export function createConfirmModule(options: ConfirmOptions = {}): {
  confirmProdAccess: (email: string) => Promise<boolean>;
} {
  const spawnFn = options.spawn ?? (Bun.spawn as unknown as SpawnFn);

  async function confirmProdAccess(email: string): Promise<boolean> {
    // Try zenity first
    try {
      const result = await tryZenity(email, spawnFn);
      if (result !== null) return result;
    } catch {
      // zenity not available, fall through to terminal
    }

    // Fallback to terminal prompt
    return tryTerminalPrompt(email);
  }

  return { confirmProdAccess };
}

async function tryZenity(email: string, spawnFn: SpawnFn): Promise<boolean | null> {
  const proc = spawnFn([
    "zenity",
    "--question",
    "--title=gcp-gate: Prod Access",
    `--text=Grant prod-level GCP access to ${email}?`,
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

async function tryTerminalPrompt(email: string): Promise<boolean> {
  // Check if stdin is a TTY
  if (!process.stdin.isTTY) {
    console.error("confirm: no interactive method available, denying prod access");
    return false;
  }

  process.stdout.write(`gcp-gate: Grant prod-level GCP access to ${email}? [y/N] `);

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
