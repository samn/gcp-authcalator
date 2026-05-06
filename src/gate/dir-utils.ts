import { mkdirSync, lstatSync, chmodSync } from "node:fs";

/**
 * Mode for socket / runtime directories. 0o750 lets a different-UID agent
 * that shares the gate UID's primary group reach the main socket; the kernel
 * still enforces per-socket access via file mode (0o660 main / 0o600 operator
 * in UID mode), so this only affects listdir / traversal, not connect().
 *
 * Carve-out: $XDG_RUNTIME_DIR is system-managed and required to be 0o700 by
 * spec, and is shared with other apps. Don't widen it — group access requires
 * placing the socket path outside $XDG_RUNTIME_DIR.
 */
export function chooseSocketDirMode(dir: string): number {
  return dir === process.env.XDG_RUNTIME_DIR ? 0o700 : 0o750;
}

/**
 * Create `dir` at exactly `mode`, or verify+chmod an existing directory.
 *
 * `mkdirSync({recursive:true,mode})` silently no-ops `mode` on a
 * pre-existing directory, so a loose-perm survivor (attacker pre-create
 * or upgrade leftover) would otherwise pass through unchanged.
 *
 * Throws if `dir` is a symlink, is owned by another uid, or has any
 * permission bits set beyond `mode`.
 */
export function ensurePrivateDir(dir: string, mode: number): void {
  let stat;
  try {
    stat = lstatSync(dir);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    mkdirSync(dir, { recursive: true, mode });
    chmodSync(dir, mode);
    return;
  }

  if (stat.isSymbolicLink()) {
    throw new Error(`directory ${dir} is a symlink — refusing to use`);
  }
  if (!stat.isDirectory()) {
    throw new Error(`path ${dir} exists but is not a directory`);
  }

  const uid = process.getuid?.();
  if (uid !== undefined && stat.uid !== uid) {
    throw new Error(
      `directory ${dir} is owned by uid ${stat.uid}, not the current user (uid ${uid}) — refusing to use`,
    );
  }

  const actualPerms = stat.mode & 0o777;
  if ((actualPerms & ~mode) !== 0) {
    throw new Error(
      `directory ${dir} has permissions ${actualPerms.toString(8)} (octal) which exceed the required ${mode.toString(8)} — chmod or remove and let the daemon recreate it`,
    );
  }

  chmodSync(dir, mode);
}
