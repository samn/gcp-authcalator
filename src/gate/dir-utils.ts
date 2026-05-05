// ---------------------------------------------------------------------------
// Directory permission helpers.
//
// `mkdirSync({ recursive: true, mode })` is silently a no-op on existing
// directories — its mode argument is only honoured when the directory is
// freshly created. That means a hostile pre-create with loose permissions
// (or perms inherited from an earlier version of the daemon) survives
// across restarts. The operator-socket trust boundary depends on these
// dir permissions, so the audit recommended verifying-and-tightening at
// every site where the daemon expects a `0o700`-class private directory.
// ---------------------------------------------------------------------------

import { mkdirSync, lstatSync, chmodSync } from "node:fs";

/**
 * Create `dir` with the given mode if absent; otherwise verify the
 * existing directory is owned by the current uid, is not a symlink, and
 * has no permission bits set beyond `mode`. Always re-chmods the
 * directory to exactly `mode` as defense-in-depth.
 *
 * Throws if:
 *   - `dir` exists and is a symlink (refuses to follow attacker-planted
 *     redirects),
 *   - `dir` exists and is not a directory,
 *   - `dir` exists and is owned by a different uid than the current
 *     process,
 *   - `dir` exists with permission bits that exceed `mode` (e.g. caller
 *     asked for `0o700` but the dir is `0o755`).
 *
 * Used at every gate-side `mkdirSync` for socket dirs, the audit log
 * dir, the with-prod runtime dir, and the TLS dir.
 */
export function ensurePrivateDir(dir: string, mode: number): void {
  let stat;
  try {
    stat = lstatSync(dir);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
    // Doesn't exist — create it (recursive so intermediate path components
    // are created too).
    mkdirSync(dir, { recursive: true, mode });
    // Re-chmod in case the parent's umask masked off bits we want set,
    // or `recursive: true` created intermediate components without our
    // mode (Node only applies the mode to the last component).
    chmodSync(dir, mode);
    return;
  }

  if (stat.isSymbolicLink()) {
    throw new Error(
      `directory ${dir} is a symlink — refusing to use; remove or replace with a real directory`,
    );
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

  // stat.mode includes the file type bits in the high nibble; mask them
  // off before comparing with the requested mode.
  const actualPerms = stat.mode & 0o777;
  if ((actualPerms & ~mode) !== 0) {
    throw new Error(
      `directory ${dir} has permissions ${actualPerms.toString(8)} (octal) which exceed the required ${mode.toString(8)} — refusing to use; chmod to ${mode.toString(8)} or remove and let the daemon recreate it`,
    );
  }

  // Tighten to exactly `mode` (e.g. if the dir was `0o700` but mode is
  // `0o750`, leave it; if it was `0o600`, raise to `0o700` to grant
  // the owner traversal rights). We've already rejected anything looser
  // than `mode`, so this is always a tightening or a re-set to identical
  // bits.
  chmodSync(dir, mode);
}
