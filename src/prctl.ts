import { dlopen, FFIType } from "bun:ffi";

const PR_SET_DUMPABLE = 4;

/**
 * Mark the current process as non-dumpable via prctl(PR_SET_DUMPABLE, 0).
 *
 * This prevents other users from reading /proc/<pid>/environ and blocks
 * ptrace attachment (except by root), protecting in-memory secrets such as
 * short-lived access tokens.
 *
 * Linux-only — returns silently on other platforms.
 */
export function setNonDumpable(): void {
  if (process.platform !== "linux") return;

  const libc = dlopen("libc.so.6", {
    prctl: {
      args: [FFIType.i32, FFIType.u64, FFIType.u64, FFIType.u64, FFIType.u64],
      returns: FFIType.i32,
    },
  });

  const result = libc.symbols.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  if (result !== 0) {
    throw new Error(`prctl(PR_SET_DUMPABLE, 0) failed with return code ${result}`);
  }
}
