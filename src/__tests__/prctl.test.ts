import { describe, expect, test } from "bun:test";
import { dlopen, FFIType } from "bun:ffi";
import { setNonDumpable } from "../prctl.ts";

const PR_GET_DUMPABLE = 3;

/** Read the current dumpable flag via prctl(PR_GET_DUMPABLE). */
function getDumpable(): number {
  const libc = dlopen("libc.so.6", {
    prctl: {
      args: [FFIType.i32, FFIType.u64, FFIType.u64, FFIType.u64, FFIType.u64],
      returns: FFIType.i32,
    },
  });
  return libc.symbols.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
}

describe("setNonDumpable", () => {
  if (process.platform !== "linux") {
    test("is a no-op on non-Linux platforms", () => {
      // Should not throw
      setNonDumpable();
    });
  } else {
    test("sets PR_SET_DUMPABLE to 0 on Linux", () => {
      setNonDumpable();
      expect(getDumpable()).toBe(0);
    });

    test("is idempotent (calling twice does not throw)", () => {
      setNonDumpable();
      setNonDumpable();
      expect(getDumpable()).toBe(0);
    });
  }
});
