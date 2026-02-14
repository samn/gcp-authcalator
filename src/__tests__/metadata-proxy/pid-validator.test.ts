import { describe, expect, test } from "bun:test";
import { getOwnerPid, isDescendantOf, type ProcFS } from "../../metadata-proxy/pid-validator.ts";

// ---------------------------------------------------------------------------
// Helpers to build fake /proc data
// ---------------------------------------------------------------------------

/** Realistic /proc/net/tcp header */
const TCP_HEADER =
  "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

/** Build a /proc/net/tcp line. port and inode are decimal, IP is always 127.0.0.1. */
function tcpLine(slot: number, port: number, inode: number): string {
  const portHex = port.toString(16).toUpperCase().padStart(4, "0");
  // 127.0.0.1 in little-endian hex = 0100007F
  return `   ${slot}: 0100007F:${portHex} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 ${inode} 1 0000000000000000 100 0 0 10 0`;
}

const TCP6_HEADER =
  "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

/** Build a /proc/net/tcp6 line for IPv4-mapped 127.0.0.1. */
function tcp6Line(slot: number, port: number, inode: number): string {
  const portHex = port.toString(16).toUpperCase().padStart(4, "0");
  return `   ${slot}: 0000000000000000FFFF00000100007F:${portHex} 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 ${inode} 1 0000000000000000 100 0 0 10 0`;
}

/** Build a /proc/<pid>/status string with given PPid. */
function statusFile(ppid: number): string {
  return `Name:\ttest\nPid:\t100\nPPid:\t${ppid}\nTracerPid:\t0\n`;
}

/**
 * Create a fake ProcFS from a simple description of the process tree and sockets.
 *
 * `sockets` maps "tcp"|"tcp6" → array of {port, inode}
 * `pids` maps pid → { ppid, fds: Map<fdNum, symlinkTarget> }
 */
function fakeProcFS(opts: {
  sockets?: { file: "tcp" | "tcp6"; port: number; inode: number }[];
  pids?: Map<number, { ppid: number; fds?: Map<string, string> }>;
}): ProcFS {
  const sockets = opts.sockets ?? [];
  const pids = opts.pids ?? new Map();

  // Build /proc/net/tcp and /proc/net/tcp6 content
  const tcpLines = sockets.filter((s) => s.file === "tcp");
  const tcp6Lines = sockets.filter((s) => s.file === "tcp6");

  const tcpContent =
    TCP_HEADER + "\n" + tcpLines.map((s, i) => tcpLine(i, s.port, s.inode)).join("\n") + "\n";
  const tcp6Content =
    TCP6_HEADER + "\n" + tcp6Lines.map((s, i) => tcp6Line(i, s.port, s.inode)).join("\n") + "\n";

  return {
    readFileSync(path: string): string {
      if (path === "/proc/net/tcp") return tcpContent;
      if (path === "/proc/net/tcp6") return tcp6Content;
      // /proc/<pid>/status
      const statusMatch = path.match(/^\/proc\/(\d+)\/status$/);
      if (statusMatch) {
        const pid = parseInt(statusMatch[1]!, 10);
        const info = pids.get(pid);
        if (!info) throw new Error("ENOENT");
        return statusFile(info.ppid);
      }
      throw new Error("ENOENT");
    },
    readdirSync(path: string): string[] {
      if (path === "/proc") {
        return [...pids.keys()].map(String);
      }
      const fdMatch = path.match(/^\/proc\/(\d+)\/fd$/);
      if (fdMatch) {
        const pid = parseInt(fdMatch[1]!, 10);
        const info = pids.get(pid);
        if (!info?.fds) throw new Error("ENOENT");
        return [...info.fds.keys()];
      }
      throw new Error("ENOENT");
    },
    readlinkSync(path: string): string {
      const linkMatch = path.match(/^\/proc\/(\d+)\/fd\/(.+)$/);
      if (linkMatch) {
        const pid = parseInt(linkMatch[1]!, 10);
        const fd = linkMatch[2]!;
        const info = pids.get(pid);
        const target = info?.fds?.get(fd);
        if (target) return target;
      }
      throw new Error("ENOENT");
    },
  };
}

// ---------------------------------------------------------------------------
// getOwnerPid
// ---------------------------------------------------------------------------

describe("getOwnerPid", () => {
  test("finds PID via /proc/net/tcp (IPv4)", () => {
    const fs = fakeProcFS({
      sockets: [{ file: "tcp", port: 8080, inode: 12345 }],
      pids: new Map([[42, { ppid: 1, fds: new Map([["3", "socket:[12345]"]]) }]]),
    });
    expect(getOwnerPid(8080, fs)).toBe(42);
  });

  test("finds PID via /proc/net/tcp6 (IPv4-mapped IPv6)", () => {
    const fs = fakeProcFS({
      sockets: [{ file: "tcp6", port: 9090, inode: 67890 }],
      pids: new Map([[99, { ppid: 1, fds: new Map([["5", "socket:[67890]"]]) }]]),
    });
    expect(getOwnerPid(9090, fs)).toBe(99);
  });

  test("prefers tcp over tcp6 when both match", () => {
    const fs = fakeProcFS({
      sockets: [
        { file: "tcp", port: 3000, inode: 111 },
        { file: "tcp6", port: 3000, inode: 222 },
      ],
      pids: new Map([
        [10, { ppid: 1, fds: new Map([["3", "socket:[111]"]]) }],
        [20, { ppid: 1, fds: new Map([["3", "socket:[222]"]]) }],
      ]),
    });
    expect(getOwnerPid(3000, fs)).toBe(10);
  });

  test("returns null when port not found in either tcp file", () => {
    const fs = fakeProcFS({
      sockets: [{ file: "tcp", port: 8080, inode: 100 }],
      pids: new Map([[42, { ppid: 1, fds: new Map([["3", "socket:[100]"]]) }]]),
    });
    expect(getOwnerPid(9999, fs)).toBeNull();
  });

  test("returns null when inode found but no PID owns it", () => {
    const fs = fakeProcFS({
      sockets: [{ file: "tcp", port: 8080, inode: 12345 }],
      pids: new Map([[42, { ppid: 1, fds: new Map([["3", "socket:[99999]"]]) }]]),
    });
    expect(getOwnerPid(8080, fs)).toBeNull();
  });

  test("returns null when /proc/net/tcp is unreadable", () => {
    const fs: ProcFS = {
      readFileSync() {
        throw new Error("EACCES");
      },
      readdirSync() {
        return [];
      },
      readlinkSync() {
        throw new Error("ENOENT");
      },
    };
    expect(getOwnerPid(8080, fs)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// isDescendantOf
// ---------------------------------------------------------------------------

describe("isDescendantOf", () => {
  test("returns true when pid equals ancestorPid", () => {
    const fs = fakeProcFS({ pids: new Map() });
    expect(isDescendantOf(100, 100, fs)).toBe(true);
  });

  test("returns true for direct child", () => {
    const fs = fakeProcFS({
      pids: new Map([[200, { ppid: 100 }]]),
    });
    expect(isDescendantOf(200, 100, fs)).toBe(true);
  });

  test("returns true for deep descendant", () => {
    const fs = fakeProcFS({
      pids: new Map([
        [400, { ppid: 300 }],
        [300, { ppid: 200 }],
        [200, { ppid: 100 }],
      ]),
    });
    expect(isDescendantOf(400, 100, fs)).toBe(true);
  });

  test("returns false when pid is not a descendant", () => {
    const fs = fakeProcFS({
      pids: new Map([
        [200, { ppid: 100 }],
        [300, { ppid: 50 }],
      ]),
    });
    expect(isDescendantOf(300, 100, fs)).toBe(false);
  });

  test("returns false when pid is an ancestor (not descendant) of target", () => {
    const fs = fakeProcFS({
      pids: new Map([[200, { ppid: 100 }]]),
    });
    expect(isDescendantOf(100, 200, fs)).toBe(false);
  });

  test("returns false for PID 1 (init) when ancestor is not 1", () => {
    const fs = fakeProcFS({
      pids: new Map([[2, { ppid: 1 }]]),
    });
    // PID 2's parent is 1, but we're looking for ancestor 999
    expect(isDescendantOf(2, 999, fs)).toBe(false);
  });

  test("handles missing /proc/<pid>/status gracefully", () => {
    // PID 500 exists but its parent PID 400 has no status file
    const fs = fakeProcFS({
      pids: new Map([
        [500, { ppid: 400 }],
        // 400 is not in the map, so readFileSync will throw
      ]),
    });
    expect(isDescendantOf(500, 100, fs)).toBe(false);
  });
});
