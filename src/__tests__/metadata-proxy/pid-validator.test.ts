import { describe, expect, test } from "bun:test";
import { getOwnerPid, isDescendantOf, type ProcFS } from "../../metadata-proxy/pid-validator.ts";

// ---------------------------------------------------------------------------
// Helpers to build fake /proc data
// ---------------------------------------------------------------------------

/**
 * The proxy's own listen port used across these tests. getOwnerPid matches the
 * caller socket's rem_address against the proxy, so sockets default to being
 * connected to this port (the realistic case).
 */
const PROXY_PORT = 8173;

function portHex(port: number): string {
  return port.toString(16).toUpperCase().padStart(4, "0");
}

/** Build the rem_address hex ("IP:port") for 127.0.0.1:port (IPv4 /proc/net/tcp). */
function rem4(port: number): string {
  return `0100007F:${portHex(port)}`;
}

/** Build the rem_address hex for IPv4-mapped 127.0.0.1:port (/proc/net/tcp6). */
function rem6(port: number): string {
  return `0000000000000000FFFF00000100007F:${portHex(port)}`;
}

/** Realistic /proc/net/tcp header */
const TCP_HEADER =
  "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

/**
 * Build a /proc/net/tcp line. port and inode are decimal, IP is always
 * 127.0.0.1. State defaults to "01" (TCP_ESTABLISHED) — the validator
 * filters out non-ESTABLISHED rows. `rem` is the rem_address field
 * (hex "IP:port"), defaulting to the proxy (the realistic caller socket).
 */
function tcpLine(
  slot: number,
  port: number,
  inode: number,
  state: string = "01",
  rem: string = rem4(PROXY_PORT),
): string {
  // 127.0.0.1 in little-endian hex = 0100007F
  return `   ${slot}: 0100007F:${portHex(port)} ${rem} ${state} 00000000:00000000 00:00000000 00000000     0        0 ${inode} 1 0000000000000000 100 0 0 10 0`;
}

const TCP6_HEADER =
  "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

/** Build a /proc/net/tcp6 line for IPv4-mapped 127.0.0.1. */
function tcp6Line(
  slot: number,
  port: number,
  inode: number,
  state: string = "01",
  rem: string = rem6(PROXY_PORT),
): string {
  return `   ${slot}: 0000000000000000FFFF00000100007F:${portHex(port)} ${rem} ${state} 00000000:00000000 00:00000000 00000000     0        0 ${inode} 1 0000000000000000 100 0 0 10 0`;
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
  sockets?: { file: "tcp" | "tcp6"; port: number; inode: number; state?: string; rem?: string }[];
  pids?: Map<number, { ppid: number; fds?: Map<string, string> }>;
}): ProcFS {
  const sockets = opts.sockets ?? [];
  const pids = opts.pids ?? new Map();

  // Build /proc/net/tcp and /proc/net/tcp6 content
  const tcpLines = sockets.filter((s) => s.file === "tcp");
  const tcp6Lines = sockets.filter((s) => s.file === "tcp6");

  const tcpContent =
    TCP_HEADER +
    "\n" +
    tcpLines.map((s, i) => tcpLine(i, s.port, s.inode, s.state, s.rem)).join("\n") +
    "\n";
  const tcp6Content =
    TCP6_HEADER +
    "\n" +
    tcp6Lines.map((s, i) => tcp6Line(i, s.port, s.inode, s.state, s.rem)).join("\n") +
    "\n";

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
    expect(getOwnerPid(8080, PROXY_PORT, fs)).toBe(42);
  });

  test("finds PID via /proc/net/tcp6 (IPv4-mapped IPv6)", () => {
    const fs = fakeProcFS({
      sockets: [{ file: "tcp6", port: 9090, inode: 67890 }],
      pids: new Map([[99, { ppid: 1, fds: new Map([["5", "socket:[67890]"]]) }]]),
    });
    expect(getOwnerPid(9090, PROXY_PORT, fs)).toBe(99);
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
    expect(getOwnerPid(3000, PROXY_PORT, fs)).toBe(10);
  });

  test("returns null when port not found in either tcp file", () => {
    const fs = fakeProcFS({
      sockets: [{ file: "tcp", port: 8080, inode: 100 }],
      pids: new Map([[42, { ppid: 1, fds: new Map([["3", "socket:[100]"]]) }]]),
    });
    expect(getOwnerPid(9999, PROXY_PORT, fs)).toBeNull();
  });

  test("returns null when caller socket is connected to a different remote, not the proxy", () => {
    // Same local port and ESTABLISHED, but the only matching socket connects
    // somewhere other than the proxy → must not be attributed to any PID.
    const fs = fakeProcFS({
      sockets: [{ file: "tcp", port: 8080, inode: 100, rem: rem4(9999) }],
      pids: new Map([[42, { ppid: 1, fds: new Map([["3", "socket:[100]"]]) }]]),
    });
    expect(getOwnerPid(8080, PROXY_PORT, fs)).toBeNull();
  });

  test("returns null when inode found but no PID owns it", () => {
    const fs = fakeProcFS({
      sockets: [{ file: "tcp", port: 8080, inode: 12345 }],
      pids: new Map([[42, { ppid: 1, fds: new Map([["3", "socket:[99999]"]]) }]]),
    });
    expect(getOwnerPid(8080, PROXY_PORT, fs)).toBeNull();
  });

  test("returns null when /proc readdir fails", () => {
    const fs: ProcFS = {
      readFileSync(path: string) {
        // An ESTABLISHED socket connected to the proxy exists, so its inode is
        // found — but /proc can't be listed to map the inode → PID.
        if (path === "/proc/net/tcp") return `${TCP_HEADER}\n${tcpLine(0, 8080, 55555)}\n`;
        if (path === "/proc/net/tcp6") return `${TCP6_HEADER}\n`;
        throw new Error("ENOENT");
      },
      readdirSync() {
        throw new Error("EACCES");
      },
      readlinkSync() {
        throw new Error("ENOENT");
      },
    };
    expect(getOwnerPid(8080, PROXY_PORT, fs)).toBeNull();
  });

  test("skips PIDs with unreadable fd directories", () => {
    // Create a scenario where the first PID's fd dir throws but a second PID succeeds
    const fs = fakeProcFS({
      sockets: [{ file: "tcp", port: 7070, inode: 44444 }],
      pids: new Map([
        [10, { ppid: 1 }], // no fds → will throw ENOENT on readdirSync
        [20, { ppid: 1, fds: new Map([["4", "socket:[44444]"]]) }],
      ]),
    });
    expect(getOwnerPid(7070, PROXY_PORT, fs)).toBe(20);
  });

  test("ignores TCP_LISTEN rows (state 0A)", () => {
    const fs = fakeProcFS({
      sockets: [
        // First row: a LISTEN socket on the same port → must be skipped.
        { file: "tcp", port: 8080, inode: 100, state: "0A" },
        // Second row: an ESTABLISHED connection → this is the one we want.
        { file: "tcp", port: 8080, inode: 200, state: "01" },
      ],
      pids: new Map([
        [10, { ppid: 1, fds: new Map([["3", "socket:[100]"]]) }],
        [42, { ppid: 1, fds: new Map([["3", "socket:[200]"]]) }],
      ]),
    });
    expect(getOwnerPid(8080, PROXY_PORT, fs)).toBe(42);
  });

  test("ignores TCP_TIME_WAIT rows (state 06)", () => {
    const fs = fakeProcFS({
      sockets: [
        { file: "tcp", port: 9000, inode: 100, state: "06" },
        { file: "tcp", port: 9000, inode: 200, state: "01" },
      ],
      pids: new Map([
        [10, { ppid: 1, fds: new Map([["3", "socket:[100]"]]) }],
        [42, { ppid: 1, fds: new Map([["3", "socket:[200]"]]) }],
      ]),
    });
    expect(getOwnerPid(9000, PROXY_PORT, fs)).toBe(42);
  });

  test("returns null when only LISTEN rows match the port", () => {
    const fs = fakeProcFS({
      sockets: [{ file: "tcp", port: 8080, inode: 100, state: "0A" }],
      pids: new Map([[10, { ppid: 1, fds: new Map([["3", "socket:[100]"]]) }]]),
    });
    expect(getOwnerPid(8080, PROXY_PORT, fs)).toBeNull();
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
    expect(getOwnerPid(8080, PROXY_PORT, fs)).toBeNull();
  });

  // Finding #3: a local TCP source port is unique only as part of the full
  // 4-tuple. The validator must attribute a connection to the process whose
  // socket is actually connected to the proxy (rem_address == proxy), not just
  // any ESTABLISHED socket sharing the local port. Matching on local port alone
  // would let an unrelated socket be misattributed and bypass the gate.
  test("attributes the connection to the socket connected to the proxy, not an unrelated socket sharing the local port", () => {
    const clientPort = 40000;

    const fs = fakeProcFS({
      sockets: [
        // First row: an AUTHORIZED descendant's unrelated outbound connection
        // that happens to use the same local port, but to a DIFFERENT remote.
        { file: "tcp", port: clientPort, inode: 1111, rem: rem4(9999) },
        // Second row: the ATTACKER's actual connection to the proxy. Its
        // rem_address IS the proxy — this is the socket that sent the request.
        { file: "tcp", port: clientPort, inode: 2222, rem: rem4(PROXY_PORT) },
      ],
      pids: new Map([
        // Authorized process (would pass the ancestry check downstream).
        [5000, { ppid: 1, fds: new Map([["3", "socket:[1111]"]]) }],
        // Attacker process (NOT a with-prod descendant).
        [6000, { ppid: 1, fds: new Map([["3", "socket:[2222]"]]) }],
      ]),
    });

    // Only the socket whose rem_address is the proxy is the true owner (PID
    // 6000). Matching on local port alone would return the first row (PID
    // 5000), misattributing the attacker's request to an authorized process.
    expect(getOwnerPid(clientPort, PROXY_PORT, fs)).toBe(6000);
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

  test("returns false when max depth is exceeded (circular parentage)", () => {
    // Build a chain longer than 256 entries that never reaches the ancestor.
    // We simulate a pathological case where every pid's parent is pid+1,
    // forming a very long chain away from the target ancestor.
    const pids = new Map<number, { ppid: number }>();
    for (let i = 1000; i < 1300; i++) {
      pids.set(i, { ppid: i + 1 });
    }
    // Close the loop so it never terminates naturally
    pids.set(1300, { ppid: 1000 });

    const fs = fakeProcFS({ pids });
    expect(isDescendantOf(1000, 9999, fs)).toBe(false);
  });

  test("returns false when ppid equals current pid (self-referencing)", () => {
    const fs = fakeProcFS({
      pids: new Map([[500, { ppid: 500 }]]),
    });
    expect(isDescendantOf(500, 100, fs)).toBe(false);
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
