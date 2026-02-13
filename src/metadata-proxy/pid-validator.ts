// ---------------------------------------------------------------------------
// PID-based caller validation for the metadata proxy.
//
// Ensures that only processes in the with-prod process tree can request tokens.
// Works by mapping a TCP connection's local port → owning PID via /proc,
// then walking the PPid chain to verify ancestry.
// ---------------------------------------------------------------------------

import { readFileSync, readdirSync, readlinkSync } from "node:fs";

/** Abstraction over filesystem calls so tests can provide fake /proc data. */
export interface ProcFS {
  readFileSync(path: string): string;
  readdirSync(path: string): string[];
  readlinkSync(path: string): string;
}

const defaultProcFS: ProcFS = {
  readFileSync: (path) => readFileSync(path, "utf-8"),
  readdirSync: (path) => readdirSync(path),
  readlinkSync: (path) => readlinkSync(path),
};

/**
 * Given a local TCP port, find the PID that owns the socket.
 *
 * 1. Parse /proc/net/tcp and /proc/net/tcp6 to find the socket inode for the given local port
 * 2. Scan /proc/{pid}/fd/ symlinks to find which PID holds that inode
 */
export function getOwnerPid(localPort: number, fs: ProcFS = defaultProcFS): number | null {
  const inode = findSocketInode(localPort, fs);
  if (inode === null) return null;
  return findPidByInode(inode, fs);
}

/**
 * Check whether `pid` is a descendant of `ancestorPid` by walking the
 * PPid chain in /proc/<pid>/status.
 *
 * Returns true if pid == ancestorPid or if any ancestor of pid == ancestorPid.
 */
export function isDescendantOf(
  pid: number,
  ancestorPid: number,
  fs: ProcFS = defaultProcFS,
): boolean {
  let current = pid;
  // Limit iterations to prevent infinite loops on broken /proc
  const maxDepth = 256;

  for (let i = 0; i < maxDepth; i++) {
    if (current === ancestorPid) return true;
    if (current <= 1) return false;

    const ppid = getParentPid(current, fs);
    if (ppid === null || ppid === current) return false;
    current = ppid;
  }

  return false;
}

/**
 * Parse /proc/net/tcp and /proc/net/tcp6 to find the inode of the socket
 * bound to the given local port on 127.0.0.1.
 *
 * /proc/net/tcp format (whitespace-delimited):
 *   sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
 *
 * local_address is hex IP:hex port (e.g., "0100007F:1F90" = 127.0.0.1:8080)
 *
 * /proc/net/tcp6 uses 128-bit addresses. 127.0.0.1 appears as the
 * IPv4-mapped IPv6 address: 0000000000000000FFFF00000100007F
 */
function findSocketInode(localPort: number, fs: ProcFS): number | null {
  const portHex = localPort.toString(16).toUpperCase().padStart(4, "0");

  // Try /proc/net/tcp first (IPv4), then /proc/net/tcp6 (IPv6 / IPv4-mapped)
  const targets: [string, string][] = [
    ["/proc/net/tcp", `0100007F:${portHex}`],
    ["/proc/net/tcp6", `0000000000000000FFFF00000100007F:${portHex}`],
  ];

  for (const [path, localAddrTarget] of targets) {
    const inode = findInodeInFile(path, localAddrTarget, fs);
    if (inode !== null) return inode;
  }

  return null;
}

function findInodeInFile(path: string, localAddrTarget: string, fs: ProcFS): number | null {
  let data: string;
  try {
    data = fs.readFileSync(path);
  } catch {
    return null;
  }

  const lines = data.split("\n");
  // Skip header line
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const fields = line.trim().split(/\s+/);
    if (fields.length < 10) continue;

    const localAddr = fields[1]!.toUpperCase();
    if (localAddr === localAddrTarget) {
      const inode = parseInt(fields[9]!, 10);
      return isNaN(inode) ? null : inode;
    }
  }

  return null;
}

/**
 * Scan /proc/{pid}/fd/ to find which PID owns a socket with the given inode.
 * Socket fd symlinks look like: socket:[12345]
 */
function findPidByInode(inode: number, fs: ProcFS): number | null {
  const target = `socket:[${inode}]`;
  let entries: string[];

  try {
    entries = fs.readdirSync("/proc");
  } catch {
    return null;
  }

  for (const entry of entries) {
    // Only numeric directories (PIDs)
    const pid = parseInt(entry, 10);
    if (isNaN(pid)) continue;

    let fds: string[];
    try {
      fds = fs.readdirSync(`/proc/${pid}/fd`);
    } catch {
      // Permission denied or process gone — skip
      continue;
    }

    for (const fd of fds) {
      try {
        const link = fs.readlinkSync(`/proc/${pid}/fd/${fd}`);
        if (link === target) return pid;
      } catch {
        continue;
      }
    }
  }

  return null;
}

/**
 * Read the PPid field from /proc/<pid>/status.
 */
function getParentPid(pid: number, fs: ProcFS): number | null {
  try {
    const data = fs.readFileSync(`/proc/${pid}/status`);
    const match = data.match(/^PPid:\s*(\d+)/m);
    if (!match?.[1]) return null;
    return parseInt(match[1], 10);
  } catch {
    return null;
  }
}
