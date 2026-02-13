// ---------------------------------------------------------------------------
// PID-based caller validation for the metadata proxy.
//
// Ensures that only processes in the with-prod process tree can request tokens.
// Works by mapping a TCP connection's local port → owning PID via /proc,
// then walking the PPid chain to verify ancestry.
// ---------------------------------------------------------------------------

import { readFileSync, readdirSync, readlinkSync } from "node:fs";

/**
 * Given a local TCP port, find the PID that owns the socket.
 *
 * 1. Parse /proc/net/tcp to find the socket inode for the given local port
 * 2. Scan /proc/{pid}/fd/ symlinks to find which PID holds that inode
 */
export function getOwnerPid(localPort: number): number | null {
  // Step 1: Find the socket inode from /proc/net/tcp
  const inode = findSocketInode(localPort);
  if (inode === null) return null;

  // Step 2: Find the PID owning that inode
  return findPidByInode(inode);
}

/**
 * Check whether `pid` is a descendant of `ancestorPid` by walking the
 * PPid chain in /proc/<pid>/status.
 *
 * Returns true if pid == ancestorPid or if any ancestor of pid == ancestorPid.
 */
export function isDescendantOf(pid: number, ancestorPid: number): boolean {
  let current = pid;
  // Limit iterations to prevent infinite loops on broken /proc
  const maxDepth = 256;

  for (let i = 0; i < maxDepth; i++) {
    if (current === ancestorPid) return true;
    if (current <= 1) return false;

    const ppid = getParentPid(current);
    if (ppid === null || ppid === current) return false;
    current = ppid;
  }

  return false;
}

/**
 * Parse /proc/net/tcp to find the inode of the socket bound to the given
 * local port on 127.0.0.1.
 *
 * /proc/net/tcp format (whitespace-delimited):
 *   sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
 *
 * local_address is hex IP:hex port (e.g., "0100007F:1F90" = 127.0.0.1:8080)
 */
function findSocketInode(localPort: number): number | null {
  let data: string;
  try {
    data = readFileSync("/proc/net/tcp", "utf-8");
  } catch {
    return null;
  }

  // Port as 4-digit uppercase hex
  const portHex = localPort.toString(16).toUpperCase().padStart(4, "0");
  // 127.0.0.1 in little-endian hex
  const localAddrTarget = `0100007F:${portHex}`;

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
function findPidByInode(inode: number): number | null {
  const target = `socket:[${inode}]`;
  let entries: string[];

  try {
    entries = readdirSync("/proc");
  } catch {
    return null;
  }

  for (const entry of entries) {
    // Only numeric directories (PIDs)
    const pid = parseInt(entry, 10);
    if (isNaN(pid)) continue;

    let fds: string[];
    try {
      fds = readdirSync(`/proc/${pid}/fd`);
    } catch {
      // Permission denied or process gone — skip
      continue;
    }

    for (const fd of fds) {
      try {
        const link = readlinkSync(`/proc/${pid}/fd/${fd}`);
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
function getParentPid(pid: number): number | null {
  try {
    const data = readFileSync(`/proc/${pid}/status`, "utf-8");
    const match = data.match(/^PPid:\s*(\d+)/m);
    if (!match?.[1]) return null;
    return parseInt(match[1], 10);
  } catch {
    return null;
  }
}
