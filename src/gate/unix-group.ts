// ---------------------------------------------------------------------------
// Tiny /etc/group + /etc/passwd parser used by the operator-socket startup
// misconfiguration check.
//
// Bun does not expose getgrnam / getpwnam, and we do not want to pull in a
// native dependency for a one-shot lookup. The format is stable, the files
// are small, and reading them at startup is cheap.
// ---------------------------------------------------------------------------

import { readFileSync } from "node:fs";

export interface GroupEntry {
  name: string;
  gid: number;
  members: string[];
}

export interface PasswdEntry {
  name: string;
  uid: number;
  gid: number;
}

function* iterRecords(content: string): Iterable<string[]> {
  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    yield line.split(":");
  }
}

export function parseGroupFile(content: string): GroupEntry[] {
  const result: GroupEntry[] = [];
  for (const fields of iterRecords(content)) {
    if (fields.length < 4) continue;
    const name = fields[0]!;
    const gidStr = fields[2]!;
    const memberStr = fields[3]!;
    const gid = Number(gidStr);
    if (!Number.isInteger(gid)) continue;
    const members = memberStr === "" ? [] : memberStr.split(",").filter((m) => m !== "");
    result.push({ name, gid, members });
  }
  return result;
}

export function parsePasswdFile(content: string): PasswdEntry[] {
  const result: PasswdEntry[] = [];
  for (const fields of iterRecords(content)) {
    if (fields.length < 4) continue;
    const name = fields[0]!;
    const uid = Number(fields[2]!);
    const gid = Number(fields[3]!);
    if (!Number.isInteger(uid) || !Number.isInteger(gid)) continue;
    result.push({ name, uid, gid });
  }
  return result;
}

/**
 * Snapshot of /etc/group + /etc/passwd. Read once per gate startup and reused
 * across all lookups to avoid re-reading the same files for each check.
 */
export interface UnixGroupDb {
  groups: GroupEntry[];
  passwd: PasswdEntry[];
}

export function loadUnixGroupDb(groupFile = "/etc/group", passwdFile = "/etc/passwd"): UnixGroupDb {
  return {
    groups: parseGroupFile(readFileSync(groupFile, "utf-8")),
    passwd: parsePasswdFile(readFileSync(passwdFile, "utf-8")),
  };
}

export function lookupGroup(name: string, db: UnixGroupDb): GroupEntry | undefined {
  return db.groups.find((g) => g.name === name);
}

/**
 * Resolve a user-supplied agent identifier (numeric UID or username) to a UID.
 * Throws if the username cannot be found in /etc/passwd.
 */
export function resolveAgentUid(value: number | string, db: UnixGroupDb): number {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`agent_uid must be a non-negative integer, got ${value}`);
    }
    return value;
  }
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) {
    return Number(trimmed);
  }
  const entry = db.passwd.find((p) => p.name === trimmed);
  if (!entry) {
    throw new Error(`agent_uid: user '${trimmed}' not found in /etc/passwd`);
  }
  return entry.uid;
}

function findPasswdByUid(uid: number, db: UnixGroupDb): PasswdEntry | undefined {
  return db.passwd.find((p) => p.uid === uid);
}

/**
 * Return all gids the given UID is a member of: primary gid from /etc/passwd
 * plus every supplementary gid where the username appears in /etc/group's
 * member list. Returns an empty array if the UID is not in /etc/passwd.
 */
export function getGroupsForUid(uid: number, db: UnixGroupDb): number[] {
  const user = findPasswdByUid(uid, db);
  if (!user) return [];

  const gids = new Set<number>([user.gid]);
  for (const g of db.groups) {
    if (g.members.includes(user.name)) gids.add(g.gid);
  }
  return [...gids];
}

/**
 * True iff `uid` is in /etc/passwd. NSS-managed (LDAP/SSSD) users are
 * invisible to this parser, which the operator-socket startup check
 * uses to refuse such configurations.
 */
export function isUidInPasswd(uid: number, db: UnixGroupDb): boolean {
  return findPasswdByUid(uid, db) !== undefined;
}
