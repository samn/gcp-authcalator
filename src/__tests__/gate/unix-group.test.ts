import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  parseGroupFile,
  parsePasswdFile,
  lookupGroup,
  loadUnixGroupDb,
  resolveAgentUid,
  getGroupsForUid,
  isUidInPasswd,
} from "../../gate/unix-group.ts";

describe("parseGroupFile", () => {
  test("parses a simple group", () => {
    const out = parseGroupFile("operators:x:1500:alice,bob\n");
    expect(out).toEqual([{ name: "operators", gid: 1500, members: ["alice", "bob"] }]);
  });

  test("handles empty member list", () => {
    const out = parseGroupFile("empty:x:1600:\n");
    expect(out).toEqual([{ name: "empty", gid: 1600, members: [] }]);
  });

  test("skips blank lines and comments", () => {
    const out = parseGroupFile("\n# a comment\noperators:x:1500:alice\n  \n");
    expect(out.map((g) => g.name)).toEqual(["operators"]);
  });

  test("ignores lines with non-numeric gid", () => {
    const out = parseGroupFile("broken:x:notanumber:alice\nok:x:42:bob\n");
    expect(out.map((g) => g.name)).toEqual(["ok"]);
  });

  test("handles multiple groups", () => {
    const out = parseGroupFile("a:x:1:u1\nb:x:2:u2,u3\nc:x:3:\n");
    expect(out).toEqual([
      { name: "a", gid: 1, members: ["u1"] },
      { name: "b", gid: 2, members: ["u2", "u3"] },
      { name: "c", gid: 3, members: [] },
    ]);
  });
});

describe("parsePasswdFile", () => {
  test("parses uid and primary gid", () => {
    const out = parsePasswdFile("alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\n");
    expect(out).toEqual([{ name: "alice", uid: 1000, gid: 1000 }]);
  });

  test("skips blank lines and comments", () => {
    const out = parsePasswdFile("# comment\n\nbob:x:1001:1001::/home/bob:/bin/sh\n");
    expect(out.map((p) => p.name)).toEqual(["bob"]);
  });
});

function makeDb(opts: { group?: string; passwd?: string } = {}): {
  gf: string;
  pf: string;
  db: ReturnType<typeof loadUnixGroupDb>;
} {
  const dir = mkdtempSync(join(tmpdir(), "ug-"));
  const gf = join(dir, "group");
  const pf = join(dir, "passwd");
  writeFileSync(gf, opts.group ?? "");
  writeFileSync(pf, opts.passwd ?? "");
  return { gf, pf, db: loadUnixGroupDb(gf, pf) };
}

describe("lookupGroup", () => {
  test("finds group by name", () => {
    const { db } = makeDb({ group: "ops:x:2000:alice\nother:x:2001:bob\n" });
    expect(lookupGroup("ops", db)).toEqual({ name: "ops", gid: 2000, members: ["alice"] });
  });

  test("returns undefined when missing", () => {
    const { db } = makeDb({ group: "other:x:2001:bob\n" });
    expect(lookupGroup("ops", db)).toBeUndefined();
  });
});

describe("resolveAgentUid", () => {
  const emptyDb = { groups: [], passwd: [] };

  test("returns numeric UID directly", () => {
    expect(resolveAgentUid(1001, emptyDb)).toBe(1001);
  });

  test("parses numeric strings", () => {
    expect(resolveAgentUid("1001", emptyDb)).toBe(1001);
  });

  test("looks up username in /etc/passwd", () => {
    const { db } = makeDb({ passwd: "claude:x:1500:1500::/home/claude:/bin/sh\n" });
    expect(resolveAgentUid("claude", db)).toBe(1500);
  });

  test("throws when user is not found", () => {
    const { db } = makeDb({ passwd: "alice:x:1000:1000::/home/alice:/bin/sh\n" });
    expect(() => resolveAgentUid("missing", db)).toThrow(/not found/);
  });

  test("throws on negative integer", () => {
    expect(() => resolveAgentUid(-1, emptyDb)).toThrow(/non-negative/);
  });
});

describe("getGroupsForUid", () => {
  test("returns primary plus supplementary gids", () => {
    const { db } = makeDb({
      passwd: "alice:x:1000:1000::/home/alice:/bin/sh\n",
      group: "alice:x:1000:\nops:x:2000:alice,bob\nextra:x:2001:alice\n",
    });
    expect(getGroupsForUid(1000, db).sort()).toEqual([1000, 2000, 2001]);
  });

  test("returns only primary gid when no supplementary memberships", () => {
    const { db } = makeDb({
      passwd: "alice:x:1000:1000::/home/alice:/bin/sh\n",
      group: "ops:x:2000:bob\n",
    });
    expect(getGroupsForUid(1000, db)).toEqual([1000]);
  });

  test("returns empty array when uid not in passwd", () => {
    const { db } = makeDb({
      passwd: "alice:x:1000:1000::/home/alice:/bin/sh\n",
      group: "ops:x:2000:alice\n",
    });
    expect(getGroupsForUid(9999, db)).toEqual([]);
  });

  test("does not double-count primary gid in supplementary list", () => {
    const { db } = makeDb({
      passwd: "alice:x:1000:1000::/home/alice:/bin/sh\n",
      group: "alice:x:1000:alice\nops:x:2000:alice\n",
    });
    expect(getGroupsForUid(1000, db).sort()).toEqual([1000, 2000]);
  });
});

describe("isUidInPasswd", () => {
  test("returns true when uid is present in /etc/passwd", () => {
    const { db } = makeDb({
      passwd: "alice:x:1000:1000::/home/alice:/bin/sh\n",
    });
    expect(isUidInPasswd(1000, db)).toBe(true);
  });

  test("returns false when uid is not in /etc/passwd (e.g. NSS-managed)", () => {
    const { db } = makeDb({
      passwd: "alice:x:1000:1000::/home/alice:/bin/sh\n",
    });
    expect(isUidInPasswd(9999, db)).toBe(false);
  });

  test("returns false when /etc/passwd is empty", () => {
    const { db } = makeDb({});
    expect(isUidInPasswd(1000, db)).toBe(false);
  });
});
