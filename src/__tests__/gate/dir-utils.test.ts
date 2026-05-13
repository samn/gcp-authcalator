import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, chmodSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ensurePrivateDir } from "../../gate/dir-utils.ts";

describe("ensurePrivateDir", () => {
  test("creates a missing directory at the requested mode", () => {
    const parent = mkdtempSync(join(tmpdir(), "epd-"));
    const target = join(parent, "private");

    ensurePrivateDir(target, 0o700);

    const stat = statSync(target);
    expect(stat.isDirectory()).toBe(true);
    expect(stat.mode & 0o777).toBe(0o700);
  });

  test("creates intermediate path components", () => {
    const parent = mkdtempSync(join(tmpdir(), "epd-"));
    const target = join(parent, "a", "b", "c");

    ensurePrivateDir(target, 0o700);

    expect(statSync(target).isDirectory()).toBe(true);
  });

  test("accepts an existing directory at the requested mode", () => {
    const parent = mkdtempSync(join(tmpdir(), "epd-"));
    const target = join(parent, "p");
    mkdirSync(target, { mode: 0o700 });
    chmodSync(target, 0o700); // mkdirSync mode is masked by umask; force exact

    expect(() => ensurePrivateDir(target, 0o700)).not.toThrow();
    expect(statSync(target).mode & 0o777).toBe(0o700);
  });

  test("accepts an existing directory tighter than the requested mode and tightens to mode", () => {
    // 0o600 has no exec — can't actually traverse — but the mode-bit
    // arithmetic is what we're checking. Test with 0o500 (r-x for owner)
    // vs requested 0o700.
    const parent = mkdtempSync(join(tmpdir(), "epd-"));
    const target = join(parent, "p");
    mkdirSync(target, { mode: 0o500 });
    chmodSync(target, 0o500);

    ensurePrivateDir(target, 0o700);

    expect(statSync(target).mode & 0o777).toBe(0o700);
  });

  test("rejects an existing directory looser than the requested mode", () => {
    const parent = mkdtempSync(join(tmpdir(), "epd-"));
    const target = join(parent, "p");
    mkdirSync(target, { mode: 0o755 });
    chmodSync(target, 0o755);

    expect(() => ensurePrivateDir(target, 0o700)).toThrow(/permissions/);
  });

  test("rejects when the target is a symlink", () => {
    const parent = mkdtempSync(join(tmpdir(), "epd-"));
    const realDir = join(parent, "real");
    mkdirSync(realDir, { mode: 0o700 });
    chmodSync(realDir, 0o700);
    const link = join(parent, "link");
    symlinkSync(realDir, link);

    expect(() => ensurePrivateDir(link, 0o700)).toThrow(/symlink/);
  });

  test("rejects when the target exists as a regular file", () => {
    const parent = mkdtempSync(join(tmpdir(), "epd-"));
    const file = join(parent, "f");
    writeFileSync(file, "x");

    expect(() => ensurePrivateDir(file, 0o700)).toThrow(/not a directory/);
  });

  test("0o750 (group mode) accepts pre-existing 0o700 directory and widens to 0o750", () => {
    const parent = mkdtempSync(join(tmpdir(), "epd-"));
    const target = join(parent, "p");
    mkdirSync(target, { mode: 0o700 });
    chmodSync(target, 0o700);

    ensurePrivateDir(target, 0o750);

    expect(statSync(target).mode & 0o777).toBe(0o750);
  });

  test("0o750 (group mode) rejects pre-existing 0o755 directory", () => {
    const parent = mkdtempSync(join(tmpdir(), "epd-"));
    const target = join(parent, "p");
    mkdirSync(target, { mode: 0o755 });
    chmodSync(target, 0o755);

    expect(() => ensurePrivateDir(target, 0o750)).toThrow(/permissions/);
  });
});
