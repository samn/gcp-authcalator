import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { resolve, join } from "node:path";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

const releaseScript = resolve(import.meta.dir, "../../scripts/release.ts");

// Read the version from the real package.json (same one the script imports)
import packageJson from "../../package.json";
const VERSION = packageJson.version;
const TAG = `v${VERSION}`;

async function runRelease(
  cwd: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const proc = Bun.spawn(["bun", "run", releaseScript], {
    cwd,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const exitCode = await proc.exited;
  return { stdout, stderr, exitCode };
}

async function git(cwd: string, ...args: string[]): Promise<string> {
  const proc = Bun.spawn(["git", ...args], {
    cwd,
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdout = await new Response(proc.stdout).text();
  await proc.exited;
  return stdout.trim();
}

describe("release script", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = mkdtempSync(join(tmpdir(), "release-test-"));
    await git(tempDir, "init", "-b", "main");
    await git(tempDir, "config", "user.email", "test@test.com");
    await git(tempDir, "config", "user.name", "Test");
    await git(tempDir, "config", "commit.gpgsign", "false");
    await git(tempDir, "config", "tag.gpgsign", "false");
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  test("fails when not on main branch", async () => {
    // Need an initial commit to create branches
    writeFileSync(join(tempDir, "README.md"), "test");
    await git(tempDir, "add", ".");
    await git(tempDir, "commit", "-m", "initial");
    await git(tempDir, "checkout", "-b", "feature");

    const { stderr, exitCode } = await runRelease(tempDir);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("must be on 'main' branch");
    expect(stderr).toContain("feature");
  });

  test("fails when working tree is dirty", async () => {
    writeFileSync(join(tempDir, "README.md"), "test");
    await git(tempDir, "add", ".");
    await git(tempDir, "commit", "-m", "initial");

    // Create an untracked file to dirty the tree
    writeFileSync(join(tempDir, "dirty.txt"), "dirty");

    const { stderr, exitCode } = await runRelease(tempDir);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("working tree is not clean");
  });

  test("fails when changelog has no version entry", async () => {
    writeFileSync(join(tempDir, "CHANGELOG.md"), "# Changelog\n\n## [Unreleased]\n");
    await git(tempDir, "add", ".");
    await git(tempDir, "commit", "-m", "initial");

    const { stderr, exitCode } = await runRelease(tempDir);
    expect(exitCode).toBe(1);
    expect(stderr).toContain(`CHANGELOG.md has no entry for [${VERSION}]`);
  });

  test("changelog error message interpolates version", async () => {
    writeFileSync(join(tempDir, "CHANGELOG.md"), "# Changelog\n\n## [Unreleased]\n");
    await git(tempDir, "add", ".");
    await git(tempDir, "commit", "-m", "initial");

    const { stderr } = await runRelease(tempDir);
    // Should show the actual version, not the literal "${VERSION}"
    expect(stderr).toContain(`## [${VERSION}]`);
    expect(stderr).not.toContain("${VERSION}");
  });

  test("fails when tag already exists", async () => {
    writeFileSync(
      join(tempDir, "CHANGELOG.md"),
      `# Changelog\n\n## [Unreleased]\n\n## [${VERSION}] - 2026-01-01\n\n### Added\n- Test\n`,
    );
    await git(tempDir, "add", ".");
    await git(tempDir, "commit", "-m", "initial");
    await git(tempDir, "tag", TAG);

    const { stderr, exitCode } = await runRelease(tempDir);
    expect(exitCode).toBe(1);
    expect(stderr).toContain(`tag '${TAG}' already exists`);
  });

  test("succeeds with valid setup", async () => {
    // Create a bare remote to push to
    const remoteDir = mkdtempSync(join(tmpdir(), "release-remote-"));
    await git(remoteDir, "init", "--bare");

    // Set up valid state
    writeFileSync(
      join(tempDir, "CHANGELOG.md"),
      `# Changelog\n\n## [Unreleased]\n\n## [${VERSION}] - 2026-01-01\n\n### Added\n- Test\n`,
    );
    await git(tempDir, "add", ".");
    await git(tempDir, "commit", "-m", `release: ${TAG}`);
    await git(tempDir, "remote", "add", "origin", remoteDir);
    await git(tempDir, "push", "-u", "origin", "main");

    const { stdout, exitCode } = await runRelease(tempDir);
    expect(exitCode).toBe(0);
    expect(stdout).toContain(`Released ${TAG} successfully!`);

    // Verify tag was created locally
    const tags = await git(tempDir, "tag", "-l");
    expect(tags).toContain(TAG);

    // Verify tag was pushed to remote
    const remoteTags = await git(remoteDir, "tag", "-l");
    expect(remoteTags).toContain(TAG);

    // Verify the tag points to the user's commit (not an empty one)
    const tagCommitMsg = await git(tempDir, "log", "-1", "--format=%s", TAG);
    expect(tagCommitMsg).toBe(`release: ${TAG}`);

    rmSync(remoteDir, { recursive: true, force: true });
  });
});
