#!/usr/bin/env bun

/**
 * Release script for gcp-authcalator.
 *
 * Reads the version from package.json, validates the changelog has an entry,
 * creates a release commit, tags it, and pushes both to the remote.
 *
 * Usage: bun run release
 */

import packageJson from "../package.json";

const VERSION = packageJson.version;
const TAG = `v${VERSION}`;

async function run(cmd: string[]): Promise<{ stdout: string; exitCode: number }> {
  const proc = Bun.spawn(cmd, { stdout: "pipe", stderr: "inherit" });
  const stdout = await new Response(proc.stdout).text();
  const exitCode = await proc.exited;
  return { stdout: stdout.trim(), exitCode };
}

async function main() {
  console.log(`Preparing release ${TAG}...`);

  // 1. Check we're on main
  const { stdout: branch } = await run(["git", "rev-parse", "--abbrev-ref", "HEAD"]);
  if (branch !== "main") {
    console.error(`error: must be on 'main' branch (currently on '${branch}')`);
    process.exit(1);
  }

  // 2. Check working tree is clean
  const { stdout: status } = await run(["git", "status", "--porcelain"]);
  if (status.length > 0) {
    console.error("error: working tree is not clean — commit or stash changes first");
    console.error(status);
    process.exit(1);
  }

  // 3. Check changelog has an entry for this version
  const changelog = await Bun.file("CHANGELOG.md").text();
  if (!changelog.includes(`[${VERSION}]`)) {
    console.error(
      `error: CHANGELOG.md has no entry for [${VERSION}]`,
      "\n  Move [Unreleased] entries to a new section: ## [${VERSION}] - YYYY-MM-DD",
    );
    process.exit(1);
  }

  // 4. Check tag doesn't already exist
  const { exitCode: tagExists } = await run(["git", "rev-parse", TAG]);
  if (tagExists === 0) {
    console.error(`error: tag '${TAG}' already exists`);
    process.exit(1);
  }

  // 5. Create the release commit
  const { exitCode: commitExit } = await run([
    "git",
    "commit",
    "--allow-empty",
    "-m",
    `release: ${TAG}`,
  ]);
  if (commitExit !== 0) {
    console.error("error: failed to create release commit");
    process.exit(1);
  }

  // 6. Create the tag
  const { exitCode: tagExit } = await run(["git", "tag", TAG]);
  if (tagExit !== 0) {
    console.error(`error: failed to create tag '${TAG}'`);
    process.exit(1);
  }

  // 7. Push commit and tag
  console.log("Pushing commit and tag...");
  const { exitCode: pushExit } = await run(["git", "push"]);
  if (pushExit !== 0) {
    console.error("error: failed to push commit");
    process.exit(1);
  }

  const { exitCode: pushTagExit } = await run(["git", "push", "origin", TAG]);
  if (pushTagExit !== 0) {
    console.error(`error: failed to push tag '${TAG}'`);
    process.exit(1);
  }

  console.log(`\nReleased ${TAG} successfully!`);
  console.log("GitHub Actions will now build and publish the release.");
}

main();
