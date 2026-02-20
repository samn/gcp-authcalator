#!/usr/bin/env bun

/**
 * Build script that compiles gcp-authcalator with the git commit SHA embedded.
 *
 * Usage:
 *   bun run scripts/build.ts
 *   bun run scripts/build.ts --target=bun-linux-x64 --outfile=gcp-authcalator-linux-amd64
 */

import { spawnSync } from "node:child_process";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  args: process.argv.slice(2),
  strict: true,
  options: {
    target: { type: "string" },
    outfile: { type: "string" },
  },
});

const outfile = values.outfile ?? "gcp-authcalator";

// Get current commit SHA
const gitResult = spawnSync("git", ["rev-parse", "--short", "HEAD"], {
  timeout: 5000,
  stdio: ["ignore", "pipe", "ignore"],
});
const commitSha = gitResult.status === 0 ? Buffer.from(gitResult.stdout).toString().trim() : "";

if (!commitSha) {
  console.warn("warning: could not determine git commit SHA");
}

const args = [
  "bun",
  "build",
  "--compile",
  ...(values.target ? [`--target=${values.target}`] : []),
  `--define=process.env.COMMIT_SHA="${commitSha}"`,
  "index.ts",
  `--outfile=${outfile}`,
];

console.log(`Building ${outfile} (commit: ${commitSha || "unknown"})...`);

const cmd = args[0]!;
const result = spawnSync(cmd, args.slice(1), {
  stdio: "inherit",
});

process.exit(result.status ?? 1);
