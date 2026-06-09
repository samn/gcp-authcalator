import { spawnSync } from "node:child_process";
import packageJson from "../package.json";

export const VERSION = packageJson.version;

export function getCommitSha(): string {
  // When compiled with --define, process.env.COMMIT_SHA is replaced with a literal string.
  if (process.env.COMMIT_SHA) {
    return process.env.COMMIT_SHA;
  }
  try {
    const result = spawnSync("git", ["rev-parse", "--short", "HEAD"], {
      timeout: 1000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    if (result.status === 0 && result.stdout) {
      return Buffer.from(result.stdout).toString().trim();
    }
  } catch {
    // git not available
  }
  return "";
}

let cachedVersion: string | undefined;

export function formatVersion(): string {
  // The version+sha can't change during a process's lifetime, so compute the
  // git sha (a synchronous subprocess spawn) at most once across all callers.
  if (cachedVersion === undefined) {
    const sha = getCommitSha();
    cachedVersion = sha ? `${VERSION} (${sha})` : VERSION;
  }
  return cachedVersion;
}
