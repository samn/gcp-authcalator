/**
 * One-time kubeconfig patcher.
 *
 * Reads the kubeconfig, finds all users using `gke-gcloud-auth-plugin`,
 * and replaces them with `<absolute-path-to-this-binary> kube-token`.
 *
 * Revert by re-running `gcloud container clusters get-credentials`.
 */

import {
  accessSync,
  chmodSync,
  chownSync,
  closeSync,
  constants,
  copyFileSync,
  fsyncSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

const GKE_PLUGIN_COMMAND = "gke-gcloud-auth-plugin";
const AUTHCALATOR_ARGS = ["kube-token"];

/**
 * Resolve the absolute path of the currently running binary.
 *
 * Uses process.execPath which correctly returns the compiled binary path
 * in Bun single-file executables (process.argv[0] returns "bun" instead).
 * Falls back to resolving process.argv[0] if execPath is unavailable.
 */
function resolveCurrentBinary(): string {
  const binPath = process.execPath || process.argv[0] || "gcp-authcalator";
  try {
    return realpathSync(binPath);
  } catch {
    return resolve(binPath);
  }
}

export interface KubeSetupOptions {
  /** Override the kubeconfig path for testing. */
  kubeconfigPath?: string;
  /** If true, skip writing and only return the result. For testing. */
  dryRun?: boolean;
}

interface KubeConfigUser {
  name: string;
  user?: {
    exec?: {
      apiVersion?: string;
      command?: string;
      args?: string[];
      installHint?: string;
      provideClusterInfo?: boolean;
      interactiveMode?: string;
      env?: unknown;
    };
    [key: string]: unknown;
  };
}

interface KubeConfig {
  apiVersion?: string;
  kind?: string;
  users?: KubeConfigUser[];
  [key: string]: unknown;
}

function resolveKubeconfigPath(override?: string): string {
  if (override) return override;
  const envPath = process.env.KUBECONFIG;
  if (envPath) {
    // KUBECONFIG can be colon-separated; use the first path
    const first = envPath.split(":")[0];
    if (first) return first;
  }
  return join(homedir(), ".kube", "config");
}

function temporarySiblingPath(targetPath: string): string {
  return join(
    dirname(targetPath),
    `.${basename(targetPath)}.gcp-authcalator-${process.pid}-${randomUUID()}.tmp`,
  );
}

function syncFile(path: string): void {
  const fd = openSync(path, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Replace a file only after its complete new contents have reached disk. */
function writeFileAtomically(targetPath: string, contents: string): void {
  const targetStat = statSync(targetPath);

  // rename(2) checks the directory rather than the replaced file, so preserve
  // the existing direct-write behavior for an intentionally read-only config.
  if ((targetStat.mode & 0o222) === 0) {
    throw new Error(`kubeconfig is read-only: ${targetPath}`);
  }
  accessSync(targetPath, constants.W_OK);

  const temporaryPath = temporarySiblingPath(targetPath);
  try {
    writeFileSync(temporaryPath, contents, {
      encoding: "utf-8",
      flag: "wx",
      mode: targetStat.mode & 0o777,
    });
    // File-creation modes are filtered through the process umask. Restore the
    // exact original permissions before rename so the patch is metadata-neutral.
    chmodSync(temporaryPath, targetStat.mode & 0o777);
    chownSync(temporaryPath, targetStat.uid, targetStat.gid);
    syncFile(temporaryPath);
    renameSync(temporaryPath, targetPath);
  } catch (err) {
    try {
      unlinkSync(temporaryPath);
    } catch {
      // The file may not have been created, or rename may already have moved it.
    }
    throw err;
  }
}

/** Copy through a same-directory temporary file so a prior backup stays valid. */
function copyFileAtomically(sourcePath: string, targetPath: string): void {
  const sourceStat = statSync(sourcePath);
  const temporaryPath = temporarySiblingPath(targetPath);
  try {
    copyFileSync(sourcePath, temporaryPath, constants.COPYFILE_EXCL);
    chmodSync(temporaryPath, sourceStat.mode & 0o777);
    chownSync(temporaryPath, sourceStat.uid, sourceStat.gid);
    syncFile(temporaryPath);
    renameSync(temporaryPath, targetPath);
  } catch (err) {
    try {
      unlinkSync(temporaryPath);
    } catch {
      // The file may not have been created, or rename may already have moved it.
    }
    throw err;
  }
}

export function patchKubeconfig(
  kubeconfig: KubeConfig,
  command?: string,
): {
  patched: KubeConfig;
  patchedUsers: string[];
} {
  const authcalatorCommand = command ?? resolveCurrentBinary();
  const patchedUsers: string[] = [];

  if (!kubeconfig.users || !Array.isArray(kubeconfig.users)) {
    return { patched: kubeconfig, patchedUsers };
  }

  for (const entry of kubeconfig.users) {
    const exec = entry.user?.exec;
    if (!exec) continue;

    // Match both bare command and full path (e.g. /usr/lib/google-cloud-sdk/bin/gke-gcloud-auth-plugin)
    const cmd = exec.command ?? "";
    if (cmd !== GKE_PLUGIN_COMMAND && !cmd.endsWith(`/${GKE_PLUGIN_COMMAND}`)) {
      continue;
    }

    exec.command = authcalatorCommand;
    exec.args = [...AUTHCALATOR_ARGS];
    exec.installHint = `Install gcp-authcalator or revert with: gcloud container clusters get-credentials <cluster>`;
    // Remove env vars that were for gke-gcloud-auth-plugin
    delete exec.env;
    // Keep provideClusterInfo and apiVersion as-is

    patchedUsers.push(entry.name);
  }

  return { patched: kubeconfig, patchedUsers };
}

export async function runKubeSetup(options: KubeSetupOptions = {}): Promise<void> {
  const kubeconfigPath = resolveKubeconfigPath(options.kubeconfigPath);

  let raw: string;
  try {
    raw = readFileSync(kubeconfigPath, "utf-8");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`kube-setup: failed to read kubeconfig at ${kubeconfigPath}: ${msg}`);
    process.exit(1);
  }

  let kubeconfig: KubeConfig;
  try {
    kubeconfig = Bun.YAML.parse(raw) as KubeConfig;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`kube-setup: failed to parse kubeconfig YAML: ${msg}`);
    process.exit(1);
  }

  if (!kubeconfig || typeof kubeconfig !== "object") {
    console.error("kube-setup: kubeconfig is empty or not a valid YAML document");
    process.exit(1);
  }

  const binaryPath = resolveCurrentBinary();
  const { patched, patchedUsers } = patchKubeconfig(kubeconfig, binaryPath);

  if (patchedUsers.length === 0) {
    console.warn(
      `kube-setup: no users with exec.command '${GKE_PLUGIN_COMMAND}' found in ${kubeconfigPath}`,
    );
    console.warn(
      "  Run `gcloud container clusters get-credentials <cluster>` first to populate kubeconfig.",
    );
    return;
  }

  if (options.dryRun) {
    console.log(`kube-setup: would patch ${patchedUsers.length} user(s):`);
    for (const name of patchedUsers) {
      console.log(`  - ${name}`);
    }
    return;
  }

  // Back up the original kubeconfig
  const backupPath = `${kubeconfigPath}.bak`;
  try {
    copyFileAtomically(kubeconfigPath, backupPath);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`kube-setup: failed to create backup at ${backupPath}: ${msg}`);
    console.error("kube-setup: kubeconfig was not modified");
    process.exit(1);
  }

  const output = Bun.YAML.stringify(patched, null, 2);

  try {
    // Follow a kubeconfig symlink instead of replacing the symlink itself.
    writeFileAtomically(realpathSync(kubeconfigPath), output);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`kube-setup: failed to write kubeconfig: ${msg}`);
    process.exit(1);
  }

  console.log(`kube-setup: patched ${patchedUsers.length} user(s) in ${kubeconfigPath}:`);
  for (const name of patchedUsers) {
    console.log(`  - ${name}: exec.command → ${binaryPath} ${AUTHCALATOR_ARGS.join(" ")}`);
  }
  console.log(`kube-setup: backup saved to ${backupPath}`);
  console.log("kube-setup: to revert, run: gcloud container clusters get-credentials <cluster>");
}
