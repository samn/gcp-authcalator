/**
 * One-time kubeconfig patcher.
 *
 * Reads the kubeconfig, finds all users using `gke-gcloud-auth-plugin`,
 * and replaces them with `gcp-authcalator kube-token`.
 *
 * Revert by re-running `gcloud container clusters get-credentials`.
 */

import { readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const GKE_PLUGIN_COMMAND = "gke-gcloud-auth-plugin";
const AUTHCALATOR_COMMAND = "gcp-authcalator";
const AUTHCALATOR_ARGS = ["kube-token"];

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

export function patchKubeconfig(kubeconfig: KubeConfig): {
  patched: KubeConfig;
  patchedUsers: string[];
} {
  const patchedUsers: string[] = [];

  if (!kubeconfig.users || !Array.isArray(kubeconfig.users)) {
    return { patched: kubeconfig, patchedUsers };
  }

  for (const entry of kubeconfig.users) {
    const exec = entry.user?.exec;
    if (!exec) continue;

    // Match both bare command and full path (e.g. /usr/lib/google-cloud-sdk/bin/gke-gcloud-auth-plugin)
    const command = exec.command ?? "";
    if (command !== GKE_PLUGIN_COMMAND && !command.endsWith(`/${GKE_PLUGIN_COMMAND}`)) {
      continue;
    }

    exec.command = AUTHCALATOR_COMMAND;
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

  const { patched, patchedUsers } = patchKubeconfig(kubeconfig);

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
    copyFileSync(kubeconfigPath, backupPath);
  } catch {
    // Non-fatal: warn but continue
    console.warn(`kube-setup: could not create backup at ${backupPath}`);
  }

  const output = Bun.YAML.stringify(patched, null, 2);

  try {
    writeFileSync(kubeconfigPath, output, "utf-8");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`kube-setup: failed to write kubeconfig: ${msg}`);
    process.exit(1);
  }

  console.log(`kube-setup: patched ${patchedUsers.length} user(s) in ${kubeconfigPath}:`);
  for (const name of patchedUsers) {
    console.log(`  - ${name}: exec.command → ${AUTHCALATOR_COMMAND} ${AUTHCALATOR_ARGS.join(" ")}`);
  }
  console.log(`kube-setup: backup saved to ${backupPath}`);
  console.log("kube-setup: to revert, run: gcloud container clusters get-credentials <cluster>");
}
