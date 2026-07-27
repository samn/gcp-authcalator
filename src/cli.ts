import { parseArgs } from "node:util";
import { z } from "zod";
import { loadConfig, mapCliArgs } from "./config.ts";
import { formatVersion } from "./version.ts";
import { runGate } from "./commands/gate.ts";
import { runMetadataProxy } from "./commands/metadata-proxy.ts";
import { runWithProd } from "./commands/with-prod.ts";
import { runKubeToken } from "./commands/kube-token.ts";
import { runKubeSetup } from "./commands/kube-setup.ts";
import { runInitTls } from "./commands/init-tls.ts";
import { runApprove, runPending } from "./commands/approve.ts";
import { captureAndDeleteTlsBundleEnv } from "./tls/bundle.ts";

// Run before any code below that may spawn a subprocess (e.g. getCommitSha).
captureAndDeleteTlsBundleEnv();

const USAGE = `gcp-authcalator v${formatVersion()} — GCP auth escalator for development environments

Usage:
  gcp-authcalator <command> [options]

Commands:
  gate              Start the host-side token daemon
  metadata-proxy    Start the GCE metadata server emulator
  with-prod         Wrap a command with prod credentials
  pending           List pending prod access requests, or show one in full
  approve           Approve a pending prod access request by ID
  deny              Deny a pending prod access request
  init-tls          Generate TLS certificates for remote devcontainer support
  kube-token        kubectl exec credential plugin (outputs ExecCredential JSON)
  kube-setup        Patch kubeconfig to use gcp-authcalator instead of gke-gcloud-auth-plugin
  version           Show version

Options:
  --project-id <id>        GCP project ID (default project for with-prod)
  --project <id>           with-prod only: per-invocation target project (overrides --project-id)
  --service-account <email> Service account email to impersonate
  --socket-path <path>     Unix socket path (default: $XDG_RUNTIME_DIR/gcp-authcalator.sock)
  --admin-socket-path <path>  Admin socket path for approve/deny (default: $XDG_RUNTIME_DIR/gcp-authcalator-admin/admin.sock)
  -p, --port <port>        Metadata proxy port (default: 8173)
  --gate-tls-port <port>        Gate TCP+mTLS listener port (enables remote devcontainer support)
  --tls-dir <path>         TLS certificate directory (default: ~/.gcp-authcalator/tls/)
  --gate-url <url>         Gate URL for remote connections (must use https://)
  --tls-bundle <path>      Path to TLS client bundle file (PEM or base64-encoded)
  --bundle-b64             Print base64-encoded client bundle (init-tls only)
  --show-path              Print TLS directory path (init-tls only)
  --scopes <scopes>        Comma-separated OAuth scopes (default: cloud-platform)
  --pam-policy <id|path>   PAM entitlement for just-in-time prod escalation
  --pam-allowed-policies <ids>  Additional allowed PAM entitlements (comma-separated)
  --pam-location <loc>     PAM entitlement location (default: global)
  --token-ttl-seconds <secs>  Token lifetime in seconds (default: 3600)
  --pam-grant-ttl-seconds <secs>  PAM grant lifetime in seconds (must exceed the 5-min drain margin; range 301–43200; default: token-ttl-seconds). A longer grant amortises PAM/IAM propagation latency across many token refreshes
  --session-ttl-seconds <secs>  Prod session lifetime in seconds (default: 28800 / 8h)
  --operator-socket-path <path>      Operator socket path (auto-approve eligible — see docs)
  --operator-socket-group <name>     Optional: multi-operator mode. Sets mode 0660 with this group; without it, mode 0600 owned by gate UID
  --auto-approve-pam-policies <ids>  PAM entitlements that auto-approve on the operator socket (comma-separated; subset of --pam-allowed-policies)
  --agent-uid <uid|name>             Agent UID (or username) — required with --operator-socket-path; gate refuses to start if this UID equals the gate UID (or, in group mode, is in the operator group)
  --quota-project <id>     with-prod: GOOGLE_CLOUD_QUOTA_PROJECT for the wrapped command (default: the target project)
  --no-quota-project       with-prod: don't manage GOOGLE_CLOUD_QUOTA_PROJECT (leave the inherited value untouched)
  -e, --env <KEY=VALUE>    Extra env var for with-prod subprocess (repeatable, supports \${VAR} substitution)
  --yes                    approve only: skip the interactive confirmation (required when not on a TTY)
  -c, --config <path>      Path to TOML config file
  -h, --help               Show this help message
  -v, --version            Show version

Operator socket (gate only):
  Reduces confirmation fatigue by auto-approving allowlisted prod requests
  on a separate Unix socket only the operator can reach. Requires the
  operator and the agent to run as different UIDs in the same environment.

  Single-operator (paved path): omit --operator-socket-group. The socket is
  mode 0600 owned by the gate UID; only that UID can connect. Use when the
  operator and gate share a UID (typical local-devcontainer setup).

  Multi-operator: set --operator-socket-group. The socket is mode 0660
  group-owned; group members can connect. The agent UID MUST NOT be a member
  of the operator group, or the gate refuses to start.

Examples:
  gcp-authcalator gate --project-id my-project --service-account sa@my-project.iam.gserviceaccount.com
  gcp-authcalator metadata-proxy --config config.toml
  gcp-authcalator with-prod -- python some/script.py
  gcp-authcalator with-prod --project alt-project -- python some/script.py
  gcp-authcalator pending
  gcp-authcalator pending <id>
  gcp-authcalator approve <id>
  gcp-authcalator deny <id>
  gcp-authcalator kube-setup`;

const SUBCOMMANDS = [
  "gate",
  "metadata-proxy",
  "with-prod",
  "pending",
  "approve",
  "deny",
  "init-tls",
  "kube-token",
  "kube-setup",
  "version",
] as const;
type Subcommand = (typeof SUBCOMMANDS)[number];

function isSubcommand(value: string): value is Subcommand {
  return (SUBCOMMANDS as readonly string[]).includes(value);
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    strict: true,
    allowPositionals: true,
    options: {
      "project-id": { type: "string" },
      // `--project` is a with-prod-only per-invocation override. Kept distinct
      // from `--project-id` (which sets the config default) so it can't leak
      // into the gate/metadata-proxy commands via shared config merge.
      project: { type: "string" },
      "service-account": { type: "string" },
      "socket-path": { type: "string" },
      "admin-socket-path": { type: "string" },
      port: { type: "string", short: "p" },
      "gate-tls-port": { type: "string" },
      "tls-dir": { type: "string" },
      "gate-url": { type: "string" },
      "tls-bundle": { type: "string" },
      "bundle-b64": { type: "boolean" },
      "show-path": { type: "boolean" },
      scopes: { type: "string" },
      "pam-policy": { type: "string" },
      "pam-allowed-policies": { type: "string" },
      "pam-location": { type: "string" },
      "token-ttl-seconds": { type: "string" },
      "pam-grant-ttl-seconds": { type: "string" },
      "session-ttl-seconds": { type: "string" },
      "operator-socket-path": { type: "string" },
      "operator-socket-group": { type: "string" },
      "auto-approve-pam-policies": { type: "string" },
      "agent-uid": { type: "string" },
      "quota-project": { type: "string" },
      "no-quota-project": { type: "boolean" },
      env: { type: "string", short: "e", multiple: true },
      yes: { type: "boolean" },
      config: { type: "string", short: "c" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" },
    },
  });

  if (values.help) {
    console.log(USAGE);
    process.exit(0);
  }

  if (values.version) {
    console.log(formatVersion());
    process.exit(0);
  }

  const subcommand = positionals[0];

  if (!subcommand) {
    console.error("error: no subcommand provided\n");
    console.error(USAGE);
    process.exit(1);
  }

  if (!isSubcommand(subcommand)) {
    console.error(`error: unknown subcommand '${subcommand}'`);
    console.error(`available commands: ${SUBCOMMANDS.join(", ")}`);
    process.exit(1);
  }

  if (subcommand === "version") {
    console.log(formatVersion());
    process.exit(0);
  }

  // Commands that don't need project config.
  // kube-token runs as a kubectl credential plugin on every API call, so it
  // skips the startup version banner to avoid spamming stderr.
  if (subcommand === "kube-token") {
    await runKubeToken();
    return;
  }

  // Log version+sha to stderr so the running build is visible in any subcommand's
  // logs (verifies the deployed binary matches what was built). with-prod prints
  // its own project-aware banner once the target project is known, so skip it here.
  if (subcommand !== "with-prod") {
    console.error(`gcp-authcalator v${formatVersion()} (${subcommand})`);
  }

  if (subcommand === "kube-setup") {
    await runKubeSetup();
    return;
  }

  if (subcommand === "init-tls") {
    await runInitTls({
      bundleB64: values["bundle-b64"],
      showPath: values["show-path"],
      tlsDir: values["tls-dir"],
    });
    return;
  }

  if (subcommand === "approve" || subcommand === "deny" || subcommand === "pending") {
    try {
      const { env: _envPairs, ...scalarVals } = values;
      const approveConfig = loadConfig(mapCliArgs(scalarVals), values.config);
      const id = positionals[1];
      if (subcommand === "pending") {
        await runPending(approveConfig, id ? [id] : []);
      } else {
        await runApprove(approveConfig, id ? [id] : [], {
          deny: subcommand === "deny",
          yes: values.yes,
        });
      }
    } catch (err) {
      if (err instanceof z.ZodError) {
        console.error(`error: invalid configuration for '${subcommand}'`);
        for (const issue of err.issues) {
          console.error(`  ${issue.path.join(".")}: ${issue.message}`);
        }
        process.exit(1);
      }
      console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
    return;
  }

  // `project` is a with-prod-only override and never enters the shared config.
  const { env: envPairs, project: projectOverride, ...scalarValues } = values;
  const cliValues = mapCliArgs(scalarValues);

  // Parse --env KEY=VALUE pairs into a record
  if (envPairs) {
    const envRecord: Record<string, string> = {};
    for (const pair of envPairs) {
      const eqIndex = pair.indexOf("=");
      if (eqIndex <= 0) {
        console.error(`error: --env value must be KEY=VALUE, got: ${pair}`);
        process.exit(1);
      }
      envRecord[pair.slice(0, eqIndex)] = pair.slice(eqIndex + 1);
    }
    cliValues.env = envRecord;
  }

  let config;
  try {
    config = loadConfig(cliValues, values.config);
  } catch (err) {
    if (err instanceof z.ZodError) {
      console.error("error: invalid configuration");
      for (const issue of err.issues) {
        console.error(`  ${issue.path.join(".")}: ${issue.message}`);
      }
      process.exit(1);
    }
    throw err;
  }

  try {
    switch (subcommand) {
      case "gate":
        await runGate(config);
        break;
      case "metadata-proxy":
        await runMetadataProxy(config);
        break;
      case "with-prod": {
        const wrappedCommand = positionals.slice(1);
        await runWithProd(config, wrappedCommand, { projectOverride });
        break;
      }
    }
  } catch (err) {
    if (err instanceof z.ZodError) {
      console.error(`error: invalid configuration for '${subcommand}'`);
      for (const issue of err.issues) {
        console.error(`  ${issue.path.join(".")}: ${issue.message}`);
      }
      process.exit(1);
    }
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}
