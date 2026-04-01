import { parseArgs } from "node:util";
import { spawnSync } from "node:child_process";
import { z } from "zod";
import { loadConfig, mapCliArgs } from "./config.ts";
import { runGate } from "./commands/gate.ts";
import { runMetadataProxy } from "./commands/metadata-proxy.ts";
import { runWithProd } from "./commands/with-prod.ts";
import { runKubeToken } from "./commands/kube-token.ts";
import { runKubeSetup } from "./commands/kube-setup.ts";
import { runInitTls } from "./commands/init-tls.ts";
import { runApprove } from "./commands/approve.ts";
import packageJson from "../package.json";

const VERSION = packageJson.version;

function getCommitSha(): string {
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

function formatVersion(): string {
  const sha = getCommitSha();
  return sha ? `${VERSION} (${sha})` : VERSION;
}

const USAGE = `gcp-authcalator v${formatVersion()} — GCP auth escalator for development environments

Usage:
  gcp-authcalator <command> [options]

Commands:
  gate              Start the host-side token daemon
  metadata-proxy    Start the GCE metadata server emulator
  with-prod         Wrap a command with prod credentials
  approve           List or approve pending prod access requests
  deny              Deny a pending prod access request
  init-tls          Generate TLS certificates for remote devcontainer support
  kube-token        kubectl exec credential plugin (outputs ExecCredential JSON)
  kube-setup        Patch kubeconfig to use gcp-authcalator instead of gke-gcloud-auth-plugin
  version           Show version

Options:
  --project-id <id>        GCP project ID
  --service-account <email> Service account email to impersonate
  --socket-path <path>     Unix socket path (default: $XDG_RUNTIME_DIR/gcp-authcalator.sock)
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
  --session-ttl-seconds <secs>  Prod session lifetime in seconds (default: 28800 / 8h)
  -e, --env <KEY=VALUE>    Extra env var for with-prod subprocess (repeatable, supports \${VAR} substitution)
  -c, --config <path>      Path to TOML config file
  -h, --help               Show this help message
  -v, --version            Show version

Examples:
  gcp-authcalator gate --project-id my-project --service-account sa@my-project.iam.gserviceaccount.com
  gcp-authcalator metadata-proxy --config config.toml
  gcp-authcalator with-prod -- python some/script.py
  gcp-authcalator approve
  gcp-authcalator approve abc12def
  gcp-authcalator deny abc12def
  gcp-authcalator kube-setup`;

const SUBCOMMANDS = [
  "gate",
  "metadata-proxy",
  "with-prod",
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
      "service-account": { type: "string" },
      "socket-path": { type: "string" },
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
      "session-ttl-seconds": { type: "string" },
      env: { type: "string", short: "e", multiple: true },
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

  // Commands that don't need project config
  if (subcommand === "kube-token") {
    await runKubeToken();
    return;
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

  if (subcommand === "approve" || subcommand === "deny") {
    try {
      const { env: _envPairs, ...scalarVals } = values;
      const approveConfig = loadConfig(mapCliArgs(scalarVals), values.config);
      const isDeny = subcommand === "deny";
      const id = positionals[1];
      await runApprove(approveConfig, id ? [id] : [], { deny: isDeny });
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

  const { env: envPairs, ...scalarValues } = values;
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
        await runWithProd(config, wrappedCommand);
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
