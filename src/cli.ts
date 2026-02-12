import { parseArgs } from "node:util";
import { z } from "zod";
import { loadConfig, mapCliArgs } from "./config.ts";
import { runGate } from "./commands/gate.ts";
import { runMetadataProxy } from "./commands/metadata-proxy.ts";
import { runWithProd } from "./commands/with-prod.ts";

const VERSION = "0.0.1";

const USAGE = `gcp-authcalator — GCP auth escalator for development environments

Usage:
  gcp-authcalator <command> [options]

Commands:
  gate              Start the host-side token daemon
  metadata-proxy    Start the GCE metadata server emulator
  with-prod         Wrap a command with prod credentials

Options:
  --project-id <id>        GCP project ID
  --service-account <email> Service account email to impersonate
  --socket-path <path>     Unix socket path (default: /run/gcp-gate.sock)
  -p, --port <port>        Metadata proxy port (default: 8173)
  -c, --config <path>      Path to TOML config file
  -h, --help               Show this help message
  -v, --version            Show version

Examples:
  gcp-authcalator gate --project-id my-project --service-account sa@my-project.iam.gserviceaccount.com
  gcp-authcalator metadata-proxy --config config.toml
  gcp-authcalator with-prod -- python some/script.py`;

const SUBCOMMANDS = ["gate", "metadata-proxy", "with-prod"] as const;
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
    console.log(VERSION);
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

  const cliValues = mapCliArgs(values);

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
        runWithProd(config, wrappedCommand);
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
    throw err;
  }
}
