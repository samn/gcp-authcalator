import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import type { Config } from "../config.ts";
import { getDefaultRuntimeDir, WithProdConfigSchema } from "../config.ts";
import { fetchProdToken, type FetchProdTokenOptions } from "../with-prod/fetch-prod-token.ts";
import { createStaticTokenProvider } from "../with-prod/static-token-provider.ts";
import { startMetadataProxyServer } from "../metadata-proxy/server.ts";

export interface ChildHandle {
  exited: Promise<number | null>;
  kill(signal?: NodeJS.Signals): void;
}

type SpawnFn = (
  cmd: string[],
  opts: {
    env: Record<string, string | undefined>;
    stdio: "inherit";
  },
) => ChildHandle;

function defaultSpawn(
  cmd: string[],
  opts: { env: Record<string, string | undefined>; stdio: "inherit" },
): ChildHandle {
  const [file, ...args] = cmd;
  const child = spawn(file!, args, {
    env: opts.env as NodeJS.ProcessEnv,
    stdio: opts.stdio,
  });
  return {
    exited: new Promise<number | null>((resolve) => {
      child.on("exit", (code: number | null) => resolve(code));
    }),
    kill(signal?: NodeJS.Signals) {
      child.kill(signal);
    },
  };
}

export interface WithProdOptions {
  /** Override fetch for testing (passed to fetchProdToken). */
  fetchOptions?: FetchProdTokenOptions;
  /** Override spawn for testing. */
  spawnFn?: SpawnFn;
}

/**
 * Wrap a shell command with prod-level GCP credentials.
 *
 * 1. Fetches a prod token + engineer identity from gcp-gate
 * 2. Starts a temporary metadata proxy serving that token
 * 3. Creates an isolated CLOUDSDK_CONFIG so gcloud doesn't reuse cached creds
 * 4. Execs the wrapped command with env vars pointing at the proxy
 * 5. Forwards signals to child, propagates exit code, cleans up
 */
export async function runWithProd(
  config: Config,
  wrappedCommand: string[],
  options: WithProdOptions = {},
): Promise<never> {
  if (wrappedCommand.length === 0) {
    console.error("error: with-prod requires a command to wrap");
    console.error("usage: gcp-authcalator with-prod -- <command> [args...]");
    process.exit(1);
  }

  const wpConfig = WithProdConfigSchema.parse(config);

  // Step 1: Fetch prod token + identity from gcp-gate
  console.log("with-prod: requesting prod-level token from gcp-gate...");
  let tokenResult;
  try {
    tokenResult = await fetchProdToken(wpConfig.socket_path, {
      ...options.fetchOptions,
      command: wrappedCommand,
    });
  } catch (err) {
    console.error(
      `with-prod: failed to acquire prod token: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
  console.log(`with-prod: prod token acquired for ${tokenResult.email}`);

  // Step 2: Start temporary metadata proxy with the engineer's email so
  // gcloud can discover the account (it ignores the "default" alias).
  const expiresAt = new Date(Date.now() + tokenResult.expires_in * 1000);
  const tokenProvider = createStaticTokenProvider(tokenResult.access_token, expiresAt);

  const { server, stop } = startMetadataProxyServer(
    {
      project_id: wpConfig.project_id,
      service_account: tokenResult.email,
      socket_path: wpConfig.socket_path,
      port: 0,
    },
    {
      tokenProvider,
      installSignalHandlers: false,
      quiet: true,
      allowedAncestorPid: process.pid,
    },
  );

  const metadataHost = `127.0.0.1:${server.port}`;

  let gcloudConfigDir: string | undefined;
  let exitCode: number | undefined;
  try {
    // Step 3: Create an isolated gcloud config directory so the child process
    // doesn't reuse cached tokens from the main metadata proxy.
    // Place it in the user-private runtime directory (not /tmp) so other
    // local users cannot observe or race the temp directory.
    const runtimeDir = getDefaultRuntimeDir();
    mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });
    gcloudConfigDir = mkdtempSync(join(runtimeDir, "gcp-authcalator-gcloud-"));
    chmodSync(gcloudConfigDir, 0o700);

    // Write the access token to a file and configure gcloud to use it via
    // auth/access_token_file. This is safer than CLOUDSDK_AUTH_ACCESS_TOKEN
    // (which leaks into /proc/*/environ and is inherited by all children).
    const tokenFilePath = join(gcloudConfigDir, "access_token");
    writeFileSync(tokenFilePath, tokenResult.access_token, { mode: 0o600 });
    writeFileSync(
      join(gcloudConfigDir, "properties"),
      `[auth]\naccess_token_file = ${tokenFilePath}\n`,
      { mode: 0o600 },
    );

    // Step 4: Spawn wrapped command with metadata env vars
    const spawnFn = options.spawnFn ?? defaultSpawn;
    const {
      CLOUDSDK_AUTH_ACCESS_TOKEN: _drop1,
      CPL_GS_BEARER: _drop2,
      GOOGLE_APPLICATION_CREDENTIALS: _drop3,
      GOOGLE_OAUTH_ACCESS_TOKEN: _drop4,
      CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE: _drop5,
      CLOUDSDK_CORE_ACCOUNT: _drop6,
      CLOUDSDK_CONFIG: _drop7,
      ...parentEnv
    } = process.env;
    const env = {
      ...parentEnv,
      GCE_METADATA_HOST: metadataHost,
      GCE_METADATA_IP: metadataHost,
      CLOUDSDK_CONFIG: gcloudConfigDir,
      // Explicitly set gcloud-specific env vars so `gcloud auth list` and
      // other gcloud commands show the correct active account and project.
      // gcloud's internal account-enumeration code may not honor
      // GCE_METADATA_HOST, falling back to the original metadata proxy.
      // Tokens still flow through the PID-validated metadata proxy.
      CLOUDSDK_CORE_ACCOUNT: tokenResult.email,
      CLOUDSDK_CORE_PROJECT: wpConfig.project_id,
    };

    const child = spawnFn(wrappedCommand, {
      env,
      stdio: "inherit",
    });

    // Step 5: Forward signals to child
    const onSigterm = () => child.kill("SIGTERM");
    const onSigint = () => child.kill("SIGINT");
    const onSigwinch = () => child.kill("SIGWINCH");
    process.on("SIGTERM", onSigterm);
    process.on("SIGINT", onSigint);
    process.on("SIGWINCH", onSigwinch);

    // Step 6: Wait for child
    try {
      exitCode = (await child.exited) ?? undefined;
    } finally {
      process.removeListener("SIGTERM", onSigterm);
      process.removeListener("SIGINT", onSigint);
      process.removeListener("SIGWINCH", onSigwinch);
    }
  } finally {
    stop();
    if (gcloudConfigDir) {
      rmSync(gcloudConfigDir, { recursive: true, force: true });
    }
  }

  process.exit(exitCode ?? 1);
}
