import type { Config } from "../config.ts";
import { WithProdConfigSchema } from "../config.ts";
import { fetchProdToken, type FetchProdTokenOptions } from "../with-prod/fetch-prod-token.ts";
import { createStaticTokenProvider } from "../with-prod/static-token-provider.ts";
import { startMetadataProxyServer } from "../metadata-proxy/server.ts";
import type { Subprocess } from "bun";

type SpawnFn = (
  cmd: string[],
  opts: {
    env: Record<string, string | undefined>;
    stdin: "inherit";
    stdout: "inherit";
    stderr: "inherit";
  },
) => Subprocess;

export interface WithProdOptions {
  /** Override fetch for testing (passed to fetchProdToken). */
  fetchOptions?: FetchProdTokenOptions;
  /** Override Bun.spawn for testing. */
  spawnFn?: SpawnFn;
}

/**
 * Wrap a shell command with prod-level GCP credentials.
 *
 * 1. Fetches a prod token from gcp-gate (triggers host-side confirmation)
 * 2. Starts a temporary metadata proxy serving that token
 * 3. Execs the wrapped command with env vars pointing at the proxy
 * 4. Forwards signals to child, propagates exit code
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

  // Step 1: Fetch prod token from gcp-gate
  console.log("with-prod: requesting prod-level token from gcp-gate...");
  let tokenResult;
  try {
    tokenResult = await fetchProdToken(wpConfig.socket_path, options.fetchOptions);
  } catch (err) {
    console.error(
      `with-prod: failed to acquire prod token: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
  console.log("with-prod: prod token acquired");

  // Step 2: Start temporary metadata proxy
  const expiresAt = new Date(Date.now() + tokenResult.expires_in * 1000);
  const tokenProvider = createStaticTokenProvider(tokenResult.access_token, expiresAt);

  const { server, stop } = startMetadataProxyServer(
    {
      project_id: wpConfig.project_id,
      service_account: undefined,
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

  // Step 3: Spawn wrapped command with metadata env vars
  const spawnFn = options.spawnFn ?? (Bun.spawn as unknown as SpawnFn);
  const child = spawnFn(wrappedCommand, {
    env: {
      ...process.env,
      GCE_METADATA_HOST: metadataHost,
      CLOUDSDK_AUTH_ACCESS_TOKEN: undefined,
      CPL_GS_BEARER: undefined,
    },
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });

  // Step 4: Forward signals to child
  const forwardSignal = (signal: NodeJS.Signals) => {
    child.kill(signal === "SIGINT" ? 2 : 15);
  };
  process.on("SIGTERM", () => forwardSignal("SIGTERM"));
  process.on("SIGINT", () => forwardSignal("SIGINT"));

  // Step 5: Wait for child, clean up, propagate exit code
  const exitCode = await child.exited;
  stop();
  process.exit(exitCode ?? 1);
}
