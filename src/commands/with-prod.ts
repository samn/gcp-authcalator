import { chmodSync, mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { getDefaultRuntimeDir, WithProdConfigSchema } from "../config.ts";
import {
  createProdSession,
  revokeProdSession,
  type FetchProdTokenOptions,
} from "../with-prod/fetch-prod-token.ts";
import { createSessionTokenProvider } from "../with-prod/session-token-provider.ts";
import { startMetadataProxyServer } from "../metadata-proxy/server.ts";
import { detectNestedSession, PROD_SESSION_ENV_VAR } from "../with-prod/detect-nested-session.ts";
import { buildGateConnection } from "../gate/connection.ts";
import type { GateConnection } from "../gate/connection.ts";
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
  /** Override fetch for testing (passed to fetchProdToken and detectNestedSession). */
  fetchOptions?: FetchProdTokenOptions;
  /** Override Bun.spawn for testing. */
  spawnFn?: SpawnFn;
}

/** Resolve ${VAR} and ${VAR:-default} patterns against an env record. */
export function resolveEnvSubstitutions(
  value: string,
  env: Record<string, string | undefined>,
): string {
  return value.replace(/\$\{([^}]+)\}/g, (_, expr: string) => {
    const dashIdx = expr.indexOf(":-");
    if (dashIdx === -1) {
      return env[expr] ?? "";
    }
    const varName = expr.slice(0, dashIdx);
    const defaultValue = expr.slice(dashIdx + 2);
    return env[varName] ?? defaultValue;
  });
}

/** Apply extra env vars with substitution resolved against the base env. */
function applyExtraEnvVars(
  baseEnv: Record<string, string | undefined>,
  extraEnv: Record<string, string> | undefined,
): Record<string, string | undefined> {
  if (!extraEnv) return baseEnv;
  const result = { ...baseEnv };
  for (const [key, value] of Object.entries(extraEnv)) {
    result[key] = resolveEnvSubstitutions(value, result);
  }
  return result;
}

/** Strip credential env vars that could bypass the metadata proxy. */
function stripCredentialEnvVars(
  env: Record<string, string | undefined>,
): Record<string, string | undefined> {
  const {
    CLOUDSDK_AUTH_ACCESS_TOKEN: _drop1,
    CPL_GS_BEARER: _drop2,
    GOOGLE_APPLICATION_CREDENTIALS: _drop3,
    GOOGLE_OAUTH_ACCESS_TOKEN: _drop4,
    CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE: _drop5,
    CLOUDSDK_CORE_ACCOUNT: _drop6,
    CLOUDSDK_CONFIG: _drop7,
    ...cleaned
  } = env;
  return cleaned;
}

/** Spawn child, forward signals, wait for exit, then exit with the child's code. */
async function spawnAndWait(
  wrappedCommand: string[],
  env: Record<string, string | undefined>,
  spawnFn: SpawnFn,
): Promise<never> {
  const child = spawnFn(wrappedCommand, {
    env,
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });

  const forwardSignal = (signal: NodeJS.Signals) => {
    child.kill(signal === "SIGINT" ? 2 : 15);
  };
  process.on("SIGTERM", () => forwardSignal("SIGTERM"));
  process.on("SIGINT", () => forwardSignal("SIGINT"));

  const exitCode = (await child.exited) ?? undefined;
  process.exit(exitCode ?? 1);
}

/**
 * Wrap a shell command with prod-level GCP credentials.
 *
 * 1. If already inside a with-prod session, reuses the parent's proxy
 * 2. Otherwise fetches a prod token + engineer identity from gcp-gate
 * 3. Starts a temporary metadata proxy serving that token
 * 4. Creates an isolated CLOUDSDK_CONFIG so gcloud doesn't reuse cached creds
 * 5. Execs the wrapped command with env vars pointing at the proxy
 * 6. Forwards signals to child, propagates exit code, cleans up
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

  const spawnFn = options.spawnFn ?? (Bun.spawn as unknown as SpawnFn);

  // Check for nested session before parsing config (project_id is not required
  // when reusing an existing session, since we inherit it from the parent proxy).
  const nestedSession = await detectNestedSession(process.env, options.fetchOptions?.fetchFn);

  if (nestedSession) {
    // If the caller explicitly requested a different project, fall through to
    // a new session so the confirmation dialog reflects the correct project.
    if (config.project_id && config.project_id !== nestedSession.projectId) {
      console.log(
        `with-prod: requested project ${config.project_id} differs from active session (${nestedSession.projectId}), starting new session`,
      );
    } else {
      console.log(
        `with-prod: reusing existing prod session (proxy at ${nestedSession.metadataHost})`,
      );

      const env: Record<string, string | undefined> = {
        ...stripCredentialEnvVars(process.env),
        GCE_METADATA_HOST: nestedSession.metadataHost,
        GCE_METADATA_IP: nestedSession.metadataHost,
        GCE_METADATA_ROOT: nestedSession.metadataHost,
        CLOUDSDK_CORE_ACCOUNT: nestedSession.email,
        CLOUDSDK_CORE_PROJECT: nestedSession.projectId,
        [PROD_SESSION_ENV_VAR]: nestedSession.metadataHost,
      };

      // Preserve parent's CLOUDSDK_CONFIG if set
      if (process.env.CLOUDSDK_CONFIG) {
        env.CLOUDSDK_CONFIG = process.env.CLOUDSDK_CONFIG;
      }

      await spawnAndWait(wrappedCommand, applyExtraEnvVars(env, config.env), spawnFn);
    }
  }

  // Normal flow: create a prod session and start a fresh proxy.
  const wpConfig = WithProdConfigSchema.parse(config);

  // Step 1: Create prod session at gcp-gate (triggers confirmation dialog)
  console.log("with-prod: requesting prod session from gcp-gate...");
  let conn: GateConnection;
  let sessionResult;
  try {
    conn = await buildGateConnection(wpConfig);
    sessionResult = await createProdSession(conn, {
      ...options.fetchOptions,
      command: wrappedCommand,
      scopes: wpConfig.scopes,
      pamPolicy: wpConfig.pam_policy,
      tokenTtlSeconds: wpConfig.token_ttl_seconds,
      sessionTtlSeconds: wpConfig.session_ttl_seconds,
    });
  } catch (err) {
    console.error(
      `with-prod: failed to create prod session: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
  console.log(`with-prod: prod session created for ${sessionResult.email}`);

  // Step 2: Create an isolated gcloud config directory BEFORE the token
  // provider so onRefresh can capture the file path in its closure.
  const runtimeDir = getDefaultRuntimeDir();
  mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });
  const gcloudConfigDir = mkdtempSync(join(runtimeDir, "gcp-authcalator-gcloud-"));
  chmodSync(gcloudConfigDir, 0o700);

  const tokenFilePath = join(gcloudConfigDir, "access_token");
  writeFileSync(tokenFilePath, sessionResult.access_token, { mode: 0o600 });
  writeFileSync(
    join(gcloudConfigDir, "properties"),
    `[auth]\naccess_token_file = ${tokenFilePath}\n`,
    { mode: 0o600 },
  );

  // Step 3: Create a session token provider that auto-refreshes from the gate.
  // The session ID stays in this closure — the subprocess never sees it.
  const initialToken = {
    access_token: sessionResult.access_token,
    expires_at: new Date(Date.now() + sessionResult.expires_in * 1000),
  };
  const tokenProvider = createSessionTokenProvider(conn, sessionResult.session_id, initialToken, {
    fetchFn: options.fetchOptions?.fetchFn,
    onRefresh: (token) => {
      // Atomically update gcloud's access_token_file (write to temp, rename)
      const tmpPath = `${tokenFilePath}.tmp`;
      writeFileSync(tmpPath, token.access_token, { mode: 0o600 });
      renameSync(tmpPath, tokenFilePath);
    },
  });

  // Step 4: Start temporary metadata proxy with the engineer's email so
  // gcloud can discover the account (it ignores the "default" alias).
  const { server, stop } = startMetadataProxyServer(
    {
      project_id: wpConfig.project_id,
      service_account: sessionResult.email,
      socket_path: wpConfig.socket_path,
      port: 0,
    },
    {
      tokenProvider,
      installSignalHandlers: false,
      quiet: true,
      allowedAncestorPid: process.pid,
      scopes: wpConfig.scopes,
    },
  );

  const metadataHost = `127.0.0.1:${server.port}`;

  let exitCode: number | undefined;
  try {
    // Step 5: Spawn wrapped command with metadata env vars
    const env = applyExtraEnvVars(
      {
        ...stripCredentialEnvVars(process.env),
        GCE_METADATA_HOST: metadataHost,
        GCE_METADATA_IP: metadataHost,
        GCE_METADATA_ROOT: metadataHost,
        CLOUDSDK_CONFIG: gcloudConfigDir,
        // Explicitly set gcloud-specific env vars so `gcloud auth list` and
        // other gcloud commands show the correct active account and project.
        // gcloud's internal account-enumeration code may not honor
        // GCE_METADATA_HOST, falling back to the original metadata proxy.
        // Tokens still flow through the PID-validated metadata proxy.
        CLOUDSDK_CORE_ACCOUNT: sessionResult.email,
        CLOUDSDK_CORE_PROJECT: wpConfig.project_id,
        [PROD_SESSION_ENV_VAR]: metadataHost,
      },
      wpConfig.env,
    );

    const child = spawnFn(wrappedCommand, {
      env,
      stdin: "inherit",
      stdout: "inherit",
      stderr: "inherit",
    });

    // Step 6: Forward signals to child
    const forwardSignal = (signal: NodeJS.Signals) => {
      child.kill(signal === "SIGINT" ? 2 : 15);
    };
    process.on("SIGTERM", () => forwardSignal("SIGTERM"));
    process.on("SIGINT", () => forwardSignal("SIGINT"));

    // Step 7: Wait for child
    exitCode = (await child.exited) ?? undefined;
  } finally {
    stop();
    // Best-effort revoke the session so gate can clean up immediately
    void revokeProdSession(conn, sessionResult.session_id, {
      fetchFn: options.fetchOptions?.fetchFn,
    });
    rmSync(gcloudConfigDir, { recursive: true, force: true });
  }

  process.exit(exitCode ?? 1);
}
