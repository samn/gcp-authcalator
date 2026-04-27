import { randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { getDefaultRuntimeDir, WithProdConfigSchema } from "../config.ts";
import {
  createProdSession,
  fetchProdToken,
  revokeProdSession,
  SessionNotPermittedError,
  type FetchProdTokenOptions,
} from "../with-prod/fetch-prod-token.ts";
import { createSessionTokenProvider } from "../with-prod/session-token-provider.ts";
import { createPerRequestTokenProvider } from "../with-prod/per-request-token-provider.ts";
import type { TokenProvider } from "../metadata-proxy/types.ts";
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

  // Step 1: Create prod session at gcp-gate (triggers confirmation dialog).
  // If the gate is the operator socket, session creation returns 403 and we
  // fall back to per-request token mode (each refresh hits the gate, which
  // auto-approves silently if the PAM policy is allowlisted).
  const pendingId = randomBytes(16).toString("hex");
  console.log("with-prod: requesting prod session from gcp-gate...");
  console.log(
    `with-prod: if no prompt appears, approve with: gcp-authcalator approve ${pendingId}`,
  );
  let conn: GateConnection;
  let initialEmail: string;
  let initialAccessToken: string;
  let initialExpiresIn: number;
  let sessionId: string | undefined;
  try {
    conn = await buildGateConnection(wpConfig);
    try {
      const sessionResult = await createProdSession(conn, {
        ...options.fetchOptions,
        command: wrappedCommand,
        scopes: wpConfig.scopes,
        pamPolicy: wpConfig.pam_policy,
        tokenTtlSeconds: wpConfig.token_ttl_seconds,
        sessionTtlSeconds: wpConfig.session_ttl_seconds,
        pendingId,
      });
      sessionId = sessionResult.session_id;
      initialEmail = sessionResult.email;
      initialAccessToken = sessionResult.access_token;
      initialExpiresIn = sessionResult.expires_in;
    } catch (err) {
      if (err instanceof SessionNotPermittedError) {
        console.log(
          "with-prod: operator socket — falling back to per-request token mode (no session)",
        );
        // pendingId is for the CLI approve flow which doesn't apply on the
        // operator socket auto-approve path; the gate would 400 if we sent it.
        const tokenResult = await fetchProdToken(conn, {
          ...options.fetchOptions,
          command: wrappedCommand,
          scopes: wpConfig.scopes,
          pamPolicy: wpConfig.pam_policy,
          tokenTtlSeconds: wpConfig.token_ttl_seconds,
        });
        initialEmail = tokenResult.email;
        initialAccessToken = tokenResult.access_token;
        initialExpiresIn = tokenResult.expires_in;
      } else {
        throw err;
      }
    }
  } catch (err) {
    console.error(
      `with-prod: failed to acquire prod token: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
  console.log(`with-prod: prod access acquired for ${initialEmail}`);

  // Step 2: Create an isolated gcloud config directory BEFORE the token
  // provider so onRefresh can capture the file path in its closure.
  const runtimeDir = getDefaultRuntimeDir();
  mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });
  const gcloudConfigDir = mkdtempSync(join(runtimeDir, "gcp-authcalator-gcloud-"));
  chmodSync(gcloudConfigDir, 0o700);

  const tokenFilePath = join(gcloudConfigDir, "access_token");
  writeFileSync(tokenFilePath, initialAccessToken, { mode: 0o600 });
  writeFileSync(
    join(gcloudConfigDir, "properties"),
    `[auth]\naccess_token_file = ${tokenFilePath}\n`,
    { mode: 0o600 },
  );

  // Step 3: Create a token provider that auto-refreshes from the gate.
  // The session ID (when present) stays in this closure — the subprocess
  // never sees it. In per-request mode there is no session; each refresh
  // re-hits the gate (auto-approved on the operator socket).
  const initialToken = {
    access_token: initialAccessToken,
    expires_at: new Date(Date.now() + initialExpiresIn * 1000),
  };
  const onRefresh = (token: { access_token: string }) => {
    // Atomically update gcloud's access_token_file (write to temp, rename)
    const tmpPath = `${tokenFilePath}.tmp`;
    writeFileSync(tmpPath, token.access_token, { mode: 0o600 });
    renameSync(tmpPath, tokenFilePath);
  };
  const tokenProvider: TokenProvider = sessionId
    ? createSessionTokenProvider(conn, sessionId, initialToken, {
        fetchFn: options.fetchOptions?.fetchFn,
        onRefresh,
      })
    : createPerRequestTokenProvider(conn, initialToken, {
        fetchFn: options.fetchOptions?.fetchFn,
        command: wrappedCommand,
        scopes: wpConfig.scopes,
        pamPolicy: wpConfig.pam_policy,
        tokenTtlSeconds: wpConfig.token_ttl_seconds,
        onRefresh,
      });

  // Step 4: Start temporary metadata proxy with the engineer's email so
  // gcloud can discover the account (it ignores the "default" alias).
  const { server, stop } = startMetadataProxyServer(
    {
      project_id: wpConfig.project_id,
      service_account: initialEmail,
      socket_path: wpConfig.socket_path,
      admin_socket_path: wpConfig.admin_socket_path,
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
        CLOUDSDK_CORE_ACCOUNT: initialEmail,
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
    // Best-effort revoke the session so gate can clean up immediately.
    // In per-request mode (operator socket) there is no session to revoke.
    if (sessionId) {
      void revokeProdSession(conn, sessionId, {
        fetchFn: options.fetchOptions?.fetchFn,
      });
    }
    rmSync(gcloudConfigDir, { recursive: true, force: true });
  }

  process.exit(exitCode ?? 1);
}
