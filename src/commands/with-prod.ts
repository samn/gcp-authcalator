import { randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { getDefaultWithProdRuntimeDir, WithProdConfigSchema } from "../config.ts";
import {
  createProdSession,
  fetchProdToken,
  revokeProdSession,
  SessionNotPermittedError,
  type FetchProdTokenOptions,
} from "../with-prod/fetch-prod-token.ts";
import { CredentialsExpiredError } from "../gate/credentials-error.ts";
import { createSessionTokenProvider } from "../with-prod/session-token-provider.ts";
import { createPerRequestTokenProvider } from "../with-prod/per-request-token-provider.ts";
import type { TokenProvider } from "../metadata-proxy/types.ts";
import { startMetadataProxyServer } from "../metadata-proxy/server.ts";
import { detectNestedSession, PROD_SESSION_ENV_VAR } from "../with-prod/detect-nested-session.ts";
import {
  buildGateConnection,
  connectionFetchOpts,
  fetchWithGateTimeout,
} from "../gate/connection.ts";
import type { GateConnection } from "../gate/connection.ts";
import { formatVersion } from "../version.ts";
import type { Subprocess } from "bun";

/**
 * Delay before printing the CLI approval hint. The hint is noise in the common
 * case (a confirmation prompt appears immediately), so we only surface it once
 * a request has been outstanding long enough to look stuck.
 */
const APPROVE_HINT_DELAY_MS = 10_000;

/** Fail fast when the gate transport is unreachable before starting acquisition. */
const GATE_PREFLIGHT_TIMEOUT_MS = 3_000;

/** Give a wrapped command a short window to clean up before forcing it to exit. */
const CHILD_SIGNAL_GRACE_MS = 5_000;

async function preflightGate(
  conn: GateConnection,
  fetchFn: typeof globalThis.fetch,
  signal?: AbortSignal,
): Promise<void> {
  const { baseUrl, extraOpts } = connectionFetchOpts(conn);
  // Any complete HTTP response proves the transport is alive. Do not require a
  // 2xx here: an older-but-reachable gate may not implement /health, and the
  // real acquisition request will report its protocol error precisely.
  await fetchWithGateTimeout(
    fetchFn,
    `${baseUrl}/health`,
    { ...extraOpts, signal },
    GATE_PREFLIGHT_TIMEOUT_MS,
  );
}

class AcquisitionInterruptedError extends Error {
  constructor(readonly signal: "SIGINT" | "SIGTERM") {
    super(`with-prod acquisition interrupted by ${signal}`);
    this.name = "AcquisitionInterruptedError";
  }
}

/** Startup banner naming the running build and the project being targeted. */
function startupBanner(projectId: string): string {
  return `gcp-authcalator v${formatVersion()} with-prod for project ${projectId}`;
}

type SpawnFn = (
  cmd: string[],
  opts: {
    env: Record<string, string | undefined>;
    stdin: "inherit";
    stdout: "inherit";
    stderr: "inherit";
  },
) => Subprocess;

export interface ChildSignalSource {
  on(signal: "SIGINT" | "SIGTERM", listener: () => void): unknown;
  off(signal: "SIGINT" | "SIGTERM", listener: () => void): unknown;
}

type ScheduleForceKill = (callback: () => void, delayMs: number) => () => void;

export interface WaitForChildExitOptions {
  /** Override the signal source for deterministic tests. */
  signalSource?: ChildSignalSource;
  /** Override timer scheduling for deterministic tests. */
  scheduleForceKill?: ScheduleForceKill;
}

const scheduleForceKill: ScheduleForceKill = (callback, delayMs) => {
  const timer = setTimeout(callback, delayMs);
  timer.unref?.();
  return () => clearTimeout(timer);
};

/**
 * Wait for a wrapped child while forwarding termination signals safely.
 *
 * The first SIGINT/SIGTERM is forwarded so the child can clean up. If it has
 * not exited after the grace period, SIGKILL prevents `with-prod` from hanging
 * forever. A second signal skips the remaining grace period. Listeners and a
 * pending escalation timer are always removed before returning or throwing.
 */
export async function waitForChildExit(
  child: Subprocess,
  options: WaitForChildExitOptions = {},
): Promise<number | undefined> {
  const signalSource = options.signalSource ?? process;
  const schedule = options.scheduleForceKill ?? scheduleForceKill;
  let signalForwarded = false;
  let cancelEscalation: (() => void) | undefined;

  const tryKill = (signal: number) => {
    try {
      child.kill(signal);
    } catch {
      // The child may have exited between delivery and kill(). Its `exited`
      // promise remains the authoritative completion signal.
    }
  };

  const forceKill = () => {
    cancelEscalation = undefined;
    tryKill(9);
  };
  const forwardSignal = (signal: "SIGINT" | "SIGTERM") => {
    if (signalForwarded) {
      cancelEscalation?.();
      cancelEscalation = undefined;
      tryKill(9);
      return;
    }

    signalForwarded = true;
    tryKill(signal === "SIGINT" ? 2 : 15);
    cancelEscalation = schedule(forceKill, CHILD_SIGNAL_GRACE_MS);
  };
  const onSigint = () => forwardSignal("SIGINT");
  const onSigterm = () => forwardSignal("SIGTERM");

  signalSource.on("SIGINT", onSigint);
  signalSource.on("SIGTERM", onSigterm);
  try {
    return (await child.exited) ?? undefined;
  } finally {
    signalSource.off("SIGINT", onSigint);
    signalSource.off("SIGTERM", onSigterm);
    cancelEscalation?.();
  }
}

export interface WithProdOptions {
  /** Override fetch for testing (passed to fetchProdToken and detectNestedSession). */
  fetchOptions?: FetchProdTokenOptions;
  /** Override Bun.spawn for testing. */
  spawnFn?: SpawnFn;
  /** Override the process signal source for deterministic lifecycle tests. */
  signalSource?: ChildSignalSource;
  /**
   * Per-invocation GCP project that this `with-prod` should target, overriding
   * `config.project_id`. Wired in by the CLI's `--project` flag. The override
   * threads through to the metadata-proxy (so `gcloud config get-value
   * project` and `/computeMetadata/v1/project/project-id` reflect the target),
   * the wrapped child's `CLOUDSDK_CORE_PROJECT`, the nested-session
   * compatibility check, and the `X-Target-Project` header sent to the gate
   * (audit-only).
   */
  projectOverride?: string;
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

/**
 * Resolve the GOOGLE_CLOUD_QUOTA_PROJECT value for the wrapped command, or
 * undefined to leave the inherited environment untouched.
 *
 * Quota project matters for end-user-credential (prod) API calls, which Google
 * APIs bill/quota against a caller-chosen project. The paved default is to
 * follow the selected target project so the project being worked on pays for
 * its own quota.
 *
 * - no_quota_project: opt out — we neither set, override, nor delete the var,
 *   so a value already in the environment passes through unchanged.
 * - quota_project: static override (e.g. a dedicated billing project).
 * - otherwise: follow the resolved target project.
 *
 * Following the selected project requires the active credential to hold
 * `serviceusage.services.use` on it; no_quota_project is the escape hatch when
 * it doesn't.
 */
function resolveQuotaProject(
  projectId: string,
  quotaProject: string | undefined,
  noQuotaProject: boolean | undefined,
): string | undefined {
  if (noQuotaProject) return undefined;
  return quotaProject ?? projectId;
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

/**
 * Replace gcloud's token file without following a caller-planted temp symlink.
 *
 * The wrapped command can write inside its CLOUDSDK_CONFIG directory. A fixed
 * `access_token.tmp` path lets it pre-create a symlink and make the privileged
 * wrapper overwrite an arbitrary file on refresh. A random, exclusive-create
 * path ensures the write opens a new regular file before the atomic rename.
 */
export function replaceTokenFile(tokenFilePath: string, accessToken: string): void {
  const tmpPath = `${tokenFilePath}.${randomBytes(12).toString("hex")}.tmp`;
  try {
    writeFileSync(tmpPath, accessToken, { mode: 0o600, flag: "wx" });
    renameSync(tmpPath, tokenFilePath);
  } finally {
    rmSync(tmpPath, { force: true });
  }
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

  const exitCode = await waitForChildExit(child);
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

  // Target project for this invocation. CLI --project beats config.project_id.
  // May be undefined before the schema parse below — that's fine for the
  // nested-session reuse path, which inherits the project from the parent.
  let effectiveProjectId = options.projectOverride ?? config.project_id;

  const nestedSession = await detectNestedSession(process.env, options.fetchOptions?.fetchFn);

  if (nestedSession) {
    // If the caller explicitly requested a different project, fall through to
    // a new session so the confirmation dialog reflects the correct project.
    if (effectiveProjectId && effectiveProjectId !== nestedSession.projectId) {
      console.error(
        `with-prod: requested project ${effectiveProjectId} differs from active session (${nestedSession.projectId}), starting new session`,
      );
    } else {
      console.error(startupBanner(nestedSession.projectId));
      console.error(
        `with-prod: reusing existing prod session for project ${nestedSession.projectId} (proxy at ${nestedSession.metadataHost})`,
      );

      const env: Record<string, string | undefined> = {
        ...stripCredentialEnvVars(process.env),
        GCE_METADATA_HOST: nestedSession.metadataHost,
        GCE_METADATA_IP: nestedSession.metadataHost,
        GCE_METADATA_ROOT: nestedSession.metadataHost,
        CLOUDSDK_CORE_ACCOUNT: nestedSession.email,
        CLOUDSDK_CORE_PROJECT: nestedSession.projectId,
        // Pin the client-library project vars to the session's project (see the
        // main flow for why a leaked parent value would otherwise win).
        GOOGLE_CLOUD_PROJECT: nestedSession.projectId,
        GCLOUD_PROJECT: nestedSession.projectId,
        [PROD_SESSION_ENV_VAR]: nestedSession.metadataHost,
      };

      // Preserve parent's CLOUDSDK_CONFIG if set
      if (process.env.CLOUDSDK_CONFIG) {
        env.CLOUDSDK_CONFIG = process.env.CLOUDSDK_CONFIG;
      }

      // Quota project follows the session's project (opt-out leaves any
      // inherited value untouched — see resolveQuotaProject).
      const quotaProject = resolveQuotaProject(
        nestedSession.projectId,
        config.quota_project,
        config.no_quota_project,
      );
      if (quotaProject !== undefined) {
        env.GOOGLE_CLOUD_QUOTA_PROJECT = quotaProject;
      }

      await spawnAndWait(wrappedCommand, applyExtraEnvVars(env, config.env), spawnFn);
    }
  }

  // Normal flow: create a prod session and start a fresh proxy. The schema
  // requires project_id; fold the CLI --project override in first so it can
  // satisfy that requirement even when no project_id is configured. The parse
  // then narrows effectiveProjectId to a definite string for the rest of the
  // function (and still throws if neither a config value nor an override exists).
  const configForParse: Config = options.projectOverride
    ? { ...config, project_id: options.projectOverride }
    : config;
  const wpConfig = WithProdConfigSchema.parse(configForParse);
  effectiveProjectId = wpConfig.project_id;

  console.error(startupBanner(effectiveProjectId));

  // Install interruption handling before the first gate request. The default
  // SIGINT/SIGTERM action would terminate immediately and skip JS cleanup if a
  // session response or token-file setup were in flight. During acquisition we
  // instead abort the client request and leave the normal error/cleanup path in
  // control; once a child exists, waitForChildExit takes over signal forwarding.
  const acquisitionController = new AbortController();
  let acquisitionInterruptedBy: "SIGINT" | "SIGTERM" | undefined;
  const interruptAcquisition = (signal: "SIGINT" | "SIGTERM") => {
    if (acquisitionInterruptedBy) return;
    acquisitionInterruptedBy = signal;
    acquisitionController.abort(new AcquisitionInterruptedError(signal));
  };
  const onAcquisitionSigint = () => interruptAcquisition("SIGINT");
  const onAcquisitionSigterm = () => interruptAcquisition("SIGTERM");
  let acquisitionSignalHandlersInstalled = true;
  const signalSource = options.signalSource ?? process;
  signalSource.on("SIGINT", onAcquisitionSigint);
  signalSource.on("SIGTERM", onAcquisitionSigterm);
  const removeAcquisitionSignalHandlers = () => {
    if (!acquisitionSignalHandlersInstalled) return;
    acquisitionSignalHandlersInstalled = false;
    signalSource.off("SIGINT", onAcquisitionSigint);
    signalSource.off("SIGTERM", onAcquisitionSigterm);
  };
  const callerSignal = options.fetchOptions?.signal;
  const acquisitionSignal = callerSignal
    ? AbortSignal.any([callerSignal, acquisitionController.signal])
    : acquisitionController.signal;
  const acquisitionFetchOptions: FetchProdTokenOptions = {
    ...options.fetchOptions,
    signal: acquisitionSignal,
  };

  // Step 1: Create prod session at gcp-gate (triggers confirmation dialog).
  // If the gate is the operator socket, session creation returns 403 and we
  // fall back to per-request token mode (each refresh hits the gate, which
  // auto-approves silently if the PAM policy is allowlisted).
  const pendingId = randomBytes(16).toString("hex");
  let hintTimer: ReturnType<typeof setTimeout> | undefined;
  let conn!: GateConnection;
  let initialEmail: string;
  let initialAccessToken: string;
  let initialExpiresIn: number;
  let sessionId: string | undefined;
  try {
    conn = await buildGateConnection(wpConfig);
    await preflightGate(
      conn,
      acquisitionFetchOptions.fetchFn ?? globalThis.fetch,
      acquisitionSignal,
    );

    // Only surface the manual-approval hint if no prompt has been approved within
    // APPROVE_HINT_DELAY_MS — otherwise it's noise in the common (fast) path.
    hintTimer = setTimeout(() => {
      console.error(
        // Only mention `pending` as the no-dialog path: the gate queues a
        // request only when it has no GUI or TTY prompt available, so on a
        // desktop host this ID was never queued and `pending <id>` would report
        // it missing while the dialog is still open and waiting.
        `with-prod: still waiting for approval — check for a dialog on the host.\n` +
          `with-prod: if no prompt appears, review and approve with: ` +
          `gcp-authcalator pending ${pendingId} && gcp-authcalator approve ${pendingId}`,
      );
    }, APPROVE_HINT_DELAY_MS);
    hintTimer.unref?.(); // never keep the event loop alive for the hint alone

    try {
      const sessionResult = await createProdSession(conn, {
        ...acquisitionFetchOptions,
        command: wrappedCommand,
        scopes: wpConfig.scopes,
        pamPolicy: wpConfig.pam_policy,
        tokenTtlSeconds: wpConfig.token_ttl_seconds,
        sessionTtlSeconds: wpConfig.session_ttl_seconds,
        pendingId,
        targetProject: effectiveProjectId,
      });
      sessionId = sessionResult.session_id;
      initialEmail = sessionResult.email;
      initialAccessToken = sessionResult.access_token;
      initialExpiresIn = sessionResult.expires_in;
    } catch (err) {
      if (err instanceof SessionNotPermittedError) {
        // Operator socket auto-approves per-request; there is no human prompt to
        // hint about, so cancel the deferred approval hint.
        clearTimeout(hintTimer);
        // pendingId is for the CLI approve flow which doesn't apply on the
        // operator socket auto-approve path; the gate would 400 if we sent it.
        const tokenResult = await fetchProdToken(conn, {
          ...acquisitionFetchOptions,
          command: wrappedCommand,
          scopes: wpConfig.scopes,
          pamPolicy: wpConfig.pam_policy,
          tokenTtlSeconds: wpConfig.token_ttl_seconds,
          targetProject: effectiveProjectId,
        });
        initialEmail = tokenResult.email;
        initialAccessToken = tokenResult.access_token;
        initialExpiresIn = tokenResult.expires_in;
      } else {
        throw err;
      }
    }
  } catch (err) {
    clearTimeout(hintTimer);
    removeAcquisitionSignalHandlers();
    if (sessionId) {
      await revokeProdSession(conn, sessionId, {
        fetchFn: options.fetchOptions?.fetchFn,
      });
    }
    if (acquisitionInterruptedBy) {
      process.exit(acquisitionInterruptedBy === "SIGINT" ? 130 : 143);
    }
    // CredentialsExpiredError already carries the full reauth instruction;
    // forwarding the message verbatim keeps the actionable text intact.
    if (err instanceof CredentialsExpiredError) {
      console.error(`with-prod: ${err.message}`);
    } else {
      console.error(
        `with-prod: failed to acquire prod token: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    process.exit(1);
  }
  clearTimeout(hintTimer);
  console.error(
    `with-prod: prod access acquired for ${initialEmail} on project ${effectiveProjectId}`,
  );

  let gcloudConfigDir: string | undefined;
  let stopProxy: (() => void) | undefined;
  let previousUmask: number | undefined;
  let exitCode: number | undefined;

  // Everything after session acquisition is one transaction. Any setup error
  // must restore the process umask, revoke the live session, and remove any
  // token-bearing files that were created before the failure.
  try {
    // Tighten umask only around the token-bearing file creation below. The
    // wrapped child must not inherit it, even when mkdir/write throws.
    previousUmask = process.umask(0o077);
    try {
      // Step 2: Create an isolated gcloud config directory BEFORE the token
      // provider so onRefresh can capture the file path in its closure.
      // The sandbox dir (mkdtempSync) is the real security boundary — created
      // 0o700 owned by the caller, with 0o600 token files inside — so the
      // parent's exact mode doesn't matter. mkdirSync no-ops on existing dirs.
      const runtimeDir = getDefaultWithProdRuntimeDir();
      mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });
      gcloudConfigDir = mkdtempSync(join(runtimeDir, "gcp-authcalator-gcloud-"));
      chmodSync(gcloudConfigDir, 0o700);

      const tokenFilePath = join(gcloudConfigDir, "access_token");
      writeFileSync(tokenFilePath, initialAccessToken, { mode: 0o600 });
      writeFileSync(
        join(gcloudConfigDir, "properties"),
        `[auth]\naccess_token_file = ${tokenFilePath}\n`,
        { mode: 0o600 },
      );
    } finally {
      process.umask(previousUmask);
      previousUmask = undefined;
    }

    const tokenFilePath = join(gcloudConfigDir, "access_token");

    // Step 3: Create a token provider that auto-refreshes from the gate.
    // The session ID (when present) stays in this closure — the subprocess
    // never sees it. In per-request mode there is no session; each refresh
    // re-hits the gate (auto-approved on the operator socket).
    const initialToken = {
      access_token: initialAccessToken,
      expires_at: new Date(Date.now() + initialExpiresIn * 1000),
    };
    const onRefresh = (token: { access_token: string }) => {
      replaceTokenFile(tokenFilePath, token.access_token);
    };
    const tokenProvider: TokenProvider = sessionId
      ? createSessionTokenProvider(conn, sessionId, initialToken, {
          fetchFn: options.fetchOptions?.fetchFn,
          onRefresh,
          targetProject: effectiveProjectId,
        })
      : createPerRequestTokenProvider(conn, initialToken, {
          fetchFn: options.fetchOptions?.fetchFn,
          command: wrappedCommand,
          scopes: wpConfig.scopes,
          pamPolicy: wpConfig.pam_policy,
          tokenTtlSeconds: wpConfig.token_ttl_seconds,
          targetProject: effectiveProjectId,
          onRefresh,
        });

    // Step 4: Start temporary metadata proxy with the engineer's email so
    // gcloud can discover the account (it ignores the "default" alias).
    const { server, stop } = startMetadataProxyServer(
      {
        project_id: effectiveProjectId,
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
    stopProxy = stop;

    const metadataHost = `127.0.0.1:${server.port}`;

    // Step 5: Spawn wrapped command with metadata env vars
    const baseEnv: Record<string, string | undefined> = {
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
      CLOUDSDK_CORE_PROJECT: effectiveProjectId,
      // Google client libraries (google-auth for Python/Node/etc.) resolve
      // the project from these env vars *before* the metadata server, so a
      // parent GOOGLE_CLOUD_PROJECT/GCLOUD_PROJECT (common in devcontainers)
      // would otherwise silently override the target project. Pin them.
      GOOGLE_CLOUD_PROJECT: effectiveProjectId,
      GCLOUD_PROJECT: effectiveProjectId,
      [PROD_SESSION_ENV_VAR]: metadataHost,
    };
    // Quota project for end-user-credential API calls. Follows the target
    // project by default; opt-out leaves any inherited value untouched. Set
    // before applyExtraEnvVars so an explicit [env] entry still wins.
    const quotaProject = resolveQuotaProject(
      effectiveProjectId,
      wpConfig.quota_project,
      wpConfig.no_quota_project,
    );
    if (quotaProject !== undefined) {
      baseEnv.GOOGLE_CLOUD_QUOTA_PROJECT = quotaProject;
    }
    const env = applyExtraEnvVars(baseEnv, wpConfig.env);

    const child = spawnFn(wrappedCommand, {
      env,
      stdin: "inherit",
      stdout: "inherit",
      stderr: "inherit",
    });

    // Step 6: Forward signals with bounded cleanup, then wait for the child.
    // Switching handlers is synchronous, so no signal can be delivered in the
    // gap between removing the acquisition listener and installing the child
    // supervisor inside waitForChildExit.
    removeAcquisitionSignalHandlers();
    exitCode = await waitForChildExit(child, { signalSource });
  } finally {
    removeAcquisitionSignalHandlers();
    // Restore defensively in case setup failed inside the narrow umask block
    // before its own finally ran to completion.
    if (previousUmask !== undefined) process.umask(previousUmask);
    stopProxy?.();
    // Best-effort revoke the session so gate can clean up immediately.
    // In per-request mode (operator socket) there is no session to revoke.
    if (sessionId) {
      // Await so the DELETE is actually transmitted before process.exit() below
      // tears down the event loop. revokeProdSession swallows its own errors.
      await revokeProdSession(conn, sessionId, {
        fetchFn: options.fetchOptions?.fetchFn,
      });
    }
    if (gcloudConfigDir) rmSync(gcloudConfigDir, { recursive: true, force: true });
  }

  process.exit(exitCode ?? 1);
}
