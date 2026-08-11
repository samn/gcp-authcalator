import { z } from "zod";
import { parse as parseTOML } from "smol-toml";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, normalize } from "node:path";
import { DRAIN_MARGIN_MS } from "./gate/pam.ts";

// ---------------------------------------------------------------------------
// Runtime directory helpers
// ---------------------------------------------------------------------------

/**
 * Return a user-private directory for runtime files (sockets, temp data).
 *
 * Prefers $XDG_RUNTIME_DIR (typically /run/user/$UID, already 0o700).
 * Falls back to ~/.gcp-authcalator/.
 *
 * Using a user-private directory instead of /tmp eliminates TOCTOU symlink
 * races — no other user can create files inside the directory.
 */
export function getDefaultRuntimeDir(): string {
  const xdg = process.env.XDG_RUNTIME_DIR;
  if (xdg) return xdg;
  return join(homedir(), ".gcp-authcalator");
}

/** Default socket path inside the user-private runtime directory. */
export function getDefaultSocketPath(): string {
  return join(getDefaultRuntimeDir(), "gcp-authcalator.sock");
}

/**
 * Default admin socket path inside the user-private runtime directory.
 * The parent dir is kernel-isolated `0o700` (owned by the user), unlike
 * `/tmp` which is world-writable and lets another local user pre-create
 * the parent mode `0o777` and intercept the socket.
 */
export function getDefaultAdminSocketPath(): string {
  return join(getDefaultRuntimeDir(), "gcp-authcalator-admin", "admin.sock");
}

/**
 * Sandbox parent dir for `with-prod` (gcloud config + token files,
 * created fresh per invocation). Resolved separately from
 * `getDefaultRuntimeDir()` because the gate's runtime dir may be shared
 * across UIDs (via group perms or a symlink), whereas this dir must be
 * private to the *caller* — typically a different UID than the gate in
 * two-user setups.
 */
export function getDefaultWithProdRuntimeDir(): string {
  const xdg = process.env.XDG_RUNTIME_DIR;
  if (xdg) return xdg;
  const xdgCache = process.env.XDG_CACHE_HOME;
  if (xdgCache) return join(xdgCache, "gcp-authcalator");
  return join(homedir(), ".cache", "gcp-authcalator");
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/** Expand a leading `~` or `~/` to the user's home directory. */
export function expandTilde(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default OAuth scopes when none are configured. */
export const DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"];

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

/**
 * Unix-domain socket paths must identify one unambiguous filesystem entry.
 * Expand the supported home-directory shorthand before checking absoluteness,
 * then canonicalize `.`/`..` components so equivalent paths compare equal.
 */
const unixSocketPathSchema = z
  .string()
  .min(1)
  .transform(expandTilde)
  .refine(isAbsolute, { message: "Unix socket paths must be absolute" })
  .transform(normalize);

/** Coerced, optional seconds field with shared bounds — keeps `token_ttl_seconds`
 *  and `pam_grant_ttl_seconds` (and any future TTL sharing this range) in lockstep. */
const ttlSecondsSchema = z.coerce.number().int().min(60).max(43200).optional();

/**
 * Lower bound for `pam_grant_ttl_seconds`, in seconds. A PAM grant must outlive
 * the drain margin: `hasUsableLifetime` only treats a grant as usable while it
 * has more than `DRAIN_MARGIN_MS` of life left, and minted tokens are clamped
 * to `grant_expiry - DRAIN_MARGIN_MS`. A grant at or below the margin is never
 * usable and every token it backs is clamped to 0 s (born expired), sending the
 * client into a refresh storm. Flooring the *token clamp* instead would be
 * wrong — it would serve tokens valid past the grant's withdrawal — so the
 * guard belongs here, failing fast at config-parse time.
 */
const DRAIN_MARGIN_SECONDS = DRAIN_MARGIN_MS / 1000;

/** `pam_grant_ttl_seconds`: shared TTL bounds, plus the drain-margin floor. */
const pamGrantTtlSecondsSchema = ttlSecondsSchema.refine(
  (v) => v === undefined || v > DRAIN_MARGIN_SECONDS,
  {
    message:
      `pam_grant_ttl_seconds must be greater than the ${DRAIN_MARGIN_SECONDS}s drain margin; ` +
      `a shorter grant would mint already-expired tokens`,
  },
);

function isHttpsOrigin(value: string): boolean {
  if (value !== value.trim() || value.includes("?") || value.includes("#")) return false;

  const schemeSeparator = value.indexOf("://");
  if (schemeSeparator < 0 || value.slice(0, schemeSeparator).toLowerCase() !== "https") {
    return false;
  }

  const afterScheme = value.slice(schemeSeparator + 3);
  const pathSeparator = afterScheme.indexOf("/");
  const authority = pathSeparator < 0 ? afterScheme : afterScheme.slice(0, pathSeparator);
  const rawPath = pathSeparator < 0 ? "" : afterScheme.slice(pathSeparator);
  if (!authority || authority.includes("@") || authority.includes("\\")) return false;
  if (rawPath !== "" && rawPath !== "/") return false;

  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.pathname !== "/") return false;
    if (url.username || url.password) return false;
    return true;
  } catch {
    return false;
  }
}

export const ConfigSchema = z
  .object({
    project_id: z.string().min(1).optional(),
    service_account: z.email().optional(),
    socket_path: unixSocketPathSchema.prefault(getDefaultSocketPath),
    admin_socket_path: unixSocketPathSchema.prefault(getDefaultAdminSocketPath),
    port: z.coerce.number().int().min(1).max(65535).default(8173),
    gate_tls_port: z.coerce.number().int().min(1).max(65535).optional(),
    tls_dir: z.string().min(1).transform(expandTilde).optional(),
    gate_url: z
      .string()
      .min(1)
      .refine(isHttpsOrigin, {
        message: "gate_url must be an HTTPS origin without credentials, a path, query, or fragment",
      })
      .optional(),
    tls_bundle: z.string().min(1).transform(expandTilde).optional(),
    scopes: z.array(z.string().min(1)).min(1).optional(),
    pam_policy: z.string().min(1).optional(),
    pam_allowed_policies: z.array(z.string().min(1)).optional(),
    pam_location: z.string().min(1).optional(),
    token_ttl_seconds: ttlSecondsSchema,
    // PAM grant lifetime. When unset, the PAM grant duration matches
    // `token_ttl_seconds` (the historical behavior). Setting this longer than
    // the token TTL lets cached grants serve many token refreshes before the
    // gate rotates the grant — useful when PAM/IAM propagation latency makes
    // per-rotation pauses visible. Minted tokens stay clamped to
    // `grant_expiry - DRAIN_MARGIN_MS`, so a longer grant only changes how
    // often the gate calls PAM, not how long any individual token is valid.
    pam_grant_ttl_seconds: pamGrantTtlSecondsSchema,
    session_ttl_seconds: z.coerce.number().int().min(300).max(86400).optional(),
    // ---- Operator socket (auto-approve for human-initiated escalation) ----
    operator_socket_path: unixSocketPathSchema.optional(),
    // When set, the operator socket is created mode 0660 group-owned by this
    // group (multi-operator deployments). When unset, the operator socket is
    // mode 0600 owned by the gate UID (the paved single-operator path —
    // operator and gate share a UID, agent has a different UID).
    operator_socket_group: z.string().min(1).optional(),
    auto_approve_pam_policies: z.array(z.string().min(1)).optional(),
    // Numeric UID or username. Required when operator_socket_path is set, so the
    // gate can verify at startup that the agent UID is not the gate UID (and,
    // in group mode, not a member of the operator group). Accepts a number
    // (TOML), a numeric string (env var/CLI), or a username.
    agent_uid: z.union([z.number().int().nonnegative(), z.string().min(1)]).optional(),
    // ---- with-prod quota project (GOOGLE_CLOUD_QUOTA_PROJECT) ----
    // Static override for the quota/billing project of the wrapped command's
    // end-user-credential API calls. When unset (and no_quota_project is not
    // set), with-prod follows the selected target project. See with-prod.ts.
    quota_project: z.string().min(1).optional(),
    // Opt out of managing GOOGLE_CLOUD_QUOTA_PROJECT entirely. Takes precedence
    // over quota_project. The preprocess accepts the literal strings "true"/
    // "false" (env vars / CLI booleans always arrive as those or real booleans)
    // and lets z.boolean() reject anything else loudly — plain z.coerce.boolean()
    // would turn the string "false" into true (non-empty string is truthy).
    no_quota_project: z
      .preprocess((v) => (v === "true" ? true : v === "false" ? false : v), z.boolean())
      .optional(),
    env: z.record(z.string(), z.string()).optional(),
  })
  .strict();

export type Config = z.infer<typeof ConfigSchema>;

/**
 * gate requires project_id and at least one of service_account or pam_policy.
 * - service_account alone: dev tokens via impersonation, prod tokens via ADC
 * - pam_policy alone: prod tokens only (dev tokens disabled)
 * - both: dev tokens via impersonation, prod tokens with PAM escalation
 *
 * If operator_socket_path is set, agent_uid MUST also be set so the gate can
 * verify at startup that the agent UID is not the gate UID (and, in group
 * mode, not a member of the operator group). operator_socket_group is
 * optional: when set, the operator socket is created mode 0660 group-owned
 * by it (multi-operator setup); when unset, the socket is mode 0600 owned by
 * the gate UID (single-operator paved path). Every entry in
 * auto_approve_pam_policies must also be in pam_allowed_policies (or equal
 * pam_policy) — prevents a narrowing of the broader allowlist from leaving
 * a stale auto-approve entry.
 */
export const GateConfigSchema = ConfigSchema.required({
  project_id: true,
})
  .refine((c) => c.service_account || c.pam_policy, {
    message: "gate requires at least one of service_account or pam_policy",
  })
  .refine((c) => !c.operator_socket_path || c.agent_uid !== undefined, {
    message: "agent_uid is required when operator_socket_path is set",
    path: ["agent_uid"],
  })
  .refine(
    (c) => {
      if (!c.auto_approve_pam_policies?.length) return true;
      const allowed = new Set<string>([
        ...(c.pam_policy ? [c.pam_policy] : []),
        ...(c.pam_allowed_policies ?? []),
      ]);
      return c.auto_approve_pam_policies.every((p) => allowed.has(p));
    },
    {
      message:
        "every auto_approve_pam_policies entry must also be in pam_allowed_policies (or equal pam_policy)",
      path: ["auto_approve_pam_policies"],
    },
  )
  .refine(
    (c) => {
      // The gate only creates PAM grants when pam_policy is set (server.ts).
      if (!c.pam_policy) return true;
      // Effective grant lifetime the gate will request, mirroring server.ts:
      // explicit pam_grant_ttl_seconds, else token_ttl_seconds, else the 3600s
      // default. The pam_grant_ttl_seconds field already carries the drain-margin
      // floor on its own; this closes the fallback path where an unset grant TTL
      // silently inherits a sub-margin token_ttl_seconds and mints born-expired
      // tokens. (3600 mirrors server.ts's default; any sane default exceeds the
      // margin, so this stays correct regardless of that constant.)
      const effectiveGrantTtl = c.pam_grant_ttl_seconds ?? c.token_ttl_seconds ?? 3600;
      return effectiveGrantTtl > DRAIN_MARGIN_SECONDS;
    },
    {
      message:
        `token_ttl_seconds becomes the PAM grant lifetime when pam_grant_ttl_seconds is unset, so ` +
        `with pam_policy set it must exceed the ${DRAIN_MARGIN_SECONDS}s drain margin (a shorter grant ` +
        `mints already-expired tokens). Set pam_grant_ttl_seconds explicitly above ${DRAIN_MARGIN_SECONDS}s.`,
      path: ["token_ttl_seconds"],
    },
  )
  .superRefine((config, ctx) => {
    const socketPaths = [
      ["socket_path", config.socket_path],
      ["admin_socket_path", config.admin_socket_path],
      ["operator_socket_path", config.operator_socket_path],
    ] as const;
    const firstKeyByPath = new Map<string, string>();

    for (const [key, socketPath] of socketPaths) {
      if (socketPath === undefined) continue;
      const firstKey = firstKeyByPath.get(socketPath);
      if (firstKey !== undefined) {
        ctx.addIssue({
          code: "custom",
          message: `${key} must not resolve to the same path as ${firstKey}`,
          path: [key],
        });
      } else {
        firstKeyByPath.set(socketPath, key);
      }
    }
  });

export type GateConfig = z.infer<typeof GateConfigSchema>;

/** metadata-proxy requires project_id. */
export const MetadataProxyConfigSchema = ConfigSchema.required({
  project_id: true,
});

export type MetadataProxyConfig = z.infer<typeof MetadataProxyConfigSchema>;

/** with-prod requires project_id. */
export const WithProdConfigSchema = ConfigSchema.required({
  project_id: true,
});

export type WithProdConfig = z.infer<typeof WithProdConfigSchema>;

// ---------------------------------------------------------------------------
// CLI-arg key mapping (kebab-case → snake_case)
// ---------------------------------------------------------------------------

const cliToConfigKey: Record<string, keyof Config> = {
  "project-id": "project_id",
  "service-account": "service_account",
  "socket-path": "socket_path",
  "admin-socket-path": "admin_socket_path",
  port: "port",
  "gate-tls-port": "gate_tls_port",
  "tls-dir": "tls_dir",
  "gate-url": "gate_url",
  "tls-bundle": "tls_bundle",
  scopes: "scopes",
  "pam-policy": "pam_policy",
  "pam-allowed-policies": "pam_allowed_policies",
  "pam-location": "pam_location",
  "token-ttl-seconds": "token_ttl_seconds",
  "pam-grant-ttl-seconds": "pam_grant_ttl_seconds",
  "session-ttl-seconds": "session_ttl_seconds",
  "operator-socket-path": "operator_socket_path",
  "operator-socket-group": "operator_socket_group",
  "auto-approve-pam-policies": "auto_approve_pam_policies",
  "agent-uid": "agent_uid",
  "quota-project": "quota_project",
  "no-quota-project": "no_quota_project",
};

/** Convert a CLI-arg values object (kebab-case keys) to config keys (snake_case). */
export function mapCliArgs(
  cliValues: Record<string, string | boolean | undefined>,
): Record<string, unknown> {
  const mapped: Record<string, unknown> = {};
  for (const [cliKey, value] of Object.entries(cliValues)) {
    if (value === undefined) continue;
    const configKey = cliToConfigKey[cliKey];
    if (configKey) {
      // Split comma-separated values into arrays for list fields
      if (
        (configKey === "scopes" ||
          configKey === "pam_allowed_policies" ||
          configKey === "auto_approve_pam_policies") &&
        typeof value === "string"
      ) {
        mapped[configKey] = value.split(",").map((s) => s.trim());
      } else {
        mapped[configKey] = value;
      }
    }
  }
  return mapped;
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

/** All config keys that can be set via environment variables. */
const configKeys: readonly (keyof Config)[] = [
  "project_id",
  "service_account",
  "socket_path",
  "admin_socket_path",
  "port",
  "gate_tls_port",
  "tls_dir",
  "gate_url",
  "tls_bundle",
  "pam_policy",
  "pam_location",
  "token_ttl_seconds",
  "pam_grant_ttl_seconds",
  "session_ttl_seconds",
  "operator_socket_path",
  "operator_socket_group",
  "agent_uid",
  "quota_project",
  "no_quota_project",
];

/**
 * Read config values from GCP_AUTHCALATOR_* environment variables.
 * Each config key maps to GCP_AUTHCALATOR_{KEY_UPPERCASED}.
 */
export function loadEnvVars(): Record<string, unknown> {
  const envValues: Record<string, unknown> = {};
  for (const key of configKeys) {
    const envKey = `GCP_AUTHCALATOR_${key.toUpperCase()}`;
    const value = process.env[envKey];
    if (value !== undefined) {
      envValues[key] = value;
    }
  }
  return envValues;
}

/** Read and parse a TOML config file. */
export function loadTOML(configPath: string): Record<string, unknown> {
  const content = readFileSync(configPath, "utf-8");
  return parseTOML(content) as Record<string, unknown>;
}

/**
 * Load configuration by merging TOML file values, env-var overrides,
 * and CLI arg overrides, then validating through the base ConfigSchema.
 * Precedence: CLI args > env vars > TOML file > schema defaults.
 */
export function loadConfig(cliValues: Record<string, unknown>, configPath?: string): Config {
  const envValues = loadEnvVars();
  const fileValues = configPath ? loadTOML(configPath) : {};
  const merged = { ...fileValues, ...envValues, ...cliValues };

  // Deep-merge the env record so CLI --env values add to TOML [env] values
  const fileEnv = fileValues.env as Record<string, string> | undefined;
  const cliEnv = cliValues.env as Record<string, string> | undefined;
  if (fileEnv && cliEnv) {
    merged.env = { ...fileEnv, ...cliEnv };
  }

  return ConfigSchema.parse(merged);
}
