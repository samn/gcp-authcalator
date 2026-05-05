import { z } from "zod";
import { parse as parseTOML } from "smol-toml";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

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
 *
 * Uses `$XDG_RUNTIME_DIR/gcp-authcalator-admin/admin.sock` (typically
 * `/run/user/<uid>/gcp-authcalator-admin/admin.sock`) so the parent
 * directory is `0o700` and owned by the user — kernel-enforced
 * isolation from other local users on shared hosts.
 *
 * Falls back to `~/.gcp-authcalator/admin/admin.sock` when
 * `$XDG_RUNTIME_DIR` is not set. The previous default
 * (`/tmp/gcp-authcalator-admin-<uid>/admin.sock`) was vulnerable on
 * multi-user hosts: another local user could pre-create that
 * directory mode `0o777` before the gate started and intercept the
 * socket. Like the main socket, the admin socket is not bind-mounted
 * into containers in any sensible setup, so this change does not
 * affect the "admin socket unreachable from devcontainer processes"
 * property.
 */
export function getDefaultAdminSocketPath(): string {
  return join(getDefaultRuntimeDir(), "gcp-authcalator-admin", "admin.sock");
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

export const ConfigSchema = z.object({
  project_id: z.string().min(1).optional(),
  service_account: z.email().optional(),
  socket_path: z.string().min(1).default(getDefaultSocketPath).transform(expandTilde),
  admin_socket_path: z.string().min(1).default(getDefaultAdminSocketPath).transform(expandTilde),
  port: z.coerce.number().int().min(1).max(65535).default(8173),
  gate_tls_port: z.coerce.number().int().min(1).max(65535).optional(),
  tls_dir: z.string().min(1).transform(expandTilde).optional(),
  gate_url: z
    .string()
    .min(1)
    .refine((v) => v.startsWith("https://"), { message: "gate_url must use https://" })
    .optional(),
  tls_bundle: z.string().min(1).transform(expandTilde).optional(),
  scopes: z.array(z.string().min(1)).optional(),
  pam_policy: z.string().min(1).optional(),
  pam_allowed_policies: z.array(z.string().min(1)).optional(),
  pam_location: z.string().min(1).optional(),
  token_ttl_seconds: z.coerce.number().int().min(60).max(43200).optional(),
  session_ttl_seconds: z.coerce.number().int().min(300).max(86400).optional(),
  // ---- Operator socket (auto-approve for human-initiated escalation) ----
  operator_socket_path: z.string().min(1).transform(expandTilde).optional(),
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
  env: z.record(z.string(), z.string()).optional(),
});

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
  );

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
  "session-ttl-seconds": "session_ttl_seconds",
  "operator-socket-path": "operator_socket_path",
  "operator-socket-group": "operator_socket_group",
  "auto-approve-pam-policies": "auto_approve_pam_policies",
  "agent-uid": "agent_uid",
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
  "session_ttl_seconds",
  "operator_socket_path",
  "operator_socket_group",
  "agent_uid",
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
 * Load configuration by merging TOML file values, env-var overrides, and
 * CLI arg overrides, then validating through the base ConfigSchema.
 *
 * Precedence: CLI args > env vars > TOML file > schema defaults.
 *
 * Until v0.10 this was env > CLI > TOML, which inverted universal
 * convention and let an inherited env var silently override an explicit
 * `--flag` invocation — a footgun for operators (and a defense-in-depth
 * concern for hardened deployments). The new precedence matches every
 * other CLI in this space: the most specific source the operator typed
 * wins.
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
